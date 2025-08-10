#include "GetCrlFromCertificate.h"
#include "../../core/Logger.h"
#include <openssl/x509v3.h>

/**
 * @brief Downloads a Certificate Revocation List (CRL) from a given URL.
 *
 * This function performs the following steps:
 * 1. Takes a CRL URL.
 * 2. Makes an HTTP/S request to download the binary CRL file.
 * 3. Saves the binary CRL file to disk, naming it after the file in the URL.
 * 4. Encodes the binary CRL data into a base64 string.
 * 5. Returns a pair containing the base64-encoded CRL and the URL it was fetched from.
 *
 * @param crlUrl The URL to download the CRL from.
 * @return A std::pair containing the base64-encoded CRL response and the CRL URL.
 * @throws std::runtime_error if any step fails.
 */
std::pair<std::string, std::string> downloadCrlFromUrl(const std::string& crlUrl)
{
    Logger::info("=== Starting CRL Download Service ===");
    Logger::debug("CRL URL", crlUrl);

    auto base64_encode = [](const std::vector<unsigned char>& data) -> std::string {
        std::unique_ptr<BIO, decltype(&BIO_free)> b64(BIO_new(BIO_f_base64()), BIO_free);
        BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
        std::unique_ptr<BIO, decltype(&BIO_free)> bmem(BIO_new(BIO_s_mem()), BIO_free);
        BIO* bio = BIO_push(b64.get(), bmem.get());

        BIO_write(bio, data.data(), static_cast<int>(data.size()));
        BIO_flush(bio);

        BUF_MEM* bptr = nullptr;
        BIO_get_mem_ptr(bio, &bptr);
        if (!bptr) {
            throw std::runtime_error("Failed to encode data to base64.");
        }
        return std::string(bptr->data, bptr->length);
    };

    Logger::info("Sending HTTP GET request to CRL URL...");
    std::wstring wide_crl_url(crlUrl.begin(), crlUrl.end());

    URL_COMPONENTS url_components = { 0 };
    url_components.dwStructSize = sizeof(url_components);
    wchar_t host_name[256];
    wchar_t url_path[2048];
    url_components.lpszHostName = host_name;
    url_components.dwHostNameLength = 256;
    url_components.lpszUrlPath = url_path;
    url_components.dwUrlPathLength = 2048;

    if (!WinHttpCrackUrl(wide_crl_url.c_str(), 0, 0, &url_components)) {
        Logger::error("Failed to parse CRL URL with WinHttpCrackUrl. Error: " + std::to_string(GetLastError()));
        throw std::runtime_error("Failed to parse CRL URL with WinHttpCrackUrl. Error: " + std::to_string(GetLastError()));
    }

    HINTERNET hSession = WinHttpOpen(L"PoDoFo CRL Fetcher/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        Logger::error("WinHttpOpen failed. Error: " + std::to_string(GetLastError()));
        throw std::runtime_error("WinHttpOpen failed. Error: " + std::to_string(GetLastError()));
    }

    HINTERNET hConnect = WinHttpConnect(hSession, url_components.lpszHostName, url_components.nPort, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        Logger::error("WinHttpConnect failed. Error: " + std::to_string(GetLastError()));
        throw std::runtime_error("WinHttpConnect failed. Error: " + std::to_string(GetLastError()));
    }

    DWORD dwFlags = (url_components.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", url_components.lpszUrlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        Logger::error("WinHttpOpenRequest failed. Error: " + std::to_string(GetLastError()));
        throw std::runtime_error("WinHttpOpenRequest failed. Error: " + std::to_string(GetLastError()));
    }

    if (url_components.nScheme == INTERNET_SCHEME_HTTPS) {
        DWORD dwSslErrorIgnoreFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwSslErrorIgnoreFlags, sizeof(dwSslErrorIgnoreFlags));
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        Logger::error("WinHttpSendRequest failed. Error: " + std::to_string(GetLastError()));
        throw std::runtime_error("WinHttpSendRequest failed. Error: " + std::to_string(GetLastError()));
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        Logger::error("WinHttpReceiveResponse failed. Error: " + std::to_string(GetLastError()));
        throw std::runtime_error("WinHttpReceiveResponse failed. Error: " + std::to_string(GetLastError()));
    }
    Logger::info("CRL response received");

    DWORD dwStatusCode = 0;
    DWORD dwSize = sizeof(dwStatusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
    Logger::info("CRL server returned HTTP status " + std::to_string(dwStatusCode));
    if (dwStatusCode != 200) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        Logger::error("Failed to download CRL. HTTP Status: " + std::to_string(dwStatusCode));
        throw std::runtime_error("Failed to download CRL. HTTP Status: " + std::to_string(dwStatusCode));
    }

    Logger::info("Successfully downloaded CRL");
    std::string response_body;
    DWORD dwBytesAvailable = 0;
    do {
        dwBytesAvailable = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwBytesAvailable)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            Logger::error("WinHttpQueryDataAvailable failed. Error: " + std::to_string(GetLastError()));
            throw std::runtime_error("WinHttpQueryDataAvailable failed. Error: " + std::to_string(GetLastError()));
        }

        if (dwBytesAvailable > 0) {
            std::vector<char> buffer(dwBytesAvailable);
            DWORD dwRead = 0;
            if (WinHttpReadData(hRequest, buffer.data(), dwBytesAvailable, &dwRead)) {
                response_body.append(buffer.data(), dwRead);
            }
            else {
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                Logger::error("WinHttpReadData failed. Error: " + std::to_string(GetLastError()));
                throw std::runtime_error("WinHttpReadData failed. Error: " + std::to_string(GetLastError()));
            }
        }
    } while (dwBytesAvailable > 0);
    Logger::debug("Received CRL response body size", std::to_string(response_body.length()) + " bytes");

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    const std::string output_dir = "input";
    std::filesystem::create_directory(output_dir);
    std::string filename = crlUrl.substr(crlUrl.find_last_of('/') + 1);
    std::filesystem::path output_path(output_dir);
    output_path /= filename;
    std::ofstream ofs(output_path, std::ios::binary);
    ofs.write(response_body.c_str(), response_body.length());
    ofs.close();
    Logger::debug("CRL response saved to", output_path.string());

    Logger::info("Encoding CRL response to base64...");
    std::vector<unsigned char> crl_data(response_body.begin(), response_body.end());
    std::string base64_crl = base64_encode(crl_data);
    Logger::debug("Base64 encoded CRL size", std::to_string(base64_crl.length()) + " bytes");

    Logger::info("CRL download service completed successfully");
    Logger::info("==========================================");
    return { base64_crl, crlUrl };
}
