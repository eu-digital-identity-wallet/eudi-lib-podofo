#include "OCSPHttpService.h"
#include "../../core/Logger.h"
#include <memory>
#include <stdexcept>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <windows.h>
#include <winhttp.h>

/**
 * @brief Decodes a base64 string to a vector of unsigned chars.
 */
std::vector<unsigned char> base64Decode(const std::string& base64_string) {
    std::unique_ptr<BIO, decltype(&BIO_free)> b64(BIO_new(BIO_f_base64()), BIO_free);
    BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
    std::unique_ptr<BIO, decltype(&BIO_free)> bmem(BIO_new_mem_buf(base64_string.data(), static_cast<int>(base64_string.length())), BIO_free);
    BIO* bio = BIO_push(b64.get(), bmem.get());

    std::vector<unsigned char> decoded_data(base64_string.length());
    int decoded_length = BIO_read(bio, decoded_data.data(), static_cast<int>(decoded_data.size()));
    if (decoded_length < 0) {
        throw std::runtime_error("Failed to decode base64: " + std::string(ERR_reason_error_string(ERR_get_error())));
    }
    decoded_data.resize(decoded_length);
    return decoded_data;
}

/**
 * @brief Encodes a vector of unsigned chars to a base64 string.
 */
std::string base64Encode(const std::vector<unsigned char>& data) {
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
}

/**
 * @brief Makes an HTTP POST request to an OCSP responder and returns the response as base64.
 */
std::string makeOcspHttpPostRequest(const std::string& ocspUrl, const std::string& base64OcspRequestData) {
    Logger::info("=== Starting OCSP HTTP POST Request Service ===");
    Logger::debug("OCSP URL", ocspUrl);
    Logger::debug("Base64 OCSP Request Data Size", std::to_string(base64OcspRequestData.length()) + " bytes");

    // Decode the base64 OCSP request data
    std::vector<unsigned char> ocsp_request_data = base64Decode(base64OcspRequestData);
    Logger::debug("Decoded OCSP Request Data Size", std::to_string(ocsp_request_data.size()) + " bytes");

    Logger::info("Sending HTTP POST request to OCSP responder...");
    std::wstring wide_url(ocspUrl.begin(), ocspUrl.end());

    URL_COMPONENTS url_components = { 0 };
    url_components.dwStructSize = sizeof(url_components);
    wchar_t host_name[256];
    wchar_t url_path[2048];
    url_components.lpszHostName = host_name;
    url_components.dwHostNameLength = 256;
    url_components.lpszUrlPath = url_path;
    url_components.dwUrlPathLength = 2048;

    if (!WinHttpCrackUrl(wide_url.c_str(), 0, 0, &url_components)) {
        Logger::error("Failed to parse OCSP URL with WinHttpCrackUrl. Error: " + std::to_string(GetLastError()));
        throw std::runtime_error("Failed to parse OCSP URL with WinHttpCrackUrl. Error: " + std::to_string(GetLastError()));
    }

    HINTERNET hSession = WinHttpOpen(L"PoDoFo OCSP HTTP Client/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
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
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", url_components.lpszUrlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, dwFlags);
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

    const wchar_t* headers_post = L"Content-Type: application/ocsp-request\r\n";
    if (!WinHttpSendRequest(hRequest, headers_post, -1L, ocsp_request_data.data(), static_cast<DWORD>(ocsp_request_data.size()), static_cast<DWORD>(ocsp_request_data.size()), 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        Logger::error("WinHttpSendRequest for OCSP failed. Error: " + std::to_string(GetLastError()));
        throw std::runtime_error("WinHttpSendRequest for OCSP failed. Error: " + std::to_string(GetLastError()));
    }
    Logger::info("OCSP request sent successfully");

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        Logger::error("WinHttpReceiveResponse for OCSP failed. Error: " + std::to_string(GetLastError()));
        throw std::runtime_error("WinHttpReceiveResponse for OCSP failed. Error: " + std::to_string(GetLastError()));
    }
    Logger::info("OCSP response received");

    DWORD dwStatusCode = 0;
    DWORD dwSize = sizeof(dwStatusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
    Logger::info("OCSP server returned HTTP status " + std::to_string(dwStatusCode));
    if (dwStatusCode != 200) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        Logger::error("Failed to download OCSP response. HTTP Status: " + std::to_string(dwStatusCode));
        throw std::runtime_error("Failed to download OCSP response. HTTP Status: " + std::to_string(dwStatusCode));
    }

    Logger::info("Successfully downloaded OCSP response");
    std::string ocsp_response_body;
    DWORD dwBytesAvailable = 0;
    do {
        dwBytesAvailable = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwBytesAvailable)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            Logger::error("WinHttpQueryDataAvailable for OCSP failed. Error: " + std::to_string(GetLastError()));
            throw std::runtime_error("WinHttpQueryDataAvailable for OCSP failed. Error: " + std::to_string(GetLastError()));
        }

        if (dwBytesAvailable > 0) {
            std::vector<char> buffer(dwBytesAvailable);
            DWORD dwRead = 0;
            if (WinHttpReadData(hRequest, buffer.data(), dwBytesAvailable, &dwRead)) {
                ocsp_response_body.append(buffer.data(), dwRead);
            }
            else {
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                Logger::error("WinHttpReadData for OCSP failed. Error: " + std::to_string(GetLastError()));
                throw std::runtime_error("WinHttpReadData for OCSP failed. Error: " + std::to_string(GetLastError()));
            }
        }
    } while (dwBytesAvailable > 0);
    Logger::debug("Received OCSP response body size", std::to_string(ocsp_response_body.length()) + " bytes");

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    Logger::info("Encoding OCSP response to base64...");
    std::vector<unsigned char> ocsp_response_data(ocsp_response_body.begin(), ocsp_response_body.end());
    std::string base64_ocsp_response = base64Encode(ocsp_response_data);
    Logger::debug("Base64 encoded OCSP response size", std::to_string(base64_ocsp_response.length()) + " bytes");

    Logger::info("OCSP HTTP POST request service completed successfully");
    Logger::info("==================================================");
    return base64_ocsp_response;
}
