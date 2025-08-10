#include "CertificateHttpService.h"
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
std::vector<unsigned char> certificateBase64Decode(const std::string& base64_string) {
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
std::string certificateBase64Encode(const std::vector<unsigned char>& data) {
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
 * @brief Makes an HTTP GET request to fetch a certificate and returns it as base64.
 */
std::string fetchCertificateFromUrl(const std::string& certificateUrl) {
    Logger::info("=== Starting Certificate Download Service ===");
    Logger::debug("Certificate URL", certificateUrl);

    // Initialize WinHTTP
    HINTERNET hSession = WinHttpOpen(
        L"Certificate Fetcher/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession) {
        throw std::runtime_error("Failed to initialize WinHTTP session");
    }

    // Parse URL
    size_t protocolEnd = certificateUrl.find("://");
    if (protocolEnd == std::string::npos) {
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("Invalid URL format: missing protocol");
    }

    std::string protocol = certificateUrl.substr(0, protocolEnd);
    std::string rest = certificateUrl.substr(protocolEnd + 3);

    size_t hostEnd = rest.find('/');
    std::string host = (hostEnd == std::string::npos) ? rest : rest.substr(0, hostEnd);
    std::string path = (hostEnd == std::string::npos) ? "/" : rest.substr(hostEnd);

    // Convert host to wide string
    std::wstring whost(host.begin(), host.end());

    // Determine port
    INTERNET_PORT port = (protocol == "https") ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;

    // Connect
    HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("Failed to connect to host: " + host);
    }

    // Convert path to wide string
    std::wstring wpath(path.begin(), path.end());

    // Open request
    DWORD flags = (protocol == "https") ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        wpath.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags
    );

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("Failed to open HTTP request");
    }

    // Send request
    Logger::info("Sending HTTP GET request to certificate URL...");
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("Failed to send HTTP request");
    }

    // Receive response
    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("Failed to receive HTTP response");
    }

    // Check status code
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("Failed to query HTTP status code");
    }

    Logger::info("Certificate server returned HTTP status " + std::to_string(statusCode));

    if (statusCode != 200) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("Certificate server returned HTTP status " + std::to_string(statusCode));
    }

    // Read response data
    std::vector<unsigned char> responseData;
    DWORD bytesRead = 0;
    DWORD bytesAvailable = 0;

    do {
        if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable)) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            throw std::runtime_error("Failed to query available data");
        }

        if (bytesAvailable > 0) {
            std::vector<unsigned char> buffer(bytesAvailable);
            if (!WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead)) {
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                throw std::runtime_error("Failed to read response data");
            }
            responseData.insert(responseData.end(), buffer.begin(), buffer.begin() + bytesRead);
        }
    } while (bytesAvailable > 0);

    // Cleanup
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    Logger::info("Successfully downloaded certificate");
    Logger::debug("Received certificate response body size", std::to_string(responseData.size()) + " bytes");

    if (responseData.empty()) {
        throw std::runtime_error("Empty certificate response received");
    }

        // Encode response to base64
    Logger::info("Encoding certificate response to base64...");
    std::string base64Response = certificateBase64Encode(responseData);
    Logger::debug("Base64 encoded certificate size", std::to_string(base64Response.size()) + " bytes");

    Logger::info("Certificate download service completed successfully");
    Logger::info("==========================================");

    return base64Response;
}
