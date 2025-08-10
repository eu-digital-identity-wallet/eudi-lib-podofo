#include "SignHashService.h"
#include "../../models/CertificateBundle.h"
#include "../../core/Config.h"
#include "../../core/Logger.h"
#include <curl/curl.h>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

/**
 * @brief Signs a hash using the remote signing service with the provided credentials.
 *
 * @param cookie Session cookie for authentication
 * @param accessToken OAuth2 access token for authorization
 * @param credentialID The credential identifier to use for signing
 * @param hash The hash to be signed in base64 format
 * @return The signed hash in base64 format, or empty string on failure
 */
std::string SignHashService(
    const std::string& cookie,
    const std::string& accessToken,
    const std::string& credentialID,
    const std::string& hash
) {
    CURL* curl = curl_easy_init();
    CURLcode res;
    std::string response;
    std::string signedHash;

    const std::string url = Config::getSignHashUrl();

    Logger::info("=== Starting Sign Hash Service ===");
    Logger::info("POST URL: " + url);

    try {
        if (!curl) {
            Logger::error("Failed to initialize CURL");
            throw std::runtime_error("Failed to initialize CURL");
        }

        json body = {
            {"credentialID", credentialID},
            {"hashes", {hash}},
            {"hashAlgorithmOID", "2.16.840.1.101.3.4.2.1"},
            {"signAlgo", "1.2.840.10045.4.3.2"},
            {"operationMode", "S"}
        };

        std::string jsonStr = body.dump();
        Logger::debug("Request JSON body", jsonStr);

        Logger::info("Setting HTTP headers (Content-Type, Authorization, Cookie)");
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        std::string bearer = "Authorization: Bearer " + accessToken;
        headers = curl_slist_append(headers, bearer.c_str());

        std::string cookieHeader = "Cookie: " + cookie;
        headers = curl_slist_append(headers, cookieHeader.c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonStr.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char* ptr, size_t size, size_t nmemb, std::string* data) -> size_t {
            data->append(ptr, size * nmemb);
            return size * nmemb;
            });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        Logger::info("Sending POST request to signHash endpoint...");
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            Logger::error("CURL error: " + std::string(curl_easy_strerror(res)));
            throw std::runtime_error("CURL error: " + std::string(curl_easy_strerror(res)));
        }

        long statusCode;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &statusCode);
        Logger::info("Received HTTP status code: " + std::to_string(statusCode));
        Logger::debug("Raw JSON response", response);

        auto jsonResponse = json::parse(response);
        if (jsonResponse.contains("signatures") && jsonResponse["signatures"].is_array() && !jsonResponse["signatures"].empty()) {
            signedHash = jsonResponse["signatures"][0].get<std::string>();
            Logger::info("Successfully extracted signed hash from response");
            Logger::debug("Signed Hash", signedHash);
        }
        else {
            Logger::error("Response JSON does not contain a 'signatures' array or it is empty");
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    catch (const std::exception& e) {
        Logger::error("Exception in SignHashService: " + std::string(e.what()));
        if (curl) curl_easy_cleanup(curl);
    }

    Logger::info("Sign hash service completed");
    Logger::info("============================");
    return signedHash;
}
