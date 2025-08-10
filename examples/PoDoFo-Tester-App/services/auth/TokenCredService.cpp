#include "TokenCredService.h"
#include "../../core/Config.h"
#include "../../core/Logger.h"
#include <curl/curl.h>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

/**
 * @brief Exchanges an authorization code for a credential access token using OAuth2.
 *
 * @param code The authorization code from the OAuth2 flow
 * @param urlEncodedAuthorizationDetails URL-encoded authorization details for credential scope
 * @return The credential access token, or empty string on failure
 */
std::string TokenCredService(const std::string& code, const std::string& urlEncodedAuthorizationDetails) {
    CURL* curl = curl_easy_init();
    CURLcode res;
    std::string response;
    std::string accessToken;

    Logger::info("=== Starting Credential Token Service ===");

    try {
        if (!curl) {
            throw std::runtime_error("TokenService: Failed to initialize curl");
        }

        std::ostringstream urlBuilder;
        urlBuilder << Config::getOAuthTokenUrl()
            << "?authorization_details=" << urlEncodedAuthorizationDetails;

        std::string url = urlBuilder.str();
        const std::string client_id = Config::getClientId();
        const std::string client_secret = Config::getClientSecret();
        const std::string redirect_uri = Config::getRedirectUri();
        const std::string code_verifier = Config::getCodeVerifier();
        const std::string state = Config::getState();

        Logger::info("POST URL: " + url);
        Logger::debug("Authorization Code", code);
        Logger::debug("Authorization Details (Encoded)", urlEncodedAuthorizationDetails);

        std::ostringstream postFields;
        postFields
            << "client_id=" << client_id
            << "&redirect_uri=" << redirect_uri
            << "&grant_type=authorization_code"
            << "&code_verifier=" << code_verifier
            << "&code=" << code
            << "&state=" << state;

        std::string postData = postFields.str();
        Logger::debug("POST Data", postData);

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData.c_str());

        curl_easy_setopt(curl, CURLOPT_USERNAME, client_id.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD, client_secret.c_str());

        Logger::info("Setting HTTP headers...");
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char* ptr, size_t size, size_t nmemb, std::string* data) -> size_t {
            data->append(ptr, size * nmemb);
            return size * nmemb;
            });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        Logger::info("Sending POST request to token endpoint...");
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            throw std::runtime_error("Credential token request failed: " + std::string(curl_easy_strerror(res)));
        }

        long http_status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
        Logger::info("Received HTTP status code: " + std::to_string(http_status));
        Logger::debug("Raw Response", response);

        if (http_status >= 200 && http_status < 300) {
            auto j = json::parse(response);
            accessToken = j.value("access_token", "");
            if (!accessToken.empty()) {
                Logger::info("Successfully retrieved access token");
                Logger::debug("Access Token", accessToken);
            } else {
                Logger::error("Access token not found in the JSON response");
            }
        } else {
            Logger::error("Token request failed with HTTP status " + std::to_string(http_status));
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

    }
    catch (const std::exception& e) {
        Logger::error("Exception in TokenCredService: " + std::string(e.what()));
        Logger::debug("Full response (if any)", response);
        if (curl) curl_easy_cleanup(curl);
    }

    Logger::info("Credential token service completed");
    Logger::info("=================================");
    return accessToken;
}
