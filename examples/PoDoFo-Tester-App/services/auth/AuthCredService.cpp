#include "AuthService.h"
#include "../../core/Config.h"
#include "../../utils/Utils.h"
#include "../../core/Logger.h"
#include <curl/curl.h>
#include <iostream>
#include <string>

/**
 * @brief Makes an OAuth2 authorization request with credential scope using the given cookie and pre-encoded authorization_details.
 *
 * @param cookie Session cookie (JSESSIONID)
 * @param authorizationDetailsEncoded URL-encoded authorization_details JSON string
 * @return Redirect URL containing the authorization code, or empty string on error
 */
std::string AuthCredService(const std::string& cookie, const std::string& authorizationDetailsEncoded) {
    CURL* curl = curl_easy_init();
    CURLcode res;
    std::string redirectLocation;

    Logger::info("=== Starting Credential Authorization Service ===");

    if (!curl) {
        Logger::error("Failed to initialize curl");
        return "";
    }

    std::string url =
        Config::getOAuthAuthorizeUrl() +
        "?response_type=code"
        "&scope=credential"
        "&code_challenge_method=" + Config::getCodeChallengeMethod() +
        "&authorization_details=" + authorizationDetailsEncoded +
        "&redirect_uri=" + UrlEncode(Config::getRedirectUri()) +
        "&state=" + Config::getState() +
        "&prompt=login"
        "&client_id=" + Config::getClientId() +
        "&code_challenge=" + Config::getCodeChallenge();

    Logger::info("Requesting URL: " + url);
    Logger::debug("Session Cookie", cookie);
    Logger::debug("Authorization Details (Encoded)", authorizationDetailsEncoded);

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_COOKIE, cookie.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, +[](char* buffer, size_t size, size_t nitems, std::string* out) -> size_t {
        std::string header(buffer, size * nitems);
        const std::string locationPrefix = "Location: ";
        auto pos = header.find(locationPrefix);
        if (pos != std::string::npos) {
            auto start = pos + locationPrefix.length();
            auto end = header.find("\r\n", start);
            if (end != std::string::npos) {
                *out = header.substr(start, end - start);
            }
        }
        return nitems * size;
        });
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &redirectLocation);

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char*, size_t size, size_t nmemb, void*) -> size_t {
        return size * nmemb;
        });

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        Logger::error("Credential authorization failed: " + std::string(curl_easy_strerror(res)));
    }

    curl_easy_cleanup(curl);

    Logger::debug("Final redirect location (auth code URL)", redirectLocation);
    Logger::info("Credential authorization service completed");
    Logger::info("==========================================");

    return redirectLocation;
}
