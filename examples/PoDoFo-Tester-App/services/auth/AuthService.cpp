#include "AuthService.h"
#include "../../core/Config.h"
#include "../../utils/Utils.h"
#include "../../core/Logger.h"
#include <curl/curl.h>
#include <iostream>
#include <string>

/**
 * @brief Performs the OAuth2 authorization step and returns the redirect URL containing the code.
 *
 * @param cookie The session cookie (JSESSIONID).
 * @return The redirect URL containing the authorization code, or empty string on failure.
 */
std::string AuthService(const std::string& cookie) {
    CURL* curl = curl_easy_init();
    CURLcode res;
    std::string redirectLocation;

    Logger::info("=== Starting OAuth2 Authorization Service ===");

    if (!curl) {
        Logger::error("Failed to initialize cURL for AuthService");
        return "";
    }

    const std::string url =
        Config::getOAuthAuthorizeUrl() +
        "?response_type=code"
        "&client_id=" + Config::getClientId() +
        "&redirect_uri=" + UrlEncode(Config::getRedirectUri()) +
        "&scope=" + Config::getScope() +
        "&code_challenge=" + Config::getCodeChallenge() +
        "&code_challenge_method=" + Config::getCodeChallengeMethod() +
        "&lang=" + Config::getLang() +
        "&state=" + Config::getState() +
        "&nonce=" + Config::getNonce();

    Logger::info("Requesting URL: " + url);
    Logger::debug("Session Cookie", cookie);

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
        Logger::error("Service authorization failed: " + std::string(curl_easy_strerror(res)));
    }

    curl_easy_cleanup(curl);

    Logger::debug("Final redirect location (auth code URL)", redirectLocation);
    Logger::info("OAuth2 authorization service completed");
    Logger::info("==========================================");

    return redirectLocation;
}
