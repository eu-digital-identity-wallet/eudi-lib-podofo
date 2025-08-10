// LoginService.cpp
#include "LoginService.h"
#include "../../core/Config.h"
#include "../../core/Logger.h"
#include <iostream>
#include <curl/curl.h>

/**
 * @brief Logs in to the remote service and returns a session cookie (JSESSIONID).
 *
 * @param optionalCookie Optional cookie to reuse an existing session.
 * @return The new session cookie, or empty string on failure.
 */
std::string LoginService(const std::string& optionalCookie) {
    CURL* curl;
    CURLcode res;
    std::string responseCookie;

    const std::string usernameValue = Config::getUsername();
    const std::string passwordValue = Config::getPassword();
    const std::string url = Config::getLoginUrl();

    Logger::info("=== Starting Login Service ===");
    Logger::info("POST URL: " + url);
    Logger::debug("Username", usernameValue);
    if (!optionalCookie.empty()) {
        Logger::info("Reusing existing session cookie");
        Logger::debug("Existing Cookie", optionalCookie);
    }

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);

        curl_mime* mime = curl_mime_init(curl);
        curl_mimepart* part;

        part = curl_mime_addpart(mime);
        curl_mime_name(part, "username");
        curl_mime_data(part, usernameValue.c_str(), CURL_ZERO_TERMINATED);

        part = curl_mime_addpart(mime);
        curl_mime_name(part, "password");
        curl_mime_data(part, passwordValue.c_str(), CURL_ZERO_TERMINATED);

        curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

        if (!optionalCookie.empty()) {
            curl_easy_setopt(curl, CURLOPT_COOKIE, optionalCookie.c_str());
        }

        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, +[](char* buffer, size_t size, size_t nitems, std::string* out) -> size_t {
            std::string header(buffer, size * nitems);
            if (header.find("Set-Cookie:") != std::string::npos) {
                *out = header.substr(strlen("Set-Cookie: "), header.find(';') - strlen("Set-Cookie: "));
            }
            return nitems * size;
            });
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &responseCookie);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char* ptr, size_t size, size_t nmemb, void*) -> size_t {
            return size * nmemb;
            });

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            Logger::error("Login request failed: " + std::string(curl_easy_strerror(res)));
        }

        curl_mime_free(mime);
        curl_easy_cleanup(curl);
    }

    if (!responseCookie.empty()) {
        Logger::info("Successfully received new session cookie");
        Logger::debug("New Session Cookie", responseCookie);
    } else {
        Logger::error("No new session cookie was received from the login service");
    }
    Logger::info("Login service completed");
    Logger::info("=====================");

    return responseCookie;
}
