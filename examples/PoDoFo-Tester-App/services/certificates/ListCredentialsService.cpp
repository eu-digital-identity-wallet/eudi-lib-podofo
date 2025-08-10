#include "ListCredentialsService.h"
#include "../../models/CertificateBundle.h"
#include "../../core/Config.h"
#include "../../core/Logger.h"
#include <curl/curl.h>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

/**
 * @brief Sends a POST request to the credentials list endpoint using the given access token.
 *
 * @param accessToken The OAuth2 access token for authentication
 * @return CertificateBundle containing the credential ID, first certificate, and certificate chain
 */
CertificateBundle ListCredentialsService(const std::string& accessToken) {
    CURL* curl = curl_easy_init();
    CURLcode res;
    std::string response;
    CertificateBundle bundle;

    Logger::info("=== Starting List Credentials Service ===");

    try {
        if (!curl) {
            throw std::runtime_error("ListCredentialsService: Failed to initialize curl");
        }

        const std::string url = Config::getCredentialsListUrl();
        Logger::info("Target URL: " + url);

        json body = {
            {"credentialInfo", true},
            {"certificates", "chain"},
            {"certInfo", true},
            {"authInfo", true},
            {"onlyValid", true},
            {"lang", nullptr},
            {"clientData", nullptr}
        };

        std::string jsonBody = body.dump();
        Logger::debug("Request JSON body", jsonBody);

        Logger::info("Setting HTTP headers (including Authorization Bearer token)");
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, ("Authorization: Bearer " + accessToken).c_str());

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonBody.c_str());

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char* ptr, size_t size, size_t nmemb, std::string* data) -> size_t {
            data->append(ptr, size * nmemb);
            return size * nmemb;
            });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        Logger::info("Sending POST request to credentials/list...");
        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            throw std::runtime_error("curl_easy_perform() failed: " + std::string(curl_easy_strerror(res)));
        }

        long httpCode;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
        Logger::info("Received HTTP status code: " + std::to_string(httpCode));

        if (httpCode != 200) {
            Logger::error("Unexpected HTTP status code. Full response: " + response);
            return bundle;
        }

        Logger::info("Successfully received response from server");
        Logger::debug("Full JSON response", response);
        auto jsonResp = json::parse(response);

        bundle.credentialID = jsonResp["credentialIDs"][0];
        bundle.firstCert = jsonResp["credentialInfos"][0]["cert"]["certificates"][0];

        const auto& certificates = jsonResp["credentialInfos"][0]["cert"]["certificates"];
        for (size_t i = 1; i < certificates.size(); i++) {
            bundle.chainCertificates.push_back(certificates[i]);
        }

        Logger::info("Parsed credential information:");
        Logger::debug("Credential ID", bundle.credentialID);
        Logger::debug("End-Entity Certificate (PEM)", bundle.firstCert);
        Logger::info("Number of chain certificates found: " + std::to_string(bundle.chainCertificates.size()));

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        Logger::info("List credentials service completed successfully");
        Logger::info("=============================================");
        return bundle;
    }
    catch (const std::exception& e) {
        Logger::error("Exception in ListCredentialsService: " + std::string(e.what()));
        Logger::debug("Raw response at time of error", response);
        if (curl) curl_easy_cleanup(curl);
        return bundle;
    }

    return bundle;
}
