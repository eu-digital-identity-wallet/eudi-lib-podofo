#include "GetCredentials.h"
#include "../auth/LoginService.h"
#include "../auth/AuthService.h"
#include "../auth/TokenService.h"
#include "ListCredentialsService.h"
#include "../../utils/Utils.h"
#include "../../core/Logger.h"
#include <iostream>

/**
 * @brief Retrieves credentials from the remote service by performing the complete OAuth2 flow.
 *
 * This function handles the entire credential acquisition process including:
 * - Initial login to obtain session cookies
 * - OAuth2 authorization flow
 * - Token exchange
 * - Credential listing
 *
 * @return CertificateBundle containing the credential ID, first certificate, and certificate chain
 */
CertificateBundle GetCredentials() {
    Logger::info("=== INITIATING CREDENTIAL ACQUISITION PROCESS ===");

    Logger::info("STEP 1: First login to obtain initial session cookie (Cookie A)");
    auto cookieA = LoginService();
    if (cookieA.empty()) {
        Logger::error("First login failed. Could not retrieve Cookie A");
        throw std::runtime_error("First login failed");
    }
    Logger::info("Step 1 complete. Retrieved Cookie A");
    Logger::debug("Cookie A", cookieA);

    Logger::info("STEP 2: First authorization call with Cookie A to get wallet deeplink");
    auto firstRedirect = AuthService(cookieA);
    Logger::debug("First redirect URL (wallet deeplink)", firstRedirect);
    Logger::info("Step 2 complete");

    Logger::info("STEP 3: Second login with Cookie A to obtain new session cookie (Cookie B)");
    auto cookieB = LoginService(cookieA);
    if (cookieB.empty()) {
        Logger::error("Second login failed. Could not retrieve Cookie B");
        throw std::runtime_error("Second login failed");
    }
    Logger::info("Step 3 complete. Retrieved Cookie B");
    Logger::debug("Cookie B", cookieB);

    Logger::info("STEP 4: Second authorization call with Cookie B to get authorization code");
    auto finalRedirect = AuthService(cookieB);
    Logger::debug("Second redirect URL (should contain auth code)", finalRedirect);

    std::string authCode = ExtractAuthCodeFromUrl(finalRedirect);
    if (!authCode.empty()) {
        Logger::info("Extracted Authorization Code: " + authCode);
        Logger::debug("Authorization Code", authCode);
    }
    else {
        Logger::error("Could not extract authorization code from the final redirect URL");
        throw std::runtime_error("Could not extract authorization code from URL");
    }
    Logger::info("Step 4 complete");

    Logger::info("STEP 5: Requesting access token using the authorization code");
    std::string service_token = TokenService(authCode);

    if (service_token.empty()) {
        Logger::error("Token service failed to provide an access token");
        throw std::runtime_error("Token service failed");
    }
    Logger::info("Step 5 complete. Received access token");
    Logger::debug("Access Token", service_token);

    Logger::info("STEP 6: Listing available credentials using the access token");
    CertificateBundle bundle = ListCredentialsService(service_token);

    Logger::info("Retrieved certificate bundle");
    Logger::debug("End-Entity Certificate", bundle.firstCert);
    if (!bundle.chainCertificates.empty()) {
        Logger::info("Certificate Chain (" + std::to_string(bundle.chainCertificates.size()) + " certificates):");
        for (size_t i = 0; i < bundle.chainCertificates.size(); i++) {
            Logger::debug("Chain Certificate [" + std::to_string(i) + "]", bundle.chainCertificates[i]);
        }
    } else {
        Logger::info("No chain certificates found");
    }

    Logger::info("=== CREDENTIAL ACQUISITION PROCESS COMPLETED SUCCESSFULLY ===");
    return bundle;
}
