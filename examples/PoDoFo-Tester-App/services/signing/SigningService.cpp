#include "SigningService.h"
#include "../../models/AuthorizationDetails.h"
#include "../../utils/Utils.h"
#include "../auth/LoginService.h"
#include "../auth/AuthCredService.h"
#include "../auth/TokenCredService.h"
#include "SignHashService.h"
#include "../../core/Logger.h"
#include <iostream>

/**
 * @brief Service that handles the process of getting a signed hash through the authentication and signing flow.
 *
 * @param initial_cms_hash The initial hash to be signed
 * @param label The label for the document digest
 * @param credentialId The credential identifier to use for signing
 * @param hashAlgorithmOID The OID of the hash algorithm used
 * @param type The type of authorization
 * @return The signed hash in base64 format
 */
std::string GetSignedHash(
    const std::string& initial_cms_hash,
    const std::string& label,
    const std::string& credentialId,
    const std::string& hashAlgorithmOID,
    const std::string& type
) {
    Logger::info("=== INITIATING SIGNATURE GENERATION PROCESS ===");

    Logger::info("STEP 1: Creating URL-encoded authorization details for signing");
    std::string encoded = CreateUrlEncodedAuthorizationDetails(
        label,
        initial_cms_hash,
        credentialId,
        hashAlgorithmOID,
        type
    );
    Logger::debug("URL Encoded Authorization Details", encoded);
    Logger::info("Step 1 complete");

    Logger::info("STEP 2: Third login to get a new session cookie (Cookie C)");
    auto cookieC = LoginService();
    if (cookieC.empty()) {
        Logger::error("Third login failed. Could not retrieve Cookie C");
        throw std::runtime_error("Third login failed");
    }
    Logger::info("Step 2 complete. Retrieved Cookie C");
    Logger::debug("Cookie C", cookieC);

    Logger::info("STEP 3: Third authorization call with Cookie C");
    auto firstRedirect = AuthCredService(cookieC, encoded);
    Logger::debug("Third redirect URL (wallet deeplink)", firstRedirect);
    Logger::info("Step 3 complete");

    Logger::info("STEP 4: Fourth login with Cookie C to get another session cookie (Cookie D)");
    auto cookieD = LoginService(cookieC);
    if (cookieD.empty()) {
        Logger::error("Fourth login failed. Could not retrieve Cookie D");
        throw std::runtime_error("Fourth login failed");
    }
    Logger::info("Step 4 complete. Retrieved Cookie D");
    Logger::debug("Cookie D", cookieD);

    Logger::info("STEP 5: Fourth authorization call with Cookie D to get the final auth code");
    auto finalRedirect = AuthCredService(cookieD, encoded);
    Logger::debug("Fourth redirect URL (should contain code)", finalRedirect);

    std::string authCode = ExtractAuthCodeFromUrl(finalRedirect);
    if (!authCode.empty()) {
        Logger::info("Extracted Authorization Code for signing: " + authCode);
        Logger::debug("Authorization Code for signing", authCode);
    }
    else {
        Logger::error("Could not extract authorization code from the fourth redirect URL");
        throw std::runtime_error("Could not extract signing authorization code");
    }
    Logger::info("Step 5 complete");

    Logger::info("STEP 6: Requesting credential access token");
    std::string cred_access_token = TokenCredService(authCode, encoded);

    if (cred_access_token.empty()) {
        Logger::error("Credential access token service failed");
        throw std::runtime_error("Credential access token service failed");
    }
    Logger::info("Step 6 complete. Received credential access token");
    Logger::debug("Credential Access Token", cred_access_token);

    std::string credentialID = credentialId;

    Logger::info("STEP 7: Calling SignHash service with the credential access token");
    std::string signedHash = SignHashService(cookieD, cred_access_token, credentialID, initial_cms_hash);

    if (!signedHash.empty()) {
        Logger::info("Successfully retrieved signed hash");
        Logger::debug("Signed Hash", signedHash);
    }
    else {
        Logger::error("Failed to retrieve signed hash from the SignHash service");
        throw std::runtime_error("Failed to retrieve signed hash");
    }

    Logger::info("=== SIGNATURE GENERATION PROCESS COMPLETED SUCCESSFULLY ===");
    return signedHash;
}
