#include "AuthorizationDetails.h"
#include "../utils/Utils.h"
#include "../core/Logger.h"
#include <iostream>

/**
 * @brief Creates URL-encoded authorization details for OAuth2 credential requests.
 *
 * @param label The label for the document digest
 * @param hash The hash value of the document
 * @param credentialID The credential identifier
 * @param hashAlgorithmOID The OID of the hash algorithm used
 * @param type The type of authorization
 * @return URL-encoded JSON string containing the authorization details
 */
std::string CreateUrlEncodedAuthorizationDetails(
    const std::string& label,
    const std::string& hash,
    const std::string& credentialID,
    const std::string& hashAlgorithmOID,
    const std::string& type
) {
    Logger::info("=== Creating URL-encoded Authorization Details ===");
    Logger::info("Label: " + label);
    Logger::debug("Hash", hash);
    Logger::debug("Credential ID", credentialID);
    Logger::debug("Hash Algorithm OID", hashAlgorithmOID);
    Logger::debug("Type", type);

    json j = json::array({
        {
            { "documentDigests", {
                {
                    { "label", label },
                    { "hash", hash }
                }
            }},
            { "credentialID", credentialID },
            { "hashAlgorithmOID", hashAlgorithmOID },
            { "locations", json::array() },
            { "type", type }
        }
        });

    std::string jsonString = j.dump();
    Logger::debug("Generated JSON string", jsonString);

    Logger::info("URL-encoding the JSON string...");
    std::string encoded = UrlEncode(jsonString);
    Logger::debug("URL-encoded result", encoded);
    Logger::info("Successfully created URL-encoded authorization details");
    Logger::info("==================================================");
    return encoded;
}
