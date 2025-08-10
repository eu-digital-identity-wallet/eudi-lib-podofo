#pragma once
#include <string>
#include <nlohmann/json.hpp>
#include "../core/Logger.h"

using json = nlohmann::json;

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
);
