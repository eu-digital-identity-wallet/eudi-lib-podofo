#pragma once
#include <string>
#include "../../core/Logger.h"

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
);
