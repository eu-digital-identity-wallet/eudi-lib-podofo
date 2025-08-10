#include "TimestampHashService.h"
#include "../../core/Logger.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdexcept>
#include <iostream>
#include <vector>

/**
 * @brief Service that handles creation of timestamp hashes.
 *
 * @param signedHash The signed hash to create a timestamp hash from
 * @return Vector of unsigned char containing the SHA-256 hash digest
 */
std::vector<unsigned char> CreateTimestampHash(const std::string& signedHash) {
    Logger::info("=== Starting Timestamp Hash Creation Service ===");
    Logger::debug("Input data size", std::to_string(signedHash.size()) + " bytes");

    std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        Logger::error("Failed to create EVP_MD_CTX");
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, signedHash.data(), signedHash.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, digest.data(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        Logger::error("Failed to compute SHA-256 hash for timestamping");
        throw std::runtime_error("Failed to compute SHA256 hash");
    }
    EVP_MD_CTX_free(mdctx);

    Logger::debug("Successfully created SHA-256 hash", std::to_string(digest.size()) + " bytes");
    Logger::info("Timestamp hash creation completed successfully");
    Logger::info("=============================================");
    return digest;
}
