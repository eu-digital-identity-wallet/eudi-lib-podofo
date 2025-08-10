#include "TimestampingService.h"
#include "TimestampRequestService.h"
#include "../../utils/Utils.h"
#include "../../core/Logger.h"
#include <podofo/podofo.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <vector>
#include <iostream>
#include <filesystem>

namespace fs = std::filesystem;

namespace TimestampingService {

/**
 * @brief Requests a TSR from the timestamp service for a signed hash.
 *
 * @param signedHash The signed hash to timestamp
 * @param tsaUrl The URL of the timestamp authority service
 */
void requestTsrFromTimestampService(const std::string& signedHash, const std::string& tsaUrl) {
    Logger::info("=== Starting Timestamp Request Service for Signed Hash ===");
    Logger::debug("Signed Hash", signedHash);
    Logger::debug("TSA URL", tsaUrl);

    PoDoFo::charbuff SUPER_SIGNED_HASH = ConvertDSSHashToSignedHash(signedHash);
    Logger::debug("Converted Signed Hash Size", std::to_string(SUPER_SIGNED_HASH.size()) + " bytes");

    std::vector<unsigned char> myDigest(SHA256_DIGEST_LENGTH);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        Logger::error("Failed to create EVP_MD_CTX");
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, SUPER_SIGNED_HASH.data(), SUPER_SIGNED_HASH.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, myDigest.data(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        Logger::error("Failed to compute SHA256 hash");
        throw std::runtime_error("Failed to compute SHA256 hash");
    }
    EVP_MD_CTX_free(mdctx);
    Logger::debug("Computed SHA256 Digest Size", std::to_string(myDigest.size()) + " bytes");

    fs::create_directories("input");

    Logger::info("Creating timestamp request (.tsq)...");
    if (!TimestampRequestService::CreateTimestampRequestFromDigest(myDigest, GetInputFilePath("request.tsq"))) {
        Logger::error("Failed to create .tsq file");
        return;
    }

    Logger::info("Sending timestamp request to TSA...");
    if (!TimestampRequestService::SendTimestampRequest(GetInputFilePath("request.tsq"), GetInputFilePath("response.tsr"), tsaUrl)) {
        Logger::error("Failed to receive timestamp response (.tsr)");
        return;
    }

    Logger::info("Timestamp request service completed successfully");
    Logger::info("==================================================");
}

/**
 * @brief Requests a TSR from the timestamp service for document timestamping (LTA).
 *
 * @param base64Hash The base64 encoded hash to timestamp
 * @param tsaUrl The URL of the timestamp authority service
 */
void requestTsrFromTimestampServiceForDocTimeStamp(const std::string& base64Hash, const std::string& tsaUrl) {
    Logger::info("=== Starting DocTimeStamp Timestamp Request Service ===");
    Logger::debug("Base64 Hash", base64Hash);
    Logger::debug("TSA URL", tsaUrl);

    PoDoFo::charbuff hashData = ConvertDSSHashToSignedHash(base64Hash);
    Logger::debug("Converted Hash Data Size", std::to_string(hashData.size()) + " bytes");

    std::vector<unsigned char> originalHash(hashData.begin(), hashData.end());

    if (originalHash.size() != 32) {
        Logger::error("DocTimeStamp hash must be exactly 32 bytes for SHA-256. Received hash size: " + std::to_string(originalHash.size()) + " bytes");
        return;
    }

    fs::create_directories("input");

    Logger::info("Using original document hash directly (no double-hashing)");
    Logger::debug("Hash size", std::to_string(originalHash.size()) + " bytes");

    if (!TimestampRequestService::CreateTimestampRequestFromDigest(originalHash, GetInputFilePath("request2.tsq"))) {
        Logger::error("Failed to create DocTimeStamp .tsq file");
        return;
    }

    Logger::info("Sending DocTimeStamp timestamp request to TSA...");
    if (!TimestampRequestService::SendTimestampRequest(GetInputFilePath("request2.tsq"), GetInputFilePath("response2.tsr"), tsaUrl)) {
        Logger::error("Failed to receive DocTimeStamp timestamp response (.tsr)");
        return;
    }

    Logger::info("DocTimeStamp TSQ/TSR process completed successfully!");
    Logger::info("=====================================================");
}

}
