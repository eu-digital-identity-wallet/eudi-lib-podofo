#include "TsrFromSignedHashService.h"
#include "TimestampService.h"
#include "TsrProcessingService.h"
#include "../../core/Logger.h"
#include <string>
#include <iostream>

/**
 * @brief Creates a timestamp response (TSR) from a signed hash and returns it as base64.
 *
 * @param signedHash The signed hash to create the timestamp response for
 * @return The base64 encoded timestamp response
 */
std::string TsrFromSignedHashService::CreateTsrBase64FromSignedHash(const std::string& signedHash) {
    Logger::info("=== Starting TSR from Signed Hash Service ===");
    Logger::debug("Signed Hash Size", std::to_string(signedHash.size()) + " bytes");

    Logger::info("Delegating to TimestampService to create the timestamp request");
    CreateTimestampRequest(signedHash);
    Logger::info("Delegating to TsrProcessingService to process the response and get Base64");
    std::string result = TsrProcessingService::ProcessTsrAndReturnBase64();
    Logger::debug("Generated Base64 TSR Size", std::to_string(result.length()) + " characters");
    Logger::info("TSR from signed hash service completed successfully");
    Logger::info("=============================================");
    return result;
}
