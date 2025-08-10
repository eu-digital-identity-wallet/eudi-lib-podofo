#include "TsrRequestAndBase64Service.h"
#include "TimestampService.h"
#include "TsrFromSignedHashService.h"
#include "../../core/Logger.h"
#include <iostream>

/**
 * @brief Generates a timestamp response (TSR) from a signed hash and returns it as base64.
 *
 * @param signedHash The signed hash to create the timestamp response for
 * @return The base64 encoded timestamp response
 */
std::string TsrRequestAndBase64Service::GetTsrBase64(const std::string& signedHash) {
    Logger::info("=== Starting TSR Request and Base64 Service ===");
    Logger::debug("Signed Hash Size", std::to_string(signedHash.size()) + " bytes");

    Logger::info("Delegating to TimestampService to create the timestamp request");
    CreateTimestampRequest(signedHash);
    Logger::info("Delegating to TsrFromSignedHashService to process the response");
    auto base64_tsr = TsrFromSignedHashService::CreateTsrBase64FromSignedHash(signedHash);
    Logger::debug("Base64 TSR Size", std::to_string(base64_tsr.length()) + " characters");
    Logger::info("Successfully generated Base64 TSR");
    Logger::info("TSR Request and Base64 service completed successfully");
    Logger::info("=================================================");
    return base64_tsr;
}
