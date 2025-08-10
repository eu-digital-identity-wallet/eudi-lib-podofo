#include "GetTsrBase64.h"
#include "../../utils/Utils.h"
#include "../../core/Logger.h"

/**
 * @brief Reads a TSR file from disk and converts it to base64 encoding
 * @param tsrPath The path to the TSR file
 * @return The base64 encoded TSR data
 * @throws std::runtime_error if the TSR file is invalid or cannot be read
 */
std::string GetTsrBase64(const std::string& tsrPath) {
    Logger::info("=== Starting TSR Base64 Conversion Service ===");
    Logger::debug("TSR Path", tsrPath);

    std::string tsrData;
    ReadFile(tsrPath, tsrData);

    Logger::info("Timestamp response (.tsr) read successfully");
    Logger::debug("File size", std::to_string(tsrData.size()) + " bytes");

    if (tsrData.size() < 32) {
        Logger::error("TSR seems too small. Possibly corrupt?");
    }

    const unsigned char* p = reinterpret_cast<const unsigned char*>(tsrData.data());
    TS_RESP* response = d2i_TS_RESP(nullptr, &p, static_cast<long>(tsrData.size()));
    if (!response) {
        Logger::error("Failed to parse .tsr into TS_RESP (OpenSSL error)");
        throw std::runtime_error("Invalid TSR file format");
    }
    TS_RESP_free(response);

    Logger::info("TSR file validated successfully");
    Logger::info("Converting TSR to Base64...");

    std::vector<char> tsrDataVec(tsrData.begin(), tsrData.end());
    std::string base64Result = Base64Encode(tsrDataVec);

    Logger::debug("Base64 encoded TSR size", std::to_string(base64Result.length()) + " characters");
    Logger::info("TSR Base64 conversion completed successfully");
    Logger::info("=============================================");

    return base64Result;
}
