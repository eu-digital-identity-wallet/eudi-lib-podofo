#include "TsrProcessingService.h"
#include "TimestampRequestService.h"
#include "../../utils/Utils.h"
#include "../../core/Logger.h"
#include <openssl/ts.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <cstdio>
#include <stdexcept>

/**
 * @brief Processes a timestamp response (TSR) and returns it as base64 encoded string.
 *
 * This function sends a timestamp request to the TSA, reads the response,
 * validates it, and returns the base64 encoded TSR data.
 *
 * @return The base64 encoded timestamp response
 * @throws std::runtime_error if the TSR processing fails
 */
std::string TsrProcessingService::ProcessTsrAndReturnBase64() {
    Logger::info("=== Starting TSR Processing Service ===");

    Logger::info("Delegating to TimestampRequestService to send request...");
    if (!TimestampRequestService::SendTimestampRequest(GetInputFilePath("request.tsq"), GetInputFilePath("response.tsr"), "http://ts.cartaodecidadao.pt/tsa/server")) {
        Logger::error("Failed to receive timestamp response (.tsr) from the TSA");
        throw std::runtime_error("Failed to receive timestamp response (.tsr)");
    }
    Logger::info("Successfully received timestamp response from TSA");

    std::string tsrPath = GetInputFilePath("response.tsr");
    Logger::debug("TSR Path", tsrPath);
    std::string tsrData;
    ReadFile(tsrPath, tsrData);

    Logger::info("Timestamp response file read");
    Logger::debug("File size", std::to_string(tsrData.size()) + " bytes");

    if (tsrData.empty()) {
        Logger::error("TSR file is empty. Processing cannot continue");
        throw std::runtime_error("TSR file is empty.");
    }
    if (tsrData.size() < 32) {
        Logger::error("TSR data seems unusually small, which may indicate a corrupt or invalid response");
    }

    Logger::debug("First 16 bytes of .tsr (hex)", [&tsrData]() {
        std::string hex;
        for (size_t i = 0; i < std::min<size_t>(16, tsrData.size()); ++i) {
            char buf[4];
            snprintf(buf, sizeof(buf), "%02X ", static_cast<unsigned char>(tsrData[i]));
            hex += buf;
        }
        return hex;
    }());

    Logger::info("Validating if the received data is a proper TS_RESP structure...");
    const unsigned char* p = reinterpret_cast<const unsigned char*>(tsrData.data());
    TS_RESP* response = d2i_TS_RESP(nullptr, &p, static_cast<long>(tsrData.size()));
    if (!response) {
        Logger::error("Failed to parse .tsr file content into a TS_RESP structure. The file may be corrupt or not a valid timestamp response");
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Failed to parse TSR data.");
    }
    else {
        Logger::info("Data successfully parsed as a valid TS_RESP");
        TS_RESP_free(response);
    }

    Logger::info("Encoding the valid TSR data to Base64...");
    std::vector<char> tsrDataVec(tsrData.begin(), tsrData.end());
    std::string base64_tsr = Base64Encode(tsrDataVec);
    Logger::debug("Base64 encoded TSR size", std::to_string(base64_tsr.length()) + " characters");
    Logger::info("TSR data successfully encoded to Base64");
    Logger::info("TSR processing completed successfully");
    Logger::info("=========================================");

    return base64_tsr;
}
