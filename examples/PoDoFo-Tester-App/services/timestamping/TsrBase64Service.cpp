#include "TsrBase64Service.h"
#include "../../utils/Utils.h"
#include "../../core/Logger.h"
#include <openssl/ts.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <iostream>
#include <vector>
#include <algorithm>

/**
 * @brief Reads a TSR file from disk and converts it to base64 encoding.
 *
 * @param tsrPath The path to the TSR file
 * @return The base64 encoded TSR data
 * @throws std::runtime_error if the TSR file is invalid or cannot be read
 */
std::string TsrBase64Service::GetTsrBase64(const std::string& tsrPath) {
    Logger::info("=== Starting TSR Base64 Encoding Service ===");
    Logger::debug("TSR Path", tsrPath);

    std::string tsrData;
    ReadFile(tsrPath, tsrData);

    Logger::info("Timestamp response (.tsr) read successfully");
    Logger::debug("File size", std::to_string(tsrData.size()) + " bytes");

    if (tsrData.size() < 32) {
        Logger::error("TSR data seems unusually small. It might be invalid or corrupt");
    }

    Logger::info("Validating TSR data...");
    const unsigned char* p = reinterpret_cast<const unsigned char*>(tsrData.data());
    TS_RESP* response = d2i_TS_RESP(nullptr, &p, static_cast<long>(tsrData.size()));
    if (!response) {
        Logger::error("Failed to parse TSR data into a valid TS_RESP structure (OpenSSL d2i_TS_RESP failed)");
        throw std::runtime_error("Invalid TSR file format");
    }
    TS_RESP_free(response);
    Logger::info("TSR data is a valid timestamp response");

    Logger::info("Encoding TSR data to Base64...");
    std::vector<char> tsrDataVec(tsrData.begin(), tsrData.end());
    std::string base64Result = Base64Encode(tsrDataVec);

    Logger::debug("Base64 encoded TSR size", std::to_string(base64Result.length()) + " characters");
    Logger::info("TSR Base64 encoding completed successfully");
    Logger::info("===========================================");

    return base64Result;
}

/**
 * @brief Decodes a base64-encoded TSR string back to binary data.
 *
 * @param base64Tsr The base64-encoded TSR string
 * @return The decoded TSR binary data as a string
 * @throws std::runtime_error if decoding fails or the data is invalid
 */
std::string TsrBase64Service::DecodeBase64Tsr(const std::string& base64Tsr) {
    Logger::info("=== Starting TSR Base64 Decoding Service ===");
    Logger::debug("Input Base64 string length", std::to_string(base64Tsr.length()) + " characters");

    BIO* b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        Logger::error("Failed to create BIO for base64 decoding");
        throw std::runtime_error("Failed to create BIO for base64 decoding");
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO* mem = BIO_new_mem_buf(base64Tsr.data(), static_cast<int>(base64Tsr.size()));
    if (!mem) {
        BIO_free_all(b64);
        Logger::error("Failed to create memory BIO");
        throw std::runtime_error("Failed to create memory BIO");
    }

    BIO* bio = BIO_push(b64, mem);

    size_t maxDecodedSize = (base64Tsr.size() * 3) / 4;
    std::vector<unsigned char> decoded(maxDecodedSize);

    int decodedSize = BIO_read(bio, decoded.data(), static_cast<int>(maxDecodedSize));
    BIO_free_all(bio);

    if (decodedSize <= 0) {
        Logger::error("Failed to decode base64 TSR data. BIO_read returned non-positive value");
        throw std::runtime_error("Failed to decode base64 TSR data. BIO_read returned non-positive value.");
    }

    decoded.resize(decodedSize);
    Logger::debug("Successfully decoded Base64", std::to_string(decoded.size()) + " bytes");

    std::string tsrData(decoded.begin(), decoded.end());

    Logger::info("Validating decoded TSR data...");
    const unsigned char* p = reinterpret_cast<const unsigned char*>(tsrData.data());
    TS_RESP* response = d2i_TS_RESP(nullptr, &p, static_cast<long>(tsrData.size()));
    if (!response) {
        Logger::error("Failed to parse decoded TSR into TS_RESP (OpenSSL error after base64 decoding)");
        throw std::runtime_error("Invalid TSR data after decoding");
    }
    TS_RESP_free(response);
    Logger::info("Decoded TSR data is a valid timestamp response");
    Logger::info("TSR Base64 decoding completed successfully");
    Logger::info("===========================================");

    return tsrData;
}
