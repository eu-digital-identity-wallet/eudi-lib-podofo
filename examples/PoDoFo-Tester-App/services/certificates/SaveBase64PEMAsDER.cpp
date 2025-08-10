#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <fstream>
#include <stdexcept>
#include <iostream>
#include <vector>
#include "../../core/Logger.h"

/**
 * @brief Decodes a Base64-encoded PEM string and saves it as a binary DER file.
 *
 * @param base64PEM The base64-encoded certificate string (no headers).
 * @param outputPath The destination path to save the binary .der file.
 */
void SaveBase64PEMAsDER(const std::string& base64PEM, const std::string& outputPath) {
    Logger::info("=== Starting Base64 PEM to DER Conversion Service ===");
    Logger::debug("Output path", outputPath);

    BIO* bio = nullptr;
    BIO* b64 = nullptr;

    try {
        Logger::info("Setting up Base64 decoding BIO chain...");
        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        bio = BIO_new_mem_buf(base64PEM.data(), static_cast<int>(base64PEM.size()));
        bio = BIO_push(b64, bio);

        Logger::info("Decoding Base64 data...");
        std::vector<unsigned char> decoded(base64PEM.size());
        int len = BIO_read(bio, decoded.data(), static_cast<int>(decoded.size()));
        if (len <= 0) {
            Logger::error("Base64 decode failed. BIO_read returned non-positive value");
            throw std::runtime_error("Base64 decode failed. BIO_read returned non-positive value.");
        }
        decoded.resize(len);
        Logger::debug("Decoded data size", std::to_string(decoded.size()) + " bytes");

        Logger::info("Writing decoded data to DER file...");
        std::ofstream outFile(outputPath, std::ios::binary);
        if (!outFile) {
            Logger::error("Failed to open output file for DER writing: " + outputPath);
            throw std::runtime_error("Failed to open output file for DER writing: " + outputPath);
        }
        outFile.write(reinterpret_cast<const char*>(decoded.data()), static_cast<std::streamsize>(decoded.size()));
        outFile.close();

        Logger::info("DER file saved successfully to: " + outputPath);
        Logger::info("Base64 PEM to DER conversion completed successfully");
        Logger::info("=================================================");
    }
    catch (const std::exception& e) {
        Logger::error("Failed during SaveBase64PEMAsDER: " + std::string(e.what()));
    }

    if (bio) BIO_free_all(bio);
}
