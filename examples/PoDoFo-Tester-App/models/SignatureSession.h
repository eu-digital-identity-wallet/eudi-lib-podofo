#pragma once

#include <podofo/podofo.h>
#include <memory>
#include <sstream>
#include <iomanip>
#include "../core/Logger.h"

/**
 * @brief Structure to hold PDF signature session information including context, results, and document state.
 */
struct SignatureSession {
    PoDoFo::PdfSigningContext ctx;
    PoDoFo::PdfSigningResults results;
    PoDoFo::PdfSignerId signerId;
    PoDoFo::charbuff initialHash;
    std::shared_ptr<PoDoFo::FileStreamDevice> stream;
    std::unique_ptr<PoDoFo::PdfMemDocument> doc;

    SignatureSession() = default;

    SignatureSession(SignatureSession&&) = default;
    SignatureSession& operator=(SignatureSession&&) = default;

    SignatureSession(const SignatureSession&) = delete;
    SignatureSession& operator=(const SignatureSession&) = delete;

    /**
     * @brief Logs the signature session information
     * @param prefix Optional prefix for the log messages
     */
    void logInfo(const std::string& prefix = "") const {
        std::string logPrefix = prefix.empty() ? "" : prefix + " - ";

        Logger::info(logPrefix + "=== Signature Session Information ===");
        Logger::debug(logPrefix + "Initial Hash Size", std::to_string(initialHash.size()) + " bytes");
        Logger::debug(logPrefix + "Initial Hash (Hex)", bytesToHex(initialHash));
        Logger::debug(logPrefix + "Signer ID", signerId.ToString());
        Logger::info(logPrefix + "Stream Device: " + (stream ? "Available" : "Not available"));
        Logger::info(logPrefix + "Document: " + (doc ? "Available" : "Not available"));
        Logger::info(logPrefix + "====================================");
    }

    /**
     * @brief Logs only essential information (for INFO mode)
     * @param prefix Optional prefix for the log messages
     */
    void logInfoOnly(const std::string& prefix = "") const {
        std::string logPrefix = prefix.empty() ? "" : prefix + " - ";

        Logger::info(logPrefix + "Initial Hash: " + std::to_string(initialHash.size()) + " bytes");
        Logger::info(logPrefix + "Signer ID: " + signerId.ToString());
        Logger::info(logPrefix + "Stream Device: " + (stream ? "Available" : "Not available"));
        Logger::info(logPrefix + "Document: " + (doc ? "Available" : "Not available"));
    }

private:
    /**
     * @brief Converts bytes to hexadecimal string
     * @param bytes The bytes to convert
     * @return Hexadecimal string representation
     */
    std::string bytesToHex(const PoDoFo::charbuff& bytes) const {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (unsigned char byte : bytes) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }
};
