#ifndef CERTIFICATE_BUNDLE_H
#define CERTIFICATE_BUNDLE_H

#include <string>
#include <vector>
#include "../core/Logger.h"

/**
 * @brief Structure to hold certificate bundle information including credential ID, first certificate, and chain certificates.
 */
struct CertificateBundle {
    std::string credentialID;
    std::string firstCert;
    std::vector<std::string> chainCertificates;

    /**
     * @brief Logs the certificate bundle information
     * @param prefix Optional prefix for the log messages
     */
    void logInfo(const std::string& prefix = "") const {
        std::string logPrefix = prefix.empty() ? "" : prefix + " - ";

        Logger::info(logPrefix + "=== Certificate Bundle Information ===");
        Logger::debug(logPrefix + "Credential ID", credentialID);
        Logger::debug(logPrefix + "End-Entity Certificate (Base64)", firstCert);

        if (!chainCertificates.empty()) {
            Logger::info(logPrefix + "Certificate Chain (" + std::to_string(chainCertificates.size()) + " certificates):");
            for (size_t i = 0; i < chainCertificates.size(); i++) {
                Logger::debug(logPrefix + "Chain Certificate [" + std::to_string(i + 1) + "]", chainCertificates[i]);
            }
        } else {
            Logger::info(logPrefix + "No chain certificates");
        }
        Logger::info(logPrefix + "=====================================");
    }

    /**
     * @brief Logs only essential information (for INFO mode)
     * @param prefix Optional prefix for the log messages
     */
    void logInfoOnly(const std::string& prefix = "") const {
        std::string logPrefix = prefix.empty() ? "" : prefix + " - ";

        Logger::info(logPrefix + "Credential ID: " + credentialID);
        Logger::info(logPrefix + "End-Entity Certificate: " + std::to_string(firstCert.length()) + " characters (Base64)");
        Logger::info(logPrefix + "Chain Certificates: " + std::to_string(chainCertificates.size()) + " certificates");
    }
};

#endif
