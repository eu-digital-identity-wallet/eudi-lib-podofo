#include <podofo/podofo.h>
#include <podofo/main/PdfRemoteSignDocumentSession.h>
#include <podofo/private/OpenSSLInternal.h>
#include <openssl/applink.c>
#include <iostream>
#include <string>
#include <vector>
#include <optional>
#include <algorithm>
#include <exception>
#include <nlohmann/json.hpp>
#include "../models/CertificateBundle.h"
#include "../services/certificates/GetCredentials.h"
#include "../services/signing/SigningService.h"
#include "../services/timestamping/TsrRequestAndBase64Service.h"
#include "../services/timestamping/TimestampRequestService.h"
#include "../services/certificates/GetCrlFromCertificate.h"
#include "../services/certificates/GetTsrBase64.h"
#include "../services/certificates/OCSPHttpService.h"
#include "../services/certificates/CertificateHttpService.h"
#include "Config.h"
#include "Logger.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <curl/curl.h>
#include <openssl/ts.h>
#include <openssl/ocsp.h>

#include <openssl/rand.h>
#include <openssl/bn.h>
#include "../utils/Utils.h"
#include "../services/timestamping/TimestampingService.h"
#include "../services/timestamping/TsrBase64Service.h"
#include <chrono>
#include <sstream>
#include <ctime>
#include <iomanip>
#include <thread>

using json = nlohmann::json;
using namespace std;
using namespace PoDoFo;

// Function to get conformance level string from choice
string getConformanceLevel(int choice) {
    switch (choice) {
    case 1: return "ADES_B_B";
    case 2: return "ADES_B_T";
    case 3: return "ADES_B_LT";
    case 4: return "ADES_B_LTA";
    default: return "ADES_B_LT";
    }
}

// Function to get TSA URL from choice
string getTsaUrl(int choice) {
    switch (choice) {
    case 1: return Config::getTsaUrlCartaodecidadao();
    case 2: return Config::getTsaUrlQualified();
    case 3: return Config::getTsaUrlGlobalsignAatl();
    case 4: return Config::getTsaUrlUnqualified();
    case 5: return Config::getTsaUrlIdentrust();
    case 6: return Config::getTsaUrlQuovadis();
    case 7: return Config::getTsaUrlDigicert();
    case 8: return Config::getTsaUrlSwisssign();
    case 9: return Config::getTsaUrlEntrust();
    case 10: return Config::getTsaUrlCertum();
    case 11: return Config::getTsaUrlFreeHttp();
    case 12: return Config::getTsaUrlFree();
    case 13: return Config::getTsaUrlSsl();
    case 14: return Config::getTsaUrlWotrus();
    case 15: return Config::getTsaUrlGlobalsignR6();
    case 16: return Config::getTsaUrlCertumTime();
    default: return Config::getTsaUrlCartaodecidadao();
    }
}

// Function to process a single combination
void processSigningCombination(int conformanceChoice, int tsaChoice, const string& inputPdf, bool isAutoMode = false, int combinationNumber = 0) {
    std::string conformanceLevel = getConformanceLevel(conformanceChoice);
    std::string tsaUrl = getTsaUrl(tsaChoice);
    std::string outputPdf;

    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm now_tm;
    localtime_s(&now_tm, &now_c);

    std::stringstream ss;
    if (isAutoMode) {
        ss << "output/auto_" << combinationNumber << "_" << conformanceLevel << "_TSA" << tsaChoice << "_"
           << std::put_time(&now_tm, "%Y-%m-%d_%I-%M-%S-%p") << ".pdf";
    } else {
        ss << "output/signed_" << conformanceLevel << "_"
           << std::put_time(&now_tm, "%Y-%m-%d_%I-%M-%S-%p") << ".pdf";
    }
    outputPdf = ss.str();

    if (isAutoMode) {
        Logger::info("=== AUTOMATIC MODE - Combination " + std::to_string(combinationNumber) + " ===");
        Logger::info("Processing: " + conformanceLevel + " with TSA choice " + std::to_string(tsaChoice));
    }

    Logger::info("Selected conformance level: " + conformanceLevel);
    Logger::debug("Conformance Level", conformanceLevel);
    Logger::info("Selected timestamp service URL: " + tsaUrl);
    Logger::debug("Timestamp Service URL", tsaUrl);
    Logger::debug("Generated output filename", outputPdf);

    Logger::info("=== Configuration Summary ===");
    Logger::info("Conformance Level: " + conformanceLevel);
    Logger::info("Timestamp URL: " + tsaUrl);
    Logger::info("Input PDF: " + inputPdf);
    Logger::info("Output PDF: " + outputPdf);
    Logger::info("=============================");

    Logger::info("Starting PDF signing and timestamping process");
    CertificateBundle bundle = GetCredentials();

    Logger::info("=== Certificate Details ===");
    Logger::info("End-Entity Certificate (Base64):");
    Logger::debug("End-Entity Certificate", bundle.firstCert);

    if (!bundle.chainCertificates.empty()) {
        Logger::info("Certificate Chain (Base64):");
        for (size_t i = 0; i < bundle.chainCertificates.size(); i++) {
            Logger::debug("Chain Certificate [" + std::to_string(i + 1) + "]", bundle.chainCertificates[i]);
        }
    }

    std::string hash_algo = "2.16.840.1.101.3.4.2.1";
    std::string label = "A sample label";

    Logger::debug("Hash Algorithm", hash_algo);
    Logger::debug("Label", label);

    Logger::info("=== PDF Signature Initialization ===");
    PdfRemoteSignDocumentSession session{
            conformanceLevel,
            hash_algo,
            inputPdf,
            outputPdf,
            bundle.firstCert,
            bundle.chainCertificates,
            std::nullopt,
            label
    };
    session.printState();
    Logger::info("=============================");

    if (conformanceLevel == "ADES_B_B") {
        Logger::info("=== Signing Process (PART 1 - HASHING) ===");
        string urlEncodedHash = session.beginSigning();
        Logger::debug("URL Encoded Hash", urlEncodedHash);
        Logger::debug("Credential ID", bundle.credentialID);

        auto signedHash = GetSignedHash(urlEncodedHash, label, bundle.credentialID, hash_algo, "credential");

        Logger::info("Signed Hash from Remote Service (Base64):");
        Logger::debug("Signed Hash", signedHash);
        Logger::info("=============================");

        ValidationData validationData;

        Logger::info("=== Signing Process (PART 2 - EMBEDDING) ===");
        session.finishSigning(signedHash, "", validationData);
    }

    if (conformanceLevel == "ADES_B_T") {
        Logger::info("=== Signing Process (PART 1 - HASHING) ===");
        string urlEncodedHash = session.beginSigning();
        Logger::debug("URL Encoded Hash", urlEncodedHash);
        Logger::debug("Credential ID", bundle.credentialID);

        auto signedHash = GetSignedHash(urlEncodedHash, label, bundle.credentialID, hash_algo, "credential");

        Logger::info("Signed Hash from Remote Service (Base64):");
        Logger::debug("Signed Hash", signedHash);
        Logger::info("=============================");

        Logger::info("=== Timestamping the Signature ===");
        TimestampingService::requestTsrFromTimestampService(signedHash, tsaUrl);

        std::string tsrPath = GetInputFilePath("response.tsr");
        Logger::debug("TSR Path", tsrPath);
        std::string base64Tsr = GetTsrBase64(tsrPath);

        Logger::info("Timestamp Response (TSR) from TSA (Base64):");
        Logger::debug("Timestamp Response (TSR)", base64Tsr);
        Logger::info("=============================");

        ValidationData validationData;

        Logger::info("=== Signing Process (PART 2 - EMBEDDING) ===");
        session.finishSigning(signedHash, base64Tsr, validationData);
    }

    if (conformanceLevel == "ADES_B_LT") {
        Logger::info("=== Signing Process (PART 1 - HASHING) ===");
        string urlEncodedHash = session.beginSigning();
        Logger::debug("URL Encoded Hash", urlEncodedHash);
        Logger::debug("Credential ID", bundle.credentialID);

        auto signedHash = GetSignedHash(urlEncodedHash, label, bundle.credentialID, hash_algo, "credential");

        Logger::info("Signed Hash from Remote Service (Base64):");
        Logger::debug("Signed Hash", signedHash);
        Logger::info("=============================");

        Logger::info("=== Timestamping the Signature ===");
        TimestampingService::requestTsrFromTimestampService(signedHash, tsaUrl);

        std::string tsrPath = GetInputFilePath("response.tsr");
        Logger::debug("TSR Path", tsrPath);
        std::string base64Tsr = TsrBase64Service::GetTsrBase64(tsrPath);

        Logger::info("Timestamp Response (TSR) from TSA (Base64):");
        Logger::debug("Timestamp Response (TSR)", base64Tsr);
        Logger::info("=============================");

        ValidationData validationData;

        validationData.certificatesBase64.push_back(bundle.firstCert);
        Logger::debug("Added end-entity certificate to validation data");

        validationData.certificatesBase64.insert(
            validationData.certificatesBase64.end(),
            bundle.chainCertificates.begin(),
            bundle.chainCertificates.end()
        );
        Logger::debug("Added " + std::to_string(bundle.chainCertificates.size()) + " chain certificates to validation data");

        validationData.certificatesBase64.push_back(base64Tsr);
        Logger::debug("Added TSR to validation data");

        Logger::info("=== Fetching Revocation Data (CRL/OCSP) ===");
        Logger::info("Fetching CRL for end-entity certificate...");
        auto crlUrl = session.getCrlFromCertificate(bundle.firstCert);
        auto crlInfo = downloadCrlFromUrl(crlUrl);
        validationData.crlsBase64.push_back(crlInfo.first);
        Logger::info("Fetched CRL (Base64): " + crlInfo.first);

        for (const auto& cert : bundle.chainCertificates) {
            try {
                Logger::info("Fetching CRL for a chain certificate...");
                auto chainCrlUrl = session.getCrlFromCertificate(cert);
                auto chainCrlInfo = downloadCrlFromUrl(chainCrlUrl);
                validationData.crlsBase64.push_back(chainCrlInfo.first);
                Logger::info("Fetched CRL for chain certificate (Base64): " + chainCrlInfo.first);
            }
            catch (const std::runtime_error& e) {
                Logger::info("Could not get CRL for a certificate in the chain: " + std::string(e.what()));
            }
        }

        try {
            Logger::info("Fetching OCSP for TSA Certificate...");
            Logger::info("   - Original TSR (Base64): " + base64Tsr);

            std::string ocspUrl;
            std::string base64_ocsp_request;

            try {
                // First attempt: Try to extract certificates directly from TSR
                Logger::info("   - Attempting to extract certificates from TSR...");
                std::string tsaSignerCert = session.extractSignerCertFromTSR(base64Tsr);
                std::string tsaIssuerCert = session.extractIssuerCertFromTSR(base64Tsr);

                // Get OCSP URL and build request
                ocspUrl = session.getOCSPFromCertificate(tsaSignerCert, tsaIssuerCert);
                base64_ocsp_request = session.buildOCSPRequestFromCertificates(tsaSignerCert, tsaIssuerCert);
                Logger::info("   - Successfully retrieved OCSP data without fallback");
            }
            catch (const std::runtime_error& e) {
                Logger::info("   - Primary method failed: " + std::string(e.what()));
                Logger::info("   - Attempting fallback method with certificate downloading...");

                try {
                    // Fallback: Extract signer cert and download issuer cert
                    std::string tsaSignerCert = session.extractSignerCertFromTSR(base64Tsr);
                    Logger::info("   - Extracted signer certificate from TSR");

                    // Get issuer URL and download issuer certificate
                    std::string issuerUrl = session.getCertificateIssuerUrlFromCertificate(tsaSignerCert);
                    Logger::info("   - Found issuer URL: " + issuerUrl);

                    std::string tsaIssuerCert = fetchCertificateFromUrl(issuerUrl);
                    Logger::info("   - Downloaded issuer certificate from URL");

                    // Get OCSP URL and build request
                    ocspUrl = session.getOCSPFromCertificate(tsaSignerCert, tsaIssuerCert);
                    base64_ocsp_request = session.buildOCSPRequestFromCertificates(tsaSignerCert, tsaIssuerCert);
                    Logger::info("   - Successfully retrieved OCSP data using fallback method");
                }
                catch (const std::runtime_error& fallback_error) {
                    throw std::runtime_error("Both primary and fallback methods failed. Primary: " + std::string(e.what()) + ". Fallback: " + std::string(fallback_error.what()));
                }
            }

            Logger::info("   - Retrieved OCSP URL: " + ocspUrl);
            Logger::info("   - Built OCSP request (Base64): " + base64_ocsp_request);

            // Step 2: Make HTTP POST request to OCSP responder (returns base64)
            Logger::info("   - Making HTTP POST request to OCSP responder...");
            std::string base64_ocsp_response = makeOcspHttpPostRequest(ocspUrl, base64_ocsp_request);

            validationData.ocspsBase64.push_back(base64_ocsp_response);

            Logger::info("Fetched OCSP Response (Base64): " + base64_ocsp_response);
            Logger::info("Successfully added TSA OCSP response to validation data.");
        }
        catch (const std::runtime_error& e) {
            Logger::info("Could not get OCSP for a certificate in the chain: " + std::string(e.what()));
        }

        Logger::info("=============================");

        Logger::info("=== Signing Process (PART 2 - EMBEDDING) ===");
        session.finishSigning(signedHash, base64Tsr, validationData);
    }

    if (conformanceLevel == "ADES_B_LTA") {
        Logger::info("=== Signing Process (PART 1 - HASHING) ===");
        string urlEncodedHash = session.beginSigning();
        Logger::debug("URL Encoded Hash", urlEncodedHash);
        Logger::debug("Credential ID", bundle.credentialID);

        auto signedHash = GetSignedHash(urlEncodedHash, label, bundle.credentialID, hash_algo, "credential");

        Logger::info("Signed Hash from Remote Service (Base64):");
        Logger::debug("Signed Hash", signedHash);
        Logger::info("=============================");

        Logger::info("=== Timestamping the Signature ===");
        TimestampingService::requestTsrFromTimestampService(signedHash, tsaUrl);

        std::string tsrPath = GetInputFilePath("response.tsr");
        Logger::debug("TSR Path", tsrPath);
        std::string base64Tsr = TsrBase64Service::GetTsrBase64(tsrPath);

        Logger::info("Timestamp Response (TSR) from TSA (Base64):");
        Logger::debug("Timestamp Response (TSR)", base64Tsr);
        Logger::info("=============================");

        ValidationData validationData;

        validationData.certificatesBase64.push_back(bundle.firstCert);
        Logger::debug("Added end-entity certificate to validation data");

        validationData.certificatesBase64.insert(
        validationData.certificatesBase64.end(),
        bundle.chainCertificates.begin(),
        bundle.chainCertificates.end()
        );
        Logger::debug("Added " + std::to_string(bundle.chainCertificates.size()) + " chain certificates to validation data");

        validationData.certificatesBase64.push_back(base64Tsr);
        Logger::debug("Added TSR to validation data");

        Logger::info("=== Fetching Revocation Data (CRL/OCSP) ===");
        Logger::info("Fetching CRL for end-entity certificate...");
        auto crl_url_my_end = session.getCrlFromCertificate(bundle.firstCert);
        Logger::debug("CRL URL for end-entity certificate", crl_url_my_end);
        auto crl_info_my_end = downloadCrlFromUrl(crl_url_my_end);
        validationData.crlsBase64.push_back(crl_info_my_end.first);
        Logger::info("Fetched CRL (Base64): " + crl_info_my_end.first);

        for (const auto& cert : bundle.chainCertificates) {
        try {
            Logger::info("Fetching CRL for a chain certificate...");
            auto crl_url = session.getCrlFromCertificate(cert);
            Logger::debug("CRL URL for chain certificate", crl_url);
            auto crl_info = downloadCrlFromUrl(crl_url);
            validationData.crlsBase64.push_back(crl_info.first);
            Logger::info("Fetched CRL for chain certificate (Base64): " + crl_info.first);
        }
        catch (const std::runtime_error& e) {

            Logger::info("Could not get CRL for a certificate in the chain: " + std::string(e.what()));
        }
        }

        try {
        Logger::info("Fetching OCSP for TSA Certificate...");
        Logger::debug("Original TSR (Base64)", base64Tsr);

        std::string ocspUrl;
        std::string base64_ocsp_request;

        try {
            // First attempt: Try to extract certificates directly from TSR
            Logger::info("   - Attempting to extract certificates from TSR...");
            std::string tsaSignerCert = session.extractSignerCertFromTSR(base64Tsr);
            std::string tsaIssuerCert = session.extractIssuerCertFromTSR(base64Tsr);

            // Get OCSP URL and build request
            ocspUrl = session.getOCSPFromCertificate(tsaSignerCert, tsaIssuerCert);
            base64_ocsp_request = session.buildOCSPRequestFromCertificates(tsaSignerCert, tsaIssuerCert);
            Logger::info("   - Successfully retrieved OCSP data without fallback");
        }
        catch (const std::runtime_error& e) {
            Logger::info("   - Primary method failed: " + std::string(e.what()));
            Logger::info("   - Attempting fallback method with certificate downloading...");

            try {
                // Fallback: Extract signer cert and download issuer cert
                std::string tsaSignerCert = session.extractSignerCertFromTSR(base64Tsr);
                Logger::info("   - Extracted signer certificate from TSR");

                // Get issuer URL and download issuer certificate
                std::string issuerUrl = session.getCertificateIssuerUrlFromCertificate(tsaSignerCert);
                Logger::info("   - Found issuer URL: " + issuerUrl);

                std::string tsaIssuerCert = fetchCertificateFromUrl(issuerUrl);
                Logger::info("   - Downloaded issuer certificate from URL");

                // Get OCSP URL and build request
                ocspUrl = session.getOCSPFromCertificate(tsaSignerCert, tsaIssuerCert);
                base64_ocsp_request = session.buildOCSPRequestFromCertificates(tsaSignerCert, tsaIssuerCert);
                Logger::info("   - Successfully retrieved OCSP data using fallback method");
            }
            catch (const std::runtime_error& fallback_error) {
                throw std::runtime_error("Both primary and fallback methods failed. Primary: " + std::string(e.what()) + ". Fallback: " + std::string(fallback_error.what()));
            }
        }

        Logger::debug("OCSP URL", ocspUrl);
        Logger::debug("OCSP Request (Base64)", base64_ocsp_request);

        // Step 2: Make HTTP POST request to OCSP responder (returns base64)
        Logger::info("   - Making HTTP POST request to OCSP responder...");
        std::string base64_ocsp_response = makeOcspHttpPostRequest(ocspUrl, base64_ocsp_request);

        validationData.ocspsBase64.push_back(base64_ocsp_response);

        Logger::info("Fetched OCSP Response (Base64): " + base64_ocsp_response);
        Logger::debug("OCSP Response (Base64)", base64_ocsp_response);
        Logger::info("Successfully added TSA OCSP response to validation data.");
        }
        catch (const std::runtime_error& e) {

        Logger::info("Could not get OCSP for a certificate in the chain: " + std::string(e.what()));
        }

        Logger::info("=============================");

        Logger::info("=== Signing Process (PART 2 - EMBEDDING) ===");
        session.finishSigning(signedHash, base64Tsr, validationData);
        Logger::info("B-LT Signature completed and saved to PDF.");
        Logger::info("=============================");

        //LTA BEGINS
        Logger::info("=== LTA Extension (DOCUMENT TIMESTAMP) ===");
        auto ltaHash = session.beginSigningLTA();
        Logger::debug("LTA Hash for Document Timestamp", ltaHash);

        TimestampingService::requestTsrFromTimestampServiceForDocTimeStamp(ltaHash, tsaUrl);

        std::string tsrPathLta = GetInputFilePath("response2.tsr");
        Logger::debug("LTA TSR Path", tsrPathLta);
        std::string base64TsrLta = GetTsrBase64(tsrPathLta);

        Logger::info("LTA Timestamp Response (TSR) from server (Base64): " + base64TsrLta);
        Logger::debug("LTA Timestamp Response (TSR)", base64TsrLta);

        ValidationData ltaValidationData;

        try {
            Logger::info("Fetching validation data for LTA timestamp...");

            std::string ocspUrlLta;
            std::string base64_ocsp_request_lta;

            try {
                // First attempt: Try to extract certificates directly from LTA TSR
                Logger::info("   - Attempting to extract certificates from LTA TSR...");
                std::string tsaSignerCertLta = session.extractSignerCertFromTSR(base64TsrLta);
                std::string tsaIssuerCertLta = session.extractIssuerCertFromTSR(base64TsrLta);

                // Get OCSP URL and build request
                ocspUrlLta = session.getOCSPFromCertificate(tsaSignerCertLta, tsaIssuerCertLta);
                base64_ocsp_request_lta = session.buildOCSPRequestFromCertificates(tsaSignerCertLta, tsaIssuerCertLta);
                Logger::info("   - Successfully retrieved LTA OCSP data without fallback");
            }
            catch (const std::runtime_error& e) {
                Logger::info("   - Primary method failed: " + std::string(e.what()));
                Logger::info("   - Attempting fallback method with certificate downloading...");

                try {
                    // Fallback: Extract signer cert and download issuer cert
                    std::string tsaSignerCertLta = session.extractSignerCertFromTSR(base64TsrLta);
                    Logger::info("   - Extracted LTA signer certificate from TSR");

                    // Get issuer URL and download issuer certificate
                    std::string issuerUrlLta = session.getCertificateIssuerUrlFromCertificate(tsaSignerCertLta);
                    Logger::info("   - Found LTA issuer URL: " + issuerUrlLta);

                    std::string tsaIssuerCertLta = fetchCertificateFromUrl(issuerUrlLta);
                    Logger::info("   - Downloaded LTA issuer certificate from URL");

                    // Get OCSP URL and build request
                    ocspUrlLta = session.getOCSPFromCertificate(tsaSignerCertLta, tsaIssuerCertLta);
                    base64_ocsp_request_lta = session.buildOCSPRequestFromCertificates(tsaSignerCertLta, tsaIssuerCertLta);
                    Logger::info("   - Successfully retrieved LTA OCSP data using fallback method");
                }
                catch (const std::runtime_error& fallback_error) {
                    throw std::runtime_error("Both primary and fallback methods failed for LTA. Primary: " + std::string(e.what()) + ". Fallback: " + std::string(fallback_error.what()));
                }
            }

            Logger::debug("LTA OCSP URL", ocspUrlLta);
            Logger::debug("LTA OCSP Request (Base64)", base64_ocsp_request_lta);

            // Step 2: Make HTTP POST request to OCSP responder (returns base64)
            Logger::info("   - Making HTTP POST request to OCSP responder...");
            std::string base64_ocsp_response_lta = makeOcspHttpPostRequest(ocspUrlLta, base64_ocsp_request_lta);

            ltaValidationData.addOCSP(base64_ocsp_response_lta);
            Logger::info("Added OCSP for TSA cert to DSS data.");
            Logger::debug("LTA OCSP Response (Base64)", base64_ocsp_response_lta);

            // Extract certificates for additional validation data (CRL lookup)
            // Note: We already have these from the OCSP processing above, but we need them for CRL
            std::string tsaSignerCertForCrl = session.extractSignerCertFromTSR(base64TsrLta);
            Logger::debug("LTA TSA Signer Cert (Base64)", tsaSignerCertForCrl);
            ltaValidationData.addCertificate(tsaSignerCertForCrl);

            std::string tsaIssuerCertForCrl = session.extractIssuerCertFromTSR(base64TsrLta);
            Logger::debug("LTA TSA Issuer Cert (Base64)", tsaIssuerCertForCrl);
            ltaValidationData.addCertificate(tsaIssuerCertForCrl);
            Logger::info("Added TSA signer and issuer certs to DSS data.");

            // Get CRL for the TSA certificate
            auto crlUrlLta = session.getCrlFromCertificate(tsaSignerCertForCrl);
            Logger::debug("LTA CRL URL", crlUrlLta);
            auto crlInfoLta = downloadCrlFromUrl(crlUrlLta);
            ltaValidationData.addCRL(crlInfoLta.first);
            Logger::info("Added CRL for TSA cert to DSS data.");
            Logger::debug("LTA CRL (Base64)", crlInfoLta.first);
        }
        catch (const std::runtime_error& e) {
            Logger::info("WARNING: Could not get full validation data for LTA timestamp: " + std::string(e.what()));
        }

        session.finishSigningLTA(base64TsrLta, ltaValidationData);
        Logger::info("LTA extension completed and saved to PDF.");
        Logger::info("=============================");

        Logger::info("======== PDF SIGNING AND TIMESTAMPING PROCESS COMPLETED SUCCESSFULLY =======");
    }

    if (isAutoMode) {
        Logger::info("=== Combination " + std::to_string(combinationNumber) + " COMPLETED ===");
        Logger::info("Output saved to: " + outputPdf);
        Logger::info("================================================");
    }
}

/*
 * ============================================================================
 * LOGGING CONFIGURATION
 * ============================================================================
 * To switch between logging modes, change the Config::setDebugMode() call in main():
 *
 * - DEBUG MODE: Config::setDebugMode(true)  - Shows all values in full detail
 * - INFO MODE:  Config::setDebugMode(false) - Shows only essential information
 *
 * Look for the "LOGGING CONFIGURATION" section in the main() function below.
 * Current default: INFO MODE (false)
 * ============================================================================
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#include <filesystem>
#include <fstream>

// Function to ensure directories exist and create them if needed
void ensureDirectoriesExist() {
    namespace fs = std::filesystem;

    // Check and create "input" folder
    if (!fs::exists("input")) {
        Logger::info("Creating 'input' directory...");
        fs::create_directory("input");
        Logger::info("'input' directory created successfully.");
    } else {
        Logger::info("'input' directory already exists.");
    }

    // Check and create "output" folder
    if (!fs::exists("output")) {
        Logger::info("Creating 'output' directory...");
        fs::create_directory("output");
        Logger::info("'output' directory created successfully.");
    } else {
        Logger::info("'output' directory already exists.");
    }
}

// Function to ensure sample.pdf exists in input folder
void ensureSamplePdfExists() {
    namespace fs = std::filesystem;

    std::string inputSamplePath = "input/sample.pdf";
    // Try multiple possible paths for the Assets folder
    std::vector<std::string> possibleAssetsPaths = {
        "Assets/sample.pdf",                                    // If running from project root
        "../../../examples/PoDoFo-Tester-App/Assets/sample.pdf", // If running from build directory
        "../../../../examples/PoDoFo-Tester-App/Assets/sample.pdf", // Alternative build path
        "examples/PoDoFo-Tester-App/Assets/sample.pdf"          // If running from repo root
    };

    std::string assetsSamplePath;

        // Check if sample.pdf exists in input folder
    if (!fs::exists(inputSamplePath)) {
        Logger::info("sample.pdf not found in input folder. Searching for Assets folder...");

        // Try to find the Assets folder in various locations
        bool foundAssets = false;
        for (const auto& path : possibleAssetsPaths) {
            if (fs::exists(path)) {
                assetsSamplePath = path;
                foundAssets = true;
                Logger::info("Found sample.pdf at: " + path);
                break;
            }
        }

        if (foundAssets) {
            Logger::info("Copying sample.pdf to input folder...");

            try {
                fs::copy_file(assetsSamplePath, inputSamplePath);
                Logger::info("sample.pdf successfully copied from Assets to input folder.");
            } catch (const std::exception& e) {
                Logger::error("Failed to copy sample.pdf: " + std::string(e.what()));
                throw;
            }
        } else {
            Logger::error("sample.pdf not found in any expected Assets folder location!");
            Logger::error("Searched paths:");
            for (const auto& path : possibleAssetsPaths) {
                Logger::error("  - " + path);
            }
            Logger::error("Current working directory: " + fs::current_path().string());
            throw std::runtime_error("sample.pdf not found in Assets folder");
        }
    } else {
        Logger::info("sample.pdf already exists in input folder.");
    }
}


int main()
{
    try {
        // ===========================================
        // LOGGING CONFIGURATION - CHANGE THIS TO SWITCH MODES
        // ===========================================
        // DEBUG MODE: Config::setDebugMode(true)  - Shows all values in full detail
        // INFO MODE:  Config::setDebugMode(false) - Shows only essential information
        Config::setDebugMode(true);  // ← CHANGE THIS LINE: true=DEBUG, false=INFO
        // ===========================================

        Logger::info("=== PoDoFo-Tester-App Starting ===");

        // Ensure required directories exist
        Logger::info("=== Checking and creating required directories ===");
        ensureDirectoriesExist();

        // Ensure sample.pdf exists in input folder
        Logger::info("=== Checking for sample.pdf ===");
        ensureSamplePdfExists();

        Logger::info("=== Directory and file setup completed ===");

        std::string inputPdf = "input/sample.pdf";
        int modeChoice;

        cout << "Select Mode:" << endl;
        cout << "1. Manual Mode (select conformance level and TSA manually)" << endl;
        cout << "2. Automatic Mode (run all 7 predefined combinations)" << endl;
        cout << "3. Auto Mode B_T (run ADES_B_T with all 16 timestamp services)" << endl;
        cout << "4. Auto Mode B_LT (run ADES_B_LT with all 16 timestamp services)" << endl;
        cout << "5. Auto Mode B_LTA (run ADES_B_LTA with all 16 timestamp services)" << endl;
        cout << "6. Auto Mode ALL (run B_T + B_LT + B_LTA each with all 16 timestamp services)" << endl;
        cout << "Enter choice (1-6): ";
        cin >> modeChoice;

        if (modeChoice == 2) {
            // AUTOMATIC MODE - Run all 7 combinations
            Logger::info("=== AUTOMATIC MODE SELECTED ===");
            Logger::info("Will process all 7 combinations sequentially:");
            Logger::info("1. ADES_B_B + TSA1 (Cartao de Cidadao)");
            Logger::info("2. ADES_B_T + TSA1 (Cartao de Cidadao)");
            Logger::info("3. ADES_B_T + TSA2 (Qualified)");
            Logger::info("4. ADES_B_LT + TSA1 (Cartao de Cidadao)");
            Logger::info("5. ADES_B_LT + TSA2 (Qualified)");
            Logger::info("6. ADES_B_LTA + TSA1 (Cartao de Cidadao)");
            Logger::info("7. ADES_B_LTA + TSA2 (Qualified)");
            Logger::info("=============================");

            cout << "\nPress Enter to start automatic processing of all combinations...";
            cin.ignore();
            cin.get();

            // Define the 7 combinations: {conformanceChoice, tsaChoice}
            vector<pair<int, int>> combinations = {
                {1, 1}, // ADES_B_B + TSA1
                {2, 1}, // ADES_B_T + TSA1
                {2, 2}, // ADES_B_T + TSA2
                {3, 1}, // ADES_B_LT + TSA1
                {3, 2}, // ADES_B_LT + TSA2
                {4, 1}, // ADES_B_LTA + TSA1
                {4, 2}  // ADES_B_LTA + TSA2
            };

            Logger::info("=== STARTING AUTOMATIC PROCESSING ===");

            for (size_t i = 0; i < combinations.size(); i++) {
                int combinationNumber = static_cast<int>(i + 1);
                int conformanceChoice = combinations[i].first;
                int tsaChoice = combinations[i].second;

                Logger::info("===== STARTING COMBINATION " + std::to_string(combinationNumber) + " OF 7 =====");

                try {
                    processSigningCombination(conformanceChoice, tsaChoice, inputPdf, true, combinationNumber);
                    Logger::info("Successfully completed combination " + std::to_string(combinationNumber));
                } catch (const std::exception& e) {
                    Logger::error("Error in combination " + std::to_string(combinationNumber) + ": " + std::string(e.what()));
                    Logger::info("Continuing with next combination...");
                }

                if (i < combinations.size() - 1) {
                    Logger::info("Waiting 2 seconds before next combination...");
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                }
            }

            Logger::info("=== ALL COMBINATIONS COMPLETED ===");
            Logger::info("Check the 'output/' directory for all generated PDF files.");
            Logger::info("Files are named: auto_[combination]_[conformance]_TSA[tsa]_[timestamp].pdf");

        } else if (modeChoice == 3) {
            // AUTO MODE B_T - Run ADES_B_T with all 16 TSA services
            Logger::info("=== AUTO MODE B_T SELECTED ===");
            Logger::info("Will process ADES_B_T with all 16 timestamp services:");
            for (int i = 1; i <= 16; i++) {
                Logger::info(std::to_string(i) + ". ADES_B_T + TSA" + std::to_string(i));
            }
            Logger::info("=============================");

            cout << "\nPress Enter to start automatic processing of ADES_B_T with all TSA services...";
            cin.ignore();
            cin.get();

            Logger::info("=== STARTING AUTO MODE B_T PROCESSING ===");

            for (int tsaChoice = 1; tsaChoice <= 16; tsaChoice++) {
                Logger::info("===== STARTING B_T COMBINATION " + std::to_string(tsaChoice) + " OF 16 =====");

                try {
                    processSigningCombination(2, tsaChoice, inputPdf, true, tsaChoice); // 2 = ADES_B_T
                    Logger::info("Successfully completed B_T combination " + std::to_string(tsaChoice));
                } catch (const std::exception& e) {
                    Logger::error("Error in B_T combination " + std::to_string(tsaChoice) + ": " + std::string(e.what()));
                    Logger::info("Continuing with next combination...");
                }

                if (tsaChoice < 16) {
                    Logger::info("Waiting 2 seconds before next combination...");
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                }
            }

            Logger::info("=== AUTO MODE B_T COMPLETED ===");
            Logger::info("Check the 'output/' directory for all generated PDF files.");

        } else if (modeChoice == 4) {
            // AUTO MODE B_LT - Run ADES_B_LT with all 16 TSA services
            Logger::info("=== AUTO MODE B_LT SELECTED ===");
            Logger::info("Will process ADES_B_LT with all 16 timestamp services:");
            for (int i = 1; i <= 16; i++) {
                Logger::info(std::to_string(i) + ". ADES_B_LT + TSA" + std::to_string(i));
            }
            Logger::info("=============================");

            cout << "\nPress Enter to start automatic processing of ADES_B_LT with all TSA services...";
            cin.ignore();
            cin.get();

            Logger::info("=== STARTING AUTO MODE B_LT PROCESSING ===");

            for (int tsaChoice = 1; tsaChoice <= 16; tsaChoice++) {
                Logger::info("===== STARTING B_LT COMBINATION " + std::to_string(tsaChoice) + " OF 16 =====");

                try {
                    processSigningCombination(3, tsaChoice, inputPdf, true, tsaChoice); // 3 = ADES_B_LT
                    Logger::info("Successfully completed B_LT combination " + std::to_string(tsaChoice));
                } catch (const std::exception& e) {
                    Logger::error("Error in B_LT combination " + std::to_string(tsaChoice) + ": " + std::string(e.what()));
                    Logger::info("Continuing with next combination...");
                }

                if (tsaChoice < 16) {
                    Logger::info("Waiting 2 seconds before next combination...");
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                }
            }

            Logger::info("=== AUTO MODE B_LT COMPLETED ===");
            Logger::info("Check the 'output/' directory for all generated PDF files.");

        } else if (modeChoice == 5) {
            // AUTO MODE B_LTA - Run ADES_B_LTA with all 16 TSA services
            Logger::info("=== AUTO MODE B_LTA SELECTED ===");
            Logger::info("Will process ADES_B_LTA with all 16 timestamp services:");
            for (int i = 1; i <= 16; i++) {
                Logger::info(std::to_string(i) + ". ADES_B_LTA + TSA" + std::to_string(i));
            }
            Logger::info("=============================");

            cout << "\nPress Enter to start automatic processing of ADES_B_LTA with all TSA services...";
            cin.ignore();
            cin.get();

            Logger::info("=== STARTING AUTO MODE B_LTA PROCESSING ===");

            for (int tsaChoice = 1; tsaChoice <= 16; tsaChoice++) {
                Logger::info("===== STARTING B_LTA COMBINATION " + std::to_string(tsaChoice) + " OF 16 =====");

                try {
                    processSigningCombination(4, tsaChoice, inputPdf, true, tsaChoice); // 4 = ADES_B_LTA
                    Logger::info("Successfully completed B_LTA combination " + std::to_string(tsaChoice));
                } catch (const std::exception& e) {
                    Logger::error("Error in B_LTA combination " + std::to_string(tsaChoice) + ": " + std::string(e.what()));
                    Logger::info("Continuing with next combination...");
                }

                if (tsaChoice < 16) {
                    Logger::info("Waiting 2 seconds before next combination...");
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                }
            }

            Logger::info("=== AUTO MODE B_LTA COMPLETED ===");
            Logger::info("Check the 'output/' directory for all generated PDF files.");

        } else if (modeChoice == 6) {
            // AUTO MODE ALL - Run B_T + B_LT + B_LTA each with all 16 TSA services (48 total combinations)
            Logger::info("=== AUTO MODE ALL SELECTED ===");
            Logger::info("Will process B_T + B_LT + B_LTA each with all 16 timestamp services (48 total combinations):");
            Logger::info("B_T combinations: 1-16");
            Logger::info("B_LT combinations: 17-32");
            Logger::info("B_LTA combinations: 33-48");
            Logger::info("=============================");

            cout << "\nPress Enter to start automatic processing of ALL combinations (48 total)...";
            cin.ignore();
            cin.get();

            Logger::info("=== STARTING AUTO MODE ALL PROCESSING ===");

            int combinationNumber = 0;

            // Process B_T with all TSA services (combinations 1-16)
            Logger::info("=== PROCESSING B_T WITH ALL TSA SERVICES (1-16) ===");
            for (int tsaChoice = 1; tsaChoice <= 16; tsaChoice++) {
                combinationNumber++;
                Logger::info("===== STARTING COMBINATION " + std::to_string(combinationNumber) + " OF 48 (B_T + TSA" + std::to_string(tsaChoice) + ") =====");

                try {
                    processSigningCombination(2, tsaChoice, inputPdf, true, combinationNumber); // 2 = ADES_B_T
                    Logger::info("Successfully completed combination " + std::to_string(combinationNumber));
                } catch (const std::exception& e) {
                    Logger::error("Error in combination " + std::to_string(combinationNumber) + ": " + std::string(e.what()));
                    Logger::info("Continuing with next combination...");
                }

                if (combinationNumber < 48) {
                    Logger::info("Waiting 2 seconds before next combination...");
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                }
            }

            // Process B_LT with all TSA services (combinations 17-32)
            Logger::info("=== PROCESSING B_LT WITH ALL TSA SERVICES (17-32) ===");
            for (int tsaChoice = 1; tsaChoice <= 16; tsaChoice++) {
                combinationNumber++;
                Logger::info("===== STARTING COMBINATION " + std::to_string(combinationNumber) + " OF 48 (B_LT + TSA" + std::to_string(tsaChoice) + ") =====");

                try {
                    processSigningCombination(3, tsaChoice, inputPdf, true, combinationNumber); // 3 = ADES_B_LT
                    Logger::info("Successfully completed combination " + std::to_string(combinationNumber));
                } catch (const std::exception& e) {
                    Logger::error("Error in combination " + std::to_string(combinationNumber) + ": " + std::string(e.what()));
                    Logger::info("Continuing with next combination...");
                }

                if (combinationNumber < 48) {
                    Logger::info("Waiting 2 seconds before next combination...");
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                }
            }

            // Process B_LTA with all TSA services (combinations 33-48)
            Logger::info("=== PROCESSING B_LTA WITH ALL TSA SERVICES (33-48) ===");
            for (int tsaChoice = 1; tsaChoice <= 16; tsaChoice++) {
                combinationNumber++;
                Logger::info("===== STARTING COMBINATION " + std::to_string(combinationNumber) + " OF 48 (B_LTA + TSA" + std::to_string(tsaChoice) + ") =====");

                try {
                    processSigningCombination(4, tsaChoice, inputPdf, true, combinationNumber); // 4 = ADES_B_LTA
                    Logger::info("Successfully completed combination " + std::to_string(combinationNumber));
                } catch (const std::exception& e) {
                    Logger::error("Error in combination " + std::to_string(combinationNumber) + ": " + std::string(e.what()));
                    Logger::info("Continuing with next combination...");
                }

                if (combinationNumber < 48) {
                    Logger::info("Waiting 2 seconds before next combination...");
                    std::this_thread::sleep_for(std::chrono::seconds(2));
                }
            }

            Logger::info("=== AUTO MODE ALL COMPLETED ===");
            Logger::info("Processed all 48 combinations (B_T + B_LT + B_LTA each with all 16 TSA services)");
            Logger::info("Check the 'output/' directory for all generated PDF files.");

        } else {
            // MANUAL MODE - Original behavior
            Logger::info("=== MANUAL MODE SELECTED ===");

            int conformanceChoice, tsaChoice;

            cout << "\nSelect Conformance Level:" << endl;
            cout << "1. ADES_B_B" << endl;
            cout << "2. ADES_B_T" << endl;
            cout << "3. ADES_B_LT" << endl;
            cout << "4. ADES_B_LTA" << endl;
            cout << "Enter choice (1-4): ";
            cin >> conformanceChoice;

            cout << "\nSelect Timestamp Service:" << endl;
            cout << "1.  " << Config::getTsaUrlCartaodecidadao() << " (trusted)" << endl;
            cout << "2.  " << Config::getTsaUrlQualified() << " (trusted)" << endl;
            cout << "3.  " << Config::getTsaUrlGlobalsignAatl() << " (trusted)" << endl;
            cout << "4.  " << Config::getTsaUrlUnqualified() << " (untrusted)" << endl;
            cout << "5.  " << Config::getTsaUrlIdentrust() << " (untrusted)" << endl;
            cout << "6.  " << Config::getTsaUrlQuovadis() << " (untrusted)" << endl;
            cout << "7.  " << Config::getTsaUrlDigicert() << " (untrusted)" << endl;
            cout << "8.  " << Config::getTsaUrlSwisssign() << " (untrusted)" << endl;
            cout << "9.  " << Config::getTsaUrlEntrust() << " (untrusted)" << endl;
            cout << "10. " << Config::getTsaUrlCertum() << " (untrusted)" << endl;
            cout << "11. " << Config::getTsaUrlFreeHttp() << " (untrusted)" << endl;
            cout << "12. " << Config::getTsaUrlFree() << " (untrusted)" << endl;
            cout << "13. " << Config::getTsaUrlSsl() << " (untrusted)" << endl;
            cout << "14. " << Config::getTsaUrlWotrus() << " (untrusted)" << endl;
            cout << "15. " << Config::getTsaUrlGlobalsignR6() << " (untrusted)" << endl;
            cout << "16. " << Config::getTsaUrlCertumTime() << " (untrusted)" << endl;
            cout << "Enter choice (1-16): ";
            cin >> tsaChoice;

            processSigningCombination(conformanceChoice, tsaChoice, inputPdf, false, 0);
        }

    }
    catch (const std::exception& e) {
        Logger::error("Error in application: " + std::string(e.what()));
        return 1;
    }

    return 0;
}
