#include "TimestampRequestService.h"
#include "../../core/Logger.h"
#include <fstream>
#include <iterator>
#include <curl/curl.h>
#include <openssl/ts.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <iostream>
#include <vector>

/**
 * @brief Creates a timestamp request from a digest and saves it to a file.
 *
 * @param digest The digest to create the timestamp request from
 * @param outPath The output path for the timestamp request file
 * @return true if successful, false otherwise
 */
bool TimestampRequestService::CreateTimestampRequestFromDigest(const std::vector<unsigned char>& digest, const std::string& outPath) {
    Logger::info("=== Starting Timestamp Request Creation from Digest ===");
    Logger::debug("Digest Size", std::to_string(digest.size()) + " bytes");
    Logger::debug("Output Path", outPath);

    if (digest.size() != 32) {
        Logger::error("Digest must be exactly 32 bytes for SHA-256");
        return false;
    }

    TS_REQ* ts_req = TS_REQ_new();
    if (!ts_req || !TS_REQ_set_version(ts_req, 1)) {
        Logger::error("Failed to create or set version on TS_REQ");
        TS_REQ_free(ts_req);
        return false;
    }

    TS_MSG_IMPRINT* imprint = TS_MSG_IMPRINT_new();
    if (!imprint) {
        Logger::error("Failed to allocate TS_MSG_IMPRINT");
        TS_REQ_free(ts_req);
        return false;
    }

    const EVP_MD* md = EVP_sha256();
    X509_ALGOR* algo = X509_ALGOR_new();
    X509_ALGOR_set_md(algo, md);
    TS_MSG_IMPRINT_set_algo(imprint, algo);

    std::vector<unsigned char> non_const_digest(digest.begin(), digest.end());

    if (!TS_MSG_IMPRINT_set_msg(imprint, non_const_digest.data(), static_cast<int>(non_const_digest.size()))) {
        Logger::error("Failed to set message digest");
        TS_MSG_IMPRINT_free(imprint);
        TS_REQ_free(ts_req);
        return false;
    }

    if (!TS_REQ_set_msg_imprint(ts_req, imprint)) {
        Logger::error("Failed to attach message imprint to request");
        TS_MSG_IMPRINT_free(imprint);
        TS_REQ_free(ts_req);
        return false;
    }

    TS_REQ_set_cert_req(ts_req, 1);

    unsigned char nonce_bytes[8];
    if (!RAND_bytes(nonce_bytes, sizeof(nonce_bytes))) {
        Logger::error("Failed to generate nonce");
        TS_REQ_free(ts_req);
        return false;
    }

    BIGNUM* nonce_bn = BN_bin2bn(nonce_bytes, sizeof(nonce_bytes), nullptr);
    ASN1_INTEGER* nonce_asn1 = BN_to_ASN1_INTEGER(nonce_bn, nullptr);
    TS_REQ_set_nonce(ts_req, nonce_asn1);
    BN_free(nonce_bn);
    ASN1_INTEGER_free(nonce_asn1);

    FILE* outFile = fopen(outPath.c_str(), "wb");
    if (!outFile || !i2d_TS_REQ_fp(outFile, ts_req)) {
        Logger::error("Failed to write TS_REQ to file: " + outPath);
        if (outFile) fclose(outFile);
        TS_REQ_free(ts_req);
        return false;
    }

    fclose(outFile);
    TS_REQ_free(ts_req);
    Logger::info("Timestamp request saved to: " + outPath);
    Logger::info("Timestamp request creation completed successfully");
    Logger::info("=================================================");
    return true;
}

/**
 * @brief Sends a timestamp request to a TSA and saves the response.
 *
 * @param tsqPath The path to the timestamp request file
 * @param tsrPath The path to save the timestamp response file
 * @param tsaUrl The URL of the timestamp authority service
 * @return true if successful, false otherwise
 */
bool TimestampRequestService::SendTimestampRequest(const std::string& tsqPath, const std::string& tsrPath, const std::string& tsaUrl) {
    Logger::info("=== Starting Timestamp Request Sending Service ===");
    Logger::debug("TSQ Path", tsqPath);
    Logger::debug("TSR Path", tsrPath);
    Logger::debug("TSA URL", tsaUrl);

    CURL* curl = nullptr;
    struct curl_slist* headers = nullptr;
    std::vector<char> responseBuffer;
    FILE* outputFile = nullptr;

    try {
        Logger::info("Opening TSQ file: " + tsqPath);
        std::ifstream input(tsqPath, std::ios::binary);
        if (!input) {
            Logger::error("Cannot open file: " + tsqPath);
            return false;
        }
        std::vector<char> tsqData((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        input.close();

        Logger::debug("TSQ file size", std::to_string(tsqData.size()) + " bytes");

        if (tsqData.empty()) {
            Logger::error("TSQ file is empty or corrupted");
            return false;
        }

        Logger::info("Initializing CURL...");
        curl = curl_easy_init();
        if (!curl) {
            Logger::error("curl_easy_init() failed");
            return false;
        }

        Logger::info("Setting up CURL options...");
        headers = curl_slist_append(headers, "Content-Type: application/timestamp-query");
        headers = curl_slist_append(headers, "Accept: application/timestamp-reply");
        headers = curl_slist_append(headers, "User-Agent: PoDoFo TSA Client");

        curl_easy_setopt(curl, CURLOPT_URL, tsaUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, tsqData.data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(tsqData.size()));

        outputFile = fopen(tsrPath.c_str(), "wb");
        if (!outputFile) {
            Logger::error("Cannot open output file: " + tsrPath);
            return false;
        }

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, outputFile);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

        Logger::info("Performing CURL request to TSA...");
        CURLcode res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            Logger::error("curl_easy_perform() failed: " + std::string(curl_easy_strerror(res)));
            if (outputFile) fclose(outputFile);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return false;
        }

        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code != 200) {
            Logger::error("TSA server returned HTTP code: " + std::to_string(http_code));
            if (outputFile) fclose(outputFile);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return false;
        }

        Logger::info("CURL request completed successfully");

        if (outputFile) {
            fclose(outputFile);
            outputFile = nullptr;
        }
        curl_slist_free_all(headers);
        headers = nullptr;
        curl_easy_cleanup(curl);
        curl = nullptr;

        Logger::info("Timestamp response saved to: " + tsrPath);
        Logger::info("Timestamp request sending completed successfully");
        Logger::info("=============================================");
        return true;
    }
    catch (const std::exception& e) {
        Logger::error("Exception in SendTimestampRequest: " + std::string(e.what()));
        if (outputFile) fclose(outputFile);
        if (headers) curl_slist_free_all(headers);
        if (curl) curl_easy_cleanup(curl);
        return false;
    }
    catch (...) {
        Logger::error("Unhandled exception in SendTimestampRequest");
        if (outputFile) fclose(outputFile);
        if (headers) curl_slist_free_all(headers);
        if (curl) curl_easy_cleanup(curl);
        return false;
    }
}
