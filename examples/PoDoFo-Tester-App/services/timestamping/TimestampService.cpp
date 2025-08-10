#include "TimestampService.h"
#include "../../utils/Utils.h"
#include "../../core/Logger.h"
#include <openssl/ts.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>

/**
 * @brief Service that handles timestamp request creation and management.
 *
 * @param signedHash The signed hash to create a timestamp request for
 * @param outputPath The output path for the timestamp request file
 */
void CreateTimestampRequest(const std::string& signedHash, const std::string& outputPath) {
    Logger::info("=== Starting Timestamp Request Creation Service ===");
    Logger::debug("Signed Hash Size", std::to_string(signedHash.size()) + " bytes");
    Logger::debug("Output Path", outputPath);

    Logger::info("Step 1: Computing SHA-256 hash of the signed data");
    std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        Logger::error("Failed to create EVP_MD_CTX");
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(mdctx, signedHash.data(), signedHash.size()) != 1 ||
        EVP_DigestFinal_ex(mdctx, digest.data(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        Logger::error("Failed to compute SHA-256 hash");
        throw std::runtime_error("Failed to compute SHA256 hash");
    }
    EVP_MD_CTX_free(mdctx);
    Logger::info("SHA-256 hash computed successfully");
    Logger::debug("Computed Digest Size", std::to_string(digest.size()) + " bytes");

    std::filesystem::create_directories("input");

    if (digest.size() != 32) {
        Logger::error("Computed digest is not 32 bytes long for SHA-256. Actual size: " + std::to_string(digest.size()));
        throw std::runtime_error("Digest must be exactly 32 bytes for SHA-256");
    }

    Logger::info("Step 2: Assembling the timestamp request structure (TS_REQ)");
    TS_REQ* ts_req = TS_REQ_new();
    if (!ts_req || !TS_REQ_set_version(ts_req, 1)) {
        TS_REQ_free(ts_req);
        Logger::error("Failed to create or set version on TS_REQ");
        throw std::runtime_error("Failed to create or set version on TS_REQ");
    }

    Logger::info("Step 3: Creating message imprint");
    TS_MSG_IMPRINT* imprint = TS_MSG_IMPRINT_new();
    if (!imprint) {
        TS_REQ_free(ts_req);
        Logger::error("Failed to allocate TS_MSG_IMPRINT");
        throw std::runtime_error("Failed to allocate TS_MSG_IMPRINT");
    }

    const EVP_MD* md = EVP_sha256();
    X509_ALGOR* algo = X509_ALGOR_new();
    X509_ALGOR_set_md(algo, md);
    TS_MSG_IMPRINT_set_algo(imprint, algo);

    std::vector<unsigned char> non_const_digest(digest.begin(), digest.end());

    if (!TS_MSG_IMPRINT_set_msg(imprint, non_const_digest.data(), static_cast<int>(non_const_digest.size()))) {
        TS_MSG_IMPRINT_free(imprint);
        TS_REQ_free(ts_req);
        Logger::error("Failed to set message digest");
        throw std::runtime_error("Failed to set message digest");
    }

    if (!TS_REQ_set_msg_imprint(ts_req, imprint)) {
        TS_MSG_IMPRINT_free(imprint);
        TS_REQ_free(ts_req);
        Logger::error("Failed to attach message imprint to the request");
        throw std::runtime_error("Failed to attach message imprint to request");
    }

    Logger::info("Step 4: Requesting TSA certificate in the response");
    TS_REQ_set_cert_req(ts_req, 1);

    Logger::info("Step 5: Generating and adding a nonce");
    unsigned char nonce_bytes[8];
    if (!RAND_bytes(nonce_bytes, sizeof(nonce_bytes))) {
        TS_REQ_free(ts_req);
        Logger::error("Failed to generate random nonce");
        throw std::runtime_error("Failed to generate nonce");
    }

    BIGNUM* nonce_bn = BN_bin2bn(nonce_bytes, sizeof(nonce_bytes), nullptr);
    ASN1_INTEGER* nonce_asn1 = BN_to_ASN1_INTEGER(nonce_bn, nullptr);
    TS_REQ_set_nonce(ts_req, nonce_asn1);
    BN_free(nonce_bn);
    ASN1_INTEGER_free(nonce_asn1);

    Logger::info("Step 6: Writing the final TSQ to file: " + outputPath);
    FILE* outFile = fopen(outputPath.c_str(), "wb");
    if (!outFile || !i2d_TS_REQ_fp(outFile, ts_req)) {
        if (outFile) fclose(outFile);
        TS_REQ_free(ts_req);
        Logger::error("Failed to write TS_REQ to file: " + outputPath);
        throw std::runtime_error("Failed to write TS_REQ to file");
    }

    fclose(outFile);
    TS_REQ_free(ts_req);
    Logger::info("Timestamp request (TSQ) saved successfully to: " + outputPath);
    Logger::info("Timestamp request creation completed successfully");
    Logger::info("=================================================");
}
