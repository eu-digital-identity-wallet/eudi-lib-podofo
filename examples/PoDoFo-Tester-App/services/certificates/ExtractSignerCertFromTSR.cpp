#include "ExtractSignerCertFromTSR.h"
#include "../../core/Logger.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>

/**
 * @brief Given a base64-encoded TSR, returns the TSA signer certificate as base64 DER.
 * @param base64Tsr The base64-encoded TSR (timestamp response, as from Sectigo etc.)
 * @return std::string The base64 DER encoding of the signer certificate
 * @throws std::runtime_error on failure
 */
std::string extractSignerCertFromTSR(const std::string& base64Tsr) {
    Logger::info("=== Starting Signer Certificate Extraction from TSR Service ===");
    Logger::debug("Base64 TSR Size", std::to_string(base64Tsr.length()) + " characters");

    auto base64_decode = [](const std::string& base64_string) -> std::vector<unsigned char> {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO* mem = BIO_new_mem_buf(base64_string.data(), static_cast<int>(base64_string.size()));
        BIO* bio = BIO_push(b64, mem);

        std::vector<unsigned char> decoded_data(base64_string.length());
        int decoded_length = BIO_read(bio, decoded_data.data(), static_cast<int>(decoded_data.size()));
        BIO_free_all(bio);

        if (decoded_length < 0) {
            Logger::error("Failed to decode base64 TSR");
            throw std::runtime_error("Failed to decode base64 TSR.");
        }
        decoded_data.resize(decoded_length);
        return decoded_data;
    };

    auto base64_encode = [](const std::vector<unsigned char>& data) -> std::string {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
        BIO* mem = BIO_new(BIO_s_mem());
        BIO* bio = BIO_push(b64, mem);

        BIO_write(bio, data.data(), static_cast<int>(data.size()));
        BIO_flush(bio);

        BUF_MEM* bptr = nullptr;
        BIO_get_mem_ptr(bio, &bptr);
        std::string result(bptr->data, bptr->length);
        BIO_free_all(bio);
        return result;
    };

    Logger::info("Decoding base64 TSR...");
    std::vector<unsigned char> tsr_der = base64_decode(base64Tsr);
    Logger::debug("Decoded TSR size", std::to_string(tsr_der.size()) + " bytes");

    Logger::info("Parsing TS_RESP from DER...");
    const unsigned char* p = tsr_der.data();
    std::unique_ptr<TS_RESP, decltype(&TS_RESP_free)> ts_resp(d2i_TS_RESP(nullptr, &p, tsr_der.size()), TS_RESP_free);
    if (!ts_resp) {
        Logger::error("Failed to parse TS_RESP from DER");
        throw std::runtime_error("Failed to parse TS_RESP from DER.");
    }

    Logger::info("Extracting PKCS7 token from TSR...");
    PKCS7* pkcs7 = TS_RESP_get_token(ts_resp.get());
    if (!pkcs7) {
        Logger::error("TSR does not contain a PKCS7 token");
        throw std::runtime_error("TSR does not contain a PKCS7 token.");
    }

    Logger::info("Extracting certificates from PKCS7 token...");
    STACK_OF(X509)* certs = pkcs7->d.sign->cert;
    if (!certs || sk_X509_num(certs) < 1) {
        Logger::error("TSR does not contain any certificates to find the signer");
        throw std::runtime_error("TSR does not contain any certificates to find the signer.");
    }

    Logger::info("Getting signer certificate (index 0)...");
    X509* signerCert = sk_X509_value(certs, 0);
    if (!signerCert) {
        Logger::error("Could not get signer certificate from TSR");
        throw std::runtime_error("Could not get signer certificate from TSR.");
    }

    Logger::info("Encoding signer certificate to DER...");
    int len = i2d_X509(signerCert, nullptr);
    if (len <= 0) {
        Logger::error("Failed to get length of DER for signer cert");
        throw std::runtime_error("Failed to get length of DER for signer cert.");
    }
    std::vector<unsigned char> signer_der(len);
    unsigned char* out_p = signer_der.data();
    if (i2d_X509(signerCert, &out_p) <= 0) {
        Logger::error("Failed to encode signer cert to DER");
        throw std::runtime_error("Failed to encode signer cert to DER.");
    }

    Logger::info("Encoding signer certificate to base64...");
    std::string result = base64_encode(signer_der);
    Logger::debug("Base64 encoded signer certificate size", std::to_string(result.length()) + " characters");
    Logger::info("Signer certificate extraction completed successfully");
    Logger::info("============================================================");
    return result;
}
