#include "GetOCSPFromCertificate.h"
#include "OCSPHttpService.h"
#include "../../core/Logger.h"

/**
 * @brief Gets an OCSP request from base64-encoded certificates and returns it as base64.
 */
std::string getOCSPRequestFromCertificates(const std::string& base64Cert, const std::string& base64IssuerCert) {
    Logger::info("=== Starting OCSP Request Generation Service ===");
    Logger::debug("Base64 Certificate", base64Cert);
    Logger::debug("Base64 Issuer Certificate", base64IssuerCert);

    Logger::info("Decoding certificates from base64...");
    std::vector<unsigned char> decoded_cert = base64Decode(base64Cert);
    std::vector<unsigned char> decoded_issuer = base64Decode(base64IssuerCert);
    Logger::debug("Decoded cert size", std::to_string(decoded_cert.size()) + " bytes");
    Logger::debug("Decoded issuer cert size", std::to_string(decoded_issuer.size()) + " bytes");

    Logger::info("Parsing DER certificates into X509 structures...");
    const unsigned char* p = decoded_cert.data();
    std::unique_ptr<X509, decltype(&X509_free)> cert(d2i_X509(nullptr, &p, decoded_cert.size()), X509_free);
    if (!cert) {
        Logger::error("Failed to parse DER certificate: " + std::string(ERR_reason_error_string(ERR_get_error())));
        throw std::runtime_error("Failed to parse DER certificate: " + std::string(ERR_reason_error_string(ERR_get_error())));
    }

    const unsigned char* pi = decoded_issuer.data();
    std::unique_ptr<X509, decltype(&X509_free)> issuer(d2i_X509(nullptr, &pi, decoded_issuer.size()), X509_free);
    if (!issuer) {
        Logger::error("Failed to parse DER issuer certificate: " + std::string(ERR_reason_error_string(ERR_get_error())));
        throw std::runtime_error("Failed to parse DER issuer certificate: " + std::string(ERR_reason_error_string(ERR_get_error())));
    }

    Logger::info("Building OCSP request...");
    std::unique_ptr<OCSP_REQUEST, decltype(&OCSP_REQUEST_free)> req(OCSP_REQUEST_new(), OCSP_REQUEST_free);
    if (!req) {
        Logger::error("Failed to allocate OCSP_REQUEST");
        throw std::runtime_error("Failed to allocate OCSP_REQUEST.");
    }

    std::unique_ptr<OCSP_CERTID, decltype(&OCSP_CERTID_free)> id(
        OCSP_cert_to_id(nullptr, cert.get(), issuer.get()), OCSP_CERTID_free);
    if (!id) {
        Logger::error("Failed to create OCSP_CERTID");
        throw std::runtime_error("Failed to create OCSP_CERTID.");
    }

    if (!OCSP_request_add0_id(req.get(), id.get())) {
        Logger::error("Failed to add CertID to OCSP request");
        throw std::runtime_error("Failed to add CertID to OCSP request.");
    }
    id.release();

    Logger::info("Encoding OCSP request to DER format...");
    unsigned char* req_der = nullptr;
    int req_der_len = i2d_OCSP_REQUEST(req.get(), &req_der);
    if (req_der_len <= 0) {
        Logger::error("Failed to DER-encode OCSP request");
        throw std::runtime_error("Failed to DER-encode OCSP request.");
    }
    std::vector<unsigned char> req_data(req_der, req_der + req_der_len);
    OPENSSL_free(req_der);
    Logger::debug("DER-encoded OCSP request size", std::to_string(req_data.size()) + " bytes");

    std::string base64_request = base64Encode(req_data);
    Logger::debug("Base64 encoded OCSP request size", std::to_string(base64_request.length()) + " bytes");
    Logger::info("OCSP request generation completed successfully");
    Logger::info("=============================================");
    return base64_request;
}

/**
 * @brief Extracts the OCSP responder URL from a certificate's AIA extension.
 *
 * This function performs the following steps:
 * 1. Takes base64-encoded certificate and issuer certificate strings.
 * 2. Decodes the certificates and loads them as X509 structures.
 * 3. Finds the OCSP responder URL in the AIA extension.
 * 4. Returns the OCSP responder URL.
 *
 * @param base64Cert The certificate encoded in base64.
 * @param base64IssuerCert The issuer certificate encoded in base64.
 * @return The OCSP responder URL as a string.
 * @throws std::runtime_error if any step fails.
 */
std::string getOCSPFromCertificate(const std::string& base64Cert, const std::string& base64IssuerCert)
{
    Logger::info("=== Starting OCSP URL Extraction Service ===");
    Logger::debug("Base64 Certificate", base64Cert);
    Logger::debug("Base64 Issuer Certificate", base64IssuerCert);

    Logger::info("Decoding certificates from base64...");
    std::vector<unsigned char> decoded_cert = base64Decode(base64Cert);
    std::vector<unsigned char> decoded_issuer = base64Decode(base64IssuerCert);
    Logger::debug("Decoded cert size", std::to_string(decoded_cert.size()) + " bytes");
    Logger::debug("Decoded issuer cert size", std::to_string(decoded_issuer.size()) + " bytes");

    Logger::info("Parsing DER certificates into X509 structures...");
    const unsigned char* p = decoded_cert.data();
    std::unique_ptr<X509, decltype(&X509_free)> cert(d2i_X509(nullptr, &p, decoded_cert.size()), X509_free);
    if (!cert) {
        Logger::error("Failed to parse DER certificate: " + std::string(ERR_reason_error_string(ERR_get_error())));
        throw std::runtime_error("Failed to parse DER certificate: " + std::string(ERR_reason_error_string(ERR_get_error())));
    }

    const unsigned char* pi = decoded_issuer.data();
    std::unique_ptr<X509, decltype(&X509_free)> issuer(d2i_X509(nullptr, &pi, decoded_issuer.size()), X509_free);
    if (!issuer) {
        Logger::error("Failed to parse DER issuer certificate: " + std::string(ERR_reason_error_string(ERR_get_error())));
        throw std::runtime_error("Failed to parse DER issuer certificate: " + std::string(ERR_reason_error_string(ERR_get_error())));
    }

    Logger::info("Searching for OCSP URL in certificate's AIA extension...");
    std::string ocsp_url;
    AUTHORITY_INFO_ACCESS* info = (AUTHORITY_INFO_ACCESS*)X509_get_ext_d2i(cert.get(), NID_info_access, nullptr, nullptr);
    if (info) {
        for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(info); ++i) {
            ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(info, i);
            if (OBJ_obj2nid(ad->method) == NID_ad_OCSP) {
                if (ad->location->type == GEN_URI) {
                    ASN1_IA5STRING* uri = ad->location->d.uniformResourceIdentifier;
                    ocsp_url = std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri)), ASN1_STRING_length(uri));
                    break;
                }
            }
        }
        AUTHORITY_INFO_ACCESS_free(info);
    }
    if (ocsp_url.empty()) {
        Logger::error("No OCSP responder URL found in certificate");
        throw std::runtime_error("No OCSP responder URL found in certificate.");
    }

    Logger::debug("Found OCSP URL", ocsp_url);
    Logger::info("OCSP URL extraction completed successfully");
    Logger::info("===========================================");
    return ocsp_url;
}

/**
 * @brief Makes an HTTP request to an OCSP responder and returns the base64-encoded response.
 *
 * This function performs the following steps:
 * 1. Takes base64-encoded certificate, issuer certificate, and OCSP URL.
 * 2. Builds an OCSP request using the cert and its issuer.
 * 3. Makes an HTTP(S) POST request to the responder.
 * 4. Saves the OCSP response to disk.
 * 5. Encodes the binary OCSP data into a base64 string.
 * 6. Returns a pair containing the base64-encoded OCSP response and the OCSP URL.
 *
 * @param base64Cert The certificate encoded in base64.
 * @param base64IssuerCert The issuer certificate encoded in base64.
 * @param ocspUrl The OCSP responder URL.
 * @return A std::pair containing the base64-encoded OCSP response and the OCSP URL.
 * @throws std::runtime_error if any step fails.
 */
std::pair<std::string, std::string> getOCSPResponseFromUrl(const std::string& base64Cert, const std::string& base64IssuerCert, const std::string& ocspUrl)
{
    Logger::info("=== Starting OCSP Response Retrieval Service ===");
    Logger::debug("Base64 Certificate", base64Cert);
    Logger::debug("Base64 Issuer Certificate", base64IssuerCert);
    Logger::debug("OCSP URL", ocspUrl);

    // Step 1: Build OCSP request from certificates (returns base64)
    Logger::info("Building OCSP request from certificates...");
    std::string base64_ocsp_request = getOCSPRequestFromCertificates(base64Cert, base64IssuerCert);

    // Step 2: Make HTTP POST request to OCSP responder (returns base64)
    Logger::info("Making HTTP POST request to OCSP responder...");
    std::string base64_ocsp_response = makeOcspHttpPostRequest(ocspUrl, base64_ocsp_request);

    // Step 3: Save OCSP response to disk (optional - for debugging)
    Logger::info("Saving OCSP response to disk...");
    const std::string output_dir = "input";
    std::filesystem::create_directory(output_dir);
    std::string filename = "ocsp_response.der";
    std::filesystem::path output_path(output_dir);
    output_path /= filename;

    // Decode the base64 response to save as binary
    std::vector<unsigned char> ocsp_data = base64Decode(base64_ocsp_response);
    std::ofstream ofs(output_path, std::ios::binary);
    ofs.write(reinterpret_cast<const char*>(ocsp_data.data()), ocsp_data.size());
    ofs.close();
    Logger::debug("OCSP response saved to", output_path.string());

    Logger::info("OCSP response retrieval completed successfully");
    Logger::info("=============================================");
    return { base64_ocsp_response, ocspUrl };
}
