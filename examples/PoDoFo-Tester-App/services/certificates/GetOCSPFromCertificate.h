#ifndef GET_OCSP_FROM_CERTIFICATE_H
#define GET_OCSP_FROM_CERTIFICATE_H

#include <string>
#include <utility>
#include <vector>
#include <memory>
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/ocsp.h>
#include <openssl/err.h>
#include "../../core/Logger.h"

/**
 * @brief Gets an OCSP request from base64-encoded certificates and returns it as base64.
 *
 * This function performs the following steps:
 * 1. Decodes the base64-encoded certificate and issuer certificate.
 * 2. Parses them into X509 structures.
 * 3. Builds an OCSP request using the certificates.
 * 4. Encodes the OCSP request to DER format.
 * 5. Returns the DER-encoded OCSP request as a base64 string.
 *
 * @param base64Cert The certificate encoded in base64.
 * @param base64IssuerCert The issuer certificate encoded in base64.
 * @return std::string The base64-encoded OCSP request.
 * @throws std::runtime_error if any step fails.
 */
std::string getOCSPRequestFromCertificates(const std::string& base64Cert, const std::string& base64IssuerCert);

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
std::string getOCSPFromCertificate(const std::string& base64Cert, const std::string& base64IssuerCert);

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
std::pair<std::string, std::string> getOCSPResponseFromUrl(const std::string& base64Cert, const std::string& base64IssuerCert, const std::string& ocspUrl);

#endif
