#ifndef EXTRACT_ISSUER_CERT_FROM_TSR_H
#define EXTRACT_ISSUER_CERT_FROM_TSR_H

#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/ts.h>
#include "../../core/Logger.h"

/**
 * @brief Given a base64-encoded TSR, returns the issuer certificate as base64 DER.
 * @param base64Tsr The base64-encoded TSR (timestamp response, as from Sectigo etc.)
 * @return std::string The base64 DER encoding of the issuer certificate
 * @throws std::runtime_error on failure
 */
std::string extractIssuerCertFromTSR(const std::string& base64Tsr);

#endif
