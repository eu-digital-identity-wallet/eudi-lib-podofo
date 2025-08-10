#pragma once
#include "../../models/CertificateBundle.h"
#include "../../core/Logger.h"
#include <string>

/**
 * @brief Retrieves credentials from the remote service by performing the complete OAuth2 flow.
 *
 * This function handles the entire credential acquisition process including:
 * - Initial login to obtain session cookies
 * - OAuth2 authorization flow
 * - Token exchange
 * - Credential listing
 *
 * @return CertificateBundle containing the credential ID, first certificate, and certificate chain
 */
CertificateBundle GetCredentials();
