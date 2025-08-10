#ifndef LIST_CREDENTIALS_SERVICE_H
#define LIST_CREDENTIALS_SERVICE_H

#include "../../models/CertificateBundle.h"
#include "../../core/Logger.h"

/**
 * @brief Sends a POST request to the credentials list endpoint using the given access token.
 *
 * @param accessToken The OAuth2 access token for authentication
 * @return CertificateBundle containing the credential ID, first certificate, and certificate chain
 */
CertificateBundle ListCredentialsService(const std::string& accessToken);

#endif
