#ifndef TOKEN_CRED_SERVICE_H
#define TOKEN_CRED_SERVICE_H

#include <string>
#include "../../core/Logger.h"

/**
 * @brief Exchanges an authorization code for a credential access token using OAuth2.
 *
 * @param code The authorization code from the OAuth2 flow
 * @param urlEncodedAuthorizationDetails URL-encoded authorization details for credential scope
 * @return The credential access token, or empty string on failure
 */
std::string TokenCredService(const std::string& code, const std::string& urlEncodedAuthorizationDetails);

#endif
