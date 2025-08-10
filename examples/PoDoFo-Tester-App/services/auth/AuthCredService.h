#ifndef AUTH_CRED_SERVICE_H
#define AUTH_CRED_SERVICE_H

#include <string>
#include "../../core/Logger.h"

/**
 * @brief Makes an OAuth2 authorization request with credential scope, using the given cookie and pre-encoded authorization_details.
 *
 * @param cookie                      Session cookie (JSESSIONID).
 * @param authorizationDetailsEncoded URL-encoded authorization_details JSON string.
 * @return Redirect URL containing the authorization code, or empty string on error.
 */
std::string AuthCredService(const std::string& cookie, const std::string& authorizationDetailsEncoded);

#endif
