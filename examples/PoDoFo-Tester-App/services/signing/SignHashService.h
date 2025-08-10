#ifndef SIGN_HASH_SERVICE_H
#define SIGN_HASH_SERVICE_H

#include <string>
#include "../../core/Logger.h"

/**
 * @brief Signs a hash using the remote signing service with the provided credentials.
 *
 * @param cookie Session cookie for authentication
 * @param accessToken OAuth2 access token for authorization
 * @param credentialID The credential identifier to use for signing
 * @param hash The hash to be signed in base64 format
 * @return The signed hash in base64 format, or empty string on failure
 */
std::string SignHashService(
    const std::string& cookie,
    const std::string& accessToken,
    const std::string& credentialID,
    const std::string& hash
);

#endif
