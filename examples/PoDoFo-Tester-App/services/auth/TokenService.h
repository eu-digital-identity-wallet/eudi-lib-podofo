#ifndef TOKEN_SERVICE_H
#define TOKEN_SERVICE_H

#include <string>
#include "../../core/Logger.h"

/**
 * @brief Exchanges an authorization code for a service access token using OAuth2.
 *
 * @param code The authorization code from the OAuth2 flow
 * @return The service access token, or empty string on failure
 */
std::string TokenService(const std::string& code);

#endif
