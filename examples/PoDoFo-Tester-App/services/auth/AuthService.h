#ifndef AUTHSERVICE_H
#define AUTHSERVICE_H

#include <string>
#include "../../core/Logger.h"

/**
 * @brief Performs the OAuth2 authorization step and returns the redirect URL containing the code.
 *
 * @param cookie The session cookie (JSESSIONID).
 * @return std::string The redirect URL containing the authorization code, or empty string on failure.
 */
std::string AuthService(const std::string& cookie);

#endif
