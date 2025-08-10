#ifndef LOGINSERVICE_H
#define LOGINSERVICE_H

#include <string>
#include "../../core/Logger.h"

/**
 * @brief Logs in to the remote service and returns a session cookie (JSESSIONID).
 *
 * @param optionalCookie Optional cookie to reuse an existing session.
 * @return std::string The new session cookie, or empty string on failure.
 */
std::string LoginService(const std::string& optionalCookie = "");

#endif
