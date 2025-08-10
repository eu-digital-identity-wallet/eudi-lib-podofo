#ifndef GET_TSR_BASE64_H
#define GET_TSR_BASE64_H

#include <string>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <openssl/ts.h>
#include "../../core/Logger.h"

/**
 * @brief Reads a TSR file from disk and converts it to base64 encoding
 * @param tsrPath The path to the TSR file
 * @return The base64 encoded TSR data
 * @throws std::runtime_error if the TSR file is invalid or cannot be read
 */
std::string GetTsrBase64(const std::string& tsrPath);

#endif
