#ifndef OCSP_HTTP_SERVICE_H
#define OCSP_HTTP_SERVICE_H

#include <string>
#include <vector>
#include "../../core/Logger.h"

/**
 * @brief Makes an HTTP POST request to an OCSP responder and returns the response as base64.
 *
 * This function performs the following steps:
 * 1. Takes a URL and base64-encoded OCSP request data.
 * 2. Makes an HTTP(S) POST request to the OCSP responder.
 * 3. Receives the OCSP response.
 * 4. Encodes the response to base64.
 * 5. Returns the base64-encoded OCSP response.
 *
 * This function is completely independent and can be used by any application
 * that needs to make HTTP POST requests with base64-encoded OCSP data.
 * The base64RequestData parameter is language-agnostic and can be used by:
 * - C++ (current implementation)
 * - Swift (iOS/macOS)
 * - Kotlin (Android)
 * - Java
 * - Python
 * - JavaScript/TypeScript
 * - Any language that can produce base64-encoded strings
 *
 * @param ocspUrl The OCSP responder URL to send the request to.
 * @param base64OcspRequestData The base64-encoded OCSP request data to send.
 * @return std::string The base64-encoded OCSP response.
 * @throws std::runtime_error if any step fails.
 */
std::string makeOcspHttpPostRequest(const std::string& ocspUrl, const std::string& base64OcspRequestData);

/**
 * @brief Decodes a base64 string to a vector of unsigned chars.
 *
 * @param base64_string The base64 encoded string to decode.
 * @return std::vector<unsigned char> The decoded data.
 * @throws std::runtime_error if decoding fails.
 */
std::vector<unsigned char> base64Decode(const std::string& base64_string);

/**
 * @brief Encodes a vector of unsigned chars to a base64 string.
 *
 * @param data The data to encode.
 * @return std::string The base64 encoded string.
 * @throws std::runtime_error if encoding fails.
 */
std::string base64Encode(const std::vector<unsigned char>& data);

#endif // OCSP_HTTP_SERVICE_H
