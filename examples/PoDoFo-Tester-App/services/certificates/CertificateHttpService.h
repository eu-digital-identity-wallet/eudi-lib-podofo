#ifndef CERTIFICATE_HTTP_SERVICE_H
#define CERTIFICATE_HTTP_SERVICE_H

#include <string>
#include <vector>
#include "../../core/Logger.h"

/**
 * @brief Makes an HTTP GET request to fetch a certificate and returns it as base64.
 *
 * This function performs the following steps:
 * 1. Takes a URL where a certificate can be downloaded.
 * 2. Makes an HTTP(S) GET request to fetch the certificate.
 * 3. Receives the certificate response (typically in DER format).
 * 4. Encodes the response to base64.
 * 5. Returns the base64-encoded certificate.
 *
 * This function is completely independent and can be used by any application
 * that needs to fetch certificates from HTTP URLs (commonly used for AIA certificate fetching).
 * The returned base64 certificate can be used by:
 * - C++ (current implementation)
 * - Swift (iOS/macOS)
 * - Kotlin (Android)
 * - Java
 * - Python
 * - JavaScript/TypeScript
 * - Any language that can process base64-encoded strings
 *
 * @param certificateUrl The URL to fetch the certificate from (usually from AIA extension).
 * @return std::string The base64-encoded certificate.
 * @throws std::runtime_error if any step fails.
 */
std::string fetchCertificateFromUrl(const std::string& certificateUrl);

/**
 * @brief Decodes a base64 string to a vector of unsigned chars.
 *
 * @param base64_string The base64 encoded string to decode.
 * @return std::vector<unsigned char> The decoded data.
 * @throws std::runtime_error if decoding fails.
 */
std::vector<unsigned char> certificateBase64Decode(const std::string& base64_string);

/**
 * @brief Encodes a vector of unsigned chars to a base64 string.
 *
 * @param data The data to encode.
 * @return std::string The base64 encoded string.
 * @throws std::runtime_error if encoding fails.
 */
std::string certificateBase64Encode(const std::vector<unsigned char>& data);

#endif // CERTIFICATE_HTTP_SERVICE_H
