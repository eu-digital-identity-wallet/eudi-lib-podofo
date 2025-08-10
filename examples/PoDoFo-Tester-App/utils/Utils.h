#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <podofo/podofo.h>
#include "../core/Logger.h"

/**
 * @brief Extracts the authorization code from a URL using regex.
 *
 * @param url The URL containing the authorization code parameter
 * @return The extracted authorization code, or empty string if not found
 */
std::string ExtractAuthCodeFromUrl(const std::string& url);

/**
 * @brief URL encodes a string by replacing special characters with percent-encoded equivalents.
 *
 * @param value The string to URL encode
 * @return The URL encoded string
 */
std::string UrlEncode(const std::string& value);

/**
 * @brief Constructs the full path for an input file by prepending "input/" directory.
 *
 * @param filename The filename to construct the path for
 * @return The full path to the input file
 */
std::string GetInputFilePath(const std::string& filename);

/**
 * @brief Reads the entire contents of a file into a string.
 *
 * @param filepath The path to the file to read
 * @param str The string to store the file contents in
 * @throws std::runtime_error if the file cannot be opened or read
 */
void ReadFile(const std::string& filepath, std::string& str);

/**
 * @brief Encodes binary data to base64 string using OpenSSL BIO.
 *
 * @param data The binary data to encode
 * @return The base64 encoded string
 */
std::string Base64Encode(const std::vector<char>& data);

/**
 * @brief Converts a DSS hash to a signed hash by decoding from base64.
 *
 * @param DSSHash The base64 encoded DSS hash
 * @return PoDoFo::charbuff containing the decoded hash data
 * @throws std::runtime_error if base64 decoding fails
 */
PoDoFo::charbuff ConvertDSSHashToSignedHash(const std::string& DSSHash);

#endif
