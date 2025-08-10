#include "Utils.h"
#include "../core/Logger.h"
#include <regex>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

/**
 * @brief Extracts the authorization code from a URL using regex.
 *
 * @param url The URL containing the authorization code parameter
 * @return The extracted authorization code, or empty string if not found
 */
std::string ExtractAuthCodeFromUrl(const std::string& url) {
    Logger::debug("Attempting to extract 'code' from URL", url);
    std::regex codeRegex("code=([^&]+)");
    std::smatch match;

    if (std::regex_search(url, match, codeRegex) && match.size() > 1) {
        std::string code = match[1].str();
        Logger::debug("Successfully extracted code", code);
        return code;
    }

    Logger::debug("No 'code' parameter found in URL");
    return "";
}

/**
 * @brief URL encodes a string by replacing special characters with percent-encoded equivalents.
 *
 * @param value The string to URL encode
 * @return The URL encoded string
 */
std::string UrlEncode(const std::string& value) {
    Logger::debug("URL encoding string", value);
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (const auto& c : value) {
        if (isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        }
        else {
            escaped << '%' << std::setw(2) << std::uppercase << static_cast<int>(static_cast<unsigned char>(c));
        }
    }
    auto encoded = escaped.str();
    Logger::debug("URL encoded result", encoded);
    return encoded;
}

/**
 * @brief Constructs the full path for an input file by prepending "input/" directory.
 *
 * @param filename The filename to construct the path for
 * @return The full path to the input file
 */
std::string GetInputFilePath(const std::string& filename) {
    std::string fullPath = "input/" + filename;
    Logger::debug("Constructed input file path", fullPath);
    return fullPath;
}

/**
 * @brief Reads the entire contents of a file into a string.
 *
 * @param filepath The path to the file to read
 * @param str The string to store the file contents in
 * @throws std::runtime_error if the file cannot be opened or read
 */
void ReadFile(const std::string& filepath, std::string& str)
{
    Logger::debug("Reading file", filepath);
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open())
    {
        Logger::error("Failed to open file: " + filepath);
        throw std::runtime_error("Failed to open file: " + filepath);
    }

    file.seekg(0, std::ios::end);
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    Logger::debug("File size", std::to_string(size) + " bytes");

    str.resize(size);
    file.read(&str[0], size);

    if (!file)
    {
        Logger::error("Failed to read file content from: " + filepath);
        throw std::runtime_error("Failed to read file: " + filepath);
    }
    Logger::debug("Successfully read file", std::to_string(str.length()) + " bytes from " + filepath);
}

/**
 * @brief Encodes binary data to base64 string using OpenSSL BIO.
 *
 * @param data The binary data to encode
 * @return The base64 encoded string
 */
std::string Base64Encode(const std::vector<char>& data) {
    Logger::debug("Base64 encoding data", std::to_string(data.size()) + " bytes");
    if (data.empty()) {
        Logger::debug("Input data is empty, returning empty string");
        return "";
    }

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, data.data(), static_cast<int>(data.size()));
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);

    std::string result(bptr->data, bptr->length);
    Logger::debug("Base64 encoding successful", std::to_string(result.length()) + " characters");
    BIO_free_all(b64);

    return result;
}

/**
 * @brief Converts a DSS hash to a signed hash by decoding from base64.
 *
 * @param DSSHash The base64 encoded DSS hash
 * @return PoDoFo::charbuff containing the decoded hash data
 * @throws std::runtime_error if base64 decoding fails
 */
PoDoFo::charbuff ConvertDSSHashToSignedHash(const std::string& DSSHash) {
    Logger::debug("Converting DSS hash to signed hash", std::to_string(DSSHash.length()) + " characters");

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* mem = BIO_new_mem_buf(DSSHash.data(), static_cast<int>(DSSHash.size()));
    BIO* bio = BIO_push(b64, mem);

    std::vector<unsigned char> decoded(128);
    int len = BIO_read(bio, decoded.data(), static_cast<int>(decoded.size()));
    BIO_free_all(bio);

    if (len <= 0) {
        Logger::error("Base64 decode failed for DSS hash");
        throw std::runtime_error("Base64 decode failed");
    }

    decoded.resize(len);
    Logger::debug("Successfully decoded DSS hash", std::to_string(decoded.size()) + " bytes");

    PoDoFo::charbuff result;
    result.assign(decoded.begin(), decoded.end());
    Logger::debug("Converted to PoDoFo::charbuff", std::to_string(result.size()) + " bytes");
    return result;
}

