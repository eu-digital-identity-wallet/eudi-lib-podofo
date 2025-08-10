#ifndef TSR_BASE64_SERVICE_H
#define TSR_BASE64_SERVICE_H

#include <string>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <openssl/ts.h>
#include "../../core/Logger.h"

/**
 * @brief Service class for handling TSR (Timestamp Response) base64 encoding and decoding operations.
 */
class TsrBase64Service {
public:
    /**
     * @brief Reads a TSR file from disk and converts it to base64 encoding.
     *
     * @param tsrPath The path to the TSR file
     * @return The base64 encoded TSR data
     * @throws std::runtime_error if the TSR file is invalid or cannot be read
     */
    static std::string GetTsrBase64(const std::string& tsrPath);

    /**
     * @brief Decodes a base64-encoded TSR string back to binary data.
     *
     * @param base64Tsr The base64-encoded TSR string
     * @return The decoded TSR binary data as a string
     * @throws std::runtime_error if decoding fails or the data is invalid
     */
    static std::string DecodeBase64Tsr(const std::string& base64Tsr);
};

#endif
