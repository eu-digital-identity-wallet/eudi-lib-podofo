#ifndef TSR_REQUEST_AND_BASE64_SERVICE_H
#define TSR_REQUEST_AND_BASE64_SERVICE_H

#include <string>
#include "../../core/Logger.h"

/**
 * @brief Service class for generating timestamp responses from signed hashes.
 */
class TsrRequestAndBase64Service {
public:
    /**
     * @brief Generates a timestamp response (TSR) from a signed hash and returns it as base64.
     *
     * @param signedHash The signed hash to create the timestamp response for
     * @return The base64 encoded timestamp response
     */
    static std::string GetTsrBase64(const std::string& signedHash);
};

#endif
