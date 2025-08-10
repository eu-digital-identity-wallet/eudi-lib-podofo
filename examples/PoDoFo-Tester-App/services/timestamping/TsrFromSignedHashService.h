#ifndef TSR_FROM_SIGNED_HASH_SERVICE_H
#define TSR_FROM_SIGNED_HASH_SERVICE_H

#include <string>
#include "../../core/Logger.h"

/**
 * @brief Service class for creating timestamp responses from signed hashes.
 */
class TsrFromSignedHashService {
public:
    /**
     * @brief Creates a timestamp response (TSR) from a signed hash and returns it as base64.
     *
     * @param signedHash The signed hash to create the timestamp response for
     * @return The base64 encoded timestamp response
     */
    static std::string CreateTsrBase64FromSignedHash(const std::string& signedHash);
};

#endif
