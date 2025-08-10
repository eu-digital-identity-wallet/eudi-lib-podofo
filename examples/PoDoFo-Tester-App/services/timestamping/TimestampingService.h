#pragma once
#include <string>
#include "../../core/Logger.h"

namespace TimestampingService {
    /**
     * @brief Requests a TSR from the timestamp service for a signed hash.
     *
     * @param signedHash The signed hash to timestamp
     * @param tsaUrl The URL of the timestamp authority service
     */
    void requestTsrFromTimestampService(const std::string& signedHash, const std::string& tsaUrl);

    /**
     * @brief Requests a TSR from the timestamp service for document timestamping (LTA).
     *
     * @param base64Hash The base64 encoded hash to timestamp
     * @param tsaUrl The URL of the timestamp authority service
     */
    void requestTsrFromTimestampServiceForDocTimeStamp(const std::string& base64Hash, const std::string& tsaUrl);
}
