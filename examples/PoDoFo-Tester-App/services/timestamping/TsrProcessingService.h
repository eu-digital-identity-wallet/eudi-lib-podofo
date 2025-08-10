#ifndef TSR_PROCESSING_SERVICE_H
#define TSR_PROCESSING_SERVICE_H

#include <string>
#include "../../core/Logger.h"

/**
 * @brief Service class for processing timestamp responses (TSR).
 */
class TsrProcessingService {
public:
    /**
     * @brief Processes a timestamp response (TSR) and returns it as base64 encoded string.
     *
     * This function sends a timestamp request to the TSA, reads the response,
     * validates it, and returns the base64 encoded TSR data.
     *
     * @return The base64 encoded timestamp response
     * @throws std::runtime_error if the TSR processing fails
     */
    static std::string ProcessTsrAndReturnBase64();
};

#endif
