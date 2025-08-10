#pragma once
#include <string>
#include <vector>
#include <stdexcept>
#include "../../core/Logger.h"

/**
 * @brief Service that handles timestamp request creation and management.
 *
 * @param signedHash The signed hash to create a timestamp request for
 * @param outputPath The output path for the timestamp request file
 */
void CreateTimestampRequest(
    const std::string& signedHash,
    const std::string& outputPath = "input/request.tsq"
);
