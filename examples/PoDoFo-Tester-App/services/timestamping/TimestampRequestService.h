#pragma once

#include <string>
#include <vector>
#include "../../core/Logger.h"

namespace TimestampRequestService {
    /**
     * @brief Creates a timestamp request from a digest and saves it to a file.
     *
     * @param digest The digest to create the timestamp request from
     * @param outPath The output path for the timestamp request file
     * @return true if successful, false otherwise
     */
    bool CreateTimestampRequestFromDigest(const std::vector<unsigned char>& digest, const std::string& outPath);

    /**
     * @brief Sends a timestamp request to a TSA and saves the response.
     *
     * @param tsqPath The path to the timestamp request file
     * @param tsrPath The path to save the timestamp response file
     * @param tsaUrl The URL of the timestamp authority service
     * @return true if successful, false otherwise
     */
    bool SendTimestampRequest(const std::string& tsqPath, const std::string& tsrPath, const std::string& tsaUrl);
}
