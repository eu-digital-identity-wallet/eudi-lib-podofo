#pragma once
#include <string>
#include <vector>
#include "../../core/Logger.h"

/**
 * @brief Service that handles creation of timestamp hashes.
 *
 * @param signedHash The signed hash to create a timestamp hash from
 * @return Vector of unsigned char containing the SHA-256 hash digest
 */
std::vector<unsigned char> CreateTimestampHash(const std::string& signedHash);
