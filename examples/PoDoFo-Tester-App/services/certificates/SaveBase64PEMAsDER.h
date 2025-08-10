#include "../../core/Logger.h"

/**
 * @brief Decodes a Base64-encoded PEM string and saves it as a binary DER file.
 *
 * @param pemString The base64-encoded certificate string (no headers).
 * @param outputPath The destination path to save the binary .der file.
 */
void SaveBase64PEMAsDER(const std::string& pemString, const std::string& outputPath);
