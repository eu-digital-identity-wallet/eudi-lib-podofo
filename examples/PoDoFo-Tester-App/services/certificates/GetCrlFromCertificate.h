#ifndef GET_CRL_FROM_CERTIFICATE_H
#define GET_CRL_FROM_CERTIFICATE_H

#include <string>
#include <utility>
#include <vector>
#include <memory>
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <windows.h>
#include <winhttp.h>
#include "../../core/Logger.h"

/**
 * @brief Downloads a Certificate Revocation List (CRL) from a given URL.
 *
 * This function performs the following steps:
 * 1. Takes a CRL URL.
 * 2. Makes an HTTP/S request to download the binary CRL file.
 * 3. Saves the binary CRL file to disk, naming it after the file in the URL.
 * 4. Encodes the binary CRL data into a base64 string.
 * 5. Returns a pair containing the base64-encoded CRL and the URL it was fetched from.
 *
 * @param crlUrl The URL to download the CRL from.
 * @return A std::pair containing the base64-encoded CRL response and the CRL URL.
 * @throws std::runtime_error if any step fails.
 */
std::pair<std::string, std::string> downloadCrlFromUrl(const std::string& crlUrl);

#endif
