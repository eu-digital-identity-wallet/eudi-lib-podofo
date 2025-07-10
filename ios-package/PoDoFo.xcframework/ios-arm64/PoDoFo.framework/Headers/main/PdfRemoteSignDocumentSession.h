// PdfRemoteSignDocumentSession.h
#ifndef PDF_DSS_SIGNING_SESSION_H
#define PDF_DSS_SIGNING_SESSION_H

#ifdef _MSC_VER
#  define _CRT_SECURE_NO_WARNINGS
#endif

#include <iostream>
#include <fstream>
#include <limits>
#include <iomanip>
#include <sstream>
#include <vector>
#include <memory>
#include <optional>
#include <string>
#include <regex>
#include <thread>
#include <filesystem>

#include <podofo/podofo.h>
#include <openssl/bio.h>


using namespace std;
using namespace PoDoFo;
namespace fs = std::filesystem;

namespace PoDoFo {

    // RAII wrapper for OpenSSL BIO*
    struct PODOFO_API BioFreeAll {
        void operator()(BIO* b) const noexcept;
    };
    using BioPtr = std::unique_ptr<BIO, BioFreeAll>;

    enum class HashAlgorithm {
        SHA256,
        SHA384,
        SHA512,
        Unknown
    };

    // your document entry:
    struct DocumentConfig {
        std::string                document_input_path;
        std::string                document_output_path;
        std::string                conformance_level;
    };

    // top‐level request:
    struct SigningRequest {
        std::vector<DocumentConfig>              documents;
        std::vector<unsigned char>               endEntityCertificate;
        std::vector<std::vector<unsigned char>>  certificateChain;
        std::string                              hashAlgorithmOID;
    };

    // utility to read a file fully into a vector<byte>
    static std::vector<unsigned char> ReadBinary(const std::string& path);

    // Represents a PDF signing session
    class PODOFO_API PdfRemoteSignDocumentSession final {
    public:
        // Construct a signing session with full configuration
        PdfRemoteSignDocumentSession(
            const std::string& conformanceLevel,
            const std::string& hashAlgorithmOid,
            const std::string& documentInputPath,
            const std::string& documentOutputPath,
            const std::string& endCertificateBase64,
            const std::vector<std::string>& certificateChainBase64,
            const std::optional<std::string>& rootEntityCertificateBase64 = std::nullopt,
            const std::optional<std::string>& label = std::nullopt
        );

        PdfRemoteSignDocumentSession(const PdfRemoteSignDocumentSession&) = delete;
        PdfRemoteSignDocumentSession& operator=(const PdfRemoteSignDocumentSession&) = delete;
        PdfRemoteSignDocumentSession(PdfRemoteSignDocumentSession&&) noexcept = default;
        PdfRemoteSignDocumentSession& operator=(PdfRemoteSignDocumentSession&&) noexcept = default;
        ~PdfRemoteSignDocumentSession();

        std::string beginSigning();
        void finishSigning(const std::string& signedHash, const std::string& base64Tsr);
        void printState() const;
        void setTimestampToken(const std::string& responseTsrBase64);

    private:
        std::vector<unsigned char> ConvertBase64PEMtoDER(
            const std::optional<std::string>& base64PEM,
            const std::optional<std::string>& outputPath);
        void ReadFile(const std::string& filepath, std::string& str);
        std::string ToBase64(const charbuff& data);
        charbuff ConvertDSSHashToSignedHash(const std::string& DSSHash);
        std::vector<unsigned char> HexToBytes(const std::string& hex);
        std::string ToHexString(const charbuff& data);
        std::string UrlEncode(const std::string& value);
        std::string DecodeBase64Tsr(const std::string& base64Tsr);

        std::string                                 _conformanceLevel;
        HashAlgorithm                               _hashAlgorithm;
        std::string                                 _documentInputPath;
        std::string                                 _documentOutputPath;
        std::string                                 _endCertificateBase64;
        std::vector<std::string>                    _certificateChainBase64;
        std::optional<std::string>                  _rootCertificateBase64;
        std::optional<std::string>                  _label;
        std::optional<std::string>                  _responseTsrBase64;
        std::vector<unsigned char>                  _endCertificateDer;
        std::vector<std::vector<unsigned char>>     _certificateChainDer;
        std::vector<unsigned char>                  _rootCertificateDer;
        std::vector<unsigned char>                  _responseTsr;

        PdfMemDocument                              _doc;
        std::shared_ptr<FileStreamDevice>           _stream;
        PdfSignerCmsParams                          _cmsParams;
        PdfSigningContext                           _ctx;
        PdfSigningResults                           _results;
        PdfSignerId                                 _signerId;
        std::shared_ptr<PdfSignerCms>               _signer;

        static HashAlgorithm hashAlgorithmFromOid(const std::string& oid);
        static const char* hashAlgorithmToString(HashAlgorithm alg);
    };

} // namespace PoDoFo

#endif // PDF_DSS_SIGNING_SESSION_H
