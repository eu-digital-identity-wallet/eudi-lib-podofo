// PdfRemoteSignDocumentSession.h
/**
 * @file PdfRemoteSignDocumentSession.h
 * @brief High-level API for remote PDF signing and LTA timestamping using PoDoFo and OpenSSL.
 *
 * This header declares the `PdfRemoteSignDocumentSession` which orchestrates a two-phase
 * remote signing flow (hash extraction and signature injection), helpers for DSS/LTV
 * (embedded validation material), and a `PdfDocTimeStampSigner` for RFC3161 DocTimeStamp.
 */
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
#include <map>
#include <iostream>
#include <iomanip>
#include <utility>

#include <podofo/podofo.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/ts.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <podofo/private/OpenSSLInternal.h>


using namespace std;
using namespace PoDoFo;
namespace fs = std::filesystem;

namespace PoDoFo {

    /**
     * @brief RAII deleter for OpenSSL `BIO*` chains created via BIO_push.
     *
     * Intended for use with `std::unique_ptr<BIO, BioFreeAll>` to ensure `BIO_free_all`
     * is called exactly once in all exit paths.
     */
    struct PODOFO_API BioFreeAll {
        void operator()(BIO* b) const noexcept;
    };
    /**
     * @brief Convenience alias for a unique BIO with `BIO_free_all` deleter.
     */
    using BioPtr = std::unique_ptr<BIO, BioFreeAll>;

    /**
     * @brief Container for validation-related artifacts to embed into the PDF DSS.
     *
     * Holds base64-encoded DER blobs for certificates, CRLs and OCSP responses.
     */
    class ValidationData {
    public:
        /** Default constructor */
        ValidationData() = default;

        /**
         * @brief Construct with initial collections.
         * @param certificates Base64 DER-encoded certificates to embed.
         * @param crls Base64 DER-encoded CRLs to embed.
         * @param ocsps Base64 DER-encoded OCSP responses to embed.
         */
        ValidationData(const std::vector<std::string>& certificates,
            const std::vector<std::string>& crls = {},
            const std::vector<std::string>& ocsps = {})
            : certificatesBase64(certificates), crlsBase64(crls), ocspsBase64(ocsps) {
        }

        /**
         * @brief Adds a single certificate to the validation data
         * @param certBase64 Base64-encoded certificate data
         */
        void addCertificate(const std::string& certBase64) {
            certificatesBase64.push_back(certBase64);
        }

        /**
         * @brief Adds a single CRL to the validation data
         * @param crlBase64 Base64-encoded CRL data
         */
        void addCRL(const std::string& crlBase64) {
            crlsBase64.push_back(crlBase64);
        }

        /**
         * @brief Adds a single OCSP response to the validation data
         * @param ocspBase64 Base64-encoded OCSP response data
         */
        void addOCSP(const std::string& ocspBase64) {
            ocspsBase64.push_back(ocspBase64);
        }

        /**
         * @brief Adds multiple certificates to the validation data
         * @param certs Vector of base64-encoded certificate data
         */
        void addCertificates(const std::vector<std::string>& certs) {
            certificatesBase64.insert(certificatesBase64.end(), certs.begin(), certs.end());
        }

        /**
         * @brief Adds multiple CRLs to the validation data
         * @param crls Vector of base64-encoded CRL data
         */
        void addCRLs(const std::vector<std::string>& crls) {
            crlsBase64.insert(crlsBase64.end(), crls.begin(), crls.end());
        }

        /**
         * @brief Adds multiple OCSP responses to the validation data
         * @param ocsps Vector of base64-encoded OCSP response data
         */
        void addOCSPs(const std::vector<std::string>& ocsps) {
            ocspsBase64.insert(ocspsBase64.end(), ocsps.begin(), ocsps.end());
        }

        /** Clear all stored artifacts. */
        void clear() {
            certificatesBase64.clear();
            crlsBase64.clear();
            ocspsBase64.clear();
        }

        /**
         * @return true if no artifacts are present.
         */
        bool empty() const {
            return certificatesBase64.empty() && crlsBase64.empty() && ocspsBase64.empty();
        }

        /** @return Number of certificates. */
        size_t certificateCount() const { return certificatesBase64.size(); }
        /** @return Number of CRLs. */
        size_t crlCount() const { return crlsBase64.size(); }
        /** @return Number of OCSP responses. */
        size_t ocspCount() const { return ocspsBase64.size(); }

        // Public access to vectors (for backward compatibility)
        std::vector<std::string> certificatesBase64;
        std::vector<std::string> crlsBase64;
        std::vector<std::string> ocspsBase64;
    };

    /**
     * @brief Supported message digest algorithms for CMS/TSP.
     */
    enum class HashAlgorithm {
        SHA256,  /**< SHA-256 (OID 2.16.840.1.101.3.4.2.1) */
        SHA384,  /**< SHA-384 (OID 2.16.840.1.101.3.4.2.2) */
        SHA512,  /**< SHA-512 (OID 2.16.840.1.101.3.4.2.3) */
        Unknown  /**< Not recognized */
    };

    /**
     * @brief Simple document entry used by higher-level request structures.
     */
    struct DocumentConfig {
        std::string                document_input_path;  /**< Input PDF path */
        std::string                document_output_path; /**< Output PDF path */
        std::string                conformance_level;    /**< e.g. "ADES_B_B", "ADES_B_T", "ADES_B_LT", "ADES_B_LTA" */
    };

    /**
     * @brief Top-level request for batch operations (not all fields used by this class).
     */
    struct SigningRequest {
        std::vector<DocumentConfig>              documents;             /**< Documents to process */
        std::vector<unsigned char>               endEntityCertificate;  /**< End-entity certificate (DER) */
        std::vector<std::vector<unsigned char>>  certificateChain;      /**< Chain (DER) */
        std::string                              hashAlgorithmOID;      /**< Digest OID string */
    };

    /**
     * @brief Utility to read a file fully into a byte vector
     * @param path Path to the file to read
     * @return Vector containing the binary data
     * @throws std::runtime_error if file cannot be opened or read
     */
    static std::vector<unsigned char> ReadBinary(const std::string& path);

    /**
     * @brief Represents a single PDF remote signing session.
     *
     * The flow is split into two steps:
     * 1) beginSigning(): prepares the PDF and returns a base64-encoded hash to be signed remotely.
     * 2) finishSigning(): injects the signed value and optionally adds DSS/LTV material.
     *
     * Additional helpers support LTA DocTimeStamp creation and validation data embedding.
     */
    class PODOFO_API PdfRemoteSignDocumentSession final {
    public:
        /**
         * @brief Construct a signing session with full configuration.
         * @param conformanceLevel One of ADES_B_B, ADES_B_T, ADES_B_LT, ADES_B_LTA.
         * @param hashAlgorithmOid Digest OID string (e.g. 2.16.840.1.101.3.4.2.1 for SHA-256).
         * @param documentInputPath Source PDF path.
         * @param documentOutputPath Destination PDF path.
         * @param endCertificateBase64 End-entity certificate, base64 DER.
         * @param certificateChainBase64 Certificate chain, each item base64 DER.
         * @param rootEntityCertificateBase64 Optional root certificate, base64 DER.
         * @param label Optional label for diagnostics.
         */
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

        /**
         * @brief Copy constructor (deleted)
         */
        PdfRemoteSignDocumentSession(const PdfRemoteSignDocumentSession&) = delete;
        /**
         * @brief Copy constructor (deleted)
         */
        PdfRemoteSignDocumentSession& operator=(const PdfRemoteSignDocumentSession&) = delete;
        /**
         * @brief Move constructor
         */
        PdfRemoteSignDocumentSession(PdfRemoteSignDocumentSession&&) noexcept = default;
        /**
         * @brief Move assignment operator
         */
        PdfRemoteSignDocumentSession& operator=(PdfRemoteSignDocumentSession&&) noexcept = default;
        /**
         * @brief Destructor
         */
        ~PdfRemoteSignDocumentSession();

        /**
         * @brief Start the signing process and compute the document hash to be signed remotely.
         * @return URL-encoded base64 of the hash that should be signed by a remote service.
         */
        std::string beginSigning();
        /**
         * @brief Finish the signing by injecting the remote signature and optional timestamp and DSS.
         * @param signedHash Base64-encoded signature/content returned by the remote signer.
         * @param base64Tsr Base64-encoded TimeStampResp (required for ADES_B_T, ADES_B_LT, ADES_B_LTA).
         * @param validationData Optional validation artifacts to embed into DSS.
         */
        void finishSigning(const std::string& signedHash, const std::string& base64Tsr, const std::optional<ValidationData>& validationData = std::nullopt);

        /**
         * @brief Start a DocTimeStamp (RFC3161) LTA update flow on the existing signed PDF.
         * @return Base64-encoded hash to be sent to the TSA.
         */
        std::string beginSigningLTA();
        /**
         * @brief Complete the DocTimeStamp flow by injecting the TSA token and optional DSS.
         * @param base64Tsr Base64-encoded TSR from TSA.
         * @param validationData Optional validation artifacts to embed into DSS.
         */
        void finishSigningLTA(const std::string& base64Tsr, const std::optional<ValidationData>& validationData);

        /**
         * @brief Prints current session state to stdout (for diagnostics)
         */
        void printState() const;
        /**
         * @brief Sets the timestamp token (base64 TSR) to be used in the session
         * @param responseTsrBase64 Base64-encoded timestamp response
         */
        void setTimestampToken(const std::string& responseTsrBase64);
        /**
         * @brief Extract the first CRL Distribution Point URL from a certificate or TSR (base64 DER input).
         * @throws std::runtime_error if no URL is found or parsing fails.
         */
        std::string getCrlFromCertificate(const std::string& base64Cert);

        /**
         * @brief Gets an OCSP request from a base64-encoded TSR and returns both the OCSP URL and the base64-encoded OCSP request.
         * @param base64Tsr The base64-encoded TSR (timestamp response)
         * @return std::pair<std::string, std::string> A pair containing (ocspUrl, base64_ocsp_request)
         * @throws std::runtime_error if any step fails
         */
        std::pair<std::string, std::string> getOCSPRequestFromCertificates(const std::string& base64Tsr);

        /**
         * @brief Gets an OCSP request from a base64-encoded TSR with AIA fallback support.
         * @param base64Tsr The base64-encoded TSR (timestamp response)
         * @param httpFetcher Function to fetch certificates from HTTP URLs, should return base64-encoded certificate
         * @return std::pair<std::string, std::string> A pair containing (ocspUrl, base64_ocsp_request)
         * @throws std::runtime_error if any step fails
         */
        std::pair<std::string, std::string> getOCSPRequestFromCertificatesWithFallback(const std::string& base64Tsr,
            std::function<std::string(const std::string&)> httpFetcher);

        /**
         * @brief Extracts the TSA signer certificate from a base64-encoded TSR.
         * @param base64Tsr The base64-encoded TSR (timestamp response)
         * @return std::string The base64 DER encoding of the signer certificate
         * @throws std::runtime_error on failure
         */
        std::string extractSignerCertFromTSR(const std::string& base64Tsr);

        /**
         * @brief Extracts the TSA issuer certificate from a base64-encoded TSR.
         * @param base64Tsr The base64-encoded TSR (timestamp response)
         * @return std::string The base64 DER encoding of the issuer certificate
         * @throws std::runtime_error on failure
         */
        std::string extractIssuerCertFromTSR(const std::string& base64Tsr);

        /**
         * @brief Extracts the OCSP responder URL from a certificate's AIA extension.
         * @param base64Cert The certificate encoded in base64
         * @param base64IssuerCert The issuer certificate encoded in base64
         * @return The OCSP responder URL as a string
         * @throws std::runtime_error if any step fails
         */
        std::string getOCSPFromCertificate(const std::string& base64Cert, const std::string& base64IssuerCert);

        /**
         * @brief Gets an OCSP request from base64-encoded certificates and returns it as base64.
         * @param base64Cert The certificate encoded in base64
         * @param base64IssuerCert The issuer certificate encoded in base64
         * @return std::string The base64-encoded OCSP request
         * @throws std::runtime_error if any step fails
         */
        std::string buildOCSPRequestFromCertificates(const std::string& base64Cert, const std::string& base64IssuerCert);

        /**
         * @brief Extracts the CA Issuers URL from a certificate's AIA extension.
         * @param base64Cert The certificate encoded in base64
         * @return The CA Issuers URL as a string
         * @throws std::runtime_error if no CA Issuers URL is found
         */
        std::string getCertificateIssuerUrlFromCertificate(const std::string& base64Cert);

    private:
        /**
         * @brief Create or update the DSS dictionary in the document with provided artifacts.
         */
        void createOrUpdateDSSCatalog(PdfMemDocument& doc, const ValidationData& validationData);
        /**
         * @brief Creates a stream object for a certificate
         * @param doc The PDF document to add the stream to
         * @param certBase64 Base64-encoded certificate data
         * @return Reference to the created stream object
         */
        PdfObject& createCertificateStream(PdfMemDocument& doc, const std::string& certBase64);
        /**
         * @brief Creates a stream object for a CRL
         * @param doc The PDF document to add the stream to
         * @param crlBase64 Base64-encoded CRL data
         * @return Reference to the created stream object
         */
        PdfObject& createCRLStream(PdfMemDocument& doc, const std::string& crlBase64);
        /**
         * @brief Creates a stream object for an OCSP response
         * @param doc The PDF document to add the stream to
         * @param ocspBase64 Base64-encoded OCSP response data
         * @return Reference to the created stream object
         */
        PdfObject& createOCSPStream(PdfMemDocument& doc, const std::string& ocspBase64);

        /**
         * @brief Attempts to extract issuer certificate from TSR, with AIA fallback.
         * @param base64Tsr The base64-encoded TSR (timestamp response)
         * @param httpFetcher Optional function to fetch certificates from HTTP URLs
         * @return std::string The base64 DER encoding of the issuer certificate
         * @throws std::runtime_error on failure
         */
        std::string extractIssuerCertFromTSRWithFallback(const std::string& base64Tsr,
            std::function<std::string(const std::string&)> httpFetcher = nullptr);

        /**
         * @brief Decodes base64 (no newlines) into DER bytes
         * @param base64PEM Optional base64-encoded PEM data
         * @param outputPath Optional path to save the decoded data
         * @return Vector containing the decoded DER bytes
         */
        std::vector<unsigned char> ConvertBase64PEMtoDER(
            const std::optional<std::string>& base64PEM,
            const std::optional<std::string>& outputPath);
        /**
         * @brief Reads a file into a string (binary mode)
         * @param filepath Path to the file to read
         * @param str Reference to string where file contents will be stored
         */
        void ReadFile(const std::string& filepath, std::string& str);
        /**
         * @brief Encodes raw buffer to base64 (no newlines)
         * @param data The raw data to encode
         * @return Base64-encoded string
         */
        std::string ToBase64(const charbuff& data);
        /**
         * @brief Decodes base64-encoded DSS hash into raw bytes
         * @param DSSHash The base64-encoded DSS hash
         * @return Raw bytes of the decoded hash
         */
        charbuff ConvertDSSHashToSignedHash(const std::string& DSSHash);
        /**
         * @brief Converts hex string to byte vector
         * @param hex The hex string to convert
         * @return Vector of bytes
         */
        std::vector<unsigned char> HexToBytes(const std::string& hex);
        /**
         * @brief Converts raw buffer to lowercase hex string
         * @param data The raw data to convert
         * @return Lowercase hex string representation
         */
        std::string ToHexString(const charbuff& data);
        /**
         * @brief URL-encodes a string (RFC3986 unreserved kept)
         * @param value The string to URL-encode
         * @return URL-encoded string
         */
        std::string UrlEncode(const std::string& value);
        /**
         * @brief Decodes base64 TSR and validates it parses as TS_RESP
         * @param base64Tsr The base64-encoded TSR
         * @return The decoded TSR data
         */
        std::string DecodeBase64Tsr(const std::string& base64Tsr);
        /**
         * @brief Extracts the PKCS#7 timeStampToken from a TS_RESP blob
         * @param tsrData The TS_RESP data
         * @return The extracted timestamp token
         */
        std::string ExtractTimestampTokenFromTSR(const std::string& tsrData);

        std::string                                 _conformanceLevel;
        HashAlgorithm                               _hashAlgorithm;
        std::string                                 _documentInputPath;
        std::string                                 _documentOutputPath;
        std::string                                 _endCertificateBase64;
        std::vector<std::string>                    _certificateChainBase64;
        std::optional<std::string>                  _rootCertificateBase64;
        std::optional<std::string>                  _label;
        std::optional<std::string>                  _responseTsrBase64;
        std::optional<ValidationData>               _validationData;
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

        // Members for LTA Signing Flow
        std::unique_ptr<PdfMemDocument>             _ltaDoc;
        std::unique_ptr<PdfSigningContext>          _ltaCtx;
        std::shared_ptr<PdfSigner>                  _ltaSigner;
        PdfSignerId                                 _ltaSignerId;
        PdfSigningResults                           _ltaResults;

        /**
         * @brief Maps digest OID string to HashAlgorithm enum
         * @param oid The OID string to map
         * @return The corresponding HashAlgorithm
         */
        static HashAlgorithm hashAlgorithmFromOid(const std::string& oid);
        /**
         * @brief Returns human-readable string for HashAlgorithm
         * @param alg The HashAlgorithm enum value
         * @return String representation of the algorithm
         */
        static const char* hashAlgorithmToString(HashAlgorithm alg);
    };

    /**
     * @brief Custom signer implementing RFC3161 DocTimeStamp behavior.
     *
     * Computes the correct hash over the ByteRange of the PDF and accepts an external
     * timestamp token to be embedded as the signature contents.
     */
    class PODOFO_API PdfDocTimeStampSigner : public PdfSigner {
    private:
        charbuff m_hashBuffer;
        std::shared_ptr<StreamDevice> m_device;
        bool m_useManualByteRange;

    public:
        /**
         * @brief Constructs a DocTimeStamp signer
         */
        PdfDocTimeStampSigner();
        /**
         * @brief Provides the underlying stream device to allow manual ByteRange hashing
         * @param device Shared pointer to the stream device
         */
        void SetDevice(std::shared_ptr<StreamDevice> device);
        /**
         * @brief Resets internal buffers
         */
        void Reset() override;
        /**
         * @brief Appends PDF bytes to internal buffer (used in non-manual mode)
         * @param data The data to append
         */
        void AppendData(const bufferview& data) override;
        /**
         * @brief Produces placeholder contents in dry-run, or keeps as-is otherwise
         * @param contents Output buffer for signature contents
         * @param dryrun When true, reserves space; when false, contents are not modified here
         */
        void ComputeSignature(charbuff& contents, bool dryrun) override;
        /**
         * @brief Computes intermediate hash result (manual ByteRange if possible)
         * @param result Reference to store the intermediate result
         */
        void FetchIntermediateResult(charbuff& result) override;

    private:
        /**
         * @brief Computes hash over the exact ByteRange of the current PDF in the device
         * @return The calculated hash
         */
        charbuff calculateCorrectHash();
        /**
         * @brief Injects externally-computed token into signature contents
         * @param processedResult The processed result data
         * @param contents Reference to store the signature contents
         * @param dryrun Whether this is a dry run
         */
        void ComputeSignatureDeferred(const bufferview& processedResult, charbuff& contents, bool dryrun) override;
        /**
         * @brief Gets the signature filter name to use in PDF dictionary
         * @return The signature filter name
         */
        std::string GetSignatureFilter() const override;
        /**
         * @brief Gets the signature subfilter for RFC3161
         * @return The signature subfilter
         */
        std::string GetSignatureSubFilter() const override;
        /**
         * @brief Gets the signature type name for DocTimeStamp
         * @return The signature type name
         */
        std::string GetSignatureType() const override;
        /**
         * @brief Determines whether to skip clearing internal buffers post-use
         * @return true if buffers should not be cleared, false otherwise
         */
        bool SkipBufferClear() const override;
    };

} // namespace PoDoFo

#endif // PDF_DSS_SIGNING_SESSION_H
