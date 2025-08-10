// PdfRemoteSignDocumentSession.cpp
/**
 * @file PdfRemoteSignDocumentSession.cpp
 * @brief Implementation of remote signing workflows and RFC3161 DocTimeStamp support.
 */

#ifdef _MSC_VER
#  define _CRT_SECURE_NO_WARNINGS
#endif

#include "PdfRemoteSignDocumentSession.h"
#include <podofo/private/OpenSSLInternal.h>
#include <openssl/bio.h>
#include <iterator>
#include <openssl/ts.h>
#include <openssl/asn1.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include <openssl/err.h>
#include <iomanip>
#include <cstring>

namespace fs = std::filesystem;

/**
 * @brief Builds an input path under the local `input/` folder
 * @param filename Relative filename
 * @return Concatenated path string
 */
std::string GetInputFilePath(const std::string& filename) {
    return "input/" + filename;
}

/**
 * @brief Reads a file from disk into a byte vector
 * @param path File path
 * @return Byte vector with file contents
 * @throws std::runtime_error if file cannot be opened or read
 */
static std::vector<unsigned char> ReadBinary(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return { std::istreambuf_iterator<char>(f),
             std::istreambuf_iterator<char>() };
}

/**
 * @brief Deleter implementation; frees a BIO chain with BIO_free_all
 * @param b Pointer to the BIO chain to free
 */
void PoDoFo::BioFreeAll::operator()(BIO* b) const noexcept {
    if (b) BIO_free_all(b);
}

/**
 * @brief Constructor for PdfRemoteSignDocumentSession
 * @param conformanceLevel The conformance level for the signing operation
 * @param hashAlgorithmOid The hash algorithm OID string to use for signing
 * @param documentInputPath Path to the input PDF document
 * @param documentOutputPath Path where the signed PDF will be saved
 * @param endCertificateBase64 Base64-encoded end entity certificate
 * @param certificateChainBase64 Vector of base64-encoded certificate chain
 * @param rootEntityCertificateBase64 Optional base64-encoded root certificate
 * @param label Optional label for the signature
 */
PoDoFo::PdfRemoteSignDocumentSession::PdfRemoteSignDocumentSession(
    const std::string& conformanceLevel,
    const std::string& hashAlgorithmOid,
    const std::string& documentInputPath,
    const std::string& documentOutputPath,
    const std::string& endCertificateBase64,
    const std::vector<std::string>& certificateChainBase64,
    const std::optional<std::string>& rootEntityCertificateBase64,
    const std::optional<std::string>& label
)
    : _conformanceLevel(conformanceLevel)
    , _hashAlgorithm(hashAlgorithmFromOid(hashAlgorithmOid))
    , _documentInputPath(documentInputPath)
    , _documentOutputPath(documentOutputPath)
    , _endCertificateBase64(endCertificateBase64)
    , _certificateChainBase64(certificateChainBase64)
    , _rootCertificateBase64(rootEntityCertificateBase64)
    , _label(label)

{

    _endCertificateDer = ConvertBase64PEMtoDER(endCertificateBase64, "input/endCertificate.der");

    _certificateChainDer.reserve(certificateChainBase64.size());
    for (size_t i = 0; i < certificateChainBase64.size(); ++i) {
        std::string outputPath = "input/chainCertificate" + std::to_string(i) + ".der";
        _certificateChainDer.push_back(ConvertBase64PEMtoDER(certificateChainBase64[i], outputPath));
    }

    if (_rootCertificateBase64) {
        _rootCertificateDer = ConvertBase64PEMtoDER(*_rootCertificateBase64, "input/rootCertificate.der");
    }
}

/**
 * @brief Destructor for PdfRemoteSignDocumentSession
 */
PoDoFo::PdfRemoteSignDocumentSession::~PdfRemoteSignDocumentSession() = default;

/**
 * @brief Begins the signing process for the document
 * @return Base64-encoded hash that needs to be signed remotely
 * @throws std::runtime_error if signing process cannot be initiated
 */
std::string PoDoFo::PdfRemoteSignDocumentSession::beginSigning() {
    try {
        fs::copy_file(_documentInputPath, _documentOutputPath, fs::copy_options::overwrite_existing);
        _stream = std::make_shared<PoDoFo::FileStreamDevice>(_documentOutputPath, PoDoFo::FileMode::Open);

        std::string cert;
        cert.assign(_endCertificateDer.begin(), _endCertificateDer.end());

        _doc.Load(_stream);

        auto& acroForm = _doc.GetOrCreateAcroForm();
        acroForm.GetDictionary().AddKey("SigFlags"_n, (int64_t)3);

        auto& page = _doc.GetPages().GetPageAt(0);
        auto& field = page.CreateField("Signature", PoDoFo::PdfFieldType::Signature, PoDoFo::Rect(0, 0, 0, 0));
        auto& signature = static_cast<PoDoFo::PdfSignature&>(field);
        signature.MustGetWidget().SetFlags(PoDoFo::PdfAnnotationFlags::Invisible | PoDoFo::PdfAnnotationFlags::Hidden);
        signature.SetSignatureDate(PoDoFo::PdfDate::LocalNow());

        if (_conformanceLevel == "ADES_B_B") {
            _cmsParams.SignatureType = PoDoFo::PdfSignatureType::PAdES_B;
        }
        else if (_conformanceLevel == "ADES_B_T") {
            _cmsParams.SignatureType = PoDoFo::PdfSignatureType::PAdES_B_T;
        }
        else if (_conformanceLevel == "ADES_B_LT") {
            _cmsParams.SignatureType = PoDoFo::PdfSignatureType::PAdES_B_LT;
        }
        else if (_conformanceLevel == "ADES_B_LTA") {
            _cmsParams.SignatureType = PoDoFo::PdfSignatureType::PAdES_B_LTA;
        }
        else {
            throw std::runtime_error("Invalid conformance level");
        }

        if (_hashAlgorithm == HashAlgorithm::SHA256) {
            _cmsParams.Hashing = PoDoFo::PdfHashingAlgorithm::SHA256;
        }
        else if (_hashAlgorithm == HashAlgorithm::SHA384) {
            _cmsParams.Hashing = PoDoFo::PdfHashingAlgorithm::SHA384;
        }
        else if (_hashAlgorithm == HashAlgorithm::SHA512) {
            _cmsParams.Hashing = PoDoFo::PdfHashingAlgorithm::SHA512;
        }
        else {
            throw std::runtime_error("Hash algorithm is not supported");
        }

        std::vector<charbuff> chain;
        for (const auto& cert : _certificateChainDer)
            chain.emplace_back(reinterpret_cast<const char*>(cert.data()), cert.size());

        _signer = std::make_shared<PoDoFo::PdfSignerCms>(cert, chain, _cmsParams);
        _signer->ReserveAttributeSize(20000);
        _signerId = _ctx.AddSigner(signature, _signer);

        _ctx.StartSigning(_doc, _stream, _results, PoDoFo::PdfSaveOptions::NoMetadataUpdate);

        auto& INITIAL_hash = _results.Intermediate[_signerId];
        auto rawCmsHash = ToHexString(INITIAL_hash);

        auto binaryHash = HexToBytes(rawCmsHash);
        PoDoFo::charbuff binaryCharbuff;
        binaryCharbuff.assign(reinterpret_cast<const char*>(binaryHash.data()), binaryHash.size());

        auto base64Hash = ToBase64(binaryCharbuff);

        auto urlEncodedHash = UrlEncode(base64Hash);

        return urlEncodedHash;
    }
    catch (const std::exception& e) {
        std::cout << "\n=== Error in Signing Process ===" << std::endl;
        std::cout << "Error: " << e.what() << std::endl;
        _stream.reset();
        throw;
    }
}

/**
 * @brief Completes the signing process with the signed hash and optional validation data
 * @param signedHash The signed hash returned from the remote signing service
 * @param base64Tsr Base64-encoded timestamp response (TSR)
 * @param validationData Optional validation data including certificates, CRLs, and OCSP responses
 * @throws std::runtime_error if signing completion fails
 */
void PoDoFo::PdfRemoteSignDocumentSession::finishSigning(const std::string& signedHash, const std::string& base64Tsr, const std::optional<ValidationData>& validationData) {
    try {
        PoDoFo::charbuff buff = ConvertDSSHashToSignedHash(signedHash);
        _results.Intermediate[_signerId] = buff;

        if (!_signer) {
            throw std::runtime_error("Signer not initialized");
        }

        std::string tsr;

        if (_conformanceLevel != "ADES_B_B") {
            tsr = DecodeBase64Tsr(base64Tsr);
            _signer->SetTimestampToken({ tsr.data(), tsr.size() });

        }
        _ctx.FinishSigning(_results);


        if (_conformanceLevel == "ADES_B_LT" && validationData.has_value()) {
            PoDoFo::PdfMemDocument dss_doc;
            _stream->Seek(0, PoDoFo::SeekDirection::Begin);
            dss_doc.Load(_stream);

            createOrUpdateDSSCatalog(dss_doc, *validationData);

            dss_doc.SaveUpdate(*_stream, PoDoFo::PdfSaveOptions::NoMetadataUpdate | PoDoFo::PdfSaveOptions::NoFlateCompress);
        }

        if (_conformanceLevel == "ADES_B_LTA" && validationData.has_value()) {
            PoDoFo::PdfMemDocument dss_doc;
            _stream->Seek(0, PoDoFo::SeekDirection::Begin);
            dss_doc.Load(_stream);

            createOrUpdateDSSCatalog(dss_doc, *validationData);

            dss_doc.SaveUpdate(*_stream, PoDoFo::PdfSaveOptions::NoMetadataUpdate | PoDoFo::PdfSaveOptions::NoFlateCompress);
        }

    }
    catch (const std::exception& e) {
        std::cout << "\n=== Error in Finish Signing ===" << std::endl;
        std::cout << "Error: " << e.what() << std::endl;
        _stream.reset();
        throw;
    }
}

std::vector<unsigned char> PoDoFo::PdfRemoteSignDocumentSession::ConvertBase64PEMtoDER(
    const std::optional<std::string>& base64PEM,
    const std::optional<std::string>& outputPath)
{
    if (!base64PEM || base64PEM->empty())
        return {};

    BIO* raw_b64 = BIO_new(BIO_f_base64());
    if (!raw_b64) throw std::runtime_error("Failed to create BIO for Base64");
    BIO_set_flags(raw_b64, BIO_FLAGS_BASE64_NO_NL);

    BIO* raw_mem = BIO_new_mem_buf(base64PEM->data(), static_cast<int>(base64PEM->size()));
    if (!raw_mem) {
        BIO_free_all(raw_b64);
        throw std::runtime_error("Failed to create memory BIO");
    }

    BIO* raw_chain = BIO_push(raw_b64, raw_mem);
    PoDoFo::BioPtr bio(raw_chain);

    std::vector<unsigned char> der((base64PEM->size() * 3) / 4);
    int len = BIO_read(bio.get(), der.data(), static_cast<int>(der.size()));
    if (len <= 0) throw std::runtime_error("Base64 decode failed");
    der.resize(len);

    return der;
}

std::string PoDoFo::PdfRemoteSignDocumentSession::ToBase64(const PoDoFo::charbuff& data) {
    BIO* raw_b64 = BIO_new(BIO_f_base64()); BIO_set_flags(raw_b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* raw_mem = BIO_new(BIO_s_mem());
    BIO* raw_chain = BIO_push(raw_b64, raw_mem);
    PoDoFo::BioPtr bio(raw_chain);

    if (BIO_write(bio.get(), data.data(), static_cast<int>(data.size())) <= 0 ||
        BIO_flush(bio.get()) <= 0)
        throw std::runtime_error("BIO_write/flush failed");

    BUF_MEM* ptr;
    BIO_get_mem_ptr(bio.get(), &ptr);
    return std::string(ptr->data, ptr->length);
}

PoDoFo::charbuff PoDoFo::PdfRemoteSignDocumentSession::ConvertDSSHashToSignedHash(const std::string& DSSHash) {
    BIO* raw_b64 = BIO_new(BIO_f_base64()); BIO_set_flags(raw_b64, BIO_FLAGS_BASE64_NO_NL);
    BIO* raw_mem = BIO_new_mem_buf(DSSHash.data(), static_cast<int>(DSSHash.size()));
    BIO* raw_chain = BIO_push(raw_b64, raw_mem);
    PoDoFo::BioPtr bio(raw_chain);

    std::vector<unsigned char> decoded(128);
    int len = BIO_read(bio.get(), decoded.data(), static_cast<int>(decoded.size()));
    if (len <= 0) throw std::runtime_error("Base64 decode failed");
    decoded.resize(len);

    PoDoFo::charbuff result;
    result.assign(decoded.begin(), decoded.end());
    return result;
}

std::vector<unsigned char> PoDoFo::PdfRemoteSignDocumentSession::HexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string PoDoFo::PdfRemoteSignDocumentSession::ToHexString(const PoDoFo::charbuff& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c : data) {
        ss << std::setw(2) << static_cast<int>(c);
    }
    return ss.str();
}

std::string PoDoFo::PdfRemoteSignDocumentSession::UrlEncode(const std::string& value) {
    std::ostringstream escaped; escaped.fill('0'); escaped << std::hex;
    for (unsigned char c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
        }
        else {
            escaped << '%' << std::setw(2) << std::uppercase << static_cast<int>(c);
        }
    }
    return escaped.str();
}

void PoDoFo::PdfRemoteSignDocumentSession::printState() const {
    std::cout << "PdfSigningSession state:\n";
    std::cout << "  ConformanceLevel: " << _conformanceLevel << "\n";
    std::cout << "  HashAlgorithm:    " << hashAlgorithmToString(_hashAlgorithm) << "\n";
    std::cout << "  DocumentInput:    " << _documentInputPath << "\n";
    std::cout << "  DocumentOutput:   " << _documentOutputPath << "\n";
    std::cout << "  EndCert (bytes):  " << _endCertificateBase64.size() << "\n";
    std::cout << "  ChainCount:       " << _certificateChainBase64.size() << "\n";
    if (_rootCertificateBase64)
        std::cout << "  RootCert (bytes): " << _rootCertificateBase64->size() << "\n";
    if (_label)
        std::cout << "  Label:            " << *_label << "\n";
    if (!_responseTsr.empty())
        std::cout << "  TimestampToken:   " << _responseTsr.size() << " bytes\n";
}

std::string PoDoFo::PdfRemoteSignDocumentSession::getCrlFromCertificate(const std::string& base64Cert) {
    auto base64_decode = [](const std::string& base64_string) -> std::vector<unsigned char> {
        std::unique_ptr<BIO, decltype(&BIO_free)> b64(BIO_new(BIO_f_base64()), BIO_free);
        if (!b64) throw std::runtime_error("Failed to create BIO for base64 decoding.");
        BIO_set_flags(b64.get(), BIO_FLAGS_BASE64_NO_NL);
        std::unique_ptr<BIO, decltype(&BIO_free)> bmem(BIO_new_mem_buf(base64_string.data(), static_cast<int>(base64_string.length())), BIO_free);
        if (!bmem) throw std::runtime_error("Failed to create BIO_mem_buf for base64 decoding.");
        BIO* bio = BIO_push(b64.get(), bmem.get());

        std::vector<unsigned char> decoded_data(base64_string.length());
        int decoded_length = BIO_read(bio, decoded_data.data(), static_cast<int>(decoded_data.size()));
        if (decoded_length <= 0) throw std::runtime_error("Failed to decode base64 input.");
        decoded_data.resize(decoded_length);
        return decoded_data;
        };

    std::vector<unsigned char> decoded = base64_decode(base64Cert);
    if (decoded.size() < 50) {
        throw std::runtime_error("Decoded data too small to be valid X.509 or timestamp.");
    }

    const unsigned char* p = decoded.data();
    std::unique_ptr<X509, decltype(&X509_free)> cert(
        d2i_X509(nullptr, &p, decoded.size()), X509_free);

    if (!cert) {
        p = decoded.data();
        std::unique_ptr<TS_RESP, decltype(&TS_RESP_free)> ts_resp(
            d2i_TS_RESP(nullptr, &p, decoded.size()), TS_RESP_free);
        if (!ts_resp) {
            throw std::runtime_error("Failed to parse DER as X.509 certificate or TimeStampResp.");
        }

        PKCS7* pkcs7 = TS_RESP_get_token(ts_resp.get());
        if (!pkcs7) {
            throw std::runtime_error("TimeStampResp does not contain a timeStampToken.");
        }

        if (!PKCS7_type_is_signed(pkcs7) || !pkcs7->d.sign || !pkcs7->d.sign->cert) {
            throw std::runtime_error("timeStampToken does not contain signer certificate.");
        }

        STACK_OF(X509)* certs = pkcs7->d.sign->cert;
        if (sk_X509_num(certs) < 1) {
            throw std::runtime_error("No certificates found in timeStampToken.");
        }

        cert.reset(X509_dup(sk_X509_value(certs, 0)));
        if (!cert) {
            throw std::runtime_error("Failed to duplicate signer certificate from timeStampToken.");
        }
    }

    if (!X509_get_subject_name(cert.get()) || !X509_get_issuer_name(cert.get())) {
        throw std::runtime_error("Parsed certificate structure is invalid.");
    }

    std::unique_ptr<CRL_DIST_POINTS, decltype(&CRL_DIST_POINTS_free)> dist_points(
        static_cast<CRL_DIST_POINTS*>(X509_get_ext_d2i(cert.get(), NID_crl_distribution_points, nullptr, nullptr)),
        CRL_DIST_POINTS_free
    );

    if (dist_points) {
        for (int i = 0; i < sk_DIST_POINT_num(dist_points.get()); ++i) {
            DIST_POINT* dp = sk_DIST_POINT_value(dist_points.get(), i);
            if (dp && dp->distpoint && dp->distpoint->type == 0) {
                GENERAL_NAMES* names = dp->distpoint->name.fullname;
                for (int j = 0; j < sk_GENERAL_NAME_num(names); ++j) {
                    GENERAL_NAME* gen_name = sk_GENERAL_NAME_value(names, j);
                    if (gen_name && gen_name->type == GEN_URI) {
                        ASN1_IA5STRING* uri = gen_name->d.uniformResourceIdentifier;
                        if (uri && ASN1_STRING_length(uri) > 0) {
                            std::string crl_url(reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri)), ASN1_STRING_length(uri));
                            if (!crl_url.empty()) {
                                return crl_url;
                            }
                        }
                    }
                }
            }
        }
    }

    throw std::runtime_error("No CRL distribution point URL found in certificate.");
}

std::string PoDoFo::PdfRemoteSignDocumentSession::DecodeBase64Tsr(const std::string& base64Tsr) {
    BIO* b64 = BIO_new(BIO_f_base64());
    if (!b64) {
        throw std::runtime_error("Failed to create BIO for base64 decoding");
    }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO* mem = BIO_new_mem_buf(base64Tsr.data(), static_cast<int>(base64Tsr.size()));
    if (!mem) {
        BIO_free_all(b64);
        throw std::runtime_error("Failed to create memory BIO");
    }

    BIO* bio = BIO_push(b64, mem);

    size_t maxDecodedSize = (base64Tsr.size() * 3) / 4;
    std::vector<unsigned char> decoded(maxDecodedSize);

    int decodedSize = BIO_read(bio, decoded.data(), static_cast<int>(maxDecodedSize));
    BIO_free_all(bio);

    if (decodedSize <= 0) {
        throw std::runtime_error("Failed to decode base64 TSR data");
    }

    decoded.resize(decodedSize);

    std::string tsrData(decoded.begin(), decoded.end());

    const unsigned char* p = reinterpret_cast<const unsigned char*>(tsrData.data());
    TS_RESP* response = d2i_TS_RESP(nullptr, &p, static_cast<long>(tsrData.size()));
    if (!response) {
        std::cerr << "[ERROR] Failed to parse decoded TSR into TS_RESP (OpenSSL error)" << std::endl;
        throw std::runtime_error("Invalid TSR data after decoding");
    }
    TS_RESP_free(response);

    return tsrData;
}

PoDoFo::HashAlgorithm PoDoFo::PdfRemoteSignDocumentSession::hashAlgorithmFromOid(const std::string& oid) {
    if (oid == "2.16.840.1.101.3.4.2.1") return HashAlgorithm::SHA256;
    if (oid == "2.16.840.1.101.3.4.2.2") return HashAlgorithm::SHA384;
    if (oid == "2.16.840.1.101.3.4.2.3") return HashAlgorithm::SHA512;
    return HashAlgorithm::Unknown;
}

const char* PoDoFo::PdfRemoteSignDocumentSession::hashAlgorithmToString(PoDoFo::HashAlgorithm alg) {
    switch (alg) {
    case HashAlgorithm::SHA256: return "SHA-256";
    case HashAlgorithm::SHA384: return "SHA-384";
    case HashAlgorithm::SHA512: return "SHA-512";
    default:                    return "Unknown";
    }
}

void PoDoFo::PdfRemoteSignDocumentSession::createOrUpdateDSSCatalog(PoDoFo::PdfMemDocument& doc, const PoDoFo::ValidationData& validationData) {
    auto& catalog = doc.GetCatalog();
    auto& objects = doc.GetObjects();
    PoDoFo::PdfDictionary* pDssDict = nullptr;

    if (catalog.GetDictionary().HasKey("DSS"_n)) {
        auto* pDssObj = objects.GetObject(catalog.GetDictionary().GetKey("DSS"_n)->GetReference());
        if (pDssObj && pDssObj->IsDictionary()) {
            pDssDict = &pDssObj->GetDictionary();
        }
        else {
            throw std::runtime_error("Existing DSS object is not a dictionary.");
        }
    }
    else {
        auto& dssObj = objects.CreateDictionaryObject();
        pDssDict = &dssObj.GetDictionary();
        catalog.GetDictionary().AddKey("DSS"_n, dssObj.GetIndirectReference());
    }

    if (!pDssDict) {
        throw std::runtime_error("Failed to get or create DSS dictionary.");
    }

    auto addToDssArray = [&](const char* keyName, const std::vector<std::string>& data,
        PoDoFo::PdfObject& (PoDoFo::PdfRemoteSignDocumentSession::* createStreamFunc)(PoDoFo::PdfMemDocument&, const std::string&)) {
            const PoDoFo::PdfName key(keyName);
            PoDoFo::PdfArray* pArray = nullptr;
            if (pDssDict->HasKey(key)) {
                auto* pArrayObj = objects.GetObject(pDssDict->GetKey(key)->GetReference());
                if (pArrayObj && pArrayObj->IsArray()) {
                    pArray = &pArrayObj->GetArray();
                }
                else {
                    throw std::runtime_error("Existing DSS entry for " + std::string(keyName) + " is not an array.");
                }
            }
            else {
                auto& newArrayObj = objects.CreateArrayObject();
                pArray = &newArrayObj.GetArray();
                pDssDict->AddKey(key, newArrayObj.GetIndirectReference());
            }

            if (pArray) {
                for (const auto& itemBase64 : data) {
                    auto& stream = (this->*createStreamFunc)(doc, itemBase64);
                    pArray->Add(stream.GetIndirectReference());
                }
            }
        };

    if (!validationData.certificatesBase64.empty()) {
        addToDssArray("Certs", validationData.certificatesBase64, &PoDoFo::PdfRemoteSignDocumentSession::createCertificateStream);
    }

    if (!validationData.crlsBase64.empty()) {
        addToDssArray("CRLs", validationData.crlsBase64, &PoDoFo::PdfRemoteSignDocumentSession::createCRLStream);
    }

    if (!validationData.ocspsBase64.empty()) {
        addToDssArray("OCSPs", validationData.ocspsBase64, &PoDoFo::PdfRemoteSignDocumentSession::createOCSPStream);
    }
}

PoDoFo::PdfObject& PoDoFo::PdfRemoteSignDocumentSession::createCertificateStream(PoDoFo::PdfMemDocument& doc, const std::string& certBase64) {
    std::vector<unsigned char> certDer = ConvertBase64PEMtoDER(certBase64, std::nullopt);

    auto& streamObj = doc.GetObjects().CreateDictionaryObject();
    auto& stream = streamObj.GetOrCreateStream();

    PoDoFo::charbuff certData;
    certData.assign(reinterpret_cast<const char*>(certDer.data()), certDer.size());
    stream.SetData(certData, {}, true);

    return streamObj;
}

PoDoFo::PdfObject& PoDoFo::PdfRemoteSignDocumentSession::createCRLStream(PoDoFo::PdfMemDocument& doc, const std::string& crlBase64) {
    std::vector<unsigned char> crlDer = ConvertBase64PEMtoDER(crlBase64, std::nullopt);

    auto& streamObj = doc.GetObjects().CreateDictionaryObject();
    auto& stream = streamObj.GetOrCreateStream();

    PoDoFo::charbuff crlData;
    crlData.assign(reinterpret_cast<const char*>(crlDer.data()), crlDer.size());
    stream.SetData(crlData, {}, true);

    return streamObj;
}

PoDoFo::PdfObject& PoDoFo::PdfRemoteSignDocumentSession::createOCSPStream(PoDoFo::PdfMemDocument& doc, const std::string& ocspBase64) {
    std::vector<unsigned char> ocspDer = ConvertBase64PEMtoDER(ocspBase64, std::nullopt);

    auto& streamObj = doc.GetObjects().CreateDictionaryObject();
    auto& stream = streamObj.GetOrCreateStream();

    PoDoFo::charbuff ocspData;
    ocspData.assign(reinterpret_cast<const char*>(ocspDer.data()), ocspDer.size());
    stream.SetData(ocspData, {}, true);

    return streamObj;
}



std::string PoDoFo::PdfRemoteSignDocumentSession::beginSigningLTA() {
    try
    {
        if (!_stream) {
            throw std::runtime_error("No active stream available. Make sure finishSigning() was called successfully.");
        }

        _stream->Seek(0, PoDoFo::SeekDirection::Begin);
        _ltaDoc = std::make_unique<PoDoFo::PdfMemDocument>();
        _ltaDoc->Load(_stream);

        auto& page = _ltaDoc->GetPages().GetPageAt(0);
        auto& signature = static_cast<PoDoFo::PdfSignature&>(page.CreateField("Signature2", PoDoFo::PdfFieldType::Signature, PoDoFo::Rect(0, 0, 0, 0)));

        signature.MustGetWidget().SetFlags(static_cast<PoDoFo::PdfAnnotationFlags>(132));

        _ltaCtx = std::make_unique<PoDoFo::PdfSigningContext>();

        _ltaSigner = std::make_shared<PoDoFo::PdfDocTimeStampSigner>();
        _ltaSignerId = _ltaCtx->AddSigner(signature, _ltaSigner);

        _ltaCtx->StartSigning(*_ltaDoc, _stream, _ltaResults, PoDoFo::PdfSaveOptions::NoMetadataUpdate);

        auto& INITIAL_hash = _ltaResults.Intermediate[_ltaSignerId];
        auto rawCmsHash = ToHexString(INITIAL_hash);

        auto binaryHash = HexToBytes(rawCmsHash);
        PoDoFo::charbuff binaryCharbuff;
        binaryCharbuff.assign(reinterpret_cast<const char*>(binaryHash.data()), binaryHash.size());

        auto base64Hash = ToBase64(binaryCharbuff);

        auto urlEncodedHash = UrlEncode(base64Hash);

        return base64Hash;
    }
    catch (const std::exception& e)
    {
        std::cout << "\n=== Error in beginSigningLTA ===" << std::endl;
        std::cout << "Error: " << e.what() << std::endl;
        _ltaDoc.reset();
        _ltaCtx.reset();
        _ltaSigner.reset();
        throw;
    }
}

void PoDoFo::PdfRemoteSignDocumentSession::finishSigningLTA(const std::string& base64Tsr, const std::optional<ValidationData>& validationData)
{
    try
    {
        if (!_ltaDoc || !_ltaCtx || !_ltaSigner || !_stream) {
            throw std::runtime_error("LTA signing has not been started. Call beginSigningLTA() first.");
        }

        std::string tsr = DecodeBase64Tsr(base64Tsr);
        std::string timestampToken = ExtractTimestampTokenFromTSR(tsr);

        PoDoFo::charbuff tokenContent;
        tokenContent.assign(timestampToken.data(), timestampToken.size());
        _ltaResults.Intermediate[_ltaSignerId] = tokenContent;

        _ltaCtx->FinishSigning(_ltaResults);

        if (validationData.has_value() && !validationData->empty()) {
            _stream->Seek(0, PoDoFo::SeekDirection::Begin);
            PoDoFo::PdfMemDocument final_doc;
            final_doc.Load(_stream);

            createOrUpdateDSSCatalog(final_doc, *validationData);

            final_doc.SaveUpdate(*_stream, PoDoFo::PdfSaveOptions::NoMetadataUpdate | PoDoFo::PdfSaveOptions::NoFlateCompress);
        }

        _ltaDoc.reset();
        _ltaCtx.reset();
        _ltaSigner.reset();
    }
    catch (const std::exception& e)
    {
        std::cout << "\n=== Error in finishSigningLTA ===" << std::endl;
        std::cout << "Error: " << e.what() << std::endl;
        _ltaDoc.reset();
        _ltaCtx.reset();
        _ltaSigner.reset();
        throw;
    }
}

std::string PoDoFo::PdfRemoteSignDocumentSession::ExtractTimestampTokenFromTSR(const std::string& tsrData)
{
    const unsigned char* p = reinterpret_cast<const unsigned char*>(tsrData.data());
    TS_RESP* response = d2i_TS_RESP(nullptr, &p, static_cast<long>(tsrData.size()));

    if (!response) {
        throw std::runtime_error("Failed to parse TSR structure");
    }

    TS_STATUS_INFO* status_info = TS_RESP_get_status_info(response);
    if (!status_info) {
        TS_RESP_free(response);
        throw std::runtime_error("Failed to get TSR status info");
    }

    const ASN1_INTEGER* status_asn1 = TS_STATUS_INFO_get0_status(status_info);
    if (!status_asn1) {
        TS_RESP_free(response);
        throw std::runtime_error("Failed to get TSR status");
    }

    long status = ASN1_INTEGER_get(status_asn1);
    if (status != 0) {
        TS_RESP_free(response);
        throw std::runtime_error("TSR status indicates failure: " + std::to_string(status));
    }

    PKCS7* token = TS_RESP_get_token(response);
    if (!token) {
        TS_RESP_free(response);
        throw std::runtime_error("No timestamp token found in TSR");
    }

    int tokenLen = i2d_PKCS7(token, nullptr);
    if (tokenLen <= 0) {
        TS_RESP_free(response);
        throw std::runtime_error("Failed to get timestamp token length");
    }

    std::vector<unsigned char> tokenDer(tokenLen);
    unsigned char* p2 = tokenDer.data();
    int actualLen = i2d_PKCS7(token, &p2);

    if (actualLen != tokenLen) {
        TS_RESP_free(response);
        throw std::runtime_error("Failed to serialize timestamp token");
    }

    std::string timestampToken(reinterpret_cast<const char*>(tokenDer.data()), tokenLen);

    TS_RESP_free(response);
    return timestampToken;
}

std::string PoDoFo::PdfRemoteSignDocumentSession::extractSignerCertFromTSR(const std::string& base64Tsr) {
    std::vector<unsigned char> tsr_der = ConvertBase64PEMtoDER(std::optional<std::string>(base64Tsr), std::nullopt);
    const unsigned char* p = tsr_der.data();
    std::unique_ptr<TS_RESP, decltype(&TS_RESP_free)> ts_resp(d2i_TS_RESP(nullptr, &p, tsr_der.size()), TS_RESP_free);
    if (!ts_resp) throw std::runtime_error("Failed to parse TS_RESP from DER.");

    PKCS7* pkcs7 = TS_RESP_get_token(ts_resp.get());
    if (!pkcs7) throw std::runtime_error("TSR does not contain a PKCS7 token.");

    STACK_OF(X509)* certs = pkcs7->d.sign->cert;
    if (!certs || sk_X509_num(certs) < 1) {
        throw std::runtime_error("TSR does not contain any certificates to find the signer.");
    }

    X509* signerCert = sk_X509_value(certs, 0);
    if (!signerCert) throw std::runtime_error("Could not get signer certificate from TSR.");

    int len = i2d_X509(signerCert, nullptr);
    if (len <= 0) throw std::runtime_error("Failed to get length of DER for signer cert.");
    std::vector<unsigned char> signer_der(len);
    unsigned char* out_p = signer_der.data();
    if (i2d_X509(signerCert, &out_p) <= 0) throw std::runtime_error("Failed to encode signer cert to DER.");

    PoDoFo::charbuff signer_charbuff;
    signer_charbuff.assign(reinterpret_cast<const char*>(signer_der.data()), signer_der.size());
    return ToBase64(signer_charbuff);
}

std::string PoDoFo::PdfRemoteSignDocumentSession::extractIssuerCertFromTSR(const std::string& base64Tsr) {
    std::vector<unsigned char> tsr_der = ConvertBase64PEMtoDER(std::optional<std::string>(base64Tsr), std::nullopt);
    const unsigned char* p = tsr_der.data();
    std::unique_ptr<TS_RESP, decltype(&TS_RESP_free)> ts_resp(d2i_TS_RESP(nullptr, &p, tsr_der.size()), TS_RESP_free);
    if (!ts_resp) throw std::runtime_error("Failed to parse TS_RESP from DER.");

    PKCS7* pkcs7 = TS_RESP_get_token(ts_resp.get());
    if (!pkcs7) throw std::runtime_error("TSR does not contain a PKCS7 token.");

    STACK_OF(X509)* certs = pkcs7->d.sign->cert;
    if (!certs || sk_X509_num(certs) < 2) {
        throw std::runtime_error("TSR does not contain enough certificates to find issuer.");
    }

    X509* issuerCert = sk_X509_value(certs, 1);
    if (!issuerCert) throw std::runtime_error("Could not get issuer certificate from TSR.");

    int len = i2d_X509(issuerCert, nullptr);
    if (len <= 0) throw std::runtime_error("Failed to get length of DER for issuer cert.");
    std::vector<unsigned char> issuer_der(len);
    unsigned char* out_p = issuer_der.data();
    if (i2d_X509(issuerCert, &out_p) <= 0) throw std::runtime_error("Failed to encode issuer cert to DER.");

    PoDoFo::charbuff issuer_charbuff;
    issuer_charbuff.assign(reinterpret_cast<const char*>(issuer_der.data()), issuer_der.size());
    return ToBase64(issuer_charbuff);
}

std::string PoDoFo::PdfRemoteSignDocumentSession::getOCSPFromCertificate(const std::string& base64Cert, const std::string& base64IssuerCert) {
    std::vector<unsigned char> decoded_cert = ConvertBase64PEMtoDER(std::optional<std::string>(base64Cert), std::nullopt);
    std::vector<unsigned char> decoded_issuer = ConvertBase64PEMtoDER(std::optional<std::string>(base64IssuerCert), std::nullopt);

    const unsigned char* p = decoded_cert.data();
    std::unique_ptr<X509, decltype(&X509_free)> cert(d2i_X509(nullptr, &p, decoded_cert.size()), X509_free);
    if (!cert) throw std::runtime_error("Failed to parse DER certificate: " + std::string(ERR_reason_error_string(ERR_get_error())));

    const unsigned char* pi = decoded_issuer.data();
    std::unique_ptr<X509, decltype(&X509_free)> issuer(d2i_X509(nullptr, &pi, decoded_issuer.size()), X509_free);
    if (!issuer) throw std::runtime_error("Failed to parse DER issuer certificate: " + std::string(ERR_reason_error_string(ERR_get_error())));

    std::string ocsp_url;
    AUTHORITY_INFO_ACCESS* info = (AUTHORITY_INFO_ACCESS*)X509_get_ext_d2i(cert.get(), NID_info_access, nullptr, nullptr);
    if (info) {
        for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(info); ++i) {
            ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(info, i);
            if (OBJ_obj2nid(ad->method) == NID_ad_OCSP) {
                if (ad->location->type == GEN_URI) {
                    ASN1_IA5STRING* uri = ad->location->d.uniformResourceIdentifier;
                    ocsp_url = std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri)), ASN1_STRING_length(uri));
                    break;
                }
            }
        }
        AUTHORITY_INFO_ACCESS_free(info);
    }
    if (ocsp_url.empty()) throw std::runtime_error("No OCSP responder URL found in certificate.");

    return ocsp_url;
}

std::string PoDoFo::PdfRemoteSignDocumentSession::buildOCSPRequestFromCertificates(const std::string& base64Cert, const std::string& base64IssuerCert) {
    std::vector<unsigned char> decoded_cert = ConvertBase64PEMtoDER(std::optional<std::string>(base64Cert), std::nullopt);
    std::vector<unsigned char> decoded_issuer = ConvertBase64PEMtoDER(std::optional<std::string>(base64IssuerCert), std::nullopt);

    const unsigned char* p = decoded_cert.data();
    std::unique_ptr<X509, decltype(&X509_free)> cert(d2i_X509(nullptr, &p, decoded_cert.size()), X509_free);
    if (!cert) throw std::runtime_error("Failed to parse DER certificate: " + std::string(ERR_reason_error_string(ERR_get_error())));

    const unsigned char* pi = decoded_issuer.data();
    std::unique_ptr<X509, decltype(&X509_free)> issuer(d2i_X509(nullptr, &pi, decoded_issuer.size()), X509_free);
    if (!issuer) throw std::runtime_error("Failed to parse DER issuer certificate: " + std::string(ERR_reason_error_string(ERR_get_error())));

    std::unique_ptr<OCSP_REQUEST, decltype(&OCSP_REQUEST_free)> req(OCSP_REQUEST_new(), OCSP_REQUEST_free);
    if (!req) throw std::runtime_error("Failed to allocate OCSP_REQUEST.");

    std::unique_ptr<OCSP_CERTID, decltype(&OCSP_CERTID_free)> id(
        OCSP_cert_to_id(nullptr, cert.get(), issuer.get()), OCSP_CERTID_free);
    if (!id) throw std::runtime_error("Failed to create OCSP_CERTID.");

    if (!OCSP_request_add0_id(req.get(), id.get())) throw std::runtime_error("Failed to add CertID to OCSP request.");
    id.release();

    unsigned char* req_der = nullptr;
    int req_der_len = i2d_OCSP_REQUEST(req.get(), &req_der);
    if (req_der_len <= 0) throw std::runtime_error("Failed to DER-encode OCSP request.");
    std::vector<unsigned char> req_data(req_der, req_der + req_der_len);
    OPENSSL_free(req_der);

    PoDoFo::charbuff req_charbuff;
    req_charbuff.assign(reinterpret_cast<const char*>(req_data.data()), req_data.size());
    return ToBase64(req_charbuff);
}

std::string PoDoFo::PdfRemoteSignDocumentSession::getCertificateIssuerUrlFromCertificate(const std::string& base64Cert) {
    std::vector<unsigned char> decoded_cert = ConvertBase64PEMtoDER(std::optional<std::string>(base64Cert), std::nullopt);

    const unsigned char* p = decoded_cert.data();
    std::unique_ptr<X509, decltype(&X509_free)> cert(d2i_X509(nullptr, &p, decoded_cert.size()), X509_free);
    if (!cert) throw std::runtime_error("Failed to parse DER certificate: " + std::string(ERR_reason_error_string(ERR_get_error())));

    std::string ca_issuer_url;
    AUTHORITY_INFO_ACCESS* info = (AUTHORITY_INFO_ACCESS*)X509_get_ext_d2i(cert.get(), NID_info_access, nullptr, nullptr);
    if (info) {
        for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(info); ++i) {
            ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(info, i);
            if (OBJ_obj2nid(ad->method) == NID_ad_ca_issuers) {
                if (ad->location->type == GEN_URI) {
                    ASN1_IA5STRING* uri = ad->location->d.uniformResourceIdentifier;
                    ca_issuer_url = std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri)), ASN1_STRING_length(uri));
                    break;
                }
            }
        }
        AUTHORITY_INFO_ACCESS_free(info);
    }
    if (ca_issuer_url.empty()) throw std::runtime_error("No CA Issuers URL found in certificate AIA extension.");

    return ca_issuer_url;
}
//TODO
std::string PoDoFo::PdfRemoteSignDocumentSession::extractIssuerCertFromTSRWithFallback(const std::string& base64Tsr,
    std::function<std::string(const std::string&)> httpFetcher) {

    try {
        return extractIssuerCertFromTSR(base64Tsr);
    }
    catch (const std::runtime_error& e) {
        std::string error_msg(e.what());

        if (error_msg.find("TSR does not contain enough certificates") != std::string::npos) {

            try {
                std::string tsaSignerCert = extractSignerCertFromTSR(base64Tsr);

                std::string ca_issuer_url = getCertificateIssuerUrlFromCertificate(tsaSignerCert);

                if (httpFetcher) {
                    std::string issuer_cert_base64 = httpFetcher(ca_issuer_url);

                    if (!issuer_cert_base64.empty()) {
                        return issuer_cert_base64;
                    }
                    else {
                        throw std::runtime_error("HTTP fetcher returned empty certificate from AIA URL: " + ca_issuer_url);
                    }
                }
                else {
                    throw std::runtime_error("No HTTP fetcher provided for AIA certificate retrieval. URL: " + ca_issuer_url);
                }
            }
            catch (const std::exception& aia_error) {
                throw std::runtime_error("AIA fallback failed: " + std::string(aia_error.what()) + ". Original error: " + error_msg);
            }
        }
        else {
            throw;
        }
    }
}

std::pair<std::string, std::string> PoDoFo::PdfRemoteSignDocumentSession::getOCSPRequestFromCertificates(const std::string& base64Tsr) {
    std::string tsaSignerCert = extractSignerCertFromTSR(base64Tsr);
    std::string tsaIssuerCert = extractIssuerCertFromTSR(base64Tsr);
    std::string ocspUrl = getOCSPFromCertificate(tsaSignerCert, tsaIssuerCert);
    std::string base64_ocsp_request = buildOCSPRequestFromCertificates(tsaSignerCert, tsaIssuerCert);

    return { ocspUrl, base64_ocsp_request };
}

std::pair<std::string, std::string> PoDoFo::PdfRemoteSignDocumentSession::getOCSPRequestFromCertificatesWithFallback(const std::string& base64Tsr,
    std::function<std::string(const std::string&)> httpFetcher) {

    std::string tsaSignerCert = extractSignerCertFromTSR(base64Tsr);
    std::string tsaIssuerCert = extractIssuerCertFromTSRWithFallback(base64Tsr, httpFetcher);
    std::string ocspUrl = getOCSPFromCertificate(tsaSignerCert, tsaIssuerCert);
    std::string base64_ocsp_request = buildOCSPRequestFromCertificates(tsaSignerCert, tsaIssuerCert);

    return { ocspUrl, base64_ocsp_request };
}

PoDoFo::PdfDocTimeStampSigner::PdfDocTimeStampSigner() : m_useManualByteRange(false) {}

void PoDoFo::PdfDocTimeStampSigner::SetDevice(std::shared_ptr<PoDoFo::StreamDevice> device) {
    m_device = device;
    m_useManualByteRange = true;
}

void PoDoFo::PdfDocTimeStampSigner::Reset() {
    m_hashBuffer.clear();
}

void PoDoFo::PdfDocTimeStampSigner::AppendData(const PoDoFo::bufferview& data) {
    size_t oldSize = m_hashBuffer.size();
    m_hashBuffer.append(data.data(), data.size());

    static size_t lastEndPosition = 0;
    if (oldSize > 0 && oldSize != lastEndPosition) {
        size_t gap = oldSize - lastEndPosition;
    }
    lastEndPosition = oldSize + data.size();
}

void PoDoFo::PdfDocTimeStampSigner::ComputeSignature(PoDoFo::charbuff& contents, bool dryrun) {
    if (dryrun) {
        contents.resize(6000); //TODO
    }
    else {}
}

void PoDoFo::PdfDocTimeStampSigner::FetchIntermediateResult(PoDoFo::charbuff& result) {
    if (m_useManualByteRange && m_device) {
        result = calculateCorrectHash();
    }
    else {
        PoDoFo::PdfHashingAlgorithm hashAlg = PoDoFo::PdfHashingAlgorithm::SHA256;
        PoDoFo::bufferview dataView(m_hashBuffer.data(), m_hashBuffer.size());
        result = ssl::ComputeHash(dataView, hashAlg);
    }
}

PoDoFo::charbuff PoDoFo::PdfDocTimeStampSigner::calculateCorrectHash() {

    m_device->Seek(0, PoDoFo::SeekDirection::End);
    size_t fileSize = m_device->GetPosition();

    m_device->Seek(0, PoDoFo::SeekDirection::Begin);

    PoDoFo::charbuff fileContent;
    fileContent.resize(fileSize);
    m_device->Read(fileContent.data(), fileSize);

    std::string fileStr(fileContent.data(), fileContent.size());

    size_t byteRangePos = fileStr.find("/ByteRange[");
    if (byteRangePos == std::string::npos) {
        PoDoFo::PdfHashingAlgorithm hashAlg = PoDoFo::PdfHashingAlgorithm::SHA256;
        PoDoFo::bufferview dataView(m_hashBuffer.data(), m_hashBuffer.size());
        return ssl::ComputeHash(dataView, hashAlg);
    }

    size_t start = fileStr.find('[', byteRangePos) + 1;
    size_t end = fileStr.find(']', start);
    std::string byteRangeStr = fileStr.substr(start, end - start);

    std::istringstream iss(byteRangeStr);
    int64_t range1Start, range1Length, range2Start, range2Length;
    iss >> range1Start >> range1Length >> range2Start >> range2Length;


    PoDoFo::charbuff correctData;
    correctData.reserve(range1Length + range2Length);

    if (range1Length > 0) {
        correctData.resize(range1Length);
        std::memcpy(correctData.data(), fileContent.data() + range1Start, range1Length);
    }

    if (range2Length > 0) {
        size_t currentSize = correctData.size();
        correctData.resize(currentSize + range2Length);
        std::memcpy(correctData.data() + currentSize, fileContent.data() + range2Start, range2Length);
    }

    PoDoFo::PdfHashingAlgorithm hashAlg = PoDoFo::PdfHashingAlgorithm::SHA256;
    PoDoFo::bufferview correctDataView(correctData.data(), correctData.size());
    return ssl::ComputeHash(correctDataView, hashAlg);
}

void PoDoFo::PdfDocTimeStampSigner::ComputeSignatureDeferred(const PoDoFo::bufferview& processedResult, PoDoFo::charbuff& contents, bool dryrun) {
    if (dryrun) {
        contents.resize(20000);
    }
    else {
        contents.assign(processedResult.data(), processedResult.size());
    }
}

std::string PoDoFo::PdfDocTimeStampSigner::GetSignatureFilter() const {
    return "Adobe.PPKLite";
}

std::string PoDoFo::PdfDocTimeStampSigner::GetSignatureSubFilter() const {
    return "ETSI.RFC3161";
}

std::string PoDoFo::PdfDocTimeStampSigner::GetSignatureType() const {
    return "DocTimeStamp";
}

bool PoDoFo::PdfDocTimeStampSigner::SkipBufferClear() const {
    return false;
}
