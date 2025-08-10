find_package(CURL REQUIRED)

add_compile_options(${PODOFO_CFLAGS})

# Core files
set(CORE_SOURCES
    "core/PoDoFo-App.cpp"
    "core/Config.cpp"
    "core/Config.h"
    "core/Logger.cpp"
    "core/Logger.h"
)

# Models
set(MODEL_SOURCES
    "models/AuthorizationDetails.cpp"
    "models/AuthorizationDetails.h"
    "models/CertificateBundle.h"
    "models/SignatureSession.h"
)

# Authentication services
set(AUTH_SOURCES
    "services/auth/AuthCredService.cpp"
    "services/auth/AuthCredService.h"
    "services/auth/AuthService.cpp"
    "services/auth/AuthService.h"
    "services/auth/LoginService.cpp"
    "services/auth/LoginService.h"
    "services/auth/TokenCredService.cpp"
    "services/auth/TokenCredService.h"
    "services/auth/TokenService.cpp"
    "services/auth/TokenService.h"
)

# Signing services
set(SIGNING_SOURCES
    "services/signing/SignHashService.cpp"
    "services/signing/SignHashService.h"
    "services/signing/SigningService.cpp"
    "services/signing/SigningService.h"
)

# Timestamping services
set(TIMESTAMPING_SOURCES
    "services/timestamping/TimestampHashService.cpp"
    "services/timestamping/TimestampHashService.h"
    "services/timestamping/TimestampingService.cpp"
    "services/timestamping/TimestampingService.h"
    "services/timestamping/TimestampRequestService.cpp"
    "services/timestamping/TimestampRequestService.h"
    "services/timestamping/TimestampService.cpp"
    "services/timestamping/TimestampService.h"
    "services/timestamping/TsrBase64Service.cpp"
    "services/timestamping/TsrBase64Service.h"
    "services/timestamping/TsrFromSignedHashService.cpp"
    "services/timestamping/TsrFromSignedHashService.h"
    "services/timestamping/TsrProcessingService.cpp"
    "services/timestamping/TsrProcessingService.h"
    "services/timestamping/TsrRequestAndBase64Service.cpp"
    "services/timestamping/TsrRequestAndBase64Service.h"
)

# Certificate services
set(CERTIFICATE_SOURCES
    "services/certificates/ExtractIssuerCertFromTSR.cpp"
    "services/certificates/ExtractIssuerCertFromTSR.h"
    "services/certificates/ExtractSignerCertFromTSR.cpp"
    "services/certificates/ExtractSignerCertFromTSR.h"
    "services/certificates/GetOCSPFromCertificate.cpp"
    "services/certificates/GetOCSPFromCertificate.h"
    "services/certificates/GetCrlFromCertificate.cpp"
    "services/certificates/GetCrlFromCertificate.h"
    "services/certificates/GetTsrBase64.cpp"
    "services/certificates/GetTsrBase64.h"
    "services/certificates/OCSPHttpService.cpp"
    "services/certificates/OCSPHttpService.h"
    "services/certificates/GetCredentials.cpp"
    "services/certificates/GetCredentials.h"
    "services/certificates/ListCredentialsService.cpp"
    "services/certificates/ListCredentialsService.h"
    "services/certificates/SaveBase64PEMAsDER.cpp"
    "services/certificates/SaveBase64PEMAsDER.h"
    "services/certificates/CertificateHttpService.cpp"
    "services/certificates/CertificateHttpService.h"
)

# Utils
set(UTILS_SOURCES
    "utils/Utils.cpp"
    "utils/Utils.h"
)

# Combine all sources
set(ALL_SOURCES
    ${CORE_SOURCES}
    ${MODEL_SOURCES}
    ${AUTH_SOURCES}
    ${SIGNING_SOURCES}
    ${TIMESTAMPING_SOURCES}
    ${CERTIFICATE_SOURCES}
    ${UTILS_SOURCES}
)

add_executable(PoDoFo-App ${ALL_SOURCES})
target_include_directories(PoDoFo-App PRIVATE ${OPENSSL_INCLUDE_DIR} ${CURL_INCLUDE_DIRS})
target_link_libraries(PoDoFo-App ${PODOFO_LIBRARIES} podofo_private podofo_3rdparty ${OPENSSL_LIBRARIES} ${CURL_LIBRARIES})
