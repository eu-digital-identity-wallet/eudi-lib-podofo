#include "Config.h"

// OAuth2 endpoints
const std::string Config::OAUTH_AUTHORIZE_URL = "https://walletcentric.signer.eudiw.dev/oauth2/authorize";
const std::string Config::OAUTH_TOKEN_URL = "https://walletcentric.signer.eudiw.dev/oauth2/token";
const std::string Config::REDIRECT_URI = "https://walletcentric.signer.eudiw.dev/tester/oauth/login/code";

// CSC endpoints
const std::string Config::CREDENTIALS_LIST_URL = "https://walletcentric.signer.eudiw.dev/csc/v2/credentials/list";
const std::string Config::SIGN_HASH_URL = "https://walletcentric.signer.eudiw.dev/csc/v2/signatures/signHash";

// Login endpoint
const std::string Config::LOGIN_URL = "https://walletcentric.signer.eudiw.dev/login";

// OAuth2 configuration
const std::string Config::CLIENT_ID = "wallet-client";
const std::string Config::CLIENT_SECRET = "somesecret2";
const std::string Config::CODE_CHALLENGE = "V4n5D1_bu7BPMXWsTulFVkC4ASFmeS7lHXSqIf-vUwI";
const std::string Config::CODE_CHALLENGE_METHOD = "S256";
const std::string Config::CODE_VERIFIER = "z34oHaauNSc13ScLRDmbQrJ5bIR9IDzRCWZTRRAPtlV";
const std::string Config::STATE = "erv8utb5uie";
const std::string Config::NONCE = "rl0srg2qdl";
const std::string Config::SCOPE = "service";
const std::string Config::LANG = "pt-PT";

// Login credentials
const std::string Config::USERNAME = "8PfCAQzTmON+FHDvH4GW/g+JUtg5eVTgtqMKZFdB/+c=;FirstName;TesterUser";
const std::string Config::PASSWORD = "5adUg@35Lk_Wrm3";

// TSA URLs
const std::string Config::TSA_URL_QUALIFIED = "https://timestamp.sectigo.com/qualified";
const std::string Config::TSA_URL_UNQUALIFIED = "https://timestamp.sectigo.com";
const std::string Config::TSA_URL_FREE = "https://freetsa.org/tsr";
const std::string Config::TSA_URL_WOTRUS = "https://tsa.wotrus.com";
const std::string Config::TSA_URL_CARTAODECIDADAO = "http://ts.cartaodecidadao.pt/tsa/server";
const std::string Config::TSA_URL_GLOBALSIGN_AATL = "http://aatl-timestamp.globalsign.com/tsa/aohfewat2389535fnasgnlg5m23";
const std::string Config::TSA_URL_IDENTRUST = "http://timestamp.identrust.com";
const std::string Config::TSA_URL_QUOVADIS = "http://ts.quovadisglobal.com/ch";
const std::string Config::TSA_URL_DIGICERT = "http://timestamp.digicert.com";
const std::string Config::TSA_URL_SWISSSIGN = "http://tsa.swisssign.net";
const std::string Config::TSA_URL_ENTRUST = "http://timestamp.entrust.net/TSS/RFC3161sha2TS";
const std::string Config::TSA_URL_CERTUM = "http://timestamp.certum.pl";
const std::string Config::TSA_URL_SSL = "http://ts.ssl.com";
const std::string Config::TSA_URL_GLOBALSIGN_R6 = "http://timestamp.globalsign.com/tsa/r6advanced1";
const std::string Config::TSA_URL_CERTUM_TIME = "http://time.certum.pl";
const std::string Config::TSA_URL_FREE_HTTP = "http://freetsa.org/tsr";

// Logging configuration
bool Config::DEBUG_MODE = false;

// OAuth2 endpoints getters
const std::string& Config::getOAuthAuthorizeUrl() { return OAUTH_AUTHORIZE_URL; }
const std::string& Config::getOAuthTokenUrl() { return OAUTH_TOKEN_URL; }
const std::string& Config::getRedirectUri() { return REDIRECT_URI; }

// CSC endpoints getters
const std::string& Config::getCredentialsListUrl() { return CREDENTIALS_LIST_URL; }
const std::string& Config::getSignHashUrl() { return SIGN_HASH_URL; }

// Login endpoint getters
const std::string& Config::getLoginUrl() { return LOGIN_URL; }

// OAuth2 configuration getters
const std::string& Config::getClientId() { return CLIENT_ID; }
const std::string& Config::getClientSecret() { return CLIENT_SECRET; }
const std::string& Config::getCodeChallenge() { return CODE_CHALLENGE; }
const std::string& Config::getCodeChallengeMethod() { return CODE_CHALLENGE_METHOD; }
const std::string& Config::getCodeVerifier() { return CODE_VERIFIER; }
const std::string& Config::getState() { return STATE; }
const std::string& Config::getNonce() { return NONCE; }
const std::string& Config::getScope() { return SCOPE; }
const std::string& Config::getLang() { return LANG; }

// Login credentials getters
const std::string& Config::getUsername() { return USERNAME; }
const std::string& Config::getPassword() { return PASSWORD; }

// TSA URLs getters
const std::string& Config::getTsaUrlQualified() { return TSA_URL_QUALIFIED; }
const std::string& Config::getTsaUrlUnqualified() { return TSA_URL_UNQUALIFIED; }
const std::string& Config::getTsaUrlFree() { return TSA_URL_FREE; }
const std::string& Config::getTsaUrlWotrus() { return TSA_URL_WOTRUS; }
const std::string& Config::getTsaUrlCartaodecidadao() { return TSA_URL_CARTAODECIDADAO; }
const std::string& Config::getTsaUrlGlobalsignAatl() { return TSA_URL_GLOBALSIGN_AATL; }
const std::string& Config::getTsaUrlIdentrust() { return TSA_URL_IDENTRUST; }
const std::string& Config::getTsaUrlQuovadis() { return TSA_URL_QUOVADIS; }
const std::string& Config::getTsaUrlDigicert() { return TSA_URL_DIGICERT; }
const std::string& Config::getTsaUrlSwisssign() { return TSA_URL_SWISSSIGN; }
const std::string& Config::getTsaUrlEntrust() { return TSA_URL_ENTRUST; }
const std::string& Config::getTsaUrlCertum() { return TSA_URL_CERTUM; }
const std::string& Config::getTsaUrlSsl() { return TSA_URL_SSL; }
const std::string& Config::getTsaUrlGlobalsignR6() { return TSA_URL_GLOBALSIGN_R6; }
const std::string& Config::getTsaUrlCertumTime() { return TSA_URL_CERTUM_TIME; }
const std::string& Config::getTsaUrlFreeHttp() { return TSA_URL_FREE_HTTP; }

// Logging configuration getters
bool Config::isDebugMode() { return DEBUG_MODE; }
void Config::setDebugMode(bool debug) { DEBUG_MODE = debug; }
