#ifndef CONFIG_H
#define CONFIG_H

#include <string>

/**
 * @brief Global configuration class for PoDoFo-Tester-App
 *
 * This class centralizes all configuration values including URLs, endpoints,
 * and other constants used throughout the application.
 */
class Config {
public:
    // OAuth2 endpoints
    static const std::string& getOAuthAuthorizeUrl();
    static const std::string& getOAuthTokenUrl();
    static const std::string& getRedirectUri();

    // CSC endpoints
    static const std::string& getCredentialsListUrl();
    static const std::string& getSignHashUrl();

    // Login endpoint
    static const std::string& getLoginUrl();

    // OAuth2 configuration
    static const std::string& getClientId();
    static const std::string& getClientSecret();
    static const std::string& getCodeChallenge();
    static const std::string& getCodeChallengeMethod();
    static const std::string& getCodeVerifier();
    static const std::string& getState();
    static const std::string& getNonce();
    static const std::string& getScope();
    static const std::string& getLang();

    // Login credentials
    static const std::string& getUsername();
    static const std::string& getPassword();

    // TSA URLs (for timestamping)
    static const std::string& getTsaUrlQualified();
    static const std::string& getTsaUrlUnqualified();
    static const std::string& getTsaUrlFree();
    static const std::string& getTsaUrlWotrus();
    static const std::string& getTsaUrlCartaodecidadao();
    static const std::string& getTsaUrlGlobalsignAatl();
    static const std::string& getTsaUrlIdentrust();
    static const std::string& getTsaUrlQuovadis();
    static const std::string& getTsaUrlDigicert();
    static const std::string& getTsaUrlSwisssign();
    static const std::string& getTsaUrlEntrust();
    static const std::string& getTsaUrlCertum();
    static const std::string& getTsaUrlSsl();
    static const std::string& getTsaUrlGlobalsignR6();
    static const std::string& getTsaUrlCertumTime();
    static const std::string& getTsaUrlFreeHttp();

    // Logging configuration
    static bool isDebugMode();
    static void setDebugMode(bool debug);

private:
    // OAuth2 endpoints
    static const std::string OAUTH_AUTHORIZE_URL;
    static const std::string OAUTH_TOKEN_URL;
    static const std::string REDIRECT_URI;

    // CSC endpoints
    static const std::string CREDENTIALS_LIST_URL;
    static const std::string SIGN_HASH_URL;

    // Login endpoint
    static const std::string LOGIN_URL;

    // OAuth2 configuration
    static const std::string CLIENT_ID;
    static const std::string CLIENT_SECRET;
    static const std::string CODE_CHALLENGE;
    static const std::string CODE_CHALLENGE_METHOD;
    static const std::string CODE_VERIFIER;
    static const std::string STATE;
    static const std::string NONCE;
    static const std::string SCOPE;
    static const std::string LANG;

    // Login credentials
    static const std::string USERNAME;
    static const std::string PASSWORD;

    // TSA URLs
    static const std::string TSA_URL_QUALIFIED;
    static const std::string TSA_URL_UNQUALIFIED;
    static const std::string TSA_URL_FREE;
    static const std::string TSA_URL_WOTRUS;
    static const std::string TSA_URL_CARTAODECIDADAO;
    static const std::string TSA_URL_GLOBALSIGN_AATL;
    static const std::string TSA_URL_IDENTRUST;
    static const std::string TSA_URL_QUOVADIS;
    static const std::string TSA_URL_DIGICERT;
    static const std::string TSA_URL_SWISSSIGN;
    static const std::string TSA_URL_ENTRUST;
    static const std::string TSA_URL_CERTUM;
    static const std::string TSA_URL_SSL;
    static const std::string TSA_URL_GLOBALSIGN_R6;
    static const std::string TSA_URL_CERTUM_TIME;
    static const std::string TSA_URL_FREE_HTTP;

    // Logging configuration
    static bool DEBUG_MODE;
};

#endif // CONFIG_H
