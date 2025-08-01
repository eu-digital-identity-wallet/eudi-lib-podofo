#ifndef PODOFO_JNI_H
#define PODOFO_JNI_H

#include <jni.h>
#include <podofo/podofo.h>
#include <string>
#include <vector>
#include <memory>

// Class to manage the PoDoFo session
class PoDoFoWrapper {
private:
    std::unique_ptr<PoDoFo::PdfRemoteSignDocumentSession> nativeSession;

public:
    // Constructor - made public so std::make_unique can access it
    PoDoFoWrapper() = default;
    ~PoDoFoWrapper() = default;

    // Static factory method
    static std::unique_ptr<PoDoFoWrapper> initialize(const std::string& conformanceLevel,
                   const std::string& hashAlgorithm,
                   const std::string& inputPath,
                   const std::string& outputPath,
                   const std::string& certificate,
                   const std::vector<std::string>& chainCertificates);

    bool isLoaded() const;
    void printState() const;
    std::string calculateHash();
    void finalizeSigningWithSignedHash(const std::string& signedHash, const std::string& tsr, const std::optional<PoDoFo::ValidationData>& validationData);
    std::string beginSigningLTA();
    void finishSigningLTA(const std::string& tsr);
    std::string getCrlFromCertificate(const std::string& base64Cert);
};

// Helper methods for JNI
std::string jstringToString(JNIEnv* env, jstring jStr);
std::vector<std::string> jstringArrayToVector(JNIEnv* env, jobjectArray jArray);
jstring stringToJstring(JNIEnv* env, const std::string& str);

// JNI function declarations
extern "C" {
    JNIEXPORT jlong JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeInit(
        JNIEnv* env, jobject thiz, jstring jConformanceLevel, jstring jHashAlgorithm,
        jstring jInputPath, jstring jOutputPath, jstring jCertificate,
        jobjectArray jChainCertificates);

    JNIEXPORT void JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeCleanup(
        JNIEnv* env, jobject thiz, jlong nativeHandle);

    JNIEXPORT jboolean JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeIsLoaded(
        JNIEnv* env, jobject thiz, jlong nativeHandle);

    JNIEXPORT void JNICALL Java_com_podofo_android_PoDoFoWrapper_nativePrintState(
        JNIEnv* env, jobject thiz, jlong nativeHandle);

    JNIEXPORT jstring JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeCalculateHash(
        JNIEnv* env, jobject thiz, jlong nativeHandle);

    JNIEXPORT void JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeFinalizeSigningWithSignedHash(
        JNIEnv* env, jobject thiz, jlong nativeHandle, jstring jSignedHash, jstring jTsr,
        jobject jCertificates, jobject jCrls, jobject jOcsps);

    JNIEXPORT jstring JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeBeginSigningLTA(
        JNIEnv* env, jobject thiz, jlong nativeHandle);

    JNIEXPORT void JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeFinishSigningLTA(
        JNIEnv* env, jobject thiz, jlong nativeHandle, jstring jTsr);

    JNIEXPORT jstring JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeGetCrlFromCertificate(
        JNIEnv* env, jobject thiz, jlong nativeHandle, jstring jBase64Cert);
}

#endif // PODOFO_JNI_H
