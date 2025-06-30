#include "podofo_jni.h"
#include <android/log.h>

// PoDoFoWrapper implementation
std::unique_ptr<PoDoFoWrapper> PoDoFoWrapper::initialize(const std::string& conformanceLevel,
                                     const std::string& hashAlgorithm,
                                     const std::string& inputPath,
                                     const std::string& outputPath,
                                     const std::string& certificate,
                                     const std::vector<std::string>& chainCertificates) {
    try {
        __android_log_print(ANDROID_LOG_INFO, "PoDoFo", "Creating PoDoFoWrapper instance");
        auto wrapper = std::make_unique<PoDoFoWrapper>();
        
        __android_log_print(ANDROID_LOG_INFO, "PoDoFo", "Creating PdfRemoteSignDocumentSession with parameters:");
        __android_log_print(ANDROID_LOG_INFO, "PoDoFo", "  Conformance Level: %s", conformanceLevel.c_str());
        __android_log_print(ANDROID_LOG_INFO, "PoDoFo", "  Hash Algorithm: %s", hashAlgorithm.c_str());
        __android_log_print(ANDROID_LOG_INFO, "PoDoFo", "  Input Path: %s", inputPath.c_str());
        __android_log_print(ANDROID_LOG_INFO, "PoDoFo", "  Output Path: %s", outputPath.c_str());
        __android_log_print(ANDROID_LOG_INFO, "PoDoFo", "  Certificate length: %zu", certificate.length());
        __android_log_print(ANDROID_LOG_INFO, "PoDoFo", "  Chain Certificates count: %zu", chainCertificates.size());
        
        wrapper->nativeSession = std::make_unique<PoDoFo::PdfRemoteSignDocumentSession>(
            conformanceLevel,
            hashAlgorithm,
            inputPath,
            outputPath,
            certificate,
            chainCertificates,
            std::nullopt
        );
        
        __android_log_print(ANDROID_LOG_INFO, "PoDoFo", "PdfRemoteSignDocumentSession created successfully");
        return wrapper;
    } catch (const std::exception& e) {
        __android_log_print(ANDROID_LOG_ERROR, "PoDoFo", "Exception during initialization: %s", e.what());
        return nullptr;
    } catch (...) {
        __android_log_print(ANDROID_LOG_ERROR, "PoDoFo", "Unknown exception during initialization");
        return nullptr;
    }
}

bool PoDoFoWrapper::isLoaded() const {
    return nativeSession != nullptr;
}

void PoDoFoWrapper::printState() const {
    if (nativeSession) {
        try {
            nativeSession->printState();
        } catch (const std::exception& e) {
            // Handle exception silently
        }
    }
}

std::string PoDoFoWrapper::calculateHash() {
    if (!nativeSession) {
        return "";
    }

    try {
        return nativeSession->beginSigning();
    } catch (const std::exception& e) {
        return "";
    }
}

void PoDoFoWrapper::finalizeSigningWithSignedHash(const std::string& signedHash, const std::string& tsr) {
    if (!nativeSession || signedHash.empty()) {
        return;
    }

    try {
        nativeSession->finishSigning(signedHash, tsr);
    } catch (const std::exception& e) {
        // Handle exception silently
    }
}

// Helper functions
std::string jstringToString(JNIEnv* env, jstring jStr) {
    if (!jStr) {
        return "";
    }

    const char* cStr = env->GetStringUTFChars(jStr, nullptr);
    if (!cStr) {
        return "";
    }

    std::string str(cStr);
    env->ReleaseStringUTFChars(jStr, cStr);
    return str;
}

std::vector<std::string> jstringArrayToVector(JNIEnv* env, jobjectArray jArray) {
    std::vector<std::string> result;

    if (!jArray) {
        return result;
    }

    jsize length = env->GetArrayLength(jArray);
    result.reserve(length);

    for (jsize i = 0; i < length; i++) {
        jstring jStr = (jstring)env->GetObjectArrayElement(jArray, i);
        if (jStr) {
            result.push_back(jstringToString(env, jStr));
            env->DeleteLocalRef(jStr);
        }
    }

    return result;
}

jstring stringToJstring(JNIEnv* env, const std::string& str) {
    return env->NewStringUTF(str.c_str());
}

// JNI functions implementation
extern "C" {
    JNIEXPORT jlong JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeInit(
        JNIEnv* env, jobject thiz, jstring jConformanceLevel, jstring jHashAlgorithm,
        jstring jInputPath, jstring jOutputPath, jstring jCertificate,
        jobjectArray jChainCertificates) {

        // Convert Java strings to C++ strings
        std::string conformanceLevel = jstringToString(env, jConformanceLevel);
        std::string hashAlgorithm = jstringToString(env, jHashAlgorithm);
        std::string inputPath = jstringToString(env, jInputPath);
        std::string outputPath = jstringToString(env, jOutputPath);
        std::string certificate = jstringToString(env, jCertificate);
        std::vector<std::string> chainCertificates = jstringArrayToVector(env, jChainCertificates);

        // Create the wrapper using the static factory method
        auto wrapper_unique = PoDoFoWrapper::initialize(
            conformanceLevel, hashAlgorithm, inputPath, outputPath,
            certificate, chainCertificates);

        if (!wrapper_unique) {
            return 0;
        }

        // Transfer ownership from unique_ptr to raw pointer for JNI
        PoDoFoWrapper* wrapper = wrapper_unique.release();
        return reinterpret_cast<jlong>(wrapper);
    }

    JNIEXPORT void JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeCleanup(
        JNIEnv* env, jobject thiz, jlong nativeHandle) {

        if (nativeHandle) {
            auto* wrapper = reinterpret_cast<PoDoFoWrapper*>(nativeHandle);
            delete wrapper;
        }
    }

    JNIEXPORT jboolean JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeIsLoaded(
        JNIEnv* env, jobject thiz, jlong nativeHandle) {

        if (!nativeHandle) {
            return JNI_FALSE;
        }

        auto* wrapper = reinterpret_cast<PoDoFoWrapper*>(nativeHandle);
        return wrapper->isLoaded() ? JNI_TRUE : JNI_FALSE;
    }

    JNIEXPORT void JNICALL Java_com_podofo_android_PoDoFoWrapper_nativePrintState(
        JNIEnv* env, jobject thiz, jlong nativeHandle) {

        if (!nativeHandle) {
            return;
        }

        auto* wrapper = reinterpret_cast<PoDoFoWrapper*>(nativeHandle);
        wrapper->printState();
    }

    JNIEXPORT jstring JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeCalculateHash(
        JNIEnv* env, jobject thiz, jlong nativeHandle) {

        if (!nativeHandle) {
            return nullptr;
        }

        auto* wrapper = reinterpret_cast<PoDoFoWrapper*>(nativeHandle);
        std::string hash = wrapper->calculateHash();

        return hash.empty() ? nullptr : stringToJstring(env, hash);
    }

    JNIEXPORT void JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeFinalizeSigningWithSignedHash(
        JNIEnv* env, jobject thiz, jlong nativeHandle, jstring jSignedHash, jstring jTsr) {

        if (!nativeHandle || !jSignedHash) {
            return;
        }

        auto* wrapper = reinterpret_cast<PoDoFoWrapper*>(nativeHandle);
        std::string signedHash = jstringToString(env, jSignedHash);
        std::string tsr = jstringToString(env, jTsr);
        wrapper->finalizeSigningWithSignedHash(signedHash, tsr);
    }
}