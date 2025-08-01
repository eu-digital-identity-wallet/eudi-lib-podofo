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
        throw std::runtime_error("PoDoFo session is not initialized.");
    }

    try {
        return nativeSession->beginSigning();
    } catch (const std::exception& e) {
        __android_log_print(ANDROID_LOG_ERROR, "PoDoFo", "Exception in calculateHash: %s", e.what());
        throw;
    }
}

void PoDoFoWrapper::finalizeSigningWithSignedHash(const std::string& signedHash, const std::string& tsr, const std::optional<PoDoFo::ValidationData>& validationData) {
    if (!nativeSession) {
        throw std::runtime_error("PoDoFo session is not initialized.");
    }

    if (signedHash.empty()) {
        return;
    }

    try {
        nativeSession->finishSigning(signedHash, tsr, validationData);
    } catch (const std::exception& e) {
        __android_log_print(ANDROID_LOG_ERROR, "PoDoFo", "Exception in finalizeSigningWithSignedHash: %s", e.what());
        throw;
    }
}

std::string PoDoFoWrapper::beginSigningLTA() {
    if (!nativeSession) {
        throw std::runtime_error("PoDoFo session is not initialized.");
    }

    try {
        return nativeSession->beginSigningLTA();
    } catch (const std::exception& e) {
        __android_log_print(ANDROID_LOG_ERROR, "PoDoFo", "Exception in beginSigningLTA: %s", e.what());
        throw;
    }
}

void PoDoFoWrapper::finishSigningLTA(const std::string& tsr) {
    if (!nativeSession) {
        throw std::runtime_error("PoDoFo session is not initialized.");
    }

    try {
        nativeSession->finishSigningLTA(tsr);
    } catch (const std::exception& e) {
        __android_log_print(ANDROID_LOG_ERROR, "PoDoFo", "Exception in finishSigningLTA: %s", e.what());
        throw;
    }
}

std::string PoDoFoWrapper::getCrlFromCertificate(const std::string& base64Cert) {
	if (!nativeSession) {
		throw std::runtime_error("PoDoFo session is not initialized.");
	}

	try {
		return nativeSession->getCrlFromCertificate(base64Cert);
	} catch (const std::exception& e) {
        __android_log_print(ANDROID_LOG_ERROR, "PoDoFo", "Exception in getCrlFromCertificate: %s", e.what());
		throw;
	}
}

// Helper functions
void throwJavaException(JNIEnv* env, const char* message) {
    jclass exceptionClass = env->FindClass("com/podofo/android/PoDoFoException");
    if (exceptionClass != NULL) {
        env->ThrowNew(exceptionClass, message);
    }
}

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

std::vector<std::string> jlistToVector(JNIEnv* env, jobject jList) {
    std::vector<std::string> result;
    if (!jList) {
        return result;
    }

    jclass listClass = env->GetObjectClass(jList);
    jmethodID sizeMethod = env->GetMethodID(listClass, "size", "()I");
    jmethodID getMethod = env->GetMethodID(listClass, "get", "(I)Ljava/lang/Object;");

    jint size = env->CallIntMethod(jList, sizeMethod);
    result.reserve(size);

    for (jint i = 0; i < size; i++) {
        jstring jStr = (jstring)env->CallObjectMethod(jList, getMethod, i);
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

        try {
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
                throwJavaException(env, "Failed to initialize native PoDoFo wrapper");
                return 0;
            }

            // Transfer ownership from unique_ptr to raw pointer for JNI
            PoDoFoWrapper* wrapper = wrapper_unique.release();
            return reinterpret_cast<jlong>(wrapper);
        } catch (const std::exception& e) {
            throwJavaException(env, e.what());
            return 0;
        } catch (...) {
            throwJavaException(env, "Unknown exception during initialization");
            return 0;
        }
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
            throwJavaException(env, "Session not initialized");
            return;
        }

        auto* wrapper = reinterpret_cast<PoDoFoWrapper*>(nativeHandle);
        wrapper->printState();
    }

    JNIEXPORT jstring JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeCalculateHash(
        JNIEnv* env, jobject thiz, jlong nativeHandle) {

        if (!nativeHandle) {
            throwJavaException(env, "Session not initialized");
            return nullptr;
        }

        try {
            auto* wrapper = reinterpret_cast<PoDoFoWrapper*>(nativeHandle);
            std::string hash = wrapper->calculateHash();
            return hash.empty() ? nullptr : stringToJstring(env, hash);
        } catch (const std::exception& e) {
            throwJavaException(env, e.what());
            return nullptr;
        }
    }

    JNIEXPORT void JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeFinalizeSigningWithSignedHash(
        JNIEnv* env, jobject thiz, jlong nativeHandle, jstring jSignedHash, jstring jTsr,
        jobject jCertificates, jobject jCrls, jobject jOcsps) {

        if (!nativeHandle) {
            throwJavaException(env, "Session not initialized");
            return;
        }

        if (!jSignedHash) {
            throwJavaException(env, "Signed hash is null");
            return;
        }

        try {
            auto* wrapper = reinterpret_cast<PoDoFoWrapper*>(nativeHandle);
            std::string signedHash = jstringToString(env, jSignedHash);
            std::string tsr = jstringToString(env, jTsr);

            std::optional<PoDoFo::ValidationData> validationData;
            if (jCertificates || jCrls || jOcsps) {
                PoDoFo::ValidationData cppValidationData;
                if (jCertificates) {
                    for (const auto& cert : jlistToVector(env, jCertificates)) {
                        cppValidationData.addCertificate(cert);
                    }
                }
                if (jCrls) {
                    for (const auto& crl : jlistToVector(env, jCrls)) {
                        cppValidationData.addCRL(crl);
                    }
                }
                if (jOcsps) {
                    for (const auto& ocsp : jlistToVector(env, jOcsps)) {
                        cppValidationData.addOCSP(ocsp);
                    }
                }
                validationData = cppValidationData;
            }

            wrapper->finalizeSigningWithSignedHash(signedHash, tsr, validationData);
        } catch (const std::exception& e) {
            throwJavaException(env, e.what());
        }
    }

    JNIEXPORT jstring JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeBeginSigningLTA(
        JNIEnv* env, jobject thiz, jlong nativeHandle) {

        if (!nativeHandle) {
            throwJavaException(env, "Session not initialized");
            return nullptr;
        }

        try {
            auto* wrapper = reinterpret_cast<PoDoFoWrapper*>(nativeHandle);
            std::string hash = wrapper->beginSigningLTA();
            return hash.empty() ? nullptr : stringToJstring(env, hash);
        } catch (const std::exception& e) {
            throwJavaException(env, e.what());
            return nullptr;
        }
    }

    JNIEXPORT void JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeFinishSigningLTA(
        JNIEnv* env, jobject thiz, jlong nativeHandle, jstring jTsr) {

        if (!nativeHandle) {
            throwJavaException(env, "Session not initialized");
            return;
        }

        try {
            auto* wrapper = reinterpret_cast<PoDoFoWrapper*>(nativeHandle);
            std::string tsr = jstringToString(env, jTsr);
            wrapper->finishSigningLTA(tsr);
        } catch (const std::exception& e) {
            throwJavaException(env, e.what());
        }
    }

    JNIEXPORT jstring JNICALL Java_com_podofo_android_PoDoFoWrapper_nativeGetCrlFromCertificate(
        JNIEnv* env, jobject thiz, jlong nativeHandle, jstring jBase64Cert) {

        if (!nativeHandle) {
            throwJavaException(env, "Session not initialized");
            return nullptr;
        }

        if (!jBase64Cert) {
            throwJavaException(env, "Certificate is null");
            return nullptr;
        }

        try {
            auto* wrapper = reinterpret_cast<PoDoFoWrapper*>(nativeHandle);
            std::string base64Cert = jstringToString(env, jBase64Cert);
            std::string crlUrl = wrapper->getCrlFromCertificate(base64Cert);
            return crlUrl.empty() ? nullptr : stringToJstring(env, crlUrl);
        } catch (const std::exception& e) {
            throwJavaException(env, e.what());
            return nullptr;
        }
    }
}
