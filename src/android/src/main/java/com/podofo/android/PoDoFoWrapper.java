package com.podofo.android;

import android.util.Log;

/**
 * Java wrapper for the native PoDoFoWrapper library
 */
public class PoDoFoWrapper {

    private static final String TAG = "PoDoFoWrapper";

    // Error domain constant
    public static final String ERROR_DOMAIN = "org.podofo.PodofoSigner";

    // Load the native library
    static {
        try {
            System.loadLibrary("podofo");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Failed to load native library: " + e.getMessage());
            throw e;
        }
    }

    // Native handle to the C++ PoDoFoWrapper
    private long nativeHandle;

    private final String conformanceLevel;
    private final String hashAlgorithm;
    private final String inputPath;
    private final String outputPath;
    private final String certificate;
    private final String[] chainCertificates;

    /**
     * Initialize the PDF signer with required parameters
     *
     * @param conformanceLevel The PDF conformance level
     * @param hashAlgorithm The hash algorithm to use
     * @param inputPath Path to the input PDF file
     * @param outputPath Path to save the signed PDF file
     * @param certificate The signing certificate in PEM format
     * @param chainCertificates Array of chain certificates in PEM format
     * @throws IllegalArgumentException if any of the required parameters are null
     * @throws RuntimeException if native initialization fails
     */
    public PoDoFoWrapper(String conformanceLevel, String hashAlgorithm,
                         String inputPath, String outputPath, String certificate,
                         String[] chainCertificates) {
        this.conformanceLevel = conformanceLevel;
        this.hashAlgorithm = hashAlgorithm;
        this.inputPath = inputPath;
        this.outputPath = outputPath;
        this.certificate = certificate;
        this.chainCertificates = chainCertificates;

        // Initialize native wrapper
        System.out.println("PoDoFoWrapper: Initializing PoDoFo wrapper");
        System.out.println("PoDoFoWrapper: Conformance Level: " + conformanceLevel);
        System.out.println("PoDoFoWrapper: Hash Algorithm: " + hashAlgorithm);
        System.out.println("PoDoFoWrapper: Input Path: " + inputPath);
        System.out.println("PoDoFoWrapper: Output Path: " + outputPath);
        System.out.println("PoDoFoWrapper: Certificate: " + (certificate != null ? certificate : "null"));
        System.out.println("PoDoFoWrapper: Chain Certificates count: " + (chainCertificates != null ? chainCertificates.length : 0));

        System.out.println("PoDoFoWrapper: Calling nativeInit");
        nativeHandle = nativeInit(conformanceLevel, hashAlgorithm, inputPath, outputPath,
                certificate, chainCertificates);
        System.out.println("PoDoFoWrapper: nativeInit returned handle: " + nativeHandle);

        if (nativeHandle == 0) {
            Log.w(TAG, "Error during initialization: Failed to initialize native PoDoFo wrapper");
            throw new RuntimeException("Failed to initialize native PoDoFo wrapper");
        }
    }

    /**
     * Check if the native library is loaded and session is initialized
     *
     * @return true if the library is loaded and session is initialized, false otherwise
     */
    public boolean isLoaded() {
        return nativeIsLoaded(nativeHandle);
    }

    /**
     * Print the current state of the session (for debugging purposes)
     */
    public void printState() {
        if (nativeHandle != 0) {
            nativePrintState(nativeHandle);
        }
    }

    /**
     * Calculate hash for signing
     *
     * @return The hash as a string, or null if calculation failed
     */
    public String calculateHash() {
        if (nativeHandle == 0) {
            return null;
        }
        return nativeCalculateHash(nativeHandle);
    }

    /**
     * Finalize the signing process with the provided signed hash
     *
     * @param signedHash The signed hash to use for finalizing
     */
    public void finalizeSigningWithSignedHash(String signedHash, String tsr) {
        if (nativeHandle == 0 || signedHash == null) {
            return;
        }
        nativeFinalizeSigningWithSignedHash(nativeHandle, signedHash, tsr);
    }

    // Native methods implemented in C++
    private native long nativeInit(String conformanceLevel, String hashAlgorithm,
                                   String inputPath, String outputPath,
                                   String certificate, String[] chainCertificates);

    private native boolean nativeIsLoaded(long handle);
    private native void nativePrintState(long handle);
    private native String nativeCalculateHash(long handle);
    private native void nativeFinalizeSigningWithSignedHash(long handle, String signedHash, String tsr);

    /**
     * Clean up native resources
     */
    public void close() {
        if (nativeHandle != 0) {
            nativeCleanup(nativeHandle);
            nativeHandle = 0;
        }
    }

    /**
     * Make sure we clean up native resources on finalization
     */
    @Override
    protected void finalize() throws Throwable {
        try {
            close();
        } finally {
            super.finalize();
        }
    }

    private native void nativeCleanup(long handle);
}