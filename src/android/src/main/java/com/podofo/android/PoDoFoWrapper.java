package com.podofo.android;

import android.util.Log;

import java.util.List;

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
     * @throws PoDoFoException if native initialization fails
     */
    public PoDoFoWrapper(String conformanceLevel, String hashAlgorithm,
                         String inputPath, String outputPath, String certificate,
                         String[] chainCertificates) throws PoDoFoException {
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
            throw new PoDoFoException("Failed to initialize native PoDoFo wrapper");
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
     * @throws PoDoFoException if there is an error during hash calculation
     */
    public String calculateHash() throws PoDoFoException {
        if (nativeHandle == 0) {
            throw new PoDoFoException("Session not initialized");
        }
        return nativeCalculateHash(nativeHandle);
    }

    /**
     * Finalize the signing process with the provided signed hash
     *
     * @param signedHash The signed hash to use for finalizing
     * @param tsr The timestamp service response
     * @param certificates An array of base64-encoded certificates for the DSS dictionary
     * @param crls An array of base64-encoded CRLs for the DSS dictionary
     * @param ocsps An array of base64-encoded OCSP responses for the DSS dictionary
     * @throws PoDoFoException if there is an error during finalization
     */
    public void finalizeSigningWithSignedHash(String signedHash, String tsr,
                                              List<String> certificates, List<String> crls, List<String> ocsps) throws PoDoFoException {
        if (nativeHandle == 0) {
            throw new PoDoFoException("Session not initialized");
        }
        if (signedHash == null) {
            throw new PoDoFoException("Cannot finalize with nil signed hash");
        }
        nativeFinalizeSigningWithSignedHash(nativeHandle, signedHash, tsr, certificates, crls, ocsps);
    }

    /**
     * Begins the LTA (Long-Term Archive) signature process.
     * This should be called after a B-LT signature has been created.
     *
     * @return The hash to be sent to the Timestamping Authority.
     * @throws PoDoFoException if there is an error during the process.
     */
    public String beginSigningLTA() throws PoDoFoException {
        if (nativeHandle == 0) {
            throw new PoDoFoException("Session not initialized");
        }
        return nativeBeginSigningLTA(nativeHandle);
    }

    /**
     * Finalizes the LTA signature process with a timestamp response.
     *
     * @param tsr The timestamp service response (base64 encoded).
     * @param certificates An array of base64-encoded certificates for the DSS dictionary.
     * @param crls An array of base64-encoded CRLs for the DSS dictionary.
     * @param ocsps An array of base64-encoded OCSP responses for the DSS dictionary.
     * @throws PoDoFoException if there is an error during the process.
     */
    public void finishSigningLTA(String tsr, List<String> certificates, List<String> crls, List<String> ocsps) throws PoDoFoException {
        if (nativeHandle == 0) {
            throw new PoDoFoException("Session not initialized");
        }
        nativeFinishSigningLTA(nativeHandle, tsr, certificates, crls, ocsps);
    }

    /**
     * Extracts the CRL distribution point URL from a base64 encoded certificate.
     *
     * @param base64Cert The base64 encoded certificate.
     * @return The CRL URL as a string.
     * @throws PoDoFoException if there is an error during the process.
     */
    public String getCrlFromCertificate(String base64Cert) throws PoDoFoException {
        if (nativeHandle == 0) {
            throw new PoDoFoException("Session not initialized");
        }
        return nativeGetCrlFromCertificate(nativeHandle, base64Cert);
    }

    /**
     * Extracts the TSA signer certificate from a base64-encoded TSR.
     *
     * @param base64Tsr The base64-encoded TSR (timestamp response).
     * @return The base64 DER encoding of the signer certificate.
     * @throws PoDoFoException if there is an error during the process.
     */
    public String extractSignerCertFromTSR(String base64Tsr) throws PoDoFoException {
        if (nativeHandle == 0) {
            throw new PoDoFoException("Session not initialized");
        }
        return nativeExtractSignerCertFromTSR(nativeHandle, base64Tsr);
    }

    /**
     * Extracts the TSA issuer certificate from a base64-encoded TSR.
     *
     * @param base64Tsr The base64-encoded TSR (timestamp response).
     * @return The base64 DER encoding of the issuer certificate.
     * @throws PoDoFoException if there is an error during the process.
     */
    public String extractIssuerCertFromTSR(String base64Tsr) throws PoDoFoException {
        if (nativeHandle == 0) {
            throw new PoDoFoException("Session not initialized");
        }
        return nativeExtractIssuerCertFromTSR(nativeHandle, base64Tsr);
    }

    /**
     * Extracts the OCSP responder URL from a certificate's AIA extension.
     *
     * @param base64Cert The certificate encoded in base64.
     * @param base64IssuerCert The issuer certificate encoded in base64.
     * @return The OCSP responder URL as a string.
     * @throws PoDoFoException if there is an error during the process.
     */
    public String getOCSPFromCertificate(String base64Cert, String base64IssuerCert) throws PoDoFoException {
        if (nativeHandle == 0) {
            throw new PoDoFoException("Session not initialized");
        }
        return nativeGetOCSPFromCertificate(nativeHandle, base64Cert, base64IssuerCert);
    }

    /**
     * Gets an OCSP request from base64-encoded certificates and returns it as base64.
     *
     * @param base64Cert The certificate encoded in base64.
     * @param base64IssuerCert The issuer certificate encoded in base64.
     * @return The base64-encoded OCSP request.
     * @throws PoDoFoException if there is an error during the process.
     */
    public String buildOCSPRequestFromCertificates(String base64Cert, String base64IssuerCert) throws PoDoFoException {
        if (nativeHandle == 0) {
            throw new PoDoFoException("Session not initialized");
        }
        return nativeBuildOCSPRequestFromCertificates(nativeHandle, base64Cert, base64IssuerCert);
    }

    /**
     * Extracts the CA Issuers URL from a certificate's AIA extension.
     *
     * @param base64Cert The certificate encoded in base64.
     * @return The CA Issuers URL as a string.
     * @throws PoDoFoException if there is an error during the process.
     */
    public String getCertificateIssuerUrlFromCertificate(String base64Cert) throws PoDoFoException {
        if (nativeHandle == 0) {
            throw new PoDoFoException("Session not initialized");
        }
        return nativeGetCertificateIssuerUrlFromCertificate(nativeHandle, base64Cert);
    }

    // Native methods implemented in C++
    private native long nativeInit(String conformanceLevel, String hashAlgorithm,
                                   String inputPath, String outputPath,
                                   String certificate, String[] chainCertificates);

    private native boolean nativeIsLoaded(long handle);
    private native void nativePrintState(long handle);
    private native String nativeCalculateHash(long handle);
    private native void nativeFinalizeSigningWithSignedHash(long handle, String signedHash, String tsr,
                                                            List<String> certificates, List<String> crls, List<String> ocsps);
    private native String nativeBeginSigningLTA(long handle);
    private native void nativeFinishSigningLTA(long handle, String tsr, List<String> certificates, List<String> crls, List<String> ocsps);
    private native String nativeGetCrlFromCertificate(long handle, String base64Cert);
    private native String nativeExtractSignerCertFromTSR(long handle, String base64Tsr);
    private native String nativeExtractIssuerCertFromTSR(long handle, String base64Tsr);
    private native String nativeGetOCSPFromCertificate(long handle, String base64Cert, String base64IssuerCert);
    private native String nativeBuildOCSPRequestFromCertificates(long handle, String base64Cert, String base64IssuerCert);
    private native String nativeGetCertificateIssuerUrlFromCertificate(long handle, String base64Cert);

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