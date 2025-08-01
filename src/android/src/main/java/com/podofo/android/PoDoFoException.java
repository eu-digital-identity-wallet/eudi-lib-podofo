package com.podofo.android;

/**
 * Custom exception for PoDoFo-related errors.
 */
public class PoDoFoException extends Exception {

    // Error domain constant
    public static final String ERROR_DOMAIN = "org.podofo.PodofoSigner";

    private final int errorCode;

    /**
     * Constructs a new exception with the specified detail message.
     * @param message the detail message.
     */
    public PoDoFoException(String message) {
        super(message);
        this.errorCode = -1; // Use a default error code
    }

    /**
     * Constructs a new exception with the specified error code and detail message.
     * @param errorCode the error code.
     * @param message the detail message.
     */
    public PoDoFoException(int errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     * @param message the detail message.
     * @param cause the cause.
     */
    public PoDoFoException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = -1; // Use a default error code
    }
    
    /**
     * Returns the error code associated with this exception.
     * @return The error code.
     */
    public int getErrorCode() {
        return errorCode;
    }

    @Override
    public String toString() {
        return "PoDoFoException{" +
                "errorCode=" + errorCode +
                ", message='" + getMessage() + '\'' +
                '}';
    }
} 