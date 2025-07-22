//
//  PodofoWrapper.h
//  PodofoWrapper
//
//  Created by Panagiotis Kokkinakis on 14/3/25.
//

#ifndef PodofoWrapper_h
#define PodofoWrapper_h

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface PodofoWrapper : NSObject

/**
 * Initializes a new PodofoWrapper with the specified parameters for PDF signing.
 *
 * @param conformanceLevel The conformance level for the signature (e.g., "Ades_B_B")
 * @param hashAlgorithm The hash algorithm to use (e.g., "2.16.840.1.101.3.4.2.1")
 * @param inputPath Path to the input PDF file
 * @param outputPath Path where the signed PDF will be saved
 * @param certificate The signing certificate data
 * @param chainCertificates Array of certificate chain data
 * @return An initialized PodofoWrapper instance
 */
- (instancetype)initWithConformanceLevel:(NSString *)conformanceLevel
                                hashAlgorithm:(NSString *)hashAlgorithm
                                inputPath:(NSString *)inputPath
                                outputPath:(NSString *)outputPath
                                certificate:(NSString *)certificate
                                chainCertificates:(NSArray<NSString *> *)chainCertificates;

/**
 * Checks if the PoDoFo library is properly loaded and the session is valid.
 *
 * @return YES if library is loaded and session is valid, NO otherwise
 */
- (BOOL)isLoaded;

/**
 * Prints the current state of the signing session to the console.
 */
- (void)printState;

/**
 * Calculates the hash value for the document to be signed.
 * This is the first step in the remote signing process.
 *
 * @return The calculated hash string or nil if an error occurred
 */
- (nullable NSString *)calculateHash;

/**
 * Finalizes the signing process using the provided signed hash.
 * This is the final step that creates the signed document at the output path.
 *
 * @param signedHash The signed hash returned from a signing service
 * @param tsr The timestamp service response
 * @param certificates An array of base64-encoded certificates for the DSS dictionary
 * @param crls An array of base64-encoded CRLs for the DSS dictionary
 * @param ocsps An array of base64-encoded OCSP responses for the DSS dictionary
 */
- (void)finalizeSigningWithSignedHash:(NSString *)signedHash
                                  tsr:(NSString *)tsr
               validationCertificates:(nullable NSArray<NSString *> *)certificates
                       validationCRLs:(nullable NSArray<NSString *> *)crls
                      validationOCSPs:(nullable NSArray<NSString *> *)ocsps;

/**
 * Begins the LTA (Long-Term Archive) signature process.
 * This should be called after a B-LT signature has been created.
 *
 * @param error On input, a pointer to an error object. If an error occurs, this pointer is set to an actual error object containing the error information.
 * @return The hash to be sent to the Timestamping Authority, or nil if an error occurred.
 */
- (nullable NSString *)beginSigningLTA:(NSError **)error;

/**
 * Finalizes the LTA signature process with a timestamp response.
 *
 * @param tsr The timestamp service response (base64 encoded).
 * @param error On input, a pointer to an error object. If an error occurs, this pointer is set to an actual error object containing the error information.
 * @return YES if successful, otherwise NO.
 */
- (BOOL)finishSigningLTAWithTSR:(NSString *)tsr error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END

#endif /* PodofoWrapper_h */
