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
 */
- (void)finalizeSigningWithSignedHash:(NSString *)signedHash tsr:(NSString *)tsr;

@end

NS_ASSUME_NONNULL_END

#endif /* PodofoWrapper_h */
