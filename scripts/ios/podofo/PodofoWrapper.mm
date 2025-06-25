//
//  PodofoWrapper.mm
//  PodofoWrapper
//
//  Created by Panagiotis Kokkinakis on 29/1/25.
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

#import "PodofoWrapper.h"
#include <podofo/podofo.h>

NSString *const PodofoSignerErrorDomain = @"org.podofo.PodofoSigner";

@implementation PodofoWrapper {
     PoDoFo::PdfRemoteSignDocumentSession* _nativeSession;
}

#pragma mark - Initialization & Deallocation

- (instancetype)init {
    @throw [NSException exceptionWithName:NSInvalidArgumentException
                                   reason:@"Use initWithConformanceLevel:hashAlgorithm:inputPath:outputPath:certificate:chainCertificates: instead"
                                 userInfo:nil];
    return nil;
}

- (instancetype)initWithConformanceLevel:(NSString *)conformanceLevel
                                hashAlgorithm:(NSString *)hashAlgorithm
                                inputPath:(NSString *)inputPath
                                outputPath:(NSString *)outputPath
                                certificate:(NSString *)certificate
                                chainCertificates:(NSArray<NSString *> *)chainCertificates {

    self = [super init];
    if (self) {
        NSLog(@"PoDoFo: Initializing session");

        // Convert chain certificates to CPP vector
        std::vector<std::string> cppChainCerts;
        for (NSString *cert in chainCertificates) {
            cppChainCerts.push_back([cert UTF8String]);
        }

        // Create native session
        _nativeSession = new PoDoFo::PdfRemoteSignDocumentSession(
            [conformanceLevel UTF8String],
            [hashAlgorithm UTF8String],
            [inputPath UTF8String],
            [outputPath UTF8String],
            [certificate UTF8String],
            cppChainCerts,
            std::nullopt
        );
        NSLog(@"PoDoFo: Session successfully initialized");
    }
    return self;
}

- (void)dealloc {
    [self cleanupNativeResources];
}

- (void)cleanupNativeResources {
    if (_nativeSession != NULL) {
        delete _nativeSession;
        _nativeSession = NULL;
    }
}

#pragma mark - Public Methods

- (BOOL)isLoaded {
    if (_nativeSession != NULL) {
        NSLog(@"PoDoFo: Library successfully loaded");
        return YES;
    }

    NSLog(@"PoDoFo: Library not loaded or session not initialized");
    return NO;
}

- (void)printState {
    if (_nativeSession == NULL) {
        NSLog(@"PoDoFo: Session not initialized");
    }

    _nativeSession->printState();
}

- (nullable NSString *)calculateHash {
    if (_nativeSession == NULL) {
        NSLog(@"PoDoFo: Session not initialized");
    }

    std::string hashStr = _nativeSession->beginSigning();
    NSString *hash = [NSString stringWithUTF8String:hashStr.c_str()];
    NSLog(@"PoDoFo: Hash calculated successfully");

    return hash;
}

- (void)finalizeSigningWithSignedHash:(NSString *)signedHash tsr:(NSString *)tsr {
    if (_nativeSession == NULL) {
        NSLog(@"PoDoFo: Session not initialized");
    }

    if (signedHash == nil) {
        NSLog(@"PoDoFo: Cannot finalize with nil signed hash");
    }

    _nativeSession->finishSigning([signedHash UTF8String], [tsr UTF8String]);
    NSLog(@"PoDoFo: Document signing finalized successfully");
}

@end
