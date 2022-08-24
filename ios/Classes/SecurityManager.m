//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "SecurityManager.h"
#import "PinnedURL.h"

// Private extensions required by the implementation of SecurityManager.
@interface SecurityManager ()

// This property exists as an optimiation to provide O(1) lookup time of the
// public key for a specific host. The keys are the host element of the URL and
// the values are instances of PublicKey.
@property (nonatomic, strong, readonly) NSDictionary *dnsNameToPublicKeyMap;

// Try the same for client-certificates
@property (nonatomic, strong, readonly) NSDictionary<NSString *, ClientCertificate *> *dnsNameToClientCertificateMap;

@property (nonatomic, strong) TiProxy *proxy;

@end

@implementation SecurityManager

+ (instancetype)securityManagerWithPinnedUrlSet:(NSSet *)pinnedUrlSet andProxy:(TiProxy *)proxy
{
  DebugLog(@"%s", __PRETTY_FUNCTION__);
  return [[SecurityManager alloc] initWithPinnedURLs:pinnedUrlSet andProxy:proxy];
}

// Designated initializer.
- (instancetype)initWithPinnedURLs:(NSSet *)pinnedUrlSet andProxy:(TiProxy *)proxy
{
  DebugLog(@"%s pinnedUrlSet = %@", __PRETTY_FUNCTION__, pinnedUrlSet);

  self = [super init];
  self.proxy = proxy;

  _pinnedUrlSet = pinnedUrlSet;
  
  return self;
}

- (BOOL)isEqualToSecurityManager:(SecurityManager *)rhs
{
  if (!rhs) {
    return NO;
  }

  BOOL equal = [self.pinnedUrlSet isEqualToSet:rhs.pinnedUrlSet];
  return equal;
}

#pragma mark SecurityManagerProtocol methods

// Return NO unless this security manager was specifically configured to
// handle this URL.
- (BOOL)willHandleURL:(NSURL *)url
{
  DebugLog(@"%s url = %@", __PRETTY_FUNCTION__, url);
  if (url == nil) {
    return NO;
  }

  return YES;
}

// If this security manager was configured to handle this url then return self.
- (id<APSConnectionDelegate>)connectionDelegateForUrl:(NSURL *)url
{
  DebugLog(@"%s url = %@", __PRETTY_FUNCTION__, url);
  return self;
}

#pragma mark APSConnectionDelegate methods

// Return FALSE unless the NSURLAuthenticationChallenge is for TLS trust
// validation (aka NSURLAuthenticationMethodServerTrust) and this security
// manager was configured to handle the current url.
- (BOOL)willHandleChallenge:(NSURLAuthenticationChallenge *)challenge forSession:(NSURLSession *)session
{
  return YES;
}

- (BOOL)willHandleChallenge:(NSURLAuthenticationChallenge *)challenge forConnection:(NSURLConnection *)connection
{
  return YES;
}

#pragma mark NSURLConnectionDelegate methods

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *_Nullable))completionHandler
{
  DebugLog(@"%s session = %@, challenge = %@", __PRETTY_FUNCTION__, session, challenge);
  // Normalize the server's host name to lower case.
  NSString *host = [task.currentRequest.URL.host lowercaseString];
  DebugLog(@"%s Normalized host name = %@", __PRETTY_FUNCTION__, host);
  
  // Get the PinnedURL for this server.
  NSString *authenticationMethod = [[challenge protectionSpace] authenticationMethod];
  
  // Handle Two-phase mutual client-authentification
  if ([authenticationMethod isEqualToString:NSURLAuthenticationMethodClientCertificate]) {
    NSLog(@"[ERROR] Error in NSURLAuthenticationMethodClientCertificate");
    return;
  }
  
  if (![authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
    NSLog(@"[ERROR] Not NSURLAuthenticationMethodServerTrust");

    [challenge.sender cancelAuthenticationChallenge:challenge];
    completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
    return;
  }
  
  // It is a logic error (i.e. a bug in Titanium) if this method is
  // called with a URL the security manager was not configured to
  // handle.
  if (![self willHandleURL:task.currentRequest.URL]) {
    NSLog(@"[ERROR] Cannot handle");

    return;
  }
  
  SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
  if (serverTrust == nil) {
    NSLog(@"[ERROR] No server trust");

    return;
  }
  
  // SecTrustEvaluate performs customary X509
  // checks. Unusual conditions will cause the function to
  // return *non-success*. Unusual conditions include an
  // expired certifcate or self signed certifcate.
  SecTrustResultType result = 0;
  OSStatus status = SecTrustEvaluate(serverTrust, &result);
  if (status != errSecSuccess) {
    NSLog(@"[ERROR] Evaluation failed");
    return;
  }
  
  DebugLog(@"%s SecTrustEvaluate returned %@", __PRETTY_FUNCTION__, @(status));
    
  CFIndex count = SecTrustGetCertificateCount(serverTrust);
  CFIndex i = 0;
  DebugLog(@"Number of certificates: %ld", count);
  
  for (i = 0; i < count; i++) {
    SecCertificateRef item = SecTrustGetCertificateAtIndex(serverTrust, i);
    NSString *desc = (NSString *)CFBridgingRelease(CFCopyDescription(item));
    DebugLog(@"%ld: %@", i, desc);
  }
  
  // Obtain the server's X509 certificate and public key.
  SecCertificateRef serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
  if (serverCertificate == nil) {
    NSLog(@"[ERROR] No server certificate");

    return;
  }
  
  // Create a friendlier Objective-C wrapper around this server's X509
  // certificate.
  X509Certificate *x509Certificate = [X509Certificate x509CertificateWithSecCertificate:serverCertificate andTrustChainIndex:0];
  if (x509Certificate == nil) {
    NSLog(@"[ERROR] Certificate wrapper failed");

    return;
  }
  
  NSDictionary *event = @{
    @"fingerprint": x509Certificate.SHA1Fingerprint,
    @"issuedByDName": x509Certificate.names.firstObject
  };
  
  [_proxy fireEvent:@"sslCheck" withObject:event];
  
  NSURLCredential *credential = [NSURLCredential credentialForTrust:serverTrust];
  [challenge.sender useCredential:credential forAuthenticationChallenge:challenge];
  completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
}

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
  DebugLog(@"%s connection = %@, challenge = %@", __PRETTY_FUNCTION__, connection, challenge);

  // Normalize the server's host name to lower case.
  NSString *host = [connection.currentRequest.URL.host lowercaseString];
  DebugLog(@"%s Normalized host name = %@", __PRETTY_FUNCTION__, host);

  // Get the PinnedURL for this server.
  NSString *authenticationMethod = [[challenge protectionSpace] authenticationMethod];

  if (![authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
    return [challenge.sender cancelAuthenticationChallenge:challenge];
  }

  SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
  if (serverTrust == nil) {
    DebugLog(@"%s FAIL: challenge.protectionSpace.serverTrust is nil", __PRETTY_FUNCTION__);
    return [challenge.sender cancelAuthenticationChallenge:challenge];
  }

  // SecTrustEvaluate performs customary X509
  // checks. Unusual conditions will cause the function to
  // return *non-success*. Unusual conditions include an
  // expired certifcate or self signed certifcate.
  SecTrustResultType result = 0;
  OSStatus status = SecTrustEvaluate(serverTrust, &result);
  if (status != errSecSuccess) {
    DebugLog(@"%s FAIL: standard TLS validation failed. SecTrustEvaluate returned %@", __PRETTY_FUNCTION__, @(status));
    return [challenge.sender cancelAuthenticationChallenge:challenge];
  }
  DebugLog(@"%s SecTrustEvaluate returned %@", __PRETTY_FUNCTION__, @(status));

  CFIndex count = SecTrustGetCertificateCount(serverTrust);
  CFIndex i = 0;
  DebugLog(@"Number of certificates: %ld", count);

  // Obtain the server's X509 certificate and public key.
  SecCertificateRef serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0);
  if (serverCertificate == nil) {
    DebugLog(@"%s FAIL: Could not find the server's X509 certificate in serverTrust", __PRETTY_FUNCTION__);
    return [challenge.sender cancelAuthenticationChallenge:challenge];
  }

  // Create a friendlier Objective-C wrapper around this server's X509
  // certificate.
  X509Certificate *x509Certificate = [X509Certificate x509CertificateWithSecCertificate:serverCertificate andTrustChainIndex:0];
  if (x509Certificate == nil) {
    // CFBridgingRelease transfer's ownership of the CFStringRef
    // returned by CFCopyDescription to ARC.
    NSString *serverCertificateDescription = (NSString *)CFBridgingRelease(CFCopyDescription(serverCertificate));
    NSString *reason = [NSString stringWithFormat:@"LOGIC ERROR: appcelerator.https module bug: SecurityManager could not create an X509Certificate for host \"%@\" using the SecCertificateRef \"%@\". Please report this issue to us at https://jira.appcelerator.org/browse/MOD-1706", connection.currentRequest.URL.host, serverCertificateDescription];
    NSDictionary *userInfo = @{ @"x509Certificate" : [NSNull null] };
    NSException *exception = [NSException exceptionWithName:NSInternalInconsistencyException
                                                     reason:reason
                                                   userInfo:userInfo];
    @throw exception;
  }

  DebugLog(@"%s server's X509 certificate = %@", __PRETTY_FUNCTION__, x509Certificate);
  // Get the public key from this server's X509 certificate.
  PublicKey *serverPublicKey = x509Certificate.publicKey;
  if (serverPublicKey == nil) {
    NSString *reason = [NSString stringWithFormat:@"LOGIC ERROR: appcelerator.https module bug: SecurityManager could not find the server's public key for host \"%@\" in the X509 certificate \"%@\". Please report this issue to us at https://jira.appcelerator.org/browse/MOD-1706", connection.currentRequest.URL.host, x509Certificate];
    NSDictionary *userInfo = @{ @"x509Certificate" : x509Certificate };
    NSException *exception = [NSException exceptionWithName:NSInternalInconsistencyException
                                                     reason:reason
                                                   userInfo:userInfo];
    @throw exception;
  }

  DebugLog(@"%s server's public key = %@", __PRETTY_FUNCTION__, serverPublicKey);

  // Return success since the server holds the private key
  // corresponding to the public key held bu this security manager.
  return [challenge.sender useCredential:[NSURLCredential credentialForTrust:serverTrust] forAuthenticationChallenge:challenge];
}

#pragma mark - NSObject

- (BOOL)isEqual:(id)rhs
{
  if (self == rhs) {
    return YES;
  }

  if (![rhs isKindOfClass:[SecurityManager class]]) {
    return NO;
  }

  return [self isEqualToSecurityManager:(SecurityManager *)rhs];
}

- (NSUInteger)hash
{
  return self.pinnedUrlSet.hash;
}

- (NSString *)description
{
  return [NSString stringWithFormat:@"%@: %@", NSStringFromClass(self.class), self.pinnedUrlSet];
}

#pragma mark - Utilities

- (OSStatus)extractIdentity:(SecIdentityRef *)identity from:(CFDataRef)p12Data with:(NSString *)password
{
  OSStatus result = errSecSuccess;

  CFStringRef _password = (__bridge CFStringRef)password;
  const void *keys[] = { kSecImportExportPassphrase };
  const void *values[] = { _password };

  CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);

  CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
  result = SecPKCS12Import(p12Data, options, &items);

  if (result == 0) {
    CFDictionaryRef ident = CFArrayGetValueAtIndex(items, 0);
    const void *tempIdentity = NULL;
    tempIdentity = CFDictionaryGetValue(ident, kSecImportItemIdentity);
    *identity = (SecIdentityRef)tempIdentity;
  }

  if (options) {
    CFRelease(options);
  }

  return result;
}

@end
