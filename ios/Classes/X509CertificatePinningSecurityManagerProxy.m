//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "X509CertificatePinningSecurityManagerProxy.h"
#import "ClientCertificate.h"
#import "PinnedURL.h"
#import "PublicKey.h"
#import "SecurityManager.h"
#import "TiUtils.h"
#import "X509Certificate.h"

// Private extensions required by the implementation of
// X509CertificatePinningSecurityManagerProxy.
@interface X509CertificatePinningSecurityManagerProxy ()

@property (nonatomic, strong, readonly) SecurityManager *securityManager;

@end

// This counter is used to identify a particular
// X509CertificatePinningSecurityManagerProxy in log statements.
static int32_t proxyCount = 0;
static dispatch_queue_t syncQueue;

@implementation X509CertificatePinningSecurityManagerProxy

+ (void)initialize
{
  syncQueue = dispatch_queue_create("appcelerator.https.syncQueue", NULL);
}

- (id)init
{
  self = [super init];
  if (self) {

    dispatch_sync(syncQueue, ^{
      ++proxyCount;
    });
  }

  return self;
}

- (id)_initWithPageContext:(id<TiEvaluator>)context_ args:(NSArray *)args
{
  if (self = [super _initWithPageContext:context_]) {
    _securityManager = [SecurityManager securityManagerWithPinnedUrlSet:NSSet.set andProxy:self];
  }
  return self;
}

#pragma mark SecurityManagerProtocol methods

// Delegate to the SecurityManager.
- (BOOL)willHandleURL:(NSURL *)url
{
  return [self.securityManager willHandleURL:url];
}

// Delegate to the SecurityManager.
- (id<APSConnectionDelegate>)connectionDelegateForUrl:(NSURL *)url
{
  return [self.securityManager connectionDelegateForUrl:url];
}

@end
