/**
 * ti.sslcheck
 *
 * Created by Your Name
 * Copyright (c) 2022 Your Company. All rights reserved.
 */

#import "TiSslcheckModule.h"
#import "TiBase.h"
#import "TiHost.h"
#import "TiUtils.h"
#import "X509CertificatePinningSecurityManagerProxy.h"

@implementation TiSslcheckModule

#pragma mark Internal

- (id)moduleGUID
{
  return @"ffbd064e-b922-423e-99e1-138a23f16ab5";
}

- (NSString *)moduleId
{
  return @"ti.sslcheck";
}

#pragma mark Public APIs

- (id)createSecurityManager:(id)args
{
  id context = ([self executionContext] == nil) ? [self pageContext] : [self executionContext];
  return [[X509CertificatePinningSecurityManagerProxy alloc] _initWithPageContext:context args:args];
}

@end
