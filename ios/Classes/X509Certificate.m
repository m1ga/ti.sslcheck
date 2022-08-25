//  Author: Matt Langston
//  Copyright (c) 2014 Appcelerator. All rights reserved.

#import "X509Certificate.h"
#import "TiSslcheckModule.h"
#import "PublicKey.h"
#import "ti_sslcheck-Swift.h"
#include <openssl/x509v3.h>
#import <CommonCrypto/CommonCrypto.h>

@implementation X509Certificate

@synthesize publicKey = _publicKey;

+ (instancetype)x509CertificateWithSecCertificate:(SecCertificateRef)secCertificate andTrustChainIndex:(NSInteger)trustChainIndex
{
  return [[X509Certificate alloc] initWithSecCertificate:secCertificate andTrustChainIndex:trustChainIndex];
}

+ (instancetype)x509CertificateWithURL:(NSURL *)url andTrustChainIndex:(NSInteger)trustChainIndex
{
  return [[X509Certificate alloc] initWithURL:url andTrustChainIndex:trustChainIndex];
}

// Designated initializer.
- (instancetype)initWithSecCertificate:(SecCertificateRef)secCertificate andTrustChainIndex:(NSInteger)trustChainIndex
{
  self = [super init];
  if (self) {
    // The certificate must not be NULL.
    if (!(NULL != secCertificate)) {
      NSString *reason = @"secCertificate must not be nil";
      NSDictionary *userInfo = nil;
      NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                       reason:reason
                                                     userInfo:userInfo];

      self = nil;
      @throw exception;
    }

#ifdef DEBUG
    // CFBridgingRelease transfer's ownership of the CFStringRef
    // returned by CFCopyDescription to ARC.
    NSString *secCertificateDescription = (NSString *)CFBridgingRelease(CFCopyDescription(secCertificate));
#endif

    _SecCertificate = (SecCertificateRef)CFRetain(secCertificate);
    _trustChainIndex = trustChainIndex;
  }

  return self;
}

- (instancetype)initWithURL:(NSURL *)url andTrustChainIndex:(NSInteger)trustChainIndex
{
  // The URL must not be nill
  if (!(nil != url)) {
    NSString *reason = @"url must not be nil";
    NSDictionary *userInfo = nil;
    NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                     reason:reason
                                                   userInfo:userInfo];
    @throw exception;
  }

  // The URL must contain data.
  NSDataReadingOptions options = NSDataReadingUncached;
  NSError *error;
  NSData *certificateNSData = [NSData dataWithContentsOfURL:url options:options error:&error];
  if (!(nil == error)) {
    NSString *reason = [NSString stringWithFormat:@"Failed to read certificate data from URL %@", url];
    NSDictionary *userInfo = @{ @"url" : url, @"error" : error };
    NSException *exception = [NSException exceptionWithName:NSInvalidArgumentException
                                                     reason:reason
                                                   userInfo:userInfo];
    @throw exception;
  }

  // __bridge means do not transfer ownership from Objective-C ARC.
  CFDataRef certificateCFData = (__bridge CFDataRef)certificateNSData;

  // Call the designated initializer.
  SecCertificateRef certificate;
  @try {
    certificate = SecCertificateCreateWithData(NULL, certificateCFData);
    self = [self initWithSecCertificate:certificate andTrustChainIndex:trustChainIndex];
  }
  @finally {
    CFRelease(certificate);
  }

  return self;
}

- (void)dealloc
{
  if (_SecCertificate) {
    CFRelease(_SecCertificate);
  }
}

// The publicKey getter has to be written manually because it requires this
// object (i.e. an X509Certificate object) for initialization, meaning that
// it can be constructed in the X509Certificate designated initializer.
- (PublicKey *)publicKey
{
  if (nil == _publicKey) {
    _publicKey = [PublicKey publicKeyWithX509Certificate:self];
  }

  return _publicKey;
}

- (BOOL)isEqualToX509Certificate:(X509Certificate *)rhs
{
  if (!rhs) {
    return NO;
  }

  BOOL equal = CFEqual(self.SecCertificate, rhs.SecCertificate);
  return equal;
}

- (NSString *)issuedByCName
{
  NSData *certificateData = (__bridge NSData *) SecCertificateCopyData(self.SecCertificate);
  SecCertificateWrapper *wrapper = [[SecCertificateWrapper alloc] initWithData:certificateData];
  
  return wrapper.commonName;
}

- (NSDate *)validNotAfter
{
  NSData *certificateData = (__bridge NSData *) SecCertificateCopyData(self.SecCertificate);
  SecCertificateWrapper *wrapper = [[SecCertificateWrapper alloc] initWithData:certificateData];
  
  return wrapper.validDates[@"notValidAfterDate"];
}

- (NSDate *)validNotBefore
{
  NSData *certificateData = (__bridge NSData *) SecCertificateCopyData(self.SecCertificate);
  SecCertificateWrapper *wrapper = [[SecCertificateWrapper alloc] initWithData:certificateData];
  
  return wrapper.validDates[@"notValidBeforeDate"];
}

- (NSString *)SHA1Fingerprint
{
    SecCertificateRef certificate = self.SecCertificate;
    NSData *data = CFBridgingRelease(SecCertificateCopyData(certificate));
  
    const NSUInteger length = CC_SHA1_DIGEST_LENGTH;
    unsigned char buffer[length];

    CC_SHA1(data.bytes, (CC_LONG)data.length, buffer);

    NSMutableString *fingerprint = [NSMutableString stringWithCapacity:length * 3];

    for (int i = 0; i < length; i++) {
        [fingerprint appendFormat:@"%02x ",buffer[i]];
    }

    return [fingerprint stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
}

// CREDITS: https://stackoverflow.com/a/10839816/5537752
- (NSArray<NSString *> *)names
{
  CFDataRef der = SecCertificateCopyData(self.SecCertificate);
  const unsigned char * ptr = CFDataGetBytePtr(der);
  long len = CFDataGetLength(der);
  X509 *x509 = NULL;
  
  d2i_X509(&x509,&ptr,len);

  X509_NAME * names_s = X509_get_subject_name(x509);
  X509_NAME * names_i = X509_get_issuer_name(x509);
  GENERAL_NAMES * sANs = X509_get_ext_d2i( x509, NID_subject_alt_name, 0, 0 );

  // ASN1_INTEGER *serial = X509_get_serialNumber(x509);
  // unsigned  long s = ASN1_INTEGER_get(serial);
  
  int i, numAN = sk_GENERAL_NAME_num( sANs );
  NSMutableArray * out = [NSMutableArray arrayWithCapacity:numAN];

  for( i = 0; i < numAN; ++i ) {
      GENERAL_NAME *sAN = sk_GENERAL_NAME_value( sANs, i );

      if( sAN->type == GEN_DNS) {
          unsigned char *dns;
          int len = ASN1_STRING_to_UTF8( &dns, sAN->d.dNSName );
          if (len >0) {
              [out addObject:[[NSString alloc] initWithData:[NSData dataWithBytes:dns length:len] encoding:NSUTF8StringEncoding]];
              OPENSSL_free( dns );
          }
      }
  }
  
  return out;
}

#pragma mark - NSObject

- (BOOL)isEqual:(id)rhs
{
  if (self == rhs) {
    return YES;
  }

  if (![rhs isKindOfClass:[X509Certificate class]]) {
    return NO;
  }

  return [self isEqualToX509Certificate:(X509Certificate *)rhs];
}

- (NSUInteger)hash
{
  return CFHash(self.SecCertificate);
}

- (NSString *)description
{
  // CFBridgingRelease transfer's ownership of the CFStringRef
  // returned by CFCopyDescription to ARC.
  NSString *secCertificateDescription = (NSString *)CFBridgingRelease(CFCopyDescription(self.SecCertificate));
  return [NSString stringWithFormat:@"%@: %@", NSStringFromClass(self.class), secCertificateDescription];
}

@end
