/*!
 @author Author: Matt Langston
 @copyright Copyright (c) 2014 Appcelerator. All rights reserved.
 */

#define USE_TI_NETWORK

#import "TiBase.h"
#import "TiNetworkHTTPClientProxy.h"
#import <Foundation/Foundation.h>

/*!
 @discussion
 A JavaScript interface (aka Titanium proxy) to the SecurityManager.
 
 This Titanium proxy class is simply a JavaScript wrapper for the
 SecurityManager class. It validates the arguments passed from
 JavaScript to the createX509CertificatePinningSecurityManager
 function (defined in AppceleratorHttpsModule) and prevents the use of
 a misconfigured or otherwise invalid SecurityManager.
 
 If argument validation fails, or if the SecurityManager cannot be constructed
 into a known good state, then an exception is thrown which prevents the
 JavaScript code from using a Titanium.Network.HTTPClient without a valid
 SecurityManager. This protects a Titanium developer from accessing an unpinned
 HTTPS URL which they believed to be pinned to a public key.
 
 @seealso AppceleratorHttpsModule
 */
@interface X509CertificatePinningSecurityManagerProxy : TiProxy <SecurityManagerProtocol>

// This class provides no API for Objecive-C developers. All of this classes
// functionality is accessed from JavaScript and is only meant to be used in a
// Titanium application

@end
