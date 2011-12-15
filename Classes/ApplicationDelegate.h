//
//  ApplicationDelegate.h
//  PushMeBaby
//
//  Created by Stefan Hafeneger on 07.04.09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>

#import "ioSock.h"

@interface ApplicationDelegate : NSObject {
	NSString *_deviceToken, *_payload, *_certificate;
	otSocket socket;
	SSLContextRef context;
	SecKeychainRef keychain;
	SecCertificateRef certificate;
	SecIdentityRef identity;
}
#pragma mark IBAction
- (IBAction)push:(id)sender;
@end
