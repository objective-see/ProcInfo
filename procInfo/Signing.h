//
//  File: Signing.h
//  Project: Proc Info
//
//  Created by: Patrick Wardle
//  Copyright:  2017 Objective-See
//  License:    Creative Commons Attribution-NonCommercial 4.0 International License
//

#ifndef Signing_h
#define Signing_h

#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>

/* FUNCTIONS */

//get the signing info of a file
NSMutableDictionary* extractSigningInfo(NSString* path, SecCSFlags flags, BOOL entitlements);

//determine if a file is signed by Apple proper
BOOL isApple(NSString* path, SecCSFlags flags);

//determine if file is signed with Apple Dev ID/cert
BOOL isSignedDevID(NSString* path, SecCSFlags flags);

//determine if a file is from the app store
// gotta be signed w/ Apple Dev ID & have valid app receipt
BOOL fromAppStore(NSString* path);

//get GUID (really just computer's MAC address)
// from Apple's 'Get the GUID in OS X' (see: 'Validating Receipts Locally')
NSData* getGUID(void);

//extact entitlements
// note: execs apple's 'codesign' binary
NSDictionary* extractEntitlements(NSString* path);

#endif
