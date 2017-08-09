//
//  File: Utilities.h
//  Project: Proc Info
//
//  Created by: Patrick Wardle
//  Copyright:  2017 Objective-See
//  License:    Creative Commons Attribution-NonCommercial 4.0 International License
//

#ifndef Utilties_h
#define Utilties_h

#import <Foundation/Foundation.h>

//given a path to binary
// parse it back up to find app's bundle
NSBundle* PI_findAppBundle(NSString* binaryPath);

//check if current OS version is supported
// ->for now, just...?
BOOL PI_isSupportedOS();

//get OS version
NSDictionary* PI_getOSVersion();

//enumerate all running processes
NSMutableArray* PI_enumerateProcesses();

//given a bundle
// ->find its executable
NSString* PI_findAppBinary(NSString* appPath);

//sha256 a file
NSString* PI_hashFile(NSString* filePath);

#endif
