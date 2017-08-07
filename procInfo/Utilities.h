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
NSBundle* findAppBundle(NSString* binaryPath);

//check if current OS version is supported
// ->for now, just...?
BOOL isSupportedOS();

//get OS version
NSDictionary* getOSVersion();

//enumerate all running processes
NSMutableArray* enumerateProcesses();

//given a bundle
// ->find its executable
NSString* findAppBinary(NSString* appPath);

//sha256 a file
NSString* hashFile(NSString* filePath);

#endif
