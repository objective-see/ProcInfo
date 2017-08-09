//
//  File: Binary.m
//  Project: Proc Info
//
//  Created by: Patrick Wardle
//  Copyright:  2017 Objective-See
//  License:    Creative Commons Attribution-NonCommercial 4.0 International License
//

#import "Consts.h"
#import "Signing.h"
#import "procInfo.h"
#import "Utilities.h"

@implementation Binary

@synthesize name;
@synthesize path;
@synthesize isApple;
@synthesize attributes;
@synthesize isAppStore;
@synthesize signingInfo;

//init binary object
// ->generates signing info, classifies binary, etc
-(id)init:(NSString*)binaryPath
{
    //init super
    self = [super init];
    if(nil != self)
    {
        //save path
        self.path = binaryPath;
        
        //grab attributes
        self.attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:self.path error:nil];
        
        //figure out name
        [self determineName];
        
        //generate signing info
        [self generateSigningInfo];
    }

    return self;
}

//figure out binary's name
// ->either via app bundle, or from path
-(void)determineName
{
    //path to app bundle
    // ->just have binary
    NSBundle* appBundle = nil;
    
    //if it's an app
    // ->can directly load app bundle
    appBundle = [NSBundle bundleWithPath:path];
    if(nil == appBundle)
    {
        //find app bundle from binary
        // ->likely not an application if this fails
        appBundle = PI_findAppBundle(path);
    }
    
    //found app bundle?
    // ->grab name from 'CFBundleName'
    if(nil != appBundle)
    {
        //extract name
        self.name = [appBundle infoDictionary][@"CFBundleName"];
    }
    
    //no app bundle
    // ->just use last component from path
    else
    {
        //set name
        self.name = [self.path lastPathComponent];
    }
    
    return;
}

//generate signing info
// ->also classifies if Apple/from app store/etc.
-(void)generateSigningInfo
{
    //extract signing info (do this first!)
    // ->from Apple, App Store, signing authorities, etc
    self.signingInfo = extractSigningInfo(self.path);
    
    //perform more signing checks and lists
    // ->gotta be happily signed for checks though
    if(0 == [self.signingInfo[KEY_SIGNATURE_STATUS] intValue])
    {
        //set flag for signed by Apple proper
        self.isApple = [self.signingInfo[KEY_SIGNING_IS_APPLE] boolValue];
        
        //when not Apple proper
        // ->check flag for from official App Store or is whitelisted
        if(YES != isApple)
        {
            //set flag
            self.isAppStore = [self.signingInfo[KEY_SIGNING_IS_APP_STORE] boolValue];
        }
    }
    
    return;
}

//for pretty printing
-(NSString *)description
{
    //pretty print
    return [NSString stringWithFormat: @"name: %@\npath: %@\nattributes: %@\nsigning info: %@ (isApple: %d / isAppStore: %d)", self.name, self.path, self.attributes, self.signingInfo, self.isApple, self.isAppStore];
}

@end
