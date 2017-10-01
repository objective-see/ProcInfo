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

@synthesize icon;
@synthesize name;
@synthesize path;
@synthesize bundle;
@synthesize isApple;
@synthesize attributes;
@synthesize isAppStore;
@synthesize signingInfo;

//init binary object
// generates signing info, classifies binary, etc
-(id)init:(NSString*)binaryPath
{
    //init super
    self = [super init];
    if(nil != self)
    {
        //not a full path?
        if(YES != [binaryPath hasPrefix:@"/"])
        {
            //try find via 'which'
            self.path = PI_which(binaryPath);
            if(nil == self.path)
            {
                //stuck with short path
                self.path = binaryPath;
            }
        }
        //full path
        // use as is
        else
        {
            //save path
            self.path = binaryPath;
        }
        
        //try load app bundle
        // will be nil for non-apps
        [self getBundle];
        
        //get name
        [self getName];
        
        //get icon
        [self getIcon];
        
        //get attributes
        [self getAttributes];
        
        //generate signing info
        [self generateSigningInfo];
    }

    return self;
}

//try load app bundle
// will be nil for non-apps
-(void)getBundle
{
    //first try just with path
    self.bundle = [NSBundle bundleWithPath:path];
    
    //that failed?
    // try find it dynamically
    if(nil == self.bundle)
    {
        //find bundle
        self.bundle = PI_findAppBundle(path);
    }
    
    return;
}

//figure out binary's name
// either via app bundle, or from path
-(void)getName
{
    //found app bundle?
    // grab name from 'CFBundleName'
    if(nil != self.bundle)
    {
        //extract name
        self.name = [self.bundle infoDictionary][@"CFBundleName"];
    }
    
    //no app bundle
    // just use last component from path
    else
    {
        //set name
        self.name = [self.path lastPathComponent];
    }
    
    return;
}

//get attributes
-(void)getAttributes
{
    //grab (file) attributes
    self.attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:self.path error:nil];
    
    return;
}

//get an icon for a process
// for apps, this will be app's icon, otherwise just a standard system one
-(void)getIcon
{
    //icon's file name
    NSString* iconFile = nil;
    
    //icon's path
    NSString* iconPath = nil;
    
    //icon's path extension
    NSString* iconExtension = nil;
    
    //system's document icon
    static NSData* documentIcon = nil;
    
    //skip 'short' paths
    // otherwise system logs an error
    if( (YES != [self.path hasPrefix:@"/"]) &&
        (nil == self.bundle) )
    {
        //bail
        goto bail;
    }
    
    //for app's
    // extract their icon
    if(nil != self.bundle)
    {
        //get file
        iconFile = self.bundle.infoDictionary[@"CFBundleIconFile"];
        
        //get path extension
        iconExtension = [iconFile pathExtension];
        
        //if its blank (i.e. not specified)
        // ->go with 'icns'
        if(YES == [iconExtension isEqualTo:@""])
        {
            //set type
            iconExtension = @"icns";
        }
        
        //set full path
        iconPath = [self.bundle pathForResource:[iconFile stringByDeletingPathExtension] ofType:iconExtension];
        
        //load it
        self.icon = [[NSImage alloc] initWithContentsOfFile:iconPath];
    }
    
    //process is not an app or couldn't get icon
    // try to get it via shared workspace
    if( (nil == self.bundle) ||
        (nil == self.icon) )
    {
        //dbg msg
        #ifdef DEBUG
        logMsg(LOG_DEBUG, [NSString stringWithFormat:@"getting icon for shared workspace: %@", self.path]);
        #endif
        
        //extract icon
        self.icon = [[NSWorkspace sharedWorkspace] iconForFile:self.path];
        
        //load system document icon
        // ->static var, so only load once
        if(nil == documentIcon)
        {
            //load
            documentIcon = [[[NSWorkspace sharedWorkspace] iconForFileType:
                             NSFileTypeForHFSTypeCode(kGenericDocumentIcon)] TIFFRepresentation];
        }
        
        //if 'iconForFile' method doesn't find and icon, it returns the system 'document' icon
        // the system 'applicaiton' icon seems more applicable, so use that here...
        if(YES == [[self.icon TIFFRepresentation] isEqual:documentIcon])
        {
            //set icon to system 'applicaiton' icon
            self.icon = [[NSWorkspace sharedWorkspace]
                         iconForFileType: NSFileTypeForHFSTypeCode(kGenericApplicationIcon)];
        }
    }
    
    //make standard size...
    [self.icon setSize:NSMakeSize(128, 128)];
    
bail:
    
    return;
}


//generate signing info
// also classifies if Apple/from App Store/etc.
-(void)generateSigningInfo
{
    //extract signing info (do this first!)
    // from Apple, App Store, signing authorities, etc
    self.signingInfo = extractSigningInfo(self.path);
    
    //perform more signing checks and lists
    // gotta be happily signed for checks though
    if(0 == [self.signingInfo[KEY_SIGNATURE_STATUS] intValue])
    {
        //set flag for signed by Apple proper
        self.isApple = [self.signingInfo[KEY_SIGNING_IS_APPLE] boolValue];
        
        //when not Apple proper
        // check flag for from official App Store or is whitelisted
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
