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
@synthesize metadata;
@synthesize attributes;
@synthesize identifier;
@synthesize isAppStore;
@synthesize signingInfo;
@synthesize entitlements;

//init binary object
// note: CPU-intensive logic (code signing, etc) called manually
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
        
        //get file attributes
        [self getAttributes];
        
        //get meta data (spotlight)
        [self getMetadata];
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
    //first try get name from app bundle
    // specifically, via grab name from 'CFBundleName'
    if(nil != self.bundle)
    {
        //extract name
        self.name = [self.bundle infoDictionary][@"CFBundleName"];
    }
    
    //no app bundle || no 'CFBundleName'
    // just use last component from path
    if(nil == self.name)
    {
        //set name
        self.name = [self.path lastPathComponent];
    }
    
    return;
}

//get file attributes
-(void)getAttributes
{
    //grab (file) attributes
    self.attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:self.path error:nil];
    
    return;
}

//get (spotlight) meta data
-(void)getMetadata
{
    //md item ref
    MDItemRef mdItem = nil;
    
    //attributes names
    CFArrayRef attributeNames = nil;

    //create
    mdItem = MDItemCreate(kCFAllocatorDefault, (CFStringRef)self.path);
    if(nil == mdItem)
    {
        //bail
        goto bail;
    }
    
    //copy names
    attributeNames = MDItemCopyAttributeNames(mdItem);
    if(nil == attributeNames)
    {
        //bail
        goto bail;
    }
    
    //get metadata
    self.metadata = CFBridgingRelease(MDItemCopyAttributes(mdItem, attributeNames));
    
bail:
    
    //release names
    if(nil != attributeNames)
    {
        //release
        CFRelease(attributeNames);
    }
    
    //release item
    if(nil != mdItem)
    {
        //release
        CFRelease(mdItem);
    }

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
        // go with 'icns'
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
        //extract icon
        self.icon = [[NSWorkspace sharedWorkspace] iconForFile:self.path];
        
        //load system document icon
        // static var, so only load once
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
-(void)generateSigningInfo:(SecCSFlags)flags entitlements:(BOOL)entitlements
{
    //extract signing info (do this first!)
    // from Apple, App Store, signing authorities, etc
    self.signingInfo = extractSigningInfo(self.path, flags, entitlements);
    
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

//generate hash
-(void)generateHash
{
    //hash
    self.sha256 = PI_hashFile(self.path);
    
    return;
}

//generate id
// either signing id, or sha256 hash
// note: will generate signing info if needed
-(void)generateIdentifier
{
    //generate signing info?
    if(nil == self.signingInfo)
    {
        //generate
        [self generateSigningInfo:kSecCSDefaultFlags entitlements:NO];
    }
    
    //validly signed binary?
    // use its signing identifier
    if( (noErr == [self.signingInfo[KEY_SIGNATURE_STATUS] intValue]) &&
        (0 != [self.signingInfo[KEY_SIGNING_AUTHORITIES] count]) &&
        (nil != self.signingInfo[KEY_SIGNATURE_IDENTIFIER]) )
    {
        //use signing id
        self.identifier  = self.signingInfo[KEY_SIGNATURE_IDENTIFIER];
    }
    //not validly signed or unsigned
    // generate sha256 hash for identifier
    else
    {
        //hash
        self.identifier = PI_hashFile(self.path);
    }
    
    return;
}

//generate entitlements
// note: can also call 'generateSigningInfo' w/ 'entitlements:YES'
-(void)generateEntitlements
{
    //call into helper function
    self.entitlements = extractEntitlements(self.path);
    
    return;
}

//for pretty printing
-(NSString *)description
{
    //pretty print
    return [NSString stringWithFormat: @"name: %@\npath: %@\nattributes: %@\nsigning info: %@ (isApple: %d / isAppStore: %d)", self.name, self.path, self.attributes, self.signingInfo, self.isApple, self.isAppStore];
}

@end
