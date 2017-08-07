//
//  File: Signing.m
//  Project: Proc Info
//
//  Created by: Patrick Wardle
//  Copyright:  2017 Objective-See
//  License:    Creative Commons Attribution-NonCommercial 4.0 International License
//

#import "Consts.h"
#import "Signing.h"
#import "Utilities.h"
#import "AppReceipt.h"

#import <sys/sysctl.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <SystemConfiguration/SystemConfiguration.h>

//get the signing info of a item
NSDictionary* extractSigningInfo(NSString* path)
{
    //info dictionary
    NSMutableDictionary* signingStatus = nil;
    
    //code
    SecStaticCodeRef staticCode = NULL;
    
    //status
    OSStatus status = -1;
    
    //signing information
    CFDictionaryRef signingInformation = NULL;
    
    //cert chain
    NSArray* certificateChain = nil;
    
    //index
    NSUInteger index = 0;
    
    //cert
    SecCertificateRef certificate = NULL;
    
    //common name on chert
    CFStringRef commonName = NULL;
    
    //init signing status
    signingStatus = [NSMutableDictionary dictionary];
    
    //create static code
    status = SecStaticCodeCreateWithPath((__bridge CFURLRef)([NSURL fileURLWithPath:path]), kSecCSDefaultFlags, &staticCode);
    
    //save signature status
    signingStatus[KEY_SIGNATURE_STATUS] = [NSNumber numberWithInt:status];
    if(noErr != status)
    {
        //bail
        goto bail;
    }
    
    //check signature
    status = SecStaticCodeCheckValidityWithErrors(staticCode, kSecCSDoNotValidateResources, NULL, NULL);
    
    //(re)save signature status
    signingStatus[KEY_SIGNATURE_STATUS] = [NSNumber numberWithInt:status];
    
    //if file is signed
    // ->grab signing authorities
    if(noErr == status)
    {
        //grab signing authorities
        status = SecCodeCopySigningInformation(staticCode, kSecCSSigningInformation, &signingInformation);
        if(noErr != status)
        {
            //bail
            goto bail;
        }
        
        //determine if binary is signed by Apple
        signingStatus[KEY_SIGNING_IS_APPLE] = [NSNumber numberWithBool:isApple(path)];
        
        //not apple proper
        // ->is signed with Apple Dev ID?
        if(YES != [signingStatus[KEY_SIGNING_IS_APPLE] boolValue])
        {
            //determine if binary is Apple Dev ID
            signingStatus[KEY_SIGNING_IS_APPLE_DEV_ID] = [NSNumber numberWithBool:isSignedDevID(path)];
            
            //if dev id
            // ->from app store?
            if(YES == [signingStatus[KEY_SIGNING_IS_APPLE_DEV_ID] boolValue])
            {
                //from app store?
                signingStatus[KEY_SIGNING_IS_APP_STORE] = [NSNumber numberWithBool:fromAppStore(path)];
            }
        }
    }
    //error
    // ->not signed, or something else, so no need to check cert's names
    else
    {
        //bail
        goto bail;
    }
    
    //init array for certificate names
    signingStatus[KEY_SIGNING_AUTHORITIES] = [NSMutableArray array];
    
    //get cert chain
    certificateChain = [(__bridge NSDictionary*)signingInformation objectForKey:(__bridge NSString*)kSecCodeInfoCertificates];

    //get name of all certs
    // ->add each to list
    for(index = 0; index < certificateChain.count; index++)
    {
        //extract cert
        certificate = (__bridge SecCertificateRef)([certificateChain objectAtIndex:index]);
        
        //get common name
        status = SecCertificateCopyCommonName(certificate, &commonName);
        
        //skip ones that error out
        if( (noErr != status) ||
            (NULL == commonName))
        {
            //skip
            continue;
        }
        
        //save
        [signingStatus[KEY_SIGNING_AUTHORITIES] addObject:(__bridge NSString*)commonName];
        
        //release name
        CFRelease(commonName);
    }
    

bail:
    
    //free signing info
    if(NULL != signingInformation)
    {
        //free
        CFRelease(signingInformation);
        
        //unset
        signingInformation = NULL;
    }
    
    //free static code
    if(NULL != staticCode)
    {
        //free
        CFRelease(staticCode);
        
        //unset
        staticCode = NULL;
    }
    
    return signingStatus;
}

//determine if a file is signed by Apple proper
BOOL isApple(NSString* path)
{
    //flag
    BOOL isApple = NO;
    
    //code
    SecStaticCodeRef staticCode = NULL;
    
    //signing reqs
    SecRequirementRef requirementRef = NULL;
    
    //status
    OSStatus status = -1;
    
    //create static code
    status = SecStaticCodeCreateWithPath((__bridge CFURLRef)([NSURL fileURLWithPath:path]), kSecCSDefaultFlags, &staticCode);
    if(noErr != status)
    {
        //bail
        goto bail;
    }
    
    //create req string w/ 'anchor apple'
    // (3rd party: 'anchor apple generic')
    status = SecRequirementCreateWithString(CFSTR("anchor apple"), kSecCSDefaultFlags, &requirementRef);
    if( (noErr != status) ||
        (requirementRef == NULL) )
    {
        //bail
        goto bail;
    }
    
    //check if file is signed by apple by checking if it conforms to req string
    // note: ignore 'errSecCSBadResource' as lots of signed apple files return this issue :/
    status = SecStaticCodeCheckValidity(staticCode, kSecCSDefaultFlags, requirementRef);
    if( (noErr != status) &&
        (errSecCSBadResource != status) )
    {
        //bail
        // ->just means app isn't signed by apple
        goto bail;
    }
    
    //ok, happy (SecStaticCodeCheckValidity() didn't fail)
    // ->file is signed by Apple
    isApple = YES;
    
bail:
    
    //free req reference
    if(NULL != requirementRef)
    {
        //free
        CFRelease(requirementRef);
        
        //unset
        requirementRef = NULL;
    }
    
    //free static code
    if(NULL != staticCode)
    {
        //free
        CFRelease(staticCode);
        
        //unset
        staticCode = NULL;
    }
    
    return isApple;
}

//verify the receipt
// ->check bundle ID, app version, and receipt's hash
BOOL verifyReceipt(NSBundle* appBundle, AppReceipt* receipt)
{
    //flag
    BOOL verified = NO;
    
    //guid
    NSData* guid = nil;
    
    //hash data
    NSMutableData *digestData = nil;
    
    //hash buffer
    unsigned char digestBuffer[CC_SHA1_DIGEST_LENGTH] = {0};
    
    //check guid
    guid = getGUID();
    if(nil == guid)
    {
        //bail
        goto bail;
    }
    
    //create data obj
    digestData = [NSMutableData data];
    
    //add guid to data obj
    [digestData appendData:guid];
    
    //add receipt's 'opaque value' to data obj
    [digestData appendData:receipt.opaqueValue];
    
    //add receipt's bundle id data to data obj
    [digestData appendData:receipt.bundleIdentifierData];
    
    //CHECK 1:
    // ->app's bundle ID should match receipt's bundle ID
    if(YES != [receipt.bundleIdentifier isEqualToString:appBundle.bundleIdentifier])
    {
        //bail
        goto bail;
    }
    
    //CHECK 2:
    // ->app's version should match receipt's version
    if(YES != [receipt.appVersion isEqualToString:appBundle.infoDictionary[@"CFBundleShortVersionString"]])
    {
        //bail
        goto bail;
    }
    
    //CHECK 3:
    // ->verify receipt's hash (UUID)
    
    //init SHA 1 hash
    CC_SHA1(digestData.bytes, (CC_LONG)digestData.length, digestBuffer);
    
    //check for hash match
    if(0 != memcmp(digestBuffer, receipt.receiptHash.bytes, CC_SHA1_DIGEST_LENGTH))
    {
        //hash check failed
        goto bail;
    }
    
    //happy
    verified = YES;
    
bail:
    
    return verified;
}

//get GUID (really just computer's MAC address)
// ->from Apple's 'Get the GUID in OS X' (see: 'Validating Receipts Locally')
NSData* getGUID()
{
    //status var
    __block kern_return_t kernResult = -1;
    
    //master port
    __block mach_port_t  masterPort = 0;
    
    //matching dictionar
    __block CFMutableDictionaryRef matchingDict = NULL;
    
    //iterator
    __block io_iterator_t iterator = 0;
    
    //service
    __block io_object_t service = 0;
    
    //registry property
    __block CFDataRef registryProperty = NULL;
    
    //guid (MAC addr)
    static NSData* guid = nil;
    
    //once token
    static dispatch_once_t onceToken = 0;
    
    //only init guid once
    dispatch_once(&onceToken,
      ^{
          
          //get master port
          kernResult = IOMasterPort(MACH_PORT_NULL, &masterPort);
          if(KERN_SUCCESS != kernResult)
          {
              //bail
              goto bail;
          }
          
          //get matching dictionary for 'en0'
          matchingDict = IOBSDNameMatching(masterPort, 0, "en0");
          if(NULL == matchingDict)
          {
              //bail
              goto bail;
          }
          
          //get matching services
          kernResult = IOServiceGetMatchingServices(masterPort, matchingDict, &iterator);
          if(KERN_SUCCESS != kernResult)
          {
              //bail
              goto bail;
          }
          
          //iterate over services, looking for 'IOMACAddress'
          while((service = IOIteratorNext(iterator)) != 0)
          {
              //parent
              io_object_t parentService = 0;
              
              //get parent
              kernResult = IORegistryEntryGetParentEntry(service, kIOServicePlane, &parentService);
              if(KERN_SUCCESS == kernResult)
              {
                  //release prev
                  if(NULL != registryProperty)
                  {
                      //release
                      CFRelease(registryProperty);
                  }
                  
                  //get registry property for 'IOMACAddress'
                  registryProperty = (CFDataRef) IORegistryEntryCreateCFProperty(parentService, CFSTR("IOMACAddress"), kCFAllocatorDefault, 0);
                  
                  //release parent
                  IOObjectRelease(parentService);
              }
              
              //release service
              IOObjectRelease(service);
          }
          
          //release iterator
          IOObjectRelease(iterator);
          
          //convert guid to NSData*
          // ->also release registry property
          if(NULL != registryProperty)
          {
              //convert
              guid = [NSData dataWithData:(__bridge NSData *)registryProperty];
              
              //release
              CFRelease(registryProperty);
          }
          
bail:
        ;
          
      });//only once
    
    return guid;
}

//determine if file is signed with Apple Dev ID/cert
BOOL isSignedDevID(NSString* binary)
{
    //flag
    BOOL signedOK = NO;
    
    //code
    SecStaticCodeRef staticCode = NULL;
    
    //signing reqs
    SecRequirementRef requirementRef = NULL;
    
    //status
    OSStatus status = -1;
    
    //create static code
    status = SecStaticCodeCreateWithPath((__bridge CFURLRef)([NSURL fileURLWithPath:binary]), kSecCSDefaultFlags, &staticCode);
    if(noErr != status)
    {
        //bail
        goto bail;
    }
    
    //create req string w/ 'anchor apple generic'
    status = SecRequirementCreateWithString(CFSTR("anchor apple generic"), kSecCSDefaultFlags, &requirementRef);
    if( (noErr != status) ||
        (requirementRef == NULL) )
    {
        //bail
        goto bail;
    }
    
    //check if file is signed w/ apple dev id by checking if it conforms to req string
    status = SecStaticCodeCheckValidity(staticCode, kSecCSDefaultFlags, requirementRef);
    if(noErr != status)
    {
        //bail
        // ->just means app isn't signed by apple dev id
        goto bail;
    }
    
    //ok, happy
    // ->file is signed by Apple Dev ID
    signedOK = YES;
    
bail:
    
    //free req reference
    if(NULL != requirementRef)
    {
        //free
        CFRelease(requirementRef);
        
        //unset
        requirementRef = NULL;
    }
    
    //free static code
    if(NULL != staticCode)
    {
        //free
        CFRelease(staticCode);
        
        //unset
        staticCode = NULL;
    }
    
    return signedOK;
}

//determine if a file is from the app store
// ->gotta be signed w/ Apple Dev ID & have valid app receipt
//   note: here, assume this function is only called on Apps signed with Apple Dev ID!
BOOL fromAppStore(NSString* path)
{
    //flag
    BOOL appStoreApp = NO;
    
    //app receipt
    AppReceipt* appReceipt = nil;
    
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
        appBundle = findAppBundle(path);
        if(nil == appBundle)
        {
            //bail
            goto bail;
        }
    }
    
    //bail if it doesn't have an receipt
    // ->done here, since checking signature is expensive!
    if( (nil == appBundle.appStoreReceiptURL) ||
        (YES != [[NSFileManager defaultManager] fileExistsAtPath:appBundle.appStoreReceiptURL.path]) )
    {
        //bail
        goto bail;
    }
    
    //init
    // ->will parse/decode, etc
    appReceipt = [[AppReceipt alloc] init:appBundle];
    if(nil == appReceipt)
    {
        //bail
        goto bail;
    }
    
    //verify
    if(YES != verifyReceipt(appBundle, appReceipt))
    {
        //bail
        goto bail;
    }
    
    //happy
    // ->app is signed w/ dev ID & its receipt is solid
    appStoreApp = YES;
    
bail:
    
    return appStoreApp;
}
