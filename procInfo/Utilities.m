//
//  File: Utilities.m
//  Project: Proc Info
//
//  Created by: Patrick Wardle
//  Copyright:  2017 Objective-See
//  License:    Creative Commons Attribution-NonCommercial 4.0 International License
//

#import "Consts.h"
#import "Utilities.h"
#import "AppReceipt.h"

#import <libproc.h>
#import <sys/sysctl.h>

//disable deprecated warnings
// use 'Gestalt' as this code may run on old OS X vers.
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

//get OS version
NSDictionary* PI_getOSVersion()
{
    //os version info
    NSMutableDictionary* osVersionInfo = nil;
    
    //major v
    SInt32 majorVersion = 0;
    
    //minor v
    SInt32 minorVersion = 0;
    
    //bug fix v
    SInt32 fixVersion = 0;
    
    //alloc dictionary
    osVersionInfo = [NSMutableDictionary dictionary];
    
    //get major version
    if(noErr != Gestalt(gestaltSystemVersionMajor, &majorVersion))
    {
        //unset
        osVersionInfo = nil;
        
        //bail
        goto bail;
    }
    
    //get minor version
    if(noErr != Gestalt(gestaltSystemVersionMinor, &minorVersion))
    {
        //unset
        osVersionInfo = nil;
        
        //bail
        goto bail;
    }
    
    //get bug fix version
    if(noErr != Gestalt(gestaltSystemVersionBugFix, &fixVersion))
    {
        //unset
        osVersionInfo = nil;
        
        //bail
        goto bail;
    }
    
    //set major version
    osVersionInfo[@"majorVersion"] = [NSNumber numberWithInteger:majorVersion];
    
    //set minor version
    osVersionInfo[@"minorVersion"] = [NSNumber numberWithInteger:minorVersion];
    
    //set bug fix version
    osVersionInfo[@"bugfixVersion"] = [NSNumber numberWithInteger:fixVersion];
    
bail:
    
    return osVersionInfo;
}

//is current OS version supported?
// for now, just OS X 10.8+
BOOL PI_isSupportedOS()
{
    //support flag
    BOOL isSupported = NO;
    
    //OS version info
    NSDictionary* osVersionInfo = nil;
    
    //get OS version info
    osVersionInfo = PI_getOSVersion();
    if(nil == osVersionInfo)
    {
        //bail
        goto bail;
    }
    
    //gotta be OS X
    if(OS_MAJOR_VERSION_X != [osVersionInfo[@"majorVersion"] intValue])
    {
        //bail
        goto bail;
    }
    
    //gotta be OS X at least lion (10.8)
    if([osVersionInfo[@"minorVersion"] intValue] < OS_MINOR_VERSION_LION)
    {
        //bail
        goto bail;
    }
    
    //OS version is supported
    isSupported = YES;
    
bail:
    
    return isSupported;
}

//enumerate all running processes
NSMutableArray* PI_enumerateProcesses()
{
    //status
    int status = -1;
    
    //# of procs
    int numberOfProcesses = 0;
    
    //array of pids
    pid_t* pids = NULL;
    
    //processes
    NSMutableArray* processes = nil;
    
    //alloc array
    processes = [NSMutableArray array];
    
    //get # of procs
    numberOfProcesses = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    
    //alloc buffer for pids
    pids = calloc(numberOfProcesses, sizeof(pid_t));
    if(nil == pids)
    {
        //bail
        goto bail;
    }
    
    //get list of pids
    status = proc_listpids(PROC_ALL_PIDS, 0, pids, numberOfProcesses * sizeof(pid_t));
    if(status < 0)
    {
        //bail
        goto bail;
    }
    
    //iterate over all pids
    // save pid into return array
    for(int i = 0; i < numberOfProcesses; ++i)
    {
        //save each pid
        if(0 != pids[i])
        {
            //save
            [processes addObject:[NSNumber numberWithUnsignedInt:pids[i]]];
        }
    }
    
bail:
    
    //free buffer
    if(NULL != pids)
    {
        //free
        free(pids);
        
        //unset
        pids = NULL;
    }
    
    return processes;
}

//given a path to binary
// parse it back up to find app's bundle
NSBundle* PI_findAppBundle(NSString* binaryPath)
{
    //app's bundle
    NSBundle* appBundle = nil;
    
    //app's path
    NSString* appPath = nil;
    
    //first just try full path
    appPath = binaryPath;
    
    //try to find the app's bundle/info dictionary
    do
    {
        //try to load app's bundle
        appBundle = [NSBundle bundleWithPath:appPath];
        
        //check for match
        // binary path's match
        if( (nil != appBundle) &&
            (YES == [appBundle.executablePath isEqualToString:binaryPath]))
        {
            //all done
            break;
        }
        
        //always unset bundle var since it's being returned
        // and at this point, its not a match
        appBundle = nil;
        
        //remove last part
        // will try this next
        appPath = [appPath stringByDeletingLastPathComponent];
        
    //scan until we get to root
    // of course, loop will be exited if app info dictionary is found/loaded
    } while( (nil != appPath) &&
             (YES != [appPath isEqualToString:@"/"]) &&
             (YES != [appPath isEqualToString:@""]) );
    
    return appBundle;
}

//hash a file
// algorithm: sha256
NSString* PI_hashFile(NSString* filePath)
{
    //file's contents
    NSData* fileContents = nil;

    //hash digest
    uint8_t digestSHA256[CC_SHA256_DIGEST_LENGTH] = {0};
    
    //hash as string
    NSMutableString* sha256 = nil;
    
    //index var
    NSUInteger index = 0;
    
    //init
    sha256 = [NSMutableString string];
    
    //load file
    if(nil == (fileContents = [NSData dataWithContentsOfFile:filePath]))
    {
        //bail
        goto bail;
    }

    //sha1 it
    CC_SHA256(fileContents.bytes, (unsigned int)fileContents.length, digestSHA256);
    
    //convert to NSString
    // iterate over each bytes in computed digest and format
    for(index=0; index < CC_SHA256_DIGEST_LENGTH; index++)
    {
        //format/append
        [sha256 appendFormat:@"%02lX", (unsigned long)digestSHA256[index]];
    }
    
bail:
    
    return sha256;
}

//given a 'short' path or process name
// try find the full path by scanning $PATH
NSString* PI_which(NSString* processName)
{
    //full path
    NSString* fullPath = nil;
    
    //get path
    NSString* path = nil;
    
    //tokenized paths
    NSArray* pathComponents = nil;
    
    //candidate file
    NSString* candidateBinary = nil;
    
    //get path
    path = [[[NSProcessInfo processInfo]environment]objectForKey:@"PATH"];
    
    //split on ':'
    pathComponents = [path componentsSeparatedByString:@":"];
    
    //iterate over all path components
    // build candidate path and check if it exists
    for(NSString* pathComponent in pathComponents)
    {
        //build candidate path
        // current path component + process name
        candidateBinary = [pathComponent stringByAppendingPathComponent:processName];
        
        //check if it exists
        if(YES == [[NSFileManager defaultManager] fileExistsAtPath:candidateBinary])
        {
            //check its executable
            if(YES == [[NSFileManager defaultManager] isExecutableFileAtPath:candidateBinary])
            {
                //ok, happy now
                fullPath = candidateBinary;
                
                //stop processing
                break;
            }
        }
        
    }//for path components
    
    return fullPath;
}

//exec a process with args
NSMutableDictionary* PI_execTask(NSString* binaryPath, NSArray* arguments, BOOL shouldWait, BOOL grabOutput)
{
    //task
    NSTask* task = nil;
    
    //output pipe for stdout
    NSPipe* stdOutPipe = nil;
    
    //output pipe for stderr
    NSPipe* stdErrPipe = nil;
    
    //read handle for stdout
    NSFileHandle* stdOutReadHandle = nil;
    
    //read handle for stderr
    NSFileHandle* stdErrReadHandle = nil;
    
    //results dictionary
    NSMutableDictionary* results = nil;
    
    //output for stdout
    NSMutableData *stdOutData = nil;
    
    //output for stderr
    NSMutableData *stdErrData = nil;
    
    //init dictionary for results
    results = [NSMutableDictionary dictionary];
    
    //init task
    task = [[NSTask alloc] init];
    
    //only setup pipes if wait flag is set
    if(YES == grabOutput)
    {
        //init stdout pipe
        stdOutPipe = [NSPipe pipe];
        
        //init stderr pipe
        stdErrPipe = [NSPipe pipe];
        
        //init stdout read handle
        stdOutReadHandle = [stdOutPipe fileHandleForReading];
        
        //init stderr read handle
        stdErrReadHandle = [stdErrPipe fileHandleForReading];
        
        //init stdout output buffer
        stdOutData = [NSMutableData data];
        
        //init stderr output buffer
        stdErrData = [NSMutableData data];
        
        //set task's stdout
        task.standardOutput = stdOutPipe;
        
        //set task's stderr
        task.standardError = stdErrPipe;
    }
    
    //set task's path
    task.launchPath = binaryPath;
    
    //set task's args
    if(nil != arguments)
    {
        //set
        task.arguments = arguments;
    }
    
    //wrap task launch
    @try
    {
        //launch
        [task launch];
    }
    @catch(NSException *exception)
    {
        //bail
        goto bail;
    }
    
    //no need to wait
    // can just bail w/ no output
    if( (YES != shouldWait) &&
        (YES != grabOutput) )
    {
        //bail
        goto bail;
    }
    
    
    //wait
    // ...but no output
    else if( (YES == shouldWait) &&
            (YES != grabOutput) )
    {
        //wait
        [task waitUntilExit];
        
        //add exit code
        results[EXIT_CODE] = [NSNumber numberWithInteger:task.terminationStatus];
        
        //bail
        goto bail;
    }
    
    //grab output?
    // even if wait not set, still will wait!
    else
    {
        //read in stdout/stderr
        while(YES == [task isRunning])
        {
            //accumulate stdout
            [stdOutData appendData:[stdOutReadHandle readDataToEndOfFile]];
            
            //accumulate stderr
            [stdErrData appendData:[stdErrReadHandle readDataToEndOfFile]];
        }
        
        //grab any leftover stdout
        [stdOutData appendData:[stdOutReadHandle readDataToEndOfFile]];
        
        //grab any leftover stderr
        [stdErrData appendData:[stdErrReadHandle readDataToEndOfFile]];
        
        //add stdout
        if(0 != stdOutData.length)
        {
            //add
            results[STDOUT] = stdOutData;
        }
        
        //add stderr
        if(0 != stdErrData.length)
        {
            //add
            results[STDERR] = stdErrData;
        }
        
        //add exit code
        results[EXIT_CODE] = [NSNumber numberWithInteger:task.terminationStatus];
    }
    
bail:
    
    return results;
}
