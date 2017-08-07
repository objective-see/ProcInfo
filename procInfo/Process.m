//
//  File: Process.m
//  Project: Proc Info
//
//  Created by: Patrick Wardle
//  Copyright:  2017 Objective-See
//  License:    Creative Commons Attribution-NonCommercial 4.0 International License
//

#import "procInfo.h"
#import "Utilities.h"

@implementation Process

@synthesize pid;
@synthesize exit;
@synthesize path;
@synthesize ppid;
@synthesize ancestors;
@synthesize arguments;
@synthesize timestamp;

//init
-(id)init
{
    //init super
    self = [super init];
    if(nil != self)
    {
        //alloc args
        arguments = [NSMutableArray array];
        
        //alloc parents
        ancestors  = [NSMutableArray array];
        
        //set start time
        timestamp = [NSDate date];
        
        //init pid
        self.pid = -1;
        
        //init ppid
        self.ppid = -1;
        
        //init user
        self.user = -1;
        
        //init exit
        self.exit = -1;

    }
    
    return self;
}

//init with a pid
// ->method will then (try) fill out rest of object
-(id)init:(pid_t)processID
{
    //init self/super
    self = [self init];
    if(self)
    {
        //save pid
        self.pid = processID;
        
        //set parent
        self.ppid = getppid();
        
        //get path
        [self pathFromPid];
        if(nil == self.path)
        {
            //err msg
            NSLog(@"ERROR: failed to find path for process %d\n", self.pid);
            
            //unset
            self = nil;
            
            //bail
            goto bail;
        }
        
        //set args
        [self getArgs];
        
        //set user
        [self getUser];
        
        //enum ancestors
        [self enumerateAncestors];
    
        //init binary
        self.binary = [[Binary alloc] init:self.path];
    }
    
bail:
    
    return self;
}

//get uid
// ->sets 'user' instance var
-(void)getUser
{
    //kinfo_proc struct
    struct kinfo_proc processStruct = {0};
    
    //size
    size_t procBufferSize = 0;
    
    //mib
    const u_int mibLength = 4;
    
    //syscall result
    int sysctlResult = -1;
    
    //init buffer length
    procBufferSize = sizeof(processStruct);
    
    //init mib
    int mib[mibLength] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, self.pid};
    
    //make syscall
    sysctlResult = sysctl(mib, mibLength, &processStruct, &procBufferSize, NULL, 0);
    
    //check if got ppid
    if( (noErr == sysctlResult) &&
        (0 != procBufferSize) )
    {
        //save uuid
        self.user = processStruct.kp_eproc.e_ucred.cr_uid;
    }
    
    return;
}

//generate list of ancestors
-(void)enumerateAncestors
{
    //current process id
    pid_t currentPID = -1;
    
    //parent pid
    pid_t parentPID = -1;
    
    //add parent
    if(-1 != self.ppid)
    {
        //add
        [self.ancestors addObject:[NSNumber numberWithInt:self.ppid]];
        
        //set current to parent
        currentPID = self.ppid;
    }
    //don't know parent
    // ->just start with self
    else
    {
        //start w/ self
        currentPID = self.pid;
    }
    
    //add until we get to to end (pid 0)
    // ->or error out during the traversal
    while(YES)
    {
        //get parent pid
        parentPID = [Process getParentID:currentPID];
        if( (0 == parentPID) ||
            (-1 == parentPID) ||
            (currentPID == parentPID) )
        {
            //bail
            break;
        }
        
        //update
        currentPID = parentPID;
        
        //add
        [self.ancestors addObject:[NSNumber numberWithInt:parentPID]];
    }
    
    return;
}

//set process's path
-(void)pathFromPid
{
    //buffer for process path
    char pathBuffer[PROC_PIDPATHINFO_MAXSIZE] = {0};
    
    //status
    int status = -1;
    
    //'management info base' array
    int mib[3] = {0};
    
    //system's size for max args
    int systemMaxArgs = 0;
    
    //process's args
    char* processArgs = NULL;
    
    //size of buffers, etc
    size_t size = 0;
    
    //clear out buffer
    bzero(pathBuffer, PROC_PIDPATHINFO_MAXSIZE);
    
    //first attempt to get path via 'proc_pidpath()'
    status = proc_pidpath(self.pid, pathBuffer, sizeof(pathBuffer));
    if(0 != status)
    {
        //init path
        self.path = [NSString stringWithUTF8String:pathBuffer];
    }
    //otherwise
    // ->try via process's args ('KERN_PROCARGS2')
    else
    {
        //init mib
        // ->want system's size for max args
        mib[0] = CTL_KERN;
        mib[1] = KERN_ARGMAX;
        
        //set size
        size = sizeof(systemMaxArgs);
        
        //get system's size for max args
        if(-1 == sysctl(mib, 2, &systemMaxArgs, &size, NULL, 0))
        {
            //bail
            goto bail;
        }
        
        //alloc space for args
        processArgs = malloc(systemMaxArgs);
        if(NULL == processArgs)
        {
            //bail
            goto bail;
        }
        
        //init mib
        // ->want process args
        mib[0] = CTL_KERN;
        mib[1] = KERN_PROCARGS2;
        mib[2] = pid;
        
        //set size
        size = (size_t)systemMaxArgs;
        
        //get process's args
        if(-1 == sysctl(mib, 3, processArgs, &size, NULL, 0))
        {
            //bail
            goto bail;
        }
        
        //sanity check
        // ->ensure buffer is somewhat sane
        if(size <= sizeof(int))
        {
            //bail
            goto bail;
        }
        
        //extract process name
        // ->follows # of args (int) and is NULL-terminated
        self.path = [NSString stringWithUTF8String:processArgs + sizeof(int)];
    }
    
bail:
    
    //free process args
    if(NULL != processArgs)
    {
        //free
        free(processArgs);
        
        //unset
        processArgs = NULL;
    }
    
    return;
}

//check if process is alive
-(BOOL)isProcessAlive
{
    //ret var
    BOOL bIsAlive = NO;
    
    //signal status
    int signalStatus = -1;
    
    //send kill with 0 to determine if alive
    // -> see: http://stackoverflow.com/questions/9152979/check-if-process-exists-given-its-pid
    signalStatus = kill(self.pid, 0);
    
    //is alive?
    if( (0 == signalStatus) ||
        ( (0 != signalStatus) && (errno != ESRCH) ) )
    {
        //alive!
        bIsAlive = YES;
    }
    
    return bIsAlive;
}

//extract commandline args
//  ->saves into 'arguments' ivar
-(void)getArgs
{
    //'management info base' array
    int mib[3] = {0};
    
    //system's size for max args
    int systemMaxArgs = 0;
    
    //process's args
    char* processArgs = NULL;
    
    //# of args
    int numberOfArgs = 0;
    
    //start of (each) arg
    char* argStart = NULL;
    
    //size of buffers, etc
    size_t size = 0;
    
    //parser pointer
    char* parser = NULL;
    
    //init mib
    // ->want system's size for max args
    mib[0] = CTL_KERN;
    mib[1] = KERN_ARGMAX;
    
    //alloc array for args
    arguments = [NSMutableArray array];
    
    //set size
    size = sizeof(systemMaxArgs);
    
    //get system's size for max args
    if(-1 == sysctl(mib, 2, &systemMaxArgs, &size, NULL, 0))
    {
        //bail
        goto bail;
    }
    
    //alloc space for args
    processArgs = malloc(systemMaxArgs);
    if(NULL == processArgs)
    {
        //bail
        goto bail;
    }
    
    //init mib
    // ->want process args
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROCARGS2;
    mib[2] = pid;
    
    //set size
    size = (size_t)systemMaxArgs;
    
    //get process's args
    if(-1 == sysctl(mib, 3, processArgs, &size, NULL, 0))
    {
        //bail
        goto bail;
    }
    
    //sanity check
    // ->ensure buffer is somewhat sane
    if(size <= sizeof(int))
    {
        //bail
        goto bail;
    }
    
    //extract number of args
    // ->at start of buffer
    memcpy(&numberOfArgs, processArgs, sizeof(numberOfArgs));
    

    //init pointer to start of args
    // ->they start right after # of args
    parser = processArgs + sizeof(numberOfArgs);
    
    //scan until end of process's NULL-terminated path
    while(parser < &processArgs[size])
    {
        //scan till NULL-terminator
        if(0x0 == *parser)
        {
            //end of exe name
            break;
        }
        
        //next char
        parser++;
    }
    
    //sanity check
    // ->make sure end-of-buffer wasn't reached
    if(parser == &processArgs[size])
    {
        //bail
        goto bail;
    }
    
    //skip all trailing NULLs
    // ->scan will end when non-NULL is found
    while(parser < &processArgs[size])
    {
        //scan till NULL-terminator
        if(0x0 != *parser)
        {
            //ok, got to argv[0]
            break;
        }
        
        //next char
        parser++;
    }
    
    //sanity check
    // ->(again), make sure end-of-buffer wasn't reached
    if(parser == &processArgs[size])
    {
        //bail
        goto bail;
    }
    
    //parser should now point to argv[0], process name
    // ->init arg start
    argStart = parser;
    
    //keep scanning until all args are found
    // ->each is NULL-terminated
    while(parser < &processArgs[size])
    {
        //each arg is NULL-terminated
        // ->so scan till NULL, then save into array
        if(*parser == '\0')
        {
            //save arg
            if(NULL != argStart)
            {
                //save
                [self.arguments addObject:[NSString stringWithUTF8String:argStart]];
            }
            
            //init string pointer to (possibly) next arg
            argStart = ++parser;
            
            //bail if we've hit arg cnt
            if(self.arguments.count == numberOfArgs)
            {
                //bail
                break;
            }
        }
        
        //next char
        parser++;
    }
    
bail:
    
    //free process args
    if(NULL != processArgs)
    {
        //free
        free(processArgs);
        
        //unset
        processArgs = NULL;
    }
    
    return;
}

//for pretty printing
-(NSString *)description
{
    //pretty print
    return [NSString stringWithFormat: @"%d:%@\nuser: %d\nargs: %@\nancestors: %@\nbinary: %@", self.pid, self.path, self.user, self.arguments, self.ancestors, self.binary];
}

//class method to get parent of arbitrary process
+(pid_t)getParentID:(pid_t)child
{
    //parent id
    pid_t parentID = -1;
    
    //kinfo_proc struct
    struct kinfo_proc processStruct = {0};
    
    //size
    size_t procBufferSize = 0;
    
    //mib
    const u_int mibLength = 4;
    
    //syscall result
    int sysctlResult = -1;
    
    //init buffer length
    procBufferSize = sizeof(processStruct);
    
    //init mib
    int mib[mibLength] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, child};
    
    //make syscall
    sysctlResult = sysctl(mib, mibLength, &processStruct, &procBufferSize, NULL, 0);
    
    //check if got ppid
    if( (noErr == sysctlResult) &&
        (0 != procBufferSize) )
    {
        //save ppid
        parentID = processStruct.kp_eproc.e_ppid;
    }
    
    return parentID;
}


@end
