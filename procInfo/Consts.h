//
//  File: Consts.h
//  Project: Proc Info
//
//  Created by: Patrick Wardle
//  Copyright:  2017 Objective-See
//  License:    Creative Commons Attribution-NonCommercial 4.0 International License
//

#ifndef Consts_h
#define Consts_h

//OS version x
#define OS_MAJOR_VERSION_X 10

//OS version lion
#define OS_MINOR_VERSION_LION 8

//OS version sierra
#define OS_MINOR_VERSION_SIERRA 12

//audit pipe
#define AUDIT_PIPE "/dev/auditpipe"

//audit class for proc events
#define AUDIT_CLASS_PROCESS 0x00000080

//audit class for exec events
#define AUDIT_CLASS_EXEC 0x40000000

//signature status
#define KEY_SIGNATURE_STATUS @"signatureStatus"

//signing auths
#define KEY_SIGNING_AUTHORITIES @"signingAuthorities"

//file belongs to apple?
#define KEY_SIGNING_IS_APPLE @"signedByApple"

//file signed with apple dev id
#define KEY_SIGNING_IS_APPLE_DEV_ID @"signedWithDevID"

//from app store
#define KEY_SIGNING_IS_APP_STORE @"fromAppStore"

//key for exit code
#define EXIT_CODE @"exitCode"

#endif /* Consts_h */
