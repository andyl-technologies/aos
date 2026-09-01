#ifndef __APPLICATIONSERVICES__
#define __APPLICATIONSERVICES__

#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <CoreServices/CoreServices.h>
#include <CoreText/CoreText.h>

CF_EXTERN_C_BEGIN
typedef SInt32 AXError;
enum {
  kAXErrorFailure = -25200,
  kAXErrorIllegalArgument = -25201
};
#define kAXMenuOpenedNotification CFSTR("AXMenuOpened")
#define kAXMenuClosedNotification CFSTR("AXMenuClosed")
#define kAXMenuItemSelectedNotification CFSTR("AXMenuItemSelected")
typedef const struct __AXUIElement *AXUIElementRef;

AXUIElementRef AXUIElementCreateSystemWide(void);
AXError AXUIElementPostKeyboardEvent(
  AXUIElementRef application,
  CGCharCode keyChar,
  CGKeyCode virtualKey,
  Boolean keyDown
);

typedef struct OpaquePMPrintSettings *PMPrintSettings;
typedef UInt32 PMDuplexMode;
enum {
  kPMDuplexNone = 0x0001,
  kPMDuplexNoTumble = 0x0002,
  kPMDuplexTumble = 0x0003,
  kPMSimplexTumble = 0x0004,
};
OSStatus PMGetDuplex(PMPrintSettings printSettings, PMDuplexMode *duplexSetting);
OSStatus PMSetDuplex(PMPrintSettings printSettings, PMDuplexMode duplexSetting);

typedef UInt32 LSLaunchFlags;
enum { kLSLaunchDefaults = 0x00000001 };

typedef UInt32 LSRolesMask;
enum { kLSRolesAll = 0xffffffffU };

enum {
  kLSUnknownCreator = 0,
  kLSApplicationNotFoundErr = -10814
};

typedef struct AEDesc AEDesc;
typedef struct FSRef { UInt8 hidden[80]; } FSRef;

typedef struct LSLaunchURLSpec {
  CFURLRef appURL;
  CFArrayRef itemURLs;
  const AEDesc *passThruParams;
  LSLaunchFlags launchFlags;
  void *asyncRefCon;
} LSLaunchURLSpec;

CFArrayRef LSCopyApplicationURLsForBundleIdentifier(
  CFStringRef bundleIdentifier,
  CFErrorRef *error
);
OSStatus LSFindApplicationForInfo(
  OSType creator,
  CFStringRef bundleIdentifier,
  CFStringRef name,
  FSRef *applicationRef,
  CFURLRef *applicationURL
);
OSStatus LSOpenFromURLSpec(const LSLaunchURLSpec *urlSpec, CFURLRef *launchedURL);
CF_EXPORT OSStatus LSOpenCFURLRef(CFURLRef inURL, CFURLRef *outLaunchedURL);
CFArrayRef LSCopyAllHandlersForURLScheme(CFStringRef scheme);
CFArrayRef LSCopyAllRoleHandlersForContentType(
  CFStringRef contentType,
  LSRolesMask roles
);
CFURLRef LSCopyDefaultApplicationURLForContentType(
  CFStringRef contentType,
  LSRolesMask roles,
  CFErrorRef *error
);
CFStringRef LSCopyDefaultRoleHandlerForContentType(
  CFStringRef contentType,
  LSRolesMask roles
);
CFStringRef LSCopyDefaultHandlerForURLScheme(CFStringRef scheme);
CF_EXTERN_C_END

#endif
