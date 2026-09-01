#ifndef _AOS_CARBON_JDK_H_
#define _AOS_CARBON_JDK_H_

/* Exact public Carbon/CoreServices subset consumed by the Darwin JDK. */
typedef SInt16 FSVolumeRefNum;
typedef OptionBits LSRequestedInfo;
typedef OptionBits LSItemInfoFlags;
typedef OptionBits LSRolesMask;
typedef OptionBits LSLaunchFlags;
typedef AEDesc AppleEvent;
typedef AEDesc AEKeyDesc;

typedef struct LSItemInfoRecord {
  LSItemInfoFlags flags;
  OSType filetype;
  OSType creator;
  CFStringRef extension;
} LSItemInfoRecord;

typedef struct LSApplicationParameters {
  CFIndex version;
  LSLaunchFlags flags;
  const FSRef *application;
  void *asyncLaunchRefCon;
  CFDictionaryRef environment;
  CFArrayRef argv;
  AppleEvent *initialEvent;
} LSApplicationParameters;

typedef struct OpaqueIconRef *IconRef;
typedef UInt32 HIThemeFocusRing;
typedef struct __TISInputSource *TISInputSourceRef;
typedef OptionBits ATSOptionFlags;
typedef UInt32 ATSFontContext;
typedef UInt32 ATSFontContainerRef;
typedef UInt32 ATSFontFormat;

typedef struct UCKeyboardTypeHeader {
  UInt32 keyboardTypeFirst;
  UInt32 keyboardTypeLast;
  UInt32 keyModifiersToTableNumOffset;
  UInt32 keyToCharTableIndexOffset;
  UInt32 keyStateRecordsIndexOffset;
  UInt32 keyStateTerminatorsOffset;
  UInt32 keySequenceDataIndexOffset;
} UCKeyboardTypeHeader;

typedef struct UCKeyboardLayout {
  UInt16 keyLayoutHeaderFormat;
  UInt16 keyLayoutDataVersion;
  UInt32 keyLayoutFeatureInfoOffset;
  UInt32 keyboardTypeCount;
  UCKeyboardTypeHeader keyboardTypeList[1];
} UCKeyboardLayout;

enum {
  kOnSystemDisk = -32768L,
  kSystemIconsCreator = 'macs',
  kFSPathMakeRefDoNotFollowLeafSymlink = 0x01,
  kResolveAliasFileNoUI = 0x00000001,
  kLSRequestBasicFlagsOnly = 0x00000004,
  kLSLaunchAndPrint = 0x00000002,
  kHIThemeFocusRingOnly = 0,
  kHIThemeFocusRingAbove = 1,
  kHIThemeFocusRingBelow = 2,
  kUCKeyActionDown = 0,
  kUCKeyTranslateNoDeadKeysBit = 0,
  kATSFontContextLocal = 2,
  kATSFontFormatUnspecified = 0,
};

extern const CFStringRef kTISPropertyUnicodeKeyLayoutData;

OSStatus FSPathMakeRef(const UInt8 *path, FSRef *ref, Boolean *isDirectory);
OSStatus FSPathMakeRefWithOptions(
  const UInt8 *path,
  OptionBits options,
  FSRef *ref,
  Boolean *isDirectory
);
OSErr FSResolveAliasFileWithMountFlags(
  FSRef *theRef,
  Boolean resolveAliasChains,
  Boolean *targetIsFolder,
  Boolean *wasAliased,
  unsigned long mountFlags
);
OSStatus LSCopyItemInfoForRef(
  const FSRef *inItemRef,
  LSRequestedInfo inWhichInfo,
  LSItemInfoRecord *outItemInfo
);
OSStatus LSCopyDisplayNameForRef(const FSRef *inRef, CFStringRef *outDisplayName);
OSStatus LSOpenURLsWithRole(
  CFArrayRef inURLs,
  LSRolesMask inRole,
  const AEKeyDesc *inAEParam,
  const LSApplicationParameters *inAppParams,
  ProcessSerialNumber *outPSNs,
  CFIndex inMaxPSNCount
);
OSErr GetIconRef(SInt16 vRefNum, OSType creator, OSType iconType, IconRef *theIconRef);
OSErr ReleaseIconRef(IconRef theIconRef);
OSStatus HIThemeBeginFocus(
  CGContextRef inContext,
  HIThemeFocusRing inRingStyle,
  void *inReserved
);
OSStatus HIThemeEndFocus(CGContextRef inContext);
TISInputSourceRef TISCopyCurrentKeyboardInputSource(void);
void *TISGetInputSourceProperty(TISInputSourceRef inputSource, CFStringRef propertyKey);
OSStatus UCKeyTranslate(
  const UCKeyboardLayout *keyLayoutPtr,
  UInt16 virtualKeyCode,
  UInt16 keyAction,
  UInt32 modifierKeyState,
  UInt32 keyboardType,
  OptionBits keyTranslateOptions,
  UInt32 *deadKeyState,
  UniCharCount maxStringLength,
  UniCharCount *actualStringLength,
  UniChar unicodeString[]
);
UInt32 GetCurrentEventKeyModifiers(void);
UInt8 LMGetKbdType(void);
#define MacGetCurrentProcess GetCurrentProcess
OSErr MacGetCurrentProcess(ProcessSerialNumber *psn);
OSStatus ATSFontActivateFromFileReference(
  const FSRef *iFile,
  ATSFontContext iContext,
  ATSFontFormat iFormat,
  void *iReserved,
  ATSOptionFlags iOptions,
  ATSFontContainerRef *oContainer
);

#endif
