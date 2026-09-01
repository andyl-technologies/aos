#ifndef __CORESERVICES__
#define __CORESERVICES__

#include <CFNetwork/CFNetwork.h>
#include <CoreFoundation/CoreFoundation.h>
#include <MacTypes.h>
#include <dispatch/dispatch.h>
#include <stdint.h>
#include <sys/types.h>
#include <CoreServices/JDKSurface.h>

CF_EXTERN_C_BEGIN

/*
 * Apple's public MacLocales.h declares this legacy locale mapping
 * API with a NUL-terminated ASCII locale string and MacTypes ABI
 * result codes. CPack uses it to encode Script Manager region codes
 * in multilingual disk-image license resources.
 */
enum {
  kLocalesBufferTooSmallErr = -30001,
  kLocalesTableFormatErr = -30002,
  kLocalesDefaultDisplayStatus = -30029
};
OSStatus LocaleStringToLangAndRegionCodes(
  const char localeString[],
  LangCode *lang,
  RegionCode *region
);

Boolean UTTypeEqual(CFStringRef inUTI1, CFStringRef inUTI2);
Boolean UTTypeConformsTo(CFStringRef inUTI, CFStringRef inConformsToUTI);
CFStringRef UTTypeCopyDescription(CFStringRef inUTI);
CFStringRef UTTypeCreatePreferredIdentifierForTag(
  CFStringRef inTagClass,
  CFStringRef inTag,
  CFStringRef inConformingToUTI
);
CFStringRef UTTypeCopyPreferredTagWithClass(
  CFStringRef inUTI,
  CFStringRef inTagClass
);
CF_EXPORT const CFStringRef kUTTypeApplication;
CF_EXPORT const CFStringRef kUTTypeVolume;
CF_EXPORT const CFStringRef kUTTypeFolder;
CF_EXPORT const CFStringRef kUTTypeXML;
CF_EXPORT const CFStringRef kUTTagClassMIMEType;
CF_EXPORT const CFStringRef kUTTagClassFilenameExtension;

typedef uint64_t FSEventStreamEventId;
typedef uint32_t FSEventStreamCreateFlags;
typedef uint32_t FSEventStreamEventFlags;
typedef struct __FSEventStream *FSEventStreamRef;
typedef const struct __FSEventStream *ConstFSEventStreamRef;
typedef void (*FSEventStreamCallback)(
  ConstFSEventStreamRef streamRef,
  void *clientCallBackInfo,
  size_t numEvents,
  void *eventPaths,
  const FSEventStreamEventFlags eventFlags[],
  const FSEventStreamEventId eventIds[]
);
typedef struct {
  CFIndex version;
  void *info;
  const void *(*retain)(const void *info);
  void (*release)(const void *info);
  CFStringRef (*copyDescription)(const void *info);
} FSEventStreamContext;

enum {
  kFSEventStreamCreateFlagNone = 0x00000000,
  kFSEventStreamCreateFlagUseCFTypes = 0x00000001,
  kFSEventStreamCreateFlagNoDefer = 0x00000002,
  kFSEventStreamCreateFlagWatchRoot = 0x00000004,
  kFSEventStreamCreateFlagIgnoreSelf = 0x00000008,
  kFSEventStreamCreateFlagFileEvents = 0x00000010,
  kFSEventStreamCreateFlagMarkSelf = 0x00000020,
  kFSEventStreamCreateFlagUseExtendedData = 0x00000040,
  kFSEventStreamCreateFlagFullHistory = 0x00000080,
  kFSEventStreamCreateFlagWithDocID = 0x00000100
};
enum {
  kFSEventStreamEventFlagNone = 0x00000000,
  kFSEventStreamEventFlagMustScanSubDirs = 0x00000001,
  kFSEventStreamEventFlagUserDropped = 0x00000002,
  kFSEventStreamEventFlagKernelDropped = 0x00000004,
  kFSEventStreamEventFlagEventIdsWrapped = 0x00000008,
  kFSEventStreamEventFlagHistoryDone = 0x00000010,
  kFSEventStreamEventFlagRootChanged = 0x00000020,
  kFSEventStreamEventFlagMount = 0x00000040,
  kFSEventStreamEventFlagUnmount = 0x00000080,
  kFSEventStreamEventFlagItemCreated = 0x00000100,
  kFSEventStreamEventFlagItemRemoved = 0x00000200,
  kFSEventStreamEventFlagItemInodeMetaMod = 0x00000400,
  kFSEventStreamEventFlagItemRenamed = 0x00000800,
  kFSEventStreamEventFlagItemModified = 0x00001000,
  kFSEventStreamEventFlagItemFinderInfoMod = 0x00002000,
  kFSEventStreamEventFlagItemChangeOwner = 0x00004000,
  kFSEventStreamEventFlagItemXattrMod = 0x00008000,
  kFSEventStreamEventFlagItemIsFile = 0x00010000,
  kFSEventStreamEventFlagItemIsDir = 0x00020000,
  kFSEventStreamEventFlagItemIsSymlink = 0x00040000,
  kFSEventStreamEventFlagOwnEvent = 0x00080000,
  kFSEventStreamEventFlagItemIsHardlink = 0x00100000,
  kFSEventStreamEventFlagItemIsLastHardlink = 0x00200000,
  kFSEventStreamEventFlagItemCloned = 0x00400000
};

#define kFSEventStreamEventIdSinceNow ((FSEventStreamEventId)UINT64_MAX)

FSEventStreamRef FSEventStreamCreate(
  CFAllocatorRef allocator,
  FSEventStreamCallback callback,
  FSEventStreamContext *context,
  CFArrayRef pathsToWatch,
  FSEventStreamEventId sinceWhen,
  CFTimeInterval latency,
  FSEventStreamCreateFlags flags
);
void FSEventStreamSetDispatchQueue(FSEventStreamRef streamRef, dispatch_queue_t queue);
void FSEventStreamScheduleWithRunLoop(
  FSEventStreamRef streamRef,
  CFRunLoopRef runLoop,
  CFStringRef runLoopMode
);
Boolean FSEventStreamStart(FSEventStreamRef streamRef);
void FSEventStreamStop(FSEventStreamRef streamRef);
void FSEventStreamInvalidate(FSEventStreamRef streamRef);
void FSEventStreamRelease(FSEventStreamRef streamRef);
dev_t FSEventStreamGetDeviceBeingWatched(ConstFSEventStreamRef streamRef);
FSEventStreamEventId FSEventsGetCurrentEventId(void);
Boolean FSEventsPurgeEventsForDeviceUpToEventId(dev_t device, FSEventStreamEventId eventId);

CF_EXTERN_C_END

#endif
