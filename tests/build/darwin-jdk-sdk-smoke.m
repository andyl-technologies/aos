#import <Cocoa/Cocoa.h>
#include <Carbon/Carbon.h>

#define AOS_SUBCLASS(name, superclass) \
  @interface name : superclass @end \
  @implementation name @end

AOS_SUBCLASS(AOSSmokeAppleEventDescriptor, NSAppleEventDescriptor)
AOS_SUBCLASS(AOSSmokeAppleEventManager, NSAppleEventManager)
AOS_SUBCLASS(AOSSmokeDate, NSDate)
AOS_SUBCLASS(AOSSmokeFileManager, NSFileManager)
AOS_SUBCLASS(AOSSmokeInvocation, NSInvocation)
AOS_SUBCLASS(AOSSmokeMethodSignature, NSMethodSignature)
AOS_SUBCLASS(AOSSmokeMutableData, NSMutableData)
AOS_SUBCLASS(AOSSmokeMutableSet, NSMutableSet)
AOS_SUBCLASS(AOSSmokeNotificationCenter, NSNotificationCenter)
AOS_SUBCLASS(AOSSmokeNull, NSNull)
AOS_SUBCLASS(AOSSmokeSet, NSSet)
AOS_SUBCLASS(AOSSmokeValue, NSValue)

@interface AOSSmokeApplicationDelegate : NSObject <NSApplicationDelegate>
@end

@implementation AOSSmokeApplicationDelegate
- (void)application:(NSApplication *)sender openFiles:(NSArray<NSString *> *)filenames {
  (void)sender;
  (void)filenames;
}

- (NSApplicationPrintReply)application:(NSApplication *)application
                             printFiles:(NSArray<NSString *> *)fileNames
                           withSettings:(NSDictionary *)printSettings
                        showPrintPanels:(BOOL)showPrintPanels {
  (void)application;
  (void)fileNames;
  (void)printSettings;
  return showPrintPanels ? NSPrintingSuccess : NSPrintingCancelled;
}

- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender
                    hasVisibleWindows:(BOOL)flag {
  (void)sender;
  return flag;
}

- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender {
  (void)sender;
  return NSTerminateLater;
}
@end

int main(int argc, char **argv) {
  NSDate *date = [NSDate dateWithTimeIntervalSince1970:0.0];
  NSTimeInterval interval = [date timeIntervalSince1970];
  NSString *string = [NSString stringWithString:[NSString stringWithUTF8String:"aos"]];
  unichar character = 0;
  [string getCharacters:&character];
  NSString *bytesString = [[NSString alloc] initWithBytes:"aos" length:3 encoding:NSUTF8StringEncoding];

  NSNumber *number = [NSNumber numberWithFloat:1.0f];
  number = [NSNumber numberWithChar:(char)[number floatValue]];
  NSMutableData *data = [NSMutableData dataWithLength:8];
  [data getBytes:[data mutableBytes]];

  NSMutableArray *array = [NSMutableArray arrayWithCapacity:2];
  [array addObject:string];
  NSArray *objects = [[NSArray alloc] initWithObjects:string, number, nil];
  NSEnumerator *objectEnumerator = [objects objectEnumerator];
  [array removeAllObjects];

  NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
  [dictionary setObject:string forKey:string];
  NSEnumerator *keyEnumerator = [dictionary keyEnumerator];
  NSArray *keys = [dictionary allKeys];
  NSMutableSet *set = [[NSMutableSet alloc] init];
  [set addObject:[NSNull null]];

  NSFileManager *fileManager = [NSFileManager defaultManager];
  const char *path = [fileManager fileSystemRepresentationWithPath:string];
  NSString *roundTrip = [fileManager stringWithFileSystemRepresentation:path length:3];

  NSMethodSignature *signature = [AOSSmokeValue instanceMethodSignatureForSelector:@selector(objCType)];
  NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
  [invocation retainArguments];
  [invocation setSelector:@selector(objCType)];
  [invocation setTarget:[NSValue valueWithBytes:&interval objCType:@encode(NSTimeInterval)]];
  [invocation setArgument:&interval atIndex:2];
  [invocation invoke];
  const char *returnValue = NULL;
  [invocation getReturnValue:&returnValue];

  NSValue *value = [NSValue valueWithBytes:&interval objCType:@encode(NSTimeInterval)];
  NSSize size = [value sizeValue];
  NSPoint point = [value pointValue];
  NSRange range = [value rangeValue];
  NSRect rect = [value rectValue];

  NSAppleEventDescriptor *descriptor = [NSAppleEventDescriptor descriptorWithDescriptorType:kAEGetURL data:data];
  descriptor = [NSAppleEventDescriptor descriptorWithDescriptorType:kInternetEventClass bytes:"aos" length:3];
  descriptor = [descriptor coerceToDescriptorType:kAEGetURL];
  [descriptor insertDescriptor:[NSAppleEventDescriptor descriptorWithString:string] atIndex:1];
  [descriptor setDescriptor:[NSAppleEventDescriptor descriptorWithBoolean:YES] forKeyword:kAEGetURL];
  NSAppleEventDescriptor *indexed = [descriptor descriptorAtIndex:1];
  AEKeyword keyword = [descriptor keywordForDescriptorAtIndex:1];
  const AEDesc *aeDesc = [descriptor aeDesc];
  NSData *descriptorData = [descriptor data];
  int32_t integer = [[NSAppleEventDescriptor descriptorWithInt32:1] int32Value];
  BOOL boolean = [[NSAppleEventDescriptor nullDescriptor] booleanValue];
  NSInteger itemCount = [[NSAppleEventDescriptor listDescriptor] numberOfItems];
  DescType descriptorType = [[NSAppleEventDescriptor recordDescriptor] descriptorType];

  NSAppleEventManager *manager = [NSAppleEventManager sharedAppleEventManager];
  [manager setEventHandler:manager andSelector:@selector(description) forEventClass:kInternetEventClass andEventID:kAEGetURL];
  [manager removeEventHandlerForEventClass:kInternetEventClass andEventID:kAEGetURL];
  NSNotificationCenter *center = [NSNotificationCenter defaultCenter];
  [center addObserver:center selector:@selector(description) name:NSApplicationWillFinishLaunchingNotification object:nil];
  [center removeObserver:center];

  NSImage *image = [[NSImage alloc] initWithData:data];
  NSData *tiff = [image TIFFRepresentation];
  const void *volatile dataSymbols[] = {
    NSDefaultRunLoopMode,
    NSInvalidArgumentException,
    NSModalPanelRunLoopMode,
    NSEventTrackingRunLoopMode,
    NSApplicationWillFinishLaunchingNotification,
    NSWorkspaceWillPowerOffNotification,
    NSApplicationDidBecomeActiveNotification,
    NSApplicationDidResignActiveNotification,
    NSApplicationDidHideNotification,
    NSApplicationDidUnhideNotification
  };

  if (argc > 10) {
    NSException *exception = [[NSException alloc] initWithName:NSInvalidArgumentException reason:string userInfo:dictionary];
    [NSException raise:NSInvalidArgumentException format:@"%@", [exception reason]];
    [exception raise];
    [exception performSelectorOnMainThread:@selector(description) withObject:nil waitUntilDone:NO modes:@[ NSDefaultRunLoopMode ]];
  }

  [bytesString release];
  [objects autorelease];
  [image release];
  return argv == NULL || character == 0 || interval < 0 || number == nil || data.length == 0 || objectEnumerator == nil || keyEnumerator == nil || keys.count == 0 || set == nil || roundTrip == nil || returnValue == NULL || size.width != point.x || range.length == rect.size.height || indexed == nil || keyword == 0 || aeDesc == NULL || descriptorData == nil || integer == 0 || boolean || itemCount < 0 || descriptorType == 0 || tiff == nil || dataSymbols[0] == NULL;
}
