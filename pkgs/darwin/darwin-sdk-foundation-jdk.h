#ifndef _AOS_FOUNDATION_JDK_H_
#define _AOS_FOUNDATION_JDK_H_
#import <Foundation/NSDate.h>
#import <Foundation/NSString.h>
#import <Foundation/NSValue.h>
#include <Carbon/Carbon.h>
#include <limits.h>

#define NSIntegerMax LONG_MAX
#define NSUIntegerMax ULONG_MAX
enum { NSNotFound = NSIntegerMax };
NS_INLINE NSUInteger NSMaxRange(NSRange range) {
  return range.location + range.length;
}

typedef NSString *NSExceptionName;
typedef NSString *NSNotificationName;
typedef NSString *NSRunLoopMode;
typedef NSRange *NSRangePointer;
typedef NSUInteger NSStringCompareOptions;
enum { NSBackwardsSearch = 1UL << 2 };

typedef NSComparisonResult (^NSComparator)(id object1, id object2);

extern NSExceptionName const NSInvalidArgumentException;
extern NSExceptionName const NSMallocException;
extern NSRunLoopMode const NSDefaultRunLoopMode;

typedef void NSUncaughtExceptionHandler(NSException *exception);
extern void NSSetUncaughtExceptionHandler(NSUncaughtExceptionHandler *handler);
extern SEL NSSelectorFromString(NSString *aSelectorName);

@class NSAppleEventDescriptor;
@class NSMethodSignature;
@class NSPort;

@interface NSObject (AOSJDKSurface)
+ (instancetype)alloc;
+ (Class)class;
+ (NSMethodSignature *)instanceMethodSignatureForSelector:(SEL)aSelector;
- (instancetype)init;
- (instancetype)autorelease;
- (oneway void)release;
- (void)dealloc;
- (Class)class;
- (BOOL)isKindOfClass:(Class)aClass;
- (void)performSelectorOnMainThread:(SEL)aSelector
                         withObject:(id)argument
                      waitUntilDone:(BOOL)wait
                              modes:(NSArray<NSRunLoopMode> *)array;
- (void)performSelectorOnMainThread:(SEL)aSelector
                         withObject:(id)argument
                      waitUntilDone:(BOOL)wait;
- (id)valueForKey:(NSString *)key;
- (void)setValue:(id)value forKey:(NSString *)key;
- (BOOL)isCaseInsensitiveLike:(NSString *)object;
- (BOOL)isEqualTo:(id)object;
@end

@interface NSException (AOSJDKSurface)
+ (NSException *)exceptionWithName:(NSExceptionName)name
                            reason:(NSString *)reason
                          userInfo:(NSDictionary *)userInfo;
+ (void)raise:(NSExceptionName)name format:(NSString *)format, ...;
- (instancetype)initWithName:(NSExceptionName)aName
                       reason:(NSString *)aReason
                     userInfo:(NSDictionary *)aUserInfo;
- (void)raise;
- (NSString *)reason;
- (NSString *)description;
@end

@interface NSNumber (AOSJDKSurface)
+ (NSNumber *)numberWithChar:(char)value;
+ (NSNumber *)numberWithFloat:(float)value;
+ (NSNumber *)numberWithUnsignedInt:(unsigned int)value;
+ (NSNumber *)numberWithInteger:(NSInteger)value;
- (char)charValue;
- (float)floatValue;
- (NSInteger)integerValue;
@end

@interface NSData (AOSJDKSurface)
+ (instancetype)dataWithBytes:(const void *)bytes length:(NSUInteger)length;
+ (instancetype)dataWithBytesNoCopy:(void *)bytes
                              length:(NSUInteger)length
                        freeWhenDone:(BOOL)flag;
- (instancetype)initWithBytesNoCopy:(void *)bytes
                              length:(NSUInteger)length
                        freeWhenDone:(BOOL)flag;
- (void)getBytes:(void *)buffer;
@end

@interface NSMutableData : NSData
+ (instancetype)dataWithLength:(NSUInteger)length;
- (void *)mutableBytes;
@end

@interface NSArray<ObjectType> (AOSJDKSurface)
+ (instancetype)array;
+ (instancetype)arrayWithObject:(ObjectType)anObject;
+ (instancetype)arrayWithObjects:(ObjectType)firstObject, ...;
- (instancetype)initWithObjects:(ObjectType)firstObject, ...;
- (NSUInteger)count;
- (NSEnumerator<ObjectType> *)objectEnumerator;
- (BOOL)containsObject:(ObjectType)object;
- (NSUInteger)indexOfObject:(ObjectType)anObject;
- (ObjectType)lastObject;
- (NSArray<ObjectType> *)arrayByAddingObject:(ObjectType)anObject;
- (void)enumerateObjectsUsingBlock:(void (^)(ObjectType object, NSUInteger idx, BOOL *stop))block;
- (NSUInteger)indexOfObjectPassingTest:(BOOL (^)(ObjectType object, NSUInteger idx, BOOL *stop))predicate;
- (NSArray<ObjectType> *)sortedArrayUsingComparator:(NSComparator)comparator;
@end

@interface NSMutableArray<ObjectType> (AOSJDKSurface)
+ (instancetype)array;
+ (instancetype)arrayWithCapacity:(NSUInteger)numItems;
- (instancetype)initWithCapacity:(NSUInteger)numItems;
- (void)addObjectsFromArray:(NSArray<ObjectType> *)otherArray;
- (void)insertObject:(ObjectType)anObject atIndex:(NSUInteger)index;
- (void)removeAllObjects;
- (void)removeLastObject;
- (void)removeObjectAtIndex:(NSUInteger)index;
- (void)replaceObjectAtIndex:(NSUInteger)index withObject:(ObjectType)anObject;
@end

@interface NSDictionary<KeyType, ObjectType> (AOSJDKSurface)
+ (instancetype)dictionary;
+ (instancetype)dictionaryWithObject:(ObjectType)object forKey:(KeyType)key;
+ (instancetype)dictionaryWithContentsOfFile:(NSString *)path;
+ (instancetype)dictionaryWithObjectsAndKeys:(ObjectType)firstObject, ...;
- (NSArray<KeyType> *)allKeys;
- (NSArray<KeyType> *)allKeysForObject:(ObjectType)anObject;
- (NSUInteger)count;
- (ObjectType)objectForKey:(KeyType)aKey;
- (NSEnumerator<KeyType> *)keyEnumerator;
@end

@interface NSMutableDictionary<KeyType, ObjectType> (AOSJDKSurface)
- (instancetype)initWithCapacity:(NSUInteger)numItems;
@end

@interface NSSet<ObjectType> : NSObject <NSFastEnumeration>
- (NSEnumerator<ObjectType> *)objectEnumerator;
- (BOOL)containsObject:(ObjectType)object;
@end

@interface NSMutableSet<ObjectType> : NSSet<ObjectType>
- (instancetype)init;
- (void)addObject:(ObjectType)object;
@end

@interface NSNull : NSObject <NSCopying>
+ (NSNull *)null;
@end

@interface NSFileManager : NSObject
+ (NSFileManager *)defaultManager;
- (const char *)fileSystemRepresentationWithPath:(NSString *)path;
- (NSString *)stringWithFileSystemRepresentation:(const char *)string
                                           length:(NSUInteger)len;
- (BOOL)changeFileAttributes:(NSDictionary *)attributes atPath:(NSString *)path;
- (NSDictionary *)fileAttributesAtPath:(NSString *)path traverseLink:(BOOL)flag;
- (BOOL)fileExistsAtPath:(NSString *)path;
@end

@interface NSBundle (AOSJDKSurface)
+ (NSBundle *)bundleWithIdentifier:(NSString *)identifier;
+ (NSBundle *)bundleWithPath:(NSString *)path;
- (NSString *)pathForResource:(NSString *)name ofType:(NSString *)extension;
- (NSString *)pathForResource:(NSString *)name
                       ofType:(NSString *)extension
                  inDirectory:(NSString *)subpath;
@end

typedef struct _NSZone NSZone;

@interface NSBundle (NSNibLoading)
+ (BOOL)loadNibFile:(NSString *)fileName
  externalNameTable:(NSDictionary *)context
           withZone:(NSZone *)zone;
@end

@interface NSProcessInfo (AOSJDKSurface)
- (int)processIdentifier;
- (NSTimeInterval)systemUptime;
- (void)enableSuddenTermination;
- (void)disableSuddenTermination;
@end

@interface NSThread (AOSJDKSurface)
+ (NSThread *)currentThread;
+ (void)detachNewThreadSelector:(SEL)selector
                       toTarget:(id)target
                     withObject:(id)argument;
+ (BOOL)isMultiThreaded;
+ (BOOL)isMainThread;
+ (NSArray<NSString *> *)callStackSymbols;
- (void)setName:(NSString *)name;
- (NSMutableDictionary *)threadDictionary;
@end

@interface NSURL (AOSJDKSurface)
+ (instancetype)URLWithString:(NSString *)URLString;
- (BOOL)getResourceValue:(out id *)value
                   forKey:(NSString *)key
                    error:(out NSError **)error;
@end

extern NSString *const NSURLIsRegularFileKey;

@interface NSString (AOSJDKSurface)
- (NSStringEncoding)fastestEncoding;
- (NSUInteger)lengthOfBytesUsingEncoding:(NSStringEncoding)encoding;
- (BOOL)hasPrefix:(NSString *)string;
- (BOOL)hasSuffix:(NSString *)string;
- (BOOL)isEqualToString:(NSString *)string;
- (NSString *)lastPathComponent;
- (NSString *)lowercaseString;
- (NSRange)rangeOfString:(NSString *)aString options:(NSStringCompareOptions)mask;
- (NSString *)stringByAppendingString:(NSString *)aString;
- (NSString *)stringByDeletingPathExtension;
- (NSString *)substringFromIndex:(NSUInteger)from;
- (NSString *)substringToIndex:(NSUInteger)to;
- (const char *)fileSystemRepresentation;
@end

@interface NSMutableString : NSString
- (instancetype)initWithString:(NSString *)aString;
@end

@interface NSDate (AOSJDKSurface)
+ (instancetype)date;
+ (instancetype)dateWithTimeIntervalSinceNow:(NSTimeInterval)seconds;
- (NSTimeInterval)timeIntervalSinceReferenceDate;
@end

@interface NSValue (AOSJDKSurface)
+ (NSValue *)value:(const void *)value withObjCType:(const char *)type;
+ (NSValue *)valueWithPoint:(NSPoint)point;
+ (NSValue *)valueWithSize:(NSSize)size;
@end

@interface NSRunLoop : NSObject
+ (NSRunLoop *)currentRunLoop;
- (void)addPort:(NSPort *)aPort forMode:(NSString *)mode;
- (CFRunLoopRef)getCFRunLoop;
- (BOOL)runMode:(NSString *)mode beforeDate:(NSDate *)limitDate;
- (NSString *)currentMode;
@end

@interface NSPort : NSObject
+ (NSPort *)port;
@end

@interface NSCharacterSet : NSObject
+ (instancetype)letterCharacterSet;
+ (instancetype)decimalDigitCharacterSet;
- (BOOL)characterIsMember:(unichar)aCharacter;
@end

@interface NSAttributedString : NSObject
- (NSUInteger)length;
- (NSDictionary *)attributesAtIndex:(NSUInteger)location
                      effectiveRange:(NSRangePointer)range;
- (NSString *)string;
- (instancetype)initWithString:(NSString *)aString;
- (instancetype)initWithString:(NSString *)aString attributes:(NSDictionary *)attributes;
- (instancetype)initWithRTFD:(NSData *)data documentAttributes:(NSDictionary **)dict;
- (NSData *)RTFDFromRange:(NSRange)range documentAttributes:(NSDictionary *)dict;
@end

typedef NSUInteger NSPropertyListMutabilityOptions;
enum { NSPropertyListImmutable = kCFPropertyListImmutable };
typedef NSUInteger NSPropertyListFormat;

@interface NSPropertyListSerialization : NSObject
+ (id)propertyListFromData:(NSData *)data
          mutabilityOption:(NSPropertyListMutabilityOptions)option
                    format:(NSPropertyListFormat *)format
          errorDescription:(out __strong NSString **)errorString;
@end

@interface NSAppleScript : NSObject
- (instancetype)initWithContentsOfURL:(NSURL *)url error:(NSDictionary **)errorInfo;
- (instancetype)initWithSource:(NSString *)source;
- (NSAppleEventDescriptor *)executeAndReturnError:(NSDictionary **)errorInfo;
- (NSAppleEventDescriptor *)executeAppleEvent:(NSAppleEventDescriptor *)event
                                        error:(NSDictionary **)errorInfo;
@end

@interface NSConditionLock : NSObject
- (instancetype)initWithCondition:(NSInteger)condition;
- (void)lock;
- (void)unlock;
- (void)lockWhenCondition:(NSInteger)condition;
- (BOOL)lockWhenCondition:(NSInteger)condition beforeDate:(NSDate *)limit;
- (void)unlockWithCondition:(NSInteger)condition;
@end

extern NSString *const NSAppleScriptErrorMessage;
extern NSString *const NSFileHFSTypeCode;
extern NSString *const NSFileHFSCreatorCode;

@interface NSMethodSignature : NSObject
@end

@interface NSInvocation : NSObject
+ (NSInvocation *)invocationWithMethodSignature:(NSMethodSignature *)signature;
- (void)retainArguments;
- (void)setSelector:(SEL)selector;
- (void)setTarget:(id)target;
- (void)setArgument:(void *)argumentLocation atIndex:(NSInteger)idx;
- (void)invoke;
- (void)invokeWithTarget:(id)target;
- (void)getReturnValue:(void *)retLocation;
@end

@interface NSAppleEventDescriptor : NSObject <NSCopying>
+ (NSAppleEventDescriptor *)listDescriptor;
+ (NSAppleEventDescriptor *)recordDescriptor;
+ (NSAppleEventDescriptor *)nullDescriptor;
+ (NSAppleEventDescriptor *)descriptorWithString:(NSString *)string;
+ (NSAppleEventDescriptor *)descriptorWithBoolean:(BOOL)value;
+ (NSAppleEventDescriptor *)descriptorWithInt32:(int32_t)value;
+ (NSAppleEventDescriptor *)descriptorWithDescriptorType:(DescType)descriptorType
                                                   bytes:(const void *)bytes
                                                  length:(NSUInteger)byteCount;
+ (NSAppleEventDescriptor *)descriptorWithDescriptorType:(DescType)descriptorType
                                                    data:(NSData *)data;
- (NSAppleEventDescriptor *)coerceToDescriptorType:(DescType)descriptorType;
- (DescType)descriptorType;
- (NSInteger)numberOfItems;
- (NSAppleEventDescriptor *)descriptorAtIndex:(NSInteger)index;
- (void)insertDescriptor:(NSAppleEventDescriptor *)descriptor atIndex:(NSInteger)index;
- (void)setDescriptor:(NSAppleEventDescriptor *)descriptor forKeyword:(AEKeyword)keyword;
- (AEKeyword)keywordForDescriptorAtIndex:(NSInteger)index;
- (NSString *)stringValue;
- (int32_t)int32Value;
- (BOOL)booleanValue;
- (const AEDesc *)aeDesc;
- (NSData *)data;
- (NSAppleEventDescriptor *)paramDescriptorForKeyword:(AEKeyword)keyword;
@end

@interface NSAppleEventManager : NSObject
+ (NSAppleEventManager *)sharedAppleEventManager;
- (void)setEventHandler:(id)handler
            andSelector:(SEL)handleEventSelector
          forEventClass:(AEEventClass)eventClass
             andEventID:(AEEventID)eventID;
- (void)removeEventHandlerForEventClass:(AEEventClass)eventClass
                             andEventID:(AEEventID)eventID;
- (NSAppleEventDescriptor *)currentAppleEvent;
@end

@interface NSNotificationCenter : NSObject
+ (NSNotificationCenter *)defaultCenter;
- (void)addObserver:(id)observer
           selector:(SEL)aSelector
               name:(NSNotificationName)aName
             object:(id)anObject;
- (void)removeObserver:(id)observer;
- (void)postNotificationName:(NSNotificationName)aName object:(id)anObject;
@end

@interface NSUserDefaults (AOSJDKSurface)
- (void)registerDefaults:(NSDictionary *)registrationDictionary;
- (void)setBool:(BOOL)value forKey:(NSString *)defaultName;
@end

#endif
