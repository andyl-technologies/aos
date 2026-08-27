#ifndef _AOS_FOUNDATION_JDK_H_
#define _AOS_FOUNDATION_JDK_H_
#import <Foundation/NSDate.h>
#import <Foundation/NSString.h>
#import <Foundation/NSValue.h>
#include <Carbon/Carbon.h>

typedef NSString *NSExceptionName;
typedef NSString *NSNotificationName;
typedef NSString *NSRunLoopMode;

extern NSExceptionName const NSInvalidArgumentException;
extern NSRunLoopMode const NSDefaultRunLoopMode;

@class NSMethodSignature;

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
@end

@interface NSException (AOSJDKSurface)
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
- (char)charValue;
- (float)floatValue;
@end

@interface NSData (AOSJDKSurface)
- (void)getBytes:(void *)buffer;
@end

@interface NSMutableData : NSData
+ (instancetype)dataWithLength:(NSUInteger)length;
- (void *)mutableBytes;
@end

@interface NSArray<ObjectType> (AOSJDKSurface)
+ (instancetype)arrayWithObjects:(ObjectType)firstObject, ...;
- (instancetype)initWithObjects:(ObjectType)firstObject, ...;
- (NSUInteger)count;
- (NSEnumerator<ObjectType> *)objectEnumerator;
@end

@interface NSMutableArray<ObjectType> (AOSJDKSurface)
+ (instancetype)array;
- (void)removeAllObjects;
@end

@interface NSDictionary<KeyType, ObjectType> (AOSJDKSurface)
+ (instancetype)dictionary;
- (NSArray<KeyType> *)allKeys;
@end

@interface NSMutableDictionary<KeyType, ObjectType> (AOSJDKSurface)
- (NSEnumerator<KeyType> *)keyEnumerator;
@end

@interface NSSet<ObjectType> : NSObject <NSFastEnumeration>
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
@end

@interface NSMethodSignature : NSObject
@end

@interface NSInvocation : NSObject
+ (NSInvocation *)invocationWithMethodSignature:(NSMethodSignature *)signature;
- (void)retainArguments;
- (void)setSelector:(SEL)selector;
- (void)setTarget:(id)target;
- (void)setArgument:(void *)argumentLocation atIndex:(NSInteger)idx;
- (void)invoke;
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
@end

@interface NSAppleEventManager : NSObject
+ (NSAppleEventManager *)sharedAppleEventManager;
- (void)setEventHandler:(id)handler
            andSelector:(SEL)handleEventSelector
          forEventClass:(AEEventClass)eventClass
             andEventID:(AEEventID)eventID;
- (void)removeEventHandlerForEventClass:(AEEventClass)eventClass
                             andEventID:(AEEventID)eventID;
@end

@interface NSNotificationCenter : NSObject
+ (NSNotificationCenter *)defaultCenter;
- (void)addObserver:(id)observer
           selector:(SEL)aSelector
               name:(NSNotificationName)aName
             object:(id)anObject;
- (void)removeObserver:(id)observer;
@end

#endif
