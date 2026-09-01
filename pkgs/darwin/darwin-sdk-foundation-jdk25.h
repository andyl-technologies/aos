#ifndef _AOS_FOUNDATION_JDK25_H_
#define _AOS_FOUNDATION_JDK25_H_

#import <Foundation/Foundation.h>

extern NSString *const NSUserNotificationDefaultSoundName;

enum { NSBundleExecutableArchitectureARM64 = 0x0100000c };

extern Class NSClassFromString(NSString *className);
extern NSRange NSRangeFromString(NSString *string);
extern NSPoint NSPointFromString(NSString *string);
extern BOOL NSEqualRects(NSRect first, NSRect second);
extern NSString *NSStringFromSelector(SEL selector);

@protocol NSLocking
- (void)lock;
- (void)unlock;
@end

@interface NSLock : NSObject <NSLocking>
@end

@interface NSPointerArray : NSObject <NSCopying, NSFastEnumeration>
+ (NSPointerArray *)strongObjectsPointerArray;
@property NSUInteger count;
- (void *)pointerAtIndex:(NSUInteger)index;
- (void)replacePointerAtIndex:(NSUInteger)index withPointer:(void *)item;
@end

@interface NSArray<ObjectType> (AOSJDK25Surface)
+ (instancetype)arrayWithArray:(NSArray<ObjectType> *)array;
- (instancetype)initWithArray:(NSArray<ObjectType> *)array;
@end

@interface NSNumber (AOSJDK25Surface)
+ (NSNumber *)numberWithUnsignedInteger:(NSUInteger)value;
- (NSUInteger)unsignedIntegerValue;
@end

@interface NSProcessInfo (AOSJDK25Surface)
- (NSString *)globallyUniqueString;
@end

@interface NSURL (AOSJDK25Surface)
- (NSString *)absoluteString;
- (NSURL *)absoluteURL;
@end

@interface NSString (AOSJDK25Surface)
- (void)getCharacters:(unichar *)buffer range:(NSRange)range;
- (BOOL)containsString:(NSString *)other;
- (NSString *)localizedLowercaseString;
- (NSString *)precomposedStringWithCanonicalMapping;
- (NSString *)stringByAppendingFormat:(NSString *)format, ...;
@end

@interface NSFileManager (AOSJDK25Surface)
- (BOOL)trashItemAtURL:(NSURL *)url
      resultingItemURL:(NSURL * _Nullable *)outResultingURL
                 error:(NSError * _Nullable *)error;
@end

@interface NSValue (AOSJDK25Surface)
+ (NSValue *)valueWithRange:(NSRange)range;
+ (NSValue *)valueWithRect:(NSRect)rect;
@end

#endif
