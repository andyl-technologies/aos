/* Public Darwin declarations used by Vim but absent from the base SDK. */
#ifndef AOS_VIM_DARWIN_API_H
#define AOS_VIM_DARWIN_API_H

#import <AppKit/AppKit.h>

@interface NSMutableString (AOSVimDeclarations)
- (NSUInteger)replaceOccurrencesOfString:(NSString *)target
                             withString:(NSString *)replacement
                                options:(NSUInteger)options
                                  range:(NSRange)range;
@end

@interface NSArray (AOSVimDeclarations)
- (NSUInteger)count;
@end

@interface NSMutableDictionary (AOSVimDeclarations)
- (void)setObject:(id)object forKey:(id<NSCopying>)key;
- (void)removeObjectForKey:(id)key;
- (NSArray *)allValues;
@end

@class NSSound;

@protocol NSSoundDelegate <NSObject>
@optional
- (void)sound:(NSSound *)sound didFinishPlaying:(BOOL)finished;
@end

@interface NSSound : NSObject
+ (NSSound *)soundNamed:(NSString *)name;
- (instancetype)initWithContentsOfFile:(NSString *)path byReference:(BOOL)byReference;
- (void)setDelegate:(id<NSSoundDelegate>)delegate;
- (BOOL)play;
- (BOOL)stop;
@end

#endif
