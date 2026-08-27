#ifndef _AOS_FOUNDATION_NSSTRING_H_
#define _AOS_FOUNDATION_NSSTRING_H_
#import <Foundation/Foundation.h>

@interface NSString (AOSJDKSurface)
+ (instancetype)stringWithString:(NSString *)string;
- (instancetype)initWithBytes:(const void *)bytes
                       length:(NSUInteger)length
                     encoding:(NSStringEncoding)encoding;
- (void)getCharacters:(unichar *)buffer;
@end

#endif
