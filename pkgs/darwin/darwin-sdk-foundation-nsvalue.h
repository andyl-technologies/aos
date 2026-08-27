#ifndef _AOS_FOUNDATION_NSVALUE_H_
#define _AOS_FOUNDATION_NSVALUE_H_
#import <Foundation/Foundation.h>

@interface NSValue (AOSJDKSplitSurface)
+ (NSValue *)valueWithBytes:(const void *)value objCType:(const char *)type;
- (const char *)objCType;
- (NSSize)sizeValue;
- (NSPoint)pointValue;
- (NSRange)rangeValue;
- (NSRect)rectValue;
@end

#endif
