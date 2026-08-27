#ifndef _AOS_FOUNDATION_NSDATE_H_
#define _AOS_FOUNDATION_NSDATE_H_
#import <Foundation/Foundation.h>

typedef double NSTimeInterval;
#define NSTimeIntervalSince1970 978307200.0

@interface NSDate : NSObject <NSCopying>
+ (instancetype)dateWithTimeIntervalSince1970:(NSTimeInterval)seconds;
- (NSTimeInterval)timeIntervalSince1970;
@end

#endif
