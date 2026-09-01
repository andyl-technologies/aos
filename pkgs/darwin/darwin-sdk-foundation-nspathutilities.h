#ifndef _AOS_FOUNDATION_NSPATHUTILITIES_H_
#define _AOS_FOUNDATION_NSPATHUTILITIES_H_

#import <Foundation/NSString.h>

#ifndef FOUNDATION_EXPORT
#ifdef __cplusplus
#define FOUNDATION_EXPORT extern "C"
#else
#define FOUNDATION_EXPORT extern
#endif
#endif

FOUNDATION_EXPORT NSString *NSHomeDirectory(void);

#endif
