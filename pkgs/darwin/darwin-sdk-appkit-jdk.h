#ifndef _AOS_APPKIT_JDK_H_
#define _AOS_APPKIT_JDK_H_
#import <AppKit/AppKit.h>

extern NSRunLoopMode const NSModalPanelRunLoopMode;
extern NSRunLoopMode const NSEventTrackingRunLoopMode;
extern NSNotificationName const NSApplicationWillFinishLaunchingNotification;
extern NSNotificationName const NSWorkspaceWillPowerOffNotification;
extern NSNotificationName const NSApplicationDidBecomeActiveNotification;
extern NSNotificationName const NSApplicationDidResignActiveNotification;
extern NSNotificationName const NSApplicationDidHideNotification;
extern NSNotificationName const NSApplicationDidUnhideNotification;

@interface NSImage (AOSJDKSurface)
- (NSData *)TIFFRepresentation;
- (instancetype)initWithData:(NSData *)data;
@end

#endif
