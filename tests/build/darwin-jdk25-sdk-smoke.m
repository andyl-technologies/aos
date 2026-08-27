#import <Foundation/NSPathUtilities.h>
#import <AppKit/AppKit.h>
#include <ApplicationServices/ApplicationServices.h>
#include <AudioToolbox/AudioToolbox.h>
#include <AudioUnit/AudioUnit.h>
#include <CFNetwork/CFProxySupport.h>
#include <CoreAudio/CoreAudio.h>
#include <CoreMIDI/CoreMIDI.h>
#include <CoreText/CoreText.h>
#include <CoreVideo/CoreVideo.h>
#include <OpenGL/OpenGL.h>
#include <QuartzCore/QuartzCore.h>
#include <Security/SecItem.h>
#include <Security/SecKeychain.h>

_Static_assert(sizeof(AudioStreamBasicDescription) == 40, "ASBD ABI");
_Static_assert(sizeof(AudioBuffer) == 16, "AudioBuffer ABI");
_Static_assert(sizeof(AudioBufferList) == 24, "AudioBufferList ABI");
_Static_assert(sizeof(AudioTimeStamp) == 64, "AudioTimeStamp ABI");
_Static_assert(sizeof(MIDIPacket) == 268, "MIDIPacket ABI");
_Static_assert(sizeof(MIDIPacketList) == 272, "MIDIPacketList ABI");
_Static_assert(sizeof(CVSMPTETime) == 24, "CVSMPTETime ABI");
_Static_assert(sizeof(CVTimeStamp) == 80, "CVTimeStamp ABI");

static void proxy_result(
  void *client,
  CFArrayRef proxyList,
  CFErrorRef _Nullable error
) {
  (void)client;
  (void)proxyList;
  (void)error;
}

const void *aos_jdk25_data_exports[] = {
  &kCFProxyTypeKey,
  &kCFProxyTypeAutoConfigurationURL,
  &kCFProxyAutoConfigurationURLKey,
  &kCFProxyTypeNone,
  &kCFProxyTypeSOCKS,
  &kCFProxyPortNumberKey,
  &kCFProxyHostNameKey,
  &kSecMatchSearchList,
  &kMIDIPropertyDisplayName,
  &kMIDIPropertyDriverVersion,
  &kMIDIPropertyManufacturer,
  &kMIDIPropertyName,
  &kCAGravityTopLeft,
  &NSGenericException,
  &NSInternalInconsistencyException,
  &NSUserNotificationDefaultSoundName,
  &NSAccessibilityColumnCountAttribute,
  &NSAccessibilitySelectedTextAttribute,
  &NSAccessibilityBoundsForRangeParameterizedAttribute,
  &NSAccessibilityIncrementAction,
  &NSAccessibilityRowExpandedNotification,
  &NSAccessibilityOutlineRole,
  &NSAccessibilityTableRowSubrole,
  &NSAppearanceNameAqua,
  &NSDocumentTypeDocumentAttribute,
  &NSPrintJobSavingURL,
  &NSPrintSaveJob,
  &NSPrintSpoolJob,
  &NSRTFTextDocumentType,
  &NSTextInputContextKeyboardSelectionDidChangeNotification,
};

#define AOS_FUNCTION(name) ((const void *)&name)
const void *aos_jdk25_function_exports[] = {
  AOS_FUNCTION(CFLocaleCreate),
  AOS_FUNCTION(CFStringCreateMutable),
  AOS_FUNCTION(CFStringCreateWithCharacters),
  AOS_FUNCTION(AudioGetCurrentHostTime),
  AOS_FUNCTION(AudioConvertHostTimeToNanos),
  AOS_FUNCTION(AudioObjectGetPropertyDataSize),
  AOS_FUNCTION(AudioObjectGetPropertyData),
  AOS_FUNCTION(AudioObjectSetPropertyData),
  AOS_FUNCTION(AudioObjectAddPropertyListener),
  AOS_FUNCTION(AudioObjectRemovePropertyListener),
  AOS_FUNCTION(AudioComponentFindNext),
  AOS_FUNCTION(AudioComponentInstanceNew),
  AOS_FUNCTION(AudioComponentInstanceDispose),
  AOS_FUNCTION(AudioUnitInitialize),
  AOS_FUNCTION(AudioUnitGetProperty),
  AOS_FUNCTION(AudioUnitSetProperty),
  AOS_FUNCTION(AudioUnitRender),
  AOS_FUNCTION(AudioOutputUnitStart),
  AOS_FUNCTION(AudioOutputUnitStop),
  AOS_FUNCTION(AudioConverterNew),
  AOS_FUNCTION(AudioConverterDispose),
  AOS_FUNCTION(AudioConverterReset),
  AOS_FUNCTION(AudioConverterGetProperty),
  AOS_FUNCTION(AudioConverterFillComplexBuffer),
  AOS_FUNCTION(MIDIClientCreate),
  AOS_FUNCTION(MIDIInputPortCreate),
  AOS_FUNCTION(MIDIOutputPortCreate),
  AOS_FUNCTION(MIDIPortConnectSource),
  AOS_FUNCTION(MIDIPortDisconnectSource),
  AOS_FUNCTION(MIDIGetNumberOfSources),
  AOS_FUNCTION(MIDIGetNumberOfDestinations),
  AOS_FUNCTION(MIDIGetSource),
  AOS_FUNCTION(MIDIGetDestination),
  AOS_FUNCTION(MIDIObjectGetIntegerProperty),
  AOS_FUNCTION(MIDIObjectGetStringProperty),
  AOS_FUNCTION(MIDISend),
  AOS_FUNCTION(MIDIFlushOutput),
  AOS_FUNCTION(MIDIPacketListInit),
  AOS_FUNCTION(MIDIPacketListAdd),
  AOS_FUNCTION(CGAffineTransformScale),
  AOS_FUNCTION(CGBitmapContextGetBitmapInfo),
  AOS_FUNCTION(CGDirectDisplayCopyCurrentMetalDevice),
  AOS_FUNCTION(CGDisplayModeGetPixelWidth),
  AOS_FUNCTION(CGEventSetFlags),
  AOS_FUNCTION(CGEventSourceCreate),
  AOS_FUNCTION(CGEventSourceFlagsState),
  AOS_FUNCTION(CGRestorePermanentDisplayConfiguration),
  AOS_FUNCTION(CTFontCreateCopyWithSymbolicTraits),
  AOS_FUNCTION(CTFontDrawGlyphs),
  AOS_FUNCTION(CTFontManagerRegisterFontsForURL),
  AOS_FUNCTION(CVDisplayLinkCreateWithActiveCGDisplays),
  AOS_FUNCTION(CVDisplayLinkIsRunning),
  AOS_FUNCTION(CVDisplayLinkSetOutputCallback),
  AOS_FUNCTION(CVDisplayLinkStart),
  AOS_FUNCTION(CVDisplayLinkStop),
  AOS_FUNCTION(PMGetDuplex),
  AOS_FUNCTION(PMSetDuplex),
};
#undef AOS_FUNCTION

int main(void) {
  Class jdk25Classes[] = {
    [NSAccessibilityElement class],
    [NSAppearance class],
    [NSButton class],
    [NSLock class],
    [NSPointerArray class],
    [NSProgressIndicator class],
    [NSStatusBarButton class],
    [NSTextInputContext class],
    [NSWorkspaceOpenConfiguration class],
  };
  NSString *home = NSHomeDirectory();
  CFDictionaryRef settings = CFNetworkCopySystemProxySettings();
  CFURLRef url = NULL;
  CFArrayRef proxies = CFNetworkCopyProxiesForURL(url, settings);
  CFStreamClientContext context = { 0, NULL, NULL, NULL, NULL };
  CFRunLoopSourceRef source = CFNetworkExecuteProxyAutoConfigurationURL(
    url,
    url,
    proxy_result,
    &context
  );
  SecKeychainRef keychain = NULL;
  OSStatus status = SecKeychainOpen("aos.keychain", &keychain);
  return home == nil && settings == NULL && proxies == NULL && source == NULL &&
    keychain == NULL && status == 0 && aos_jdk25_data_exports[0] == NULL &&
    aos_jdk25_function_exports[0] == NULL && jdk25Classes[0] == Nil;
}
