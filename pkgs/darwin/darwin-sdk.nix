##! Open Darwin SDK surface used by the Linux-hosted cross toolchain.
##!
##! Zig maintains a redistributable aggregation of Apple open-source libc,
##! XNU, libdispatch, and related public headers together with a textual TAPI
##! description of libSystem.  Additional framework headers come directly from
##! Apple's open-source distributions.  This derivation installs only those
##! source/data inputs; it does not contain or extract an Xcode SDK.
{
  mkDerivation,
  fetchurl,
  buildPackages,
}: let
  version = "0.16.0";
  sdkVersion = "15.0";
  coreFoundationRevision = "761b621da93a856a48995efc29ed11028c283306";
  systemConfigurationRevision = "585b7f2fca293f4642d21d15c5daf187f63c4796";
  ioKitUserRevision = "323ead896d04424f87184d8f6ff0cce811aab106";
  xnuRevision = "f6217f891ac0bb64f3d375211650a4c1ff8ca1ea";
  ioUsbFamilyRevision = "1398331b04a6bb9ea9b9f76248b8b584811ebcd0";
  ioStorageFamilyRevision = "7edb88fbae296fb7c8ce2f64e115e116e566d51c";
  darlingIoKitUserRevision = "534684e6748dffbd875c6cd1942477a52b66a077";
  securityRevision = "db15acbe6a7f257a859ad9a3bb86097bfe0679d9";
  objcRevision = "fb265098298302243cd7eeaa1f63f0ba7786dd9a";
  libcRevision = "71bbe350ab79eef58113991d817ccc6165061a64";
  libinfoRevision = "39b70c515baee5b609e7e91693edbd934b6845a1";
  libresolvRevision = "e48cd914edc1cb14f8289b8e2dfdaac360481cd2";
  bootstrapCmdsRevision = "c71d2d72f48995baaea76148f61002e5299841de";
  launchdRevision = "d448a1c8f70a61202f8705f94337f686b87c30c4";
  hfsRevision = "d1bac2f062e6e9c0dfcce302d9aacb10173d0eea";
  libnotifyRevision = "715d461778f6b93c821d99390a0078bd6f6d8c04";
  darlingMetalRevision = "ae20248dc144beab899e38752f5a530f28a0ea56";

  coreFoundationSrc = fetchurl {
    urls = [
      "https://github.com/swiftlang/swift-corelibs-foundation/archive/${coreFoundationRevision}.tar.gz"
    ];
    hash = "sha256-rGQN0aHe9XqQsG9lEw11XXLjr98VII781mlZ3E7RbMc=";
  };

  systemConfigurationSrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/configd/archive/${systemConfigurationRevision}.tar.gz"
    ];
    hash = "sha256-o6vraL6Go4N1dq1sXg5agwfFOMmdmCW0mObpcYmnfT8=";
  };

  ioKitUserSrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/IOKitUser/archive/${ioKitUserRevision}.tar.gz"
    ];
    hash = "sha256-Gg76WBI81dEDJ1pd+vLXXjoKVjhHXS17tXPdBL/zD8w=";
  };

  xnuSrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/xnu/archive/${xnuRevision}.tar.gz"
    ];
    hash = "sha256-B2MUbStUWbBw2AKqupUmzq1/sNVdDVG6AGmBgDAVCxU=";
  };

  ioUsbFamilySrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/IOUSBFamily/archive/${ioUsbFamilyRevision}.tar.gz"
    ];
    hash = "sha256-tSgyOVFxykmfgkzhtegu3DLk9+Hr55l16PFqy3knWiI=";
  };

  ioStorageFamilySrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/IOStorageFamily/archive/${ioStorageFamilyRevision}.tar.gz"
    ];
    hash = "sha256-KiuFwzUBV+XpP5Rchym4uJFf9dwmooS+3Ikq9DUZ9BM=";
  };

  darlingIoKitUserSrc = fetchurl {
    urls = [
      "https://github.com/darlinghq/darling-iokituser/archive/${darlingIoKitUserRevision}.tar.gz"
    ];
    hash = "sha256-KTUQGg7W4wGr2aCTipF3Fjn+KBJgu+AdzFRIQB0zz3M=";
  };

  securitySrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/Security/archive/${securityRevision}.tar.gz"
    ];
    hash = "sha256-OQFd8WPEZSHROeg+yS+SFSf5Uv4WWeROGltFxqqkl9Y=";
  };

  objcSrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/objc4/archive/${objcRevision}.tar.gz"
    ];
    hash = "sha256-+DFg3gllkBpI+lr+AiPV+xBDvpry/iwr2oBJCfidsvU=";
  };

  libcSrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/Libc/archive/${libcRevision}.tar.gz"
    ];
    hash = "sha256-wjA85gC0Qm8yH6CWwDRvRknlQnnQK0BXor1uaCzlX7w=";
  };

  libinfoSrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/Libinfo/archive/${libinfoRevision}.tar.gz"
    ];
    hash = "sha256-ATGH4traRQdY99JsxRmn2knOK3gG/VXzuaiCSL/Xp8c=";
  };

  libresolvSrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/libresolv/archive/${libresolvRevision}.tar.gz"
    ];
    hash = "sha256-K7ghDWDtbetG3Ns5Hvsz2ylybXXY6tkDW4ZseAazMu0=";
  };

  bootstrapCmdsSrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/bootstrap_cmds/archive/${bootstrapCmdsRevision}.tar.gz"
    ];
    hash = "sha256-SmxCzFs5b2jIQIU5WaKxnDoQDyOybC3EhbRBMTdEvAs=";
  };

  launchdSrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/launchd/archive/${launchdRevision}.tar.gz"
    ];
    hash = "sha256-Ab6pH7z/1TD/HtRZJXOhE1kXRiYDEwq8Pmc/xaN7K54=";
  };

  hfsSrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/hfs/archive/${hfsRevision}.tar.gz"
    ];
    hash = "sha256-rkCBjserV45xh6t27BXUy6vlGFGQOYUr863j0kAWmnA=";
  };

  libnotifySrc = fetchurl {
    urls = [
      "https://github.com/apple-oss-distributions/Libnotify/archive/${libnotifyRevision}.tar.gz"
    ];
    hash = "sha256-3Y5oYWjcpcOLtnDDn00x8JLjfdbaOwMy9S4ywbjuMws=";
  };

  darlingMetalSrc = fetchurl {
    urls = [
      "https://github.com/darlinghq/darling-metal/archive/${darlingMetalRevision}.tar.gz"
    ];
    hash = "sha256-LPZdRfksAi3RY5sNAm3YTr4JPcMW5TuHtYOFCAv+vZQ=";
  };

  # Keep the framework payload out of the builder's argv: the SDK installer
  # is intentionally large and Linux limits each exec argument to 128 KiB.
  javaRuntimeSupportFragment = builtins.toFile "aos-java-runtime-support-sdk-fragment.sh" ''
    for header in \
      JavaRuntimeSupport.h \
      JRSAccessibility.h \
      JRSAppKitAWT.h \
      JRSDrag.h \
      JRSFont.h \
      JRSInputMethodController.h \
      JRSMenu.h \
      JRSUIControl.h \
      JRSUIHitTesting.h \
      JRSUIProperties.h \
      JRSUIScrollBars.h; do
      cp ${./darwin-sdk-java-runtime-support.h} \
        "$out/System/Library/Frameworks/JavaRuntimeSupport.framework/Headers/$header"
    done
    cp ${./darwin-sdk-java-runtime-support.tbd} \
      "$out/System/Library/Frameworks/JavaRuntimeSupport.framework/JavaRuntimeSupport.tbd"
    ln -s ../../JavaRuntimeSupport.tbd \
      "$out/System/Library/Frameworks/JavaRuntimeSupport.framework/Versions/A/JavaRuntimeSupport.tbd"
    ln -s JavaRuntimeSupport.tbd \
      "$out/System/Library/Frameworks/JavaRuntimeSupport.framework/Versions/A/JavaRuntimeSupport"
    ln -s ../../../../../../../JavaRuntimeSupport.framework/JavaRuntimeSupport.tbd \
      "$out/System/Library/Frameworks/JavaVM.framework/Versions/A/Frameworks/JavaRuntimeSupport.framework/Versions/A/JavaRuntimeSupport.tbd"
    ln -s JavaRuntimeSupport.tbd \
      "$out/System/Library/Frameworks/JavaVM.framework/Versions/A/Frameworks/JavaRuntimeSupport.framework/Versions/A/JavaRuntimeSupport"
  '';

  jdk25AudioFragment = builtins.toFile "aos-jdk25-audio-sdk-fragment.sh" ''
    # OpenJDK's macOS sound and MIDI backends consume these public C
    # framework ABIs. Install only the compile/link surface; the Darwin host
    # supplies each implementation at its canonical install name.
    cp ${./darwin-sdk-audio-midi.h} \
      "$out/System/Library/Frameworks/CoreAudio.framework/Headers/CoreAudioTypes.h"
    for header in CoreAudio AudioHardwareBase AudioHardware HostTime; do
      cp ${./darwin-sdk-coreaudio.h} \
        "$out/System/Library/Frameworks/CoreAudio.framework/Headers/$header.h"
    done
    for header in AudioToolbox AudioConverter; do
      cp ${./darwin-sdk-audiotoolbox.h} \
        "$out/System/Library/Frameworks/AudioToolbox.framework/Headers/$header.h"
    done
    for header in AudioUnit AUComponent AudioUnitProperties AudioOutputUnit; do
      cp ${./darwin-sdk-audiounit.h} \
        "$out/System/Library/Frameworks/AudioUnit.framework/Headers/$header.h"
    done
    for header in CoreMIDI MIDIServices; do
      cp ${./darwin-sdk-coremidi.h} \
        "$out/System/Library/Frameworks/CoreMIDI.framework/Headers/$header.h"
    done
    cp ${./darwin-sdk-coreaudio.tbd} \
      "$out/System/Library/Frameworks/CoreAudio.framework/CoreAudio.tbd"
    cp ${./darwin-sdk-audiotoolbox.tbd} \
      "$out/System/Library/Frameworks/AudioToolbox.framework/AudioToolbox.tbd"
    cp ${./darwin-sdk-audiounit.tbd} \
      "$out/System/Library/Frameworks/AudioUnit.framework/AudioUnit.tbd"
    cp ${./darwin-sdk-coremidi.tbd} \
      "$out/System/Library/Frameworks/CoreMIDI.framework/CoreMIDI.tbd"
    for framework in CoreAudio AudioToolbox AudioUnit CoreMIDI; do
      ln -s "../../$framework.tbd" \
        "$out/System/Library/Frameworks/$framework.framework/Versions/A/$framework.tbd"
      ln -s "$framework.tbd" \
        "$out/System/Library/Frameworks/$framework.framework/Versions/A/$framework"
    done
  '';

  coreVideoFragment = ./darwin-sdk-corevideo-fragment.sh;

  qemuCocoaSdkFragment = builtins.toFile "aos-qemu-cocoa-sdk-fragment.sh" ''
    # QEMU's Cocoa display presents guest scanouts with the public
    # CoreGraphics image, context, display, and event-tap APIs. Publish
    # the exact documented ABI surface it uses and let the umbrella
    # frameworks reexport it just as the platform SDK does.
    cat > "$out/System/Library/Frameworks/CoreGraphics.framework/Headers/CGGeometry.h" <<'EOF'
    #ifndef _AOS_COREGRAPHICS_CGGEOMETRY_H_
    #define _AOS_COREGRAPHICS_CGGEOMETRY_H_
    #include <CoreFoundation/CoreFoundation.h>

    #define CG_EXTERN extern

    typedef double CGFloat;
    typedef struct CGPoint { CGFloat x; CGFloat y; } CGPoint;
    typedef struct CGSize { CGFloat width; CGFloat height; } CGSize;
    typedef struct CGRect { CGPoint origin; CGSize size; } CGRect;
    typedef struct CGAffineTransform {
      CGFloat a, b, c, d;
      CGFloat tx, ty;
    } CGAffineTransform;
    extern const CGAffineTransform CGAffineTransformIdentity;
    extern const CGRect CGRectZero;

    static inline CGPoint CGPointMake(CGFloat x, CGFloat y) {
      CGPoint point = { x, y };
      return point;
    }

    static inline CGSize CGSizeMake(CGFloat width, CGFloat height) {
      CGSize size = { width, height };
      return size;
    }

    static inline CGRect CGRectMake(CGFloat x, CGFloat y, CGFloat width, CGFloat height) {
      CGRect rect = { { x, y }, { width, height } };
      return rect;
    }

    static inline CGAffineTransform CGAffineTransformMake(
      CGFloat a, CGFloat b, CGFloat c, CGFloat d, CGFloat tx, CGFloat ty
    ) {
      CGAffineTransform transform = { a, b, c, d, tx, ty };
      return transform;
    }

    static inline CGPoint CGPointApplyAffineTransform(
      CGPoint point, CGAffineTransform transform
    ) {
      return CGPointMake(
        point.x * transform.a + point.y * transform.c + transform.tx,
        point.x * transform.b + point.y * transform.d + transform.ty
      );
    }

    static inline CGSize CGSizeApplyAffineTransform(
      CGSize size, CGAffineTransform transform
    ) {
      return CGSizeMake(
        size.width * transform.a + size.height * transform.c,
        size.width * transform.b + size.height * transform.d
      );
    }
    CGAffineTransform CGAffineTransformInvert(CGAffineTransform transform);

    #endif
    EOF
    cat > "$out/System/Library/Frameworks/CoreGraphics.framework/Headers/CGColorSpace.h" <<'EOF'
    #ifndef _AOS_COREGRAPHICS_CGCOLORSPACE_H_
    #define _AOS_COREGRAPHICS_CGCOLORSPACE_H_
    #include <CoreFoundation/CoreFoundation.h>
    typedef struct CGColorSpace *CGColorSpaceRef;
    extern const CFStringRef kCGColorSpaceGenericGray;
    extern const CFStringRef kCGColorSpaceGenericRGB;
    extern const CFStringRef kCGColorSpaceSRGB;
    CGColorSpaceRef CGColorSpaceCreateDeviceRGB(void);
    CGColorSpaceRef CGColorSpaceCreateWithName(CFStringRef name);
    void CGColorSpaceRelease(CGColorSpaceRef space);
    #endif
    EOF
    cat > "$out/System/Library/Frameworks/CoreGraphics.framework/Headers/CGColor.h" <<'EOF'
    #ifndef _AOS_COREGRAPHICS_CGCOLOR_H_
    #define _AOS_COREGRAPHICS_CGCOLOR_H_
    #include <CoreGraphics/CGColorSpace.h>
    typedef struct CGColor *CGColorRef;
    CGColorRef CGColorCreate(CGColorSpaceRef space, const CGFloat components[]);
    void CGColorRelease(CGColorRef color);
    #endif
    EOF
    cat > "$out/System/Library/Frameworks/CoreGraphics.framework/Headers/CGFont.h" <<'EOF'
    #ifndef _AOS_COREGRAPHICS_CGFONT_H_
    #define _AOS_COREGRAPHICS_CGFONT_H_
    #include <stdint.h>
    typedef struct CGFont *CGFontRef;
    typedef uint16_t CGGlyph;
    void CGFontRelease(CGFontRef font);
    #endif
    EOF
    cat > "$out/System/Library/Frameworks/CoreGraphics.framework/Headers/CGPath.h" <<'EOF'
    #ifndef _AOS_COREGRAPHICS_CGPATH_H_
    #define _AOS_COREGRAPHICS_CGPATH_H_
    #include <CoreGraphics/CGGeometry.h>
    #include <stdint.h>
    typedef const struct CGPath *CGPathRef;
    typedef uint32_t CGPathElementType;
    enum {
      kCGPathElementMoveToPoint = 0,
      kCGPathElementAddLineToPoint = 1,
      kCGPathElementAddQuadCurveToPoint = 2,
      kCGPathElementAddCurveToPoint = 3,
      kCGPathElementCloseSubpath = 4
    };
    typedef struct CGPathElement {
      CGPathElementType type;
      CGPoint *points;
    } CGPathElement;
    typedef void (*CGPathApplierFunction)(void *info, const CGPathElement *element);
    void CGPathApply(CGPathRef path, void *info, CGPathApplierFunction function);
    void CGPathRelease(CGPathRef path);
    #endif
    EOF
    cat > "$out/System/Library/Frameworks/CoreGraphics.framework/Headers/CGWindow.h" <<'EOF'
    #ifndef _AOS_COREGRAPHICS_CGWINDOW_H_
    #define _AOS_COREGRAPHICS_CGWINDOW_H_
    #include <CoreFoundation/CoreFoundation.h>
    extern const CFStringRef kCGWindowBounds;
    extern const CFStringRef kCGWindowLayer;
    extern const CFStringRef kCGWindowNumber;
    #endif
    EOF
    cat > "$out/System/Library/Frameworks/CoreGraphics.framework/Headers/CGDataProvider.h" <<'EOF'
    #ifndef _AOS_COREGRAPHICS_CGDATAPROVIDER_H_
    #define _AOS_COREGRAPHICS_CGDATAPROVIDER_H_
    #include <stddef.h>
    typedef struct CGDataProvider *CGDataProviderRef;
    typedef void (*CGDataProviderReleaseDataCallback)(void *info, const void *data, size_t size);
    CGDataProviderRef CGDataProviderCreateWithData(
      void *info,
      const void *data,
      size_t size,
      CGDataProviderReleaseDataCallback releaseData
    );
    void CGDataProviderRelease(CGDataProviderRef provider);
    #endif
    EOF
    cat > "$out/System/Library/Frameworks/CoreGraphics.framework/Headers/CGImage.h" <<'EOF'
    #ifndef _AOS_COREGRAPHICS_CGIMAGE_H_
    #define _AOS_COREGRAPHICS_CGIMAGE_H_
    #include <CoreGraphics/CGColorSpace.h>
    #include <CoreGraphics/CGDataProvider.h>
    #include <CoreGraphics/CGGeometry.h>
    #include <stddef.h>
    #include <stdint.h>

    typedef struct CGImage *CGImageRef;
    typedef uint32_t CGBitmapInfo;
    typedef enum CGImageAlphaInfo {
      kCGImageAlphaNone = 0,
      kCGImageAlphaPremultipliedFirst = 2,
      kCGImageAlphaFirst = 4,
      kCGImageAlphaNoneSkipFirst = 6
    } CGImageAlphaInfo;
    typedef int32_t CGColorRenderingIntent;
    enum {
      kCGBitmapAlphaInfoMask = 0x1f,
      kCGBitmapByteOrder16Little = 1 << 12,
      kCGBitmapByteOrder32Little = 2 << 12,
      kCGRenderingIntentDefault = 0
    };
    #define kCGBitmapByteOrder16Host kCGBitmapByteOrder16Little
    #define kCGBitmapByteOrder32Host kCGBitmapByteOrder32Little

    CGImageRef CGImageCreate(
      size_t width,
      size_t height,
      size_t bitsPerComponent,
      size_t bitsPerPixel,
      size_t bytesPerRow,
      CGColorSpaceRef space,
      CGBitmapInfo bitmapInfo,
      CGDataProviderRef provider,
      const CGFloat *decode,
      bool shouldInterpolate,
      CGColorRenderingIntent intent
    );
    CGImageRef CGImageCreateWithImageInRect(CGImageRef image, CGRect rect);
    void CGImageRelease(CGImageRef image);
    #endif
    EOF
    cat > "$out/System/Library/Frameworks/CoreGraphics.framework/Headers/CGContext.h" <<'EOF'
    #ifndef _AOS_COREGRAPHICS_CGCONTEXT_H_
    #define _AOS_COREGRAPHICS_CGCONTEXT_H_
    #include <CoreGraphics/CGColor.h>
    #include <CoreGraphics/CGFont.h>
    #include <CoreGraphics/CGPath.h>
    #include <CoreGraphics/CGWindow.h>
    #include <CoreGraphics/CGImage.h>
    #include <stdint.h>
    typedef struct CGContext *CGContextRef;
    typedef enum CGInterpolationQuality {
      kCGInterpolationDefault = 0,
      kCGInterpolationNone = 1,
      kCGInterpolationLow = 2,
      kCGInterpolationHigh = 3,
      kCGInterpolationMedium = 4
    } CGInterpolationQuality;
    typedef enum CGBlendMode { kCGBlendModeCopy = 17 } CGBlendMode;
    typedef enum CGLineCap {
      kCGLineCapButt = 0,
      kCGLineCapRound = 1,
      kCGLineCapSquare = 2
    } CGLineCap;
    typedef enum CGLineJoin {
      kCGLineJoinMiter = 0,
      kCGLineJoinRound = 1,
      kCGLineJoinBevel = 2
    } CGLineJoin;
    void CGContextAddCurveToPoint(CGContextRef context, CGFloat cp1x, CGFloat cp1y, CGFloat cp2x, CGFloat cp2y, CGFloat x, CGFloat y);
    void CGContextAddLineToPoint(CGContextRef context, CGFloat x, CGFloat y);
    void CGContextAddRect(CGContextRef context, CGRect rect);
    void CGContextDrawImage(CGContextRef context, CGRect rect, CGImageRef image);
    void CGContextFillRect(CGContextRef context, CGRect rect);
    CGAffineTransform CGContextGetTextMatrix(CGContextRef context);
    void CGContextMoveToPoint(CGContextRef context, CGFloat x, CGFloat y);
    void CGContextRelease(CGContextRef context);
    void CGContextRestoreGState(CGContextRef context);
    void CGContextSaveGState(CGContextRef context);
    void CGContextScaleCTM(CGContextRef context, CGFloat sx, CGFloat sy);
    void CGContextSetFillColorWithColor(CGContextRef context, CGColorRef color);
    void CGContextSetFont(CGContextRef context, CGFontRef font);
    void CGContextSetInterpolationQuality(CGContextRef context, CGInterpolationQuality quality);
    void CGContextSetRGBFillColor(CGContextRef context, CGFloat red, CGFloat green, CGFloat blue, CGFloat alpha);
    void CGContextSetShouldAntialias(CGContextRef context, bool shouldAntialias);
    void CGContextSetStrokeColorWithColor(CGContextRef context, CGColorRef color);
    void CGContextSetTextMatrix(CGContextRef context, CGAffineTransform transform);
    void CGContextShowGlyphsAtPoint(CGContextRef context, CGFloat x, CGFloat y, const CGGlyph glyphs[], size_t count);
    void CGContextStrokeLineSegments(CGContextRef context, const CGPoint points[], size_t count);
    void CGContextStrokeRect(CGContextRef context, CGRect rect);
    #endif
    EOF
    cat > "$out/System/Library/Frameworks/CoreGraphics.framework/Headers/CGBitmapContext.h" <<'EOF'
    #ifndef _AOS_COREGRAPHICS_CGBITMAPCONTEXT_H_
    #define _AOS_COREGRAPHICS_CGBITMAPCONTEXT_H_
    #include <CoreGraphics/CGContext.h>
    CGContextRef CGBitmapContextCreate(void *data, size_t width, size_t height,
      size_t bitsPerComponent, size_t bytesPerRow, CGColorSpaceRef space,
      CGBitmapInfo bitmapInfo);
    #endif
    EOF
    cat > "$out/System/Library/Frameworks/CoreGraphics.framework/Headers/CGDirectDisplay.h" <<'EOF'
    #ifndef _AOS_COREGRAPHICS_CGDIRECTDISPLAY_H_
    #define _AOS_COREGRAPHICS_CGDIRECTDISPLAY_H_
    #include <CoreGraphics/CGGeometry.h>
    #include <stdint.h>
    typedef int32_t CGError;
    typedef uint32_t CGDirectDisplayID;
    typedef uint32_t CGDisplayCount;
    typedef struct _CGDisplayConfigRef *CGDisplayConfigRef;
    typedef uint32_t CGConfigureOption;
    typedef struct CGDisplayMode *CGDisplayModeRef;
    enum {
      kCGErrorSuccess = 0,
      kCGNullDirectDisplay = 0,
      kCGConfigureForAppOnly = 0
    };
    CGError CGBeginDisplayConfiguration(CGDisplayConfigRef *config);
    CGError CGCompleteDisplayConfiguration(CGDisplayConfigRef config, CGConfigureOption option);
    CGError CGConfigureDisplayWithDisplayMode(CGDisplayConfigRef config,
      CGDirectDisplayID display, CGDisplayModeRef mode, CFDictionaryRef options);
    CGRect CGDisplayBounds(CGDirectDisplayID display);
    CFArrayRef CGDisplayCopyAllDisplayModes(CGDirectDisplayID display, CFDictionaryRef options);
    CGDisplayModeRef CGDisplayCopyDisplayMode(CGDirectDisplayID display);
    CGDirectDisplayID CGDisplayMirrorsDisplay(CGDirectDisplayID display);
    CFStringRef CGDisplayModeCopyPixelEncoding(CGDisplayModeRef mode);
    size_t CGDisplayModeGetHeight(CGDisplayModeRef mode);
    double CGDisplayModeGetRefreshRate(CGDisplayModeRef mode);
    size_t CGDisplayModeGetWidth(CGDisplayModeRef mode);
    void CGDisplayModeRelease(CGDisplayModeRef mode);
    CGDisplayModeRef CGDisplayModeRetain(CGDisplayModeRef mode);
    CGSize CGDisplayScreenSize(CGDirectDisplayID display);
    CGError CGGetActiveDisplayList(CGDisplayCount maxDisplays,
      CGDirectDisplayID *activeDisplays, CGDisplayCount *displayCount);
    CGError CGGetOnlineDisplayList(uint32_t maxDisplays,
      CGDirectDisplayID *onlineDisplays, uint32_t *displayCount);
    #endif
    EOF
    cat > "$out/System/Library/Frameworks/CoreGraphics.framework/Headers/CGEvent.h" <<'EOF'
    #ifndef _AOS_COREGRAPHICS_CGEVENT_H_
    #define _AOS_COREGRAPHICS_CGEVENT_H_
    #include <CoreFoundation/CoreFoundation.h>
    #include <CoreGraphics/CGGeometry.h>
    #include <stdint.h>
    typedef struct __CFMachPort *CFMachPortRef;
    typedef struct __CGEvent *CGEventRef;
    typedef struct __CGEventSource *CGEventSourceRef;
    typedef void *CGEventTapProxy;
    typedef uint32_t CGEventType;
    typedef uint64_t CGEventMask;
    typedef uint32_t CGEventTapLocation;
    typedef uint32_t CGEventTapPlacement;
    typedef uint32_t CGEventTapOptions;
    typedef uint16_t CGKeyCode;
    typedef uint32_t CGMouseButton;
    typedef CGEventRef (*CGEventTapCallBack)(
      CGEventTapProxy proxy,
      CGEventType type,
      CGEventRef event,
      void *userInfo
    );
    enum {
      kCGEventMouseMoved = 5,
      kCGEventKeyDown = 10,
      kCGEventKeyUp = 11,
      kCGEventFlagsChanged = 12,
      kCGHIDEventTap = 0,
      kCGHeadInsertEventTap = 0,
      kCGEventTapOptionDefault = 0,
      kCGMouseButtonLeft = 0
    };
    #define CGEventMaskBit(eventType) ((CGEventMask)1 << (eventType))
    CFMachPortRef CGEventTapCreate(
      CGEventTapLocation tap,
      CGEventTapPlacement place,
      CGEventTapOptions options,
      CGEventMask eventsOfInterest,
      CGEventTapCallBack callback,
      void *userInfo
    );
    CGEventRef CGEventCreate(CGEventSourceRef source);
    CGEventRef CGEventCreateKeyboardEvent(
      CGEventSourceRef source, CGKeyCode virtualKey, bool keyDown);
    CGPoint CGEventGetLocation(CGEventRef event);
    #endif
    EOF
    cat > "$out/System/Library/Frameworks/CoreGraphics.framework/Headers/CGRemoteOperation.h" <<'EOF'
    #ifndef _AOS_COREGRAPHICS_CGREMOTEOPERATION_H_
    #define _AOS_COREGRAPHICS_CGREMOTEOPERATION_H_
    #include <CoreFoundation/CoreFoundation.h>
    #include <mach/boolean.h>
    #include <stdint.h>
    typedef int32_t CGError;
    typedef uint32_t CGEventFilterMask;
    typedef uint32_t CGEventSuppressionState;
    enum {
      kCGEventFilterMaskPermitLocalMouseEvents = 1,
      kCGEventFilterMaskPermitLocalKeyboardEvents = 2,
      kCGEventFilterMaskPermitSystemDefinedEvents = 4,
      kCGEventSuppressionStateSuppressionInterval = 0,
      kCGEventSuppressionStateRemoteMouseDrag = 1
    };
    #define kCGEventFilterMaskPermitAllEvents \
      (kCGEventFilterMaskPermitLocalMouseEvents | \
       kCGEventFilterMaskPermitLocalKeyboardEvents | \
       kCGEventFilterMaskPermitSystemDefinedEvents)
    #define kCGEventSupressionStateSupressionInterval \
      kCGEventSuppressionStateSuppressionInterval
    #define kCGEventSupressionStateRemoteMouseDrag \
      kCGEventSuppressionStateRemoteMouseDrag
    #define CGEventSupressionState CGEventSuppressionState
    #define CGSetLocalEventsFilterDuringSupressionState(filter, state) \
      CGSetLocalEventsFilterDuringSuppressionState((filter), (state))
    CGError CGAssociateMouseAndMouseCursorPosition(bool connected);
    CGError CGEnableEventStateCombining(boolean_t combineState);
    CGError CGSetLocalEventsFilterDuringSuppressionState(
      CGEventFilterMask filter, CGEventSuppressionState state);
    CGError CGSetLocalEventsSuppressionInterval(CFTimeInterval seconds);
    #endif
    EOF
    cat > "$out/System/Library/Frameworks/CoreGraphics.framework/Headers/CoreGraphics.h" <<'EOF'
    #ifndef _AOS_COREGRAPHICS_H_
    #define _AOS_COREGRAPHICS_H_
    #include <CoreFoundation/CoreFoundation.h>
    CF_EXTERN_C_BEGIN
    #include <CoreGraphics/CGGeometry.h>
    #include <CoreGraphics/CGColorSpace.h>
    #include <CoreGraphics/CGColor.h>
    #include <CoreGraphics/CGFont.h>
    #include <CoreGraphics/CGDataProvider.h>
    #include <CoreGraphics/CGImage.h>
    #include <CoreGraphics/CGContext.h>
    #include <CoreGraphics/CGBitmapContext.h>
    #include <CoreGraphics/CGDirectDisplay.h>
    #include <CoreGraphics/CGEvent.h>
    #include <CoreGraphics/CGRemoteOperation.h>
    #include <CoreGraphics/JDKSurface.h>
    CF_EXTERN_C_END
    #endif
    EOF
    cp ${./darwin-sdk-coregraphics-jdk.h} \
      "$out/System/Library/Frameworks/CoreGraphics.framework/Headers/JDKSurface.h"
    cat > "$out/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics.tbd" <<'EOF'
    --- !tapi-tbd
    tbd-version: 4
    targets: [ x86_64-macos, arm64-macos ]
    install-name: '/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics'
    current-version: 1894.0.0
    compatibility-version: 64.0.0
    reexported-libraries:
      - targets: [ x86_64-macos, arm64-macos ]
        libraries: [ '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation' ]
    exports:
      - targets: [ x86_64-macos, arm64-macos ]
        symbols:
          - _CGAssociateMouseAndMouseCursorPosition
          - _CGBeginDisplayConfiguration
          - _CGAffineTransformInvert
          - _CGBitmapContextCreate
          - _CGColorCreate
          - _CGColorRelease
          - _CGColorSpaceCreateDeviceRGB
          - _CGColorSpaceCreateWithName
          - _CGColorSpaceRelease
          - _CGCompleteDisplayConfiguration
          - _CGConfigureDisplayWithDisplayMode
          - _CGContextAddCurveToPoint
          - _CGContextAddLineToPoint
          - _CGContextAddRect
          - _CGContextDrawImage
          - _CGContextFillRect
          - _CGContextGetTextMatrix
          - _CGContextMoveToPoint
          - _CGContextRelease
          - _CGContextRestoreGState
          - _CGContextSaveGState
          - _CGContextScaleCTM
          - _CGContextSetFillColorWithColor
          - _CGContextSetFont
          - _CGContextSetInterpolationQuality
          - _CGContextSetRGBFillColor
          - _CGContextSetShouldAntialias
          - _CGContextSetStrokeColorWithColor
          - _CGContextSetTextMatrix
          - _CGContextShowGlyphsAtPoint
          - _CGContextStrokeLineSegments
          - _CGContextStrokeRect
          - _CGDataProviderCreateWithData
          - _CGDataProviderRelease
          - _CGDisplayBounds
          - _CGDisplayCopyAllDisplayModes
          - _CGDisplayCopyDisplayMode
          - _CGDisplayMirrorsDisplay
          - _CGDisplayModeCopyPixelEncoding
          - _CGDisplayModeGetHeight
          - _CGDisplayModeGetRefreshRate
          - _CGDisplayModeGetWidth
          - _CGDisplayModeRelease
          - _CGDisplayModeRetain
          - _CGDisplayScreenSize
          - _CGGetActiveDisplayList
          - _CGEnableEventStateCombining
          - _CGEventCreate
          - _CGEventCreateKeyboardEvent
          - _CGEventGetLocation
          - _CGEventTapCreate
          - _CGFontRelease
          - _CGGetOnlineDisplayList
          - _CGImageCreate
          - _CGImageCreateWithImageInRect
          - _CGImageRelease
          - _CGPathApply
          - _CGPathRelease
          - _CGSetLocalEventsFilterDuringSuppressionState
          - _CGSetLocalEventsSuppressionInterval
          - _CGRectApplyAffineTransform
          - _CGAffineTransformConcat
          - _CGAffineTransformMakeScale
          - _CGColorSpaceCreatePattern
          - _CGContextAddEllipseInRect
          - _CGContextAddQuadCurveToPoint
          - _CGContextBeginPath
          - _CGContextClip
          - _CGContextClipToRect
          - _CGContextClosePath
          - _CGContextConcatCTM
          - _CGContextDrawLinearGradient
          - _CGContextDrawRadialGradient
          - _CGContextDrawShading
          - _CGContextEOClip
          - _CGContextEOFillPath
          - _CGContextFillEllipseInRect
          - _CGContextFillPath
          - _CGContextFlush
          - _CGContextGetCTM
          - _CGContextGetClipBoundingBox
          - _CGContextIsPathEmpty
          - _CGContextSetAlpha
          - _CGContextSetBlendMode
          - _CGContextSetFillColorSpace
          - _CGContextSetFillPattern
          - _CGContextSetFontSize
          - _CGContextSetLineCap
          - _CGContextSetLineDash
          - _CGContextSetLineJoin
          - _CGContextSetLineWidth
          - _CGContextSetMiterLimit
          - _CGContextSetPatternPhase
          - _CGContextSetRGBStrokeColor
          - _CGContextSetStrokeColorSpace
          - _CGContextShowGlyphsWithAdvances
          - _CGContextStrokeEllipseInRect
          - _CGContextStrokePath
          - _CGContextTranslateCTM
          - _CGDisplayCapture
          - _CGDisplayRegisterReconfigurationCallback
          - _CGDisplayRelease
          - _CGDisplayRemoveReconfigurationCallback
          - _CGEventCreateMouseEvent
          - _CGEventCreateScrollWheelEvent
          - _CGEventPost
          - _CGEventPostToPSN
          - _CGEventSetIntegerValueField
          - _CGEventSourceButtonState
          - _CGFontGetAscent
          - _CGFontGetDescent
          - _CGFontGetLeading
          - _CGFontGetUnitsPerEm
          - _CGFontCreateWithDataProvider
          - _CGFontRetain
          - _CGFontCopyPostScriptName
          - _CGFontCopyTableForTag
          - _CGFunctionCreate
          - _CGFunctionRelease
          - _CGGradientCreateWithColorComponents
          - _CGGradientRelease
          - _CGMainDisplayID
          - _CGDisplayIDToOpenGLDisplayMask
          - _CGPatternCreate
          - _CGPatternRelease
          - _CGRectContainsPoint
          - _CGRectMakeWithDictionaryRepresentation
          - _CGShadingCreateAxial
          - _CGShadingRelease
          - _CGShieldingWindowLevel
          - _CGWindowLevelForKey
          - _CGWindowListCopyWindowInfo
          - _CGWindowListCreateImage
          - _CGAffineTransformScale
          - _CGBitmapContextGetBitmapInfo
          - _CGDirectDisplayCopyCurrentMetalDevice
          - _CGDisplayModeGetPixelWidth
          - _CGEventSetFlags
          - _CGEventSourceCreate
          - _CGEventSourceFlagsState
          - _CGRestorePermanentDisplayConfiguration
          - _CGRectZero
          - _CGAffineTransformIdentity
          - _kCGColorSpaceGenericGray
          - _kCGColorSpaceGenericRGB
          - _kCGColorSpaceSRGB
          - _kCGWindowBounds
          - _kCGWindowLayer
          - _kCGWindowNumber
    ...
    EOF
    ln -s ../../CoreGraphics.tbd \
      "$out/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics.tbd"
    ln -s CoreGraphics.tbd \
      "$out/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics"

  '';
in
  mkDerivation {
    pname = "darwin-sdk";
    inherit version;

    src = fetchurl {
      urls = [
        "https://ziglang.org/download/${version}/zig-${version}.tar.xz"
      ];
      hash = "sha256-QxhpWe3IfVx6G+e30qJe//0izlgHx6+ZBn+G+ZZBv98=";
    };

    buildDeps = [
      buildPackages.flex
      buildPackages.bison
    ];
    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          tar xf ${coreFoundationSrc}
          tar xf ${systemConfigurationSrc}
          tar xf ${ioKitUserSrc}
          tar xf ${xnuSrc}
          tar xf ${ioUsbFamilySrc}
          tar xf ${ioStorageFamilySrc}
          tar xf ${darlingIoKitUserSrc}
          tar xf ${securitySrc}
          tar xf ${objcSrc}
          tar xf ${libcSrc}
          tar xf ${libinfoSrc}
          tar xf ${libresolvSrc}
          tar xf ${bootstrapCmdsSrc}
          tar xf ${launchdSrc}
          tar xf ${hfsSrc}
          tar xf ${libnotifySrc}
          tar xf ${darlingMetalSrc}
          cd "zig-${version}"
        '';
      }
      {
        name = "install";
        script = ''
          coreFoundationRoot="../swift-corelibs-foundation-${coreFoundationRevision}"
          systemConfigurationRoot="../configd-${systemConfigurationRevision}"
          ioKitUserRoot="../IOKitUser-${ioKitUserRevision}"
          xnuRoot="$PWD/../xnu-${xnuRevision}"
          ioUsbFamilyRoot="../IOUSBFamily-${ioUsbFamilyRevision}"
          ioStorageFamilyRoot="../IOStorageFamily-${ioStorageFamilyRevision}"
          darlingIoKitUserRoot="../darling-iokituser-${darlingIoKitUserRevision}"
          securityRoot="../Security-${securityRevision}"
          objcRoot="../objc4-${objcRevision}"
          libcRoot="../Libc-${libcRevision}"
          libinfoRoot="../Libinfo-${libinfoRevision}"
          libresolvRoot="../libresolv-${libresolvRevision}"
          bootstrapCmdsRoot="../bootstrap_cmds-${bootstrapCmdsRevision}"
          launchdRoot="../launchd-${launchdRevision}"
          hfsRoot="../hfs-${hfsRevision}"
          libnotifyRoot="../Libnotify-${libnotifyRevision}"
          darlingMetalRoot="../darling-metal-${darlingMetalRevision}"

          mkdir -p \
            "$out/usr/include/c++/v1" \
            "$out/usr/include/hfs" \
            "$out/usr/include/libunwind" \
            "$out/usr/include/objc" \
            "$out/usr/include/os" \
            "$out/usr/include/rpc" \
            "$out/usr/include/rpcsvc" \
            "$out/usr/include/servers" \
            "$out/usr/lib" \
            "$out/System/Library/Frameworks/Accelerate.framework/Headers" \
            "$out/System/Library/Frameworks/Accelerate.framework/Versions/A/Frameworks/vImage.framework/Versions/A" \
            "$out/System/Library/Frameworks/ApplicationServices.framework/Headers" \
            "$out/System/Library/Frameworks/ApplicationServices.framework/Versions/A" \
            "$out/System/Library/Frameworks/AppKit.framework/Headers" \
            "$out/System/Library/Frameworks/AppKit.framework/Versions/C" \
            "$out/System/Library/Frameworks/AudioToolbox.framework/Headers" \
            "$out/System/Library/Frameworks/AudioToolbox.framework/Versions/A" \
            "$out/System/Library/Frameworks/AudioUnit.framework/Headers" \
            "$out/System/Library/Frameworks/AudioUnit.framework/Versions/A" \
            "$out/System/Library/Frameworks/Carbon.framework/Headers" \
            "$out/System/Library/Frameworks/Carbon.framework/Versions/A" \
            "$out/System/Library/Frameworks/CFNetwork.framework/Headers" \
            "$out/System/Library/Frameworks/CFNetwork.framework/Versions/A" \
            "$out/System/Library/Frameworks/Cocoa.framework/Headers" \
            "$out/System/Library/Frameworks/CoreFoundation.framework/Headers" \
            "$out/System/Library/Frameworks/CoreFoundation.framework/Versions/A" \
            "$out/System/Library/Frameworks/CoreAudio.framework/Headers" \
            "$out/System/Library/Frameworks/CoreAudio.framework/Versions/A" \
            "$out/System/Library/Frameworks/CoreGraphics.framework/Headers" \
            "$out/System/Library/Frameworks/CoreGraphics.framework/Versions/A" \
            "$out/System/Library/Frameworks/CoreMIDI.framework/Headers" \
            "$out/System/Library/Frameworks/CoreMIDI.framework/Versions/A" \
            "$out/System/Library/Frameworks/CoreServices.framework/Headers" \
            "$out/System/Library/Frameworks/CoreServices.framework/Versions/A" \
            "$out/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/CarbonCore.framework/Versions/A" \
            "$out/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A" \
            "$out/System/Library/Frameworks/CoreText.framework/Headers" \
            "$out/System/Library/Frameworks/CoreText.framework/Versions/A" \
            "$out/System/Library/Frameworks/CoreVideo.framework/Headers" \
            "$out/System/Library/Frameworks/CoreVideo.framework/Versions/A" \
            "$out/System/Library/Frameworks/Foundation.framework/Headers" \
            "$out/System/Library/Frameworks/Foundation.framework/Versions/C" \
            "$out/System/Library/Frameworks/Hypervisor.framework/Headers" \
            "$out/System/Library/Frameworks/Hypervisor.framework/Versions/A" \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/storage/ata" \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/storage" \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/audio" \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/graphics" \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/usb" \
            "$out/System/Library/Frameworks/IOSurface.framework/Headers" \
            "$out/System/Library/Frameworks/IOSurface.framework/Versions/A" \
            "$out/System/Library/Frameworks/JavaRuntimeSupport.framework/Headers" \
            "$out/System/Library/Frameworks/JavaRuntimeSupport.framework/Versions/A" \
            "$out/System/Library/Frameworks/JavaVM.framework/Versions/A/Frameworks/JavaRuntimeSupport.framework/Versions/A" \
            "$out/System/Library/Frameworks/Metal.framework/Headers" \
            "$out/System/Library/Frameworks/Metal.framework/Versions/A" \
            "$out/System/Library/Frameworks/OpenGL.framework/Headers" \
            "$out/System/Library/Frameworks/OpenGL.framework/Versions/A" \
            "$out/System/Library/Frameworks/QuartzCore.framework/Headers" \
            "$out/System/Library/Frameworks/QuartzCore.framework/Versions/A" \
            "$out/System/Library/Frameworks/Security.framework/Headers" \
            "$out/System/Library/Frameworks/SystemConfiguration.framework/Headers" \
            "$out/share/licenses/darwin-sdk"

          cp -R lib/libc/include/any-darwin-any/. "$out/usr/include/"
          cp -R lib/libcxx/include/. "$out/usr/include/c++/v1/"
          cp -R lib/libcxxabi/include/. "$out/usr/include/c++/v1/"
          cp -R lib/libunwind/include/. "$out/usr/include/libunwind/"
          cp lib/libc/darwin/libSystem.tbd "$out/usr/lib/libSystem.tbd"
          sed -i '$i\  - targets: [ x86_64-macos, arm64-macos ]\n    symbols: [ _iconv, _iconv_close, _iconv_open ]' \
            "$out/usr/lib/libSystem.tbd"

          . ${jdk25AudioFragment}

          # IcedTea's native font and indexed-image paths use the public
          # Accelerate umbrella for exactly two vImage operations.  Keep the
          # canonical nested-framework install name and reexport relationship;
          # these files declare ABI only and provide no implementation.
          cp ${./darwin-sdk-accelerate-jdk.h} \
            "$out/System/Library/Frameworks/Accelerate.framework/Headers/Accelerate.h"
          cp ${./darwin-sdk-accelerate.tbd} \
            "$out/System/Library/Frameworks/Accelerate.framework/Accelerate.tbd"
          cp ${./darwin-sdk-vimage.tbd} \
            "$out/System/Library/Frameworks/Accelerate.framework/Versions/A/Frameworks/vImage.framework/Versions/A/vImage.tbd"
          ln -s ../../Accelerate.tbd \
            "$out/System/Library/Frameworks/Accelerate.framework/Versions/A/Accelerate.tbd"
          ln -s Accelerate.tbd \
            "$out/System/Library/Frameworks/Accelerate.framework/Versions/A/Accelerate"
          ln -s vImage.tbd \
            "$out/System/Library/Frameworks/Accelerate.framework/Versions/A/Frameworks/vImage.framework/Versions/A/vImage"

          cp ${./darwin-sdk-coretext-jdk.h} \
            "$out/System/Library/Frameworks/CoreText.framework/Headers/CoreText.h"
          cp ${./darwin-sdk-coretext.tbd} \
            "$out/System/Library/Frameworks/CoreText.framework/CoreText.tbd"
          ln -s ../../CoreText.tbd \
            "$out/System/Library/Frameworks/CoreText.framework/Versions/A/CoreText.tbd"
          ln -s CoreText.tbd \
            "$out/System/Library/Frameworks/CoreText.framework/Versions/A/CoreText"
          # Darwin's Rust target specification and ordinary Autoconf clients
          # link iconv through its historical compatibility install name even
          # though the POSIX entry points are also exported by libSystem.
          # Publish that command-line SDK alias so `-liconv` records the same
          # dylib contract as Apple's SDK.
          cp ${./darwin-sdk-libiconv.tbd} "$out/usr/lib/libiconv.tbd"
          ln -s libiconv.tbd "$out/usr/lib/libiconv.2.tbd"
          # Apple's command-line sandbox API is a standalone system library,
          # not a libSystem re-export.  Nix and other Darwin-native tools use
          # it to retain the platform sandbox rather than weakening builds.
          cat > "$out/usr/include/sandbox.h" <<'EOF'
          #ifndef _SANDBOX_H_
          #define _SANDBOX_H_

          #include <stdint.h>
          #include <sys/cdefs.h>

          #define SANDBOX_NAMED 0x0001
          #define SANDBOX_NAMED_EXTERNAL 0x0003

          __BEGIN_DECLS
          extern const char *const kSBXProfileNoInternet;
          extern const char *const kSBXProfileNoNetwork;
          extern const char *const kSBXProfileNoWrite;
          extern const char *const kSBXProfileNoWriteExceptTemporary;
          extern const char *const kSBXProfilePureComputation;

          int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);
          void sandbox_free_error(char *errorbuf);
          __END_DECLS

          #endif
          EOF
          cp ${./darwin-sdk-libsandbox.tbd} "$out/usr/lib/libsandbox.tbd"
          ln -s libsandbox.tbd "$out/usr/lib/libsandbox.1.tbd"
          # Current Apple resolver headers bind the established public entry
          # points to their BIND 9 symbol names. Zig's older libSystem surface
          # describes only the unversioned aliases, so publish the matching
          # ABI exported by modern Darwin libSystem as well.
          sed -i '$i\  - targets: [ x86_64-macos, arm64-macos ]\n    symbols: [ _res_9_close, _res_9_dn_expand, _res_9_getservers, _res_9_init, _res_9_isourserver, _res_9_mkquery, _res_9_ndestroy, _res_9_ninit, _res_9_query, _res_9_querydomain, _res_9_search, _res_9_send, _res_9_sendsigned ]' \
            "$out/usr/lib/libSystem.tbd"
          cp "$xnuRoot/bsd/netinet/tcp_fsm.h" "$out/usr/include/netinet/"
          cp "$xnuRoot/bsd/netinet/tcp_timer.h" "$out/usr/include/netinet/"
          # OpenJDK's Darwin reachability implementation consumes the public
          # XNU ICMP wire layouts directly. Keep these headers byte-for-byte
          # from the pinned XNU source rather than recreating packet ABI.
          cp "$xnuRoot/bsd/netinet/ip_icmp.h" "$out/usr/include/netinet/"
          cp "$xnuRoot/bsd/netinet/icmp6.h" "$out/usr/include/netinet/"
          # OpenJDK's Darwin IPv6 interface enumeration uses the public XNU
          # in6_ifreq ioctl ABI. Install its exact public header closure from
          # the pinned XNU source rather than reconstructing kernel layouts.
          mkdir -p "$out/usr/include/netinet6"
          cp "$xnuRoot/bsd/netinet/in_var.h" "$out/usr/include/netinet/"
          cp "$xnuRoot/bsd/netinet6/in6_var.h" "$out/usr/include/netinet6/"
          cp "$xnuRoot/bsd/netinet6/scope6_var.h" "$out/usr/include/netinet6/"
          cp "$xnuRoot/bsd/sys/protosw.h" "$out/usr/include/sys/"
          cp "$xnuRoot/bsd/sys/kern_event.h" "$out/usr/include/sys/"
          cp "$xnuRoot/bsd/sys/sys_domain.h" "$out/usr/include/sys/"
          cp "$xnuRoot/bsd/net/if_arp.h" "$out/usr/include/net/"
          cp "$xnuRoot/bsd/net/bpf.h" "$out/usr/include/net/"
          cp "$xnuRoot/bsd/net/ethernet.h" "$out/usr/include/net/"
          cp "$xnuRoot/bsd/net/if_media.h" "$out/usr/include/net/"
          cp "$xnuRoot/bsd/sys/ptrace.h" "$out/usr/include/sys/"
          cp "$xnuRoot/bsd/sys/ttydev.h" "$out/usr/include/sys/"
          cp "$xnuRoot/bsd/sys/xattr.h" "$out/usr/include/sys/"
          # XNU generates the installed syscall-number header from its
          # authoritative master table rather than checking it into source.
          # Run Apple's generator with the hermetic AOS shell and build tools.
          (
            cd "$xnuRoot/bsd/sys"
            "$CONFIG_SHELL" ../kern/makesyscalls.sh ../kern/syscalls.master header
            cp syscall.h "$out/usr/include/sys/"
          )
          cp "$libresolvRoot/resolv.h" "$out/usr/include/"
          cp "$libresolvRoot/dns.h" "$out/usr/include/"
          cp "$libresolvRoot/arpa/nameser.h" "$out/usr/include/arpa/"
          cp "$libcRoot/include/arpa/nameser_compat.h" "$out/usr/include/arpa/"
          cp "$libinfoRoot"/rpc.subproj/*.h "$out/usr/include/rpc/"
          # NIS remains part of Darwin's public Libinfo ABI and CPython 3.12
          # builds its corresponding standard-library module when yp_match is
          # available from libSystem. Install the matching canonical protocol
          # and client declarations from the same pinned Apple source.
          cp \
            "$libinfoRoot/nis.subproj/yp_prot.h" \
            "$libinfoRoot/nis.subproj/ypclnt.h" \
            "$out/usr/include/rpcsvc/"
          cp "$libcRoot/include/fstab.h" "$out/usr/include/"
          cp "$libcRoot/stdtime/FreeBSD/tzfile.h" "$out/usr/include/"
          # launchd publishes the userspace Mach bootstrap interface at the
          # traditional SDK path consumed by Kerberos KCM and other clients.
          cp "$launchdRoot/liblaunch/bootstrap.h" \
            "$out/usr/include/servers/bootstrap.h"
          cp "$hfsRoot/core/hfs_mount.h" "$out/usr/include/hfs/"
          cp "$libnotifyRoot/notify.h" "$out/usr/include/notify.h"
          cp "$xnuRoot/libkern/os/log.h" "$out/usr/include/os/"
          # XNU publishes the core log object surface, while the user-space
          # SDK additionally declares the enablement query used by signpost
          # clients. The matching libSystem export is supplied by Zig's
          # canonical TAPI input.
          sed -i '/^__END_DECLS$/i\
          OS_EXPORT OS_NOTHROW OS_WARN_RESULT\
          bool\
          os_log_type_enabled(os_log_t log, os_log_type_t type);\
          ' "$out/usr/include/os/log.h"
          # os/signpost.h is part of the public Darwin SDK but not the open XNU
          # header set. Install the canonical public types, reserved IDs, and
          # formatted event ABI required by V8. Clang's os-log builtins retain
          # the format metadata and dynamic payload consumed by Instruments.
          cat > "$out/usr/include/os/signpost.h" <<'EOF'
          #ifndef __os_signpost_h
          #define __os_signpost_h

          #include <os/log.h>
          #include <stdint.h>

          typedef uint64_t os_signpost_id_t;

          #define OS_SIGNPOST_ID_NULL ((os_signpost_id_t)0)
          #define OS_SIGNPOST_ID_INVALID ((os_signpost_id_t)~0ull)
          #define OS_SIGNPOST_ID_EXCLUSIVE ((os_signpost_id_t)0xEEEEB0B5B2B2EEEEull)

          OS_ENUM(os_signpost_type, uint8_t,
              OS_SIGNPOST_EVENT          = 0x00,
              OS_SIGNPOST_INTERVAL_BEGIN = 0x01,
              OS_SIGNPOST_INTERVAL_END   = 0x02);

          __BEGIN_DECLS

          OS_EXPORT OS_NOTHROW OS_WARN_RESULT
          bool
          os_signpost_enabled(os_log_t log);

          OS_EXPORT OS_NOTHROW OS_WARN_RESULT
          os_signpost_id_t
          os_signpost_id_generate(os_log_t log);

          OS_EXPORT OS_NOTHROW OS_WARN_RESULT
          os_signpost_id_t
          os_signpost_id_make_with_pointer(os_log_t log, const void *pointer);

          OS_EXPORT OS_NOTHROW
          void
          _os_signpost_emit_with_name_impl(void *dso, os_log_t log,
              os_signpost_type_t type, os_signpost_id_t signpost_id,
              const char *name, const char *format, uint8_t *buffer,
              uint32_t buffer_size);

          __END_DECLS

          #define os_signpost_emit_with_type(log, type, signpost_id, name, format, ...) \
              __extension__({ \
                  os_log_t _os_signpost_log = (log); \
                  os_signpost_type_t _os_signpost_type = (type); \
                  os_signpost_id_t _os_signpost_id = (signpost_id); \
                  if (_os_signpost_id != OS_SIGNPOST_ID_NULL && \
                      _os_signpost_id != OS_SIGNPOST_ID_INVALID && \
                      os_signpost_enabled(_os_signpost_log)) { \
                      _Static_assert(__builtin_constant_p(name), \
                          "signpost name must be constant"); \
                      _Static_assert(__builtin_constant_p(format), \
                          "format string must be constant"); \
                      __attribute__((section("__TEXT,__oslogstring,cstring_literals"))) \
                      static const char _os_signpost_name[] = name; \
                      __attribute__((section("__TEXT,__oslogstring,cstring_literals"))) \
                      static const char _os_signpost_format[] = format; \
                      uint8_t _Alignas(16) _os_signpost_buffer[ \
                          __builtin_os_log_format_buffer_size(format, ##__VA_ARGS__)]; \
                      _os_signpost_emit_with_name_impl(&__dso_handle, \
                          _os_signpost_log, _os_signpost_type, _os_signpost_id, \
                          _os_signpost_name, _os_signpost_format, \
                          (uint8_t *)__builtin_os_log_format( \
                              _os_signpost_buffer, format, ##__VA_ARGS__), \
                          (uint32_t)sizeof(_os_signpost_buffer)); \
                  } \
              })

          #define os_signpost_event_emit(log, signpost_id, name, format, ...) \
              os_signpost_emit_with_type(log, OS_SIGNPOST_EVENT, signpost_id, \
                  name, format, ##__VA_ARGS__)

          #endif
          EOF
          cp \
            "$libcRoot/include/readpassphrase.h" \
            "$libcRoot/include/utmp.h" \
            "$libcRoot/include/util.h" \
            "$out/usr/include/"
          # Apple's Libc build runs util.h through unifdef before installing
          # it.  Preserve the resulting legacy login-accounting declarations
          # that OpenSSH still uses instead of publishing the raw source-only
          # UNIFDEF_LEGACY_UTMP_APIS guards.
          sed -i \
            -e '/^#ifdef UNIFDEF_LEGACY_UTMP_APIS$/d' \
            -e '/^#endif \/\* UNIFDEF_LEGACY_UTMP_APIS \*\/$/d' \
            "$out/usr/include/util.h"
          cp \
            "$libinfoRoot/membership.subproj/membership.h" \
            "$libinfoRoot/membership.subproj/ntsid.h" \
            "$out/usr/include/"

          # Apple installs mach_vm.h after compiling the Mach Interface
          # Generator and running it over XNU's authoritative mach_vm.defs.
          # Reproduce that source pipeline with Linux-executed AOS build tools
          # instead of checking in a generated SDK artifact or using Xcode.
          migBuild="$PWD/aos-mig-build"
          mkdir -p "$migBuild"
          cp -R "$bootstrapCmdsRoot/migcom.tproj/." "$migBuild/"
          cp -R "$out/usr/include" "$migBuild/apple-headers"
          chmod -R u+w "$migBuild"
          (
            cd "$migBuild"
            ${buildPackages.flex}/bin/flex -o lexxer.c lexxer.l
            ${buildPackages.bison}/bin/bison -y -d parser.y

            # migcom is a native build tool, but its implementation consumes
            # Darwin's public types. Adapt only this private header copy to the
            # Linux C runtime that executes the generator.
            sed -i 's/[[:space:]]*__asm("_".*$//' apple-headers/sys/cdefs.h
            sed -i \
              -e 's/__stdinp/stdin/g' \
              -e 's/__stdoutp/stdout/g' \
              -e 's/__stderrp/stderr/g' \
              apple-headers/_stdio.h
            sed -i 's/__error/__errno_location/g' apple-headers/sys/errno.h
            sed -i 's|#include <ctype.h>|#include "aos-mig-ctype.h"|' string.c
            cat > aos-mig-ctype.h <<'EOF'
          #define islower(c) ((unsigned int)((c) - 'a') <= (unsigned int)('z' - 'a'))
          #define toupper(c) (islower(c) ? ((c) - 'a' + 'A') : (c))
          EOF

            buildCC=${buildPackages.stdenv.cc}/bin/cc
            runBuildCC() (
              unset AOS_HARDENING_ENABLE AOS_TARGET_ARCH AOS_TARGET_PLATFORM
              unset CFLAGS CXXFLAGS CPPFLAGS LDFLAGS
              unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH CPATH LIBRARY_PATH
              unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT
              exec "$buildCC" "$@"
            )
            compilerIncludes=$(runBuildCC -print-file-name=include)
            runBuildCC -nostdinc -I. -Iapple-headers -isystem "$compilerIncludes" \
              -Ulinux -U__linux -U__linux__ -D__APPLE__=1 -D__MACH__=1 \
              -D__private_extern__= -D__kernel_ptr_semantics= \
              -D__LITTLE_ENDIAN__=1 -DNDEBUG -DMIG_VERSION='"aos-mig"' \
              -o migcom \
              error.c global.c header.c lexxer.c mig.c y.tab.c \
              routine.c server.c statement.c string.c type.c user.c utils.c

            {
              printf '#line 1 "%s"\n' "$xnuRoot/osfmk/mach/mach_vm.defs"
              cat "$xnuRoot/osfmk/mach/mach_vm.defs"
            } > mach_vm.defs.c
            # Match Apple's userspace header mode. It gives the modern routine
            # its private compatibility name so mach_vm.h can be included
            # after mach.h's legacy vm_map interface.
            runBuildCC -E -x c \
              -D__MACH30__ \
              -DLIBSYSCALL_INTERFACE=1 \
              -I "$xnuRoot/osfmk" \
              -I "$xnuRoot" \
              mach_vm.defs.c \
              | ./migcom \
                  -header "$out/usr/include/mach/mach_vm.h" \
                  -user /dev/null \
                  -server /dev/null
            test -s "$out/usr/include/mach/mach_vm.h"
          )

          # Newer Apple open-source framework headers describe bridgeOS API
          # availability, while Zig's open SDK snapshot omits that platform's
          # public macro mappings.  Preserve the annotations by teaching the
          # common availability header about the Clang-supported platform.
          sed -i '/__API_AVAILABLE_PLATFORM_driverkit/i\
          #define __API_AVAILABLE_PLATFORM_bridgeos(x) bridgeos,introduced=x\
          #define __API_DEPRECATED_PLATFORM_bridgeos(x,y) bridgeos,introduced=x,deprecated=y\
          #define __API_OBSOLETED_PLATFORM_bridgeos(x,y,z) bridgeos,introduced=x,deprecated=y,obsoleted=z\
          #define __API_UNAVAILABLE_PLATFORM_bridgeos bridgeos,unavailable' \
            "$out/usr/include/AvailabilityInternal.h"

          # Zig's source aggregation ships only MinimalDisplayName, but Clang
          # requires Version, MaximumDeploymentTarget, and either a recognized
          # CanonicalName or SupportedTargets.  Describe the open SDK surface
          # explicitly so availability and deployment checks remain enabled.
          cat > "$out/SDKSettings.json" <<'EOF'
          {
            "CanonicalName": "macosx${sdkVersion}",
            "MaximumDeploymentTarget": "${sdkVersion}",
            "MinimalDisplayName": "macOS ${sdkVersion}",
            "Version": "${sdkVersion}"
          }
          EOF
          cp LICENSE "$out/share/licenses/darwin-sdk/Zig-LICENSE"
          cp lib/libcxx/LICENSE.TXT "$out/share/licenses/darwin-sdk/libcxx-LICENSE"
          cp lib/libcxxabi/LICENSE.TXT "$out/share/licenses/darwin-sdk/libcxxabi-LICENSE"
          cp lib/libunwind/LICENSE.TXT "$out/share/licenses/darwin-sdk/libunwind-LICENSE"

          # Foundation and configd publish the framework headers needed by
          # command-line runtimes such as CPython.  Install the open-source
          # surfaces in the standard SDK layout so Clang's -isysroot framework
          # lookup finds them without host SDK paths.
          cp -R \
            "$coreFoundationRoot/Sources/CoreFoundation/include/." \
            "$out/System/Library/Frameworks/CoreFoundation.framework/Headers/"
          # swift-corelibs-foundation defaults to its Linux Swift runtime ABI.
          # Darwin framework consumers use the system CoreFoundation ABI and
          # its compiler-emitted constant-string class reference instead.
          sed -i \
            's/#define DEPLOYMENT_RUNTIME_SWIFT 1/#define DEPLOYMENT_RUNTIME_SWIFT 0/' \
            "$out/System/Library/Frameworks/CoreFoundation.framework/Headers/CFAvailability.h"
          cp \
            "$systemConfigurationRoot/SystemConfiguration.fproj/SCDynamicStore.h" \
            "$systemConfigurationRoot/SystemConfiguration.fproj/SCDynamicStoreCopySpecific.h" \
            "$systemConfigurationRoot/SystemConfiguration.fproj/SCNetwork.h" \
            "$systemConfigurationRoot/SystemConfiguration.fproj/SCNetworkConfiguration.h" \
            "$systemConfigurationRoot/SystemConfiguration.fproj/SCNetworkReachability.h" \
            "$systemConfigurationRoot/SystemConfiguration.fproj/SCSchemaDefinitions.h" \
            "$out/System/Library/Frameworks/SystemConfiguration.framework/Headers/"
          cp "$coreFoundationRoot/LICENSE" \
            "$out/share/licenses/darwin-sdk/CoreFoundation-LICENSE"
          cp "$systemConfigurationRoot/APPLE_LICENSE" \
            "$out/share/licenses/darwin-sdk/SystemConfiguration-LICENSE"

          # IOKitUser and XNU publish the user-space framework API while the
          # USB and storage families publish their framework subdirectories.
          # Install only public headers needed by command-line consumers; the
          # kernel-private source trees are not part of this SDK surface.
          cp \
            "$ioKitUserRoot/IOCFBundle.h" \
            "$ioKitUserRoot/IOCFPlugIn.h" \
            "$ioKitUserRoot/IOKitLib.h" \
            "$xnuRoot/iokit/IOKit/IOBSD.h" \
            "$xnuRoot/iokit/IOKit/IOKitKeys.h" \
            "$xnuRoot/iokit/IOKit/IOMapTypes.h" \
            "$xnuRoot/iokit/IOKit/IOReturn.h" \
            "$xnuRoot/iokit/IOKit/IOTypes.h" \
            "$xnuRoot/iokit/IOKit/OSMessageNotification.h" \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/"
          # Current Darwin IOKit umbrellas expose the public host-information
          # MIG calls used by clients such as Dawn.  The pinned open-source
          # IOKitLib header predates that transitive declaration.
          sed -i '/#include <mach\/mach_init.h>/a #include <mach/mach_host.h>' \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/IOKitLib.h"
          cp ${./darwin-sdk-ioaudio-types.h} \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/audio/IOAudioTypes.h"
          cp ${./darwin-sdk-iographics-types.h} \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/graphics/IOGraphicsTypes.h"
          cp "$xnuRoot/bsd/sys/disk.h" "$out/usr/include/sys/disk.h"
          cp \
            "$ioUsbFamilyRoot/IOUSBFamily/Headers/USB.h" \
            "$ioUsbFamilyRoot/IOUSBFamily/Headers/IOUSBLib.h" \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/usb/"
          cp \
            "$darlingIoKitUserRoot/darling/include/IOKit/usb/AppleUSBDefinitions.h" \
            "$darlingIoKitUserRoot/darling/include/IOKit/usb/IOUSBHostFamilyDefinitions.h" \
            "$darlingIoKitUserRoot/darling/include/IOKit/usb/USB.h" \
            "$darlingIoKitUserRoot/darling/include/IOKit/usb/USBSpec.h" \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/usb/"
          cp \
            "$ioStorageFamilyRoot/IOBlockStorageDevice.h" \
            "$ioStorageFamilyRoot/IOMedia.h" \
            "$ioStorageFamilyRoot/IOMediaBSDClient.h" \
            "$ioStorageFamilyRoot/IOStorage.h" \
            "$ioStorageFamilyRoot/IOStorageControllerCharacteristics.h" \
            "$ioStorageFamilyRoot/IOStorageDeviceCharacteristics.h" \
            "$ioStorageFamilyRoot/IOStorageProtocolCharacteristics.h" \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/storage/"
          cp \
            "$darlingIoKitUserRoot/darling/include/IOKit/storage/IOCDMedia.h" \
            "$darlingIoKitUserRoot/darling/include/IOKit/storage/IODVDMedia.h" \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/storage/"
          cp \
            "$darlingIoKitUserRoot/darling/include/IOKit/storage/ata/ATASMARTLib.h" \
            "$darlingIoKitUserRoot/darling/include/IOKit/storage/ata/IOATAStorageDefines.h" \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/storage/ata/"
          cp "$ioKitUserRoot/APPLE_LICENSE" \
            "$out/share/licenses/darwin-sdk/IOKitUser-LICENSE"
          cp "$xnuRoot/APPLE_LICENSE" \
            "$out/share/licenses/darwin-sdk/XNU-LICENSE"
          cp "$ioUsbFamilyRoot/APPLE_LICENSE" \
            "$out/share/licenses/darwin-sdk/IOUSBFamily-LICENSE"
          cp "$ioStorageFamilyRoot/APPLE_LICENSE" \
            "$out/share/licenses/darwin-sdk/IOStorageFamily-LICENSE"
          cp "$darlingIoKitUserRoot/APPLE_LICENSE" \
            "$out/share/licenses/darwin-sdk/Darling-IOKitUser-LICENSE"

          # Publish the command-line Security APIs used by entitlement clients
          # and libgit2's Darwin TLS transport. The complete upstream umbrella
          # also imports private keychain and CDSA headers, so describe the
          # documented SecTask, SecureTransport, certificate, and trust subset
          # directly from their canonical public declarations.
          cp "$securityRoot/OSX/APPLE_LICENSE" \
            "$out/share/licenses/darwin-sdk/Security-LICENSE"

          # Install Apple's public Objective-C runtime headers.  Darwin hosts
          # provide the implementation in libobjc; cross builds need only the
          # public compile surface and a target-library ABI description.
          cp \
            "$objcRoot/runtime/message.h" \
            "$objcRoot/runtime/NSObject.h" \
            "$objcRoot/runtime/NSObjCRuntime.h" \
            "$objcRoot/runtime/objc-api.h" \
            "$objcRoot/runtime/objc-auto.h" \
            "$objcRoot/runtime/objc-exception.h" \
            "$objcRoot/runtime/objc-sync.h" \
            "$objcRoot/runtime/objc.h" \
            "$objcRoot/runtime/runtime.h" \
            "$out/usr/include/objc/"
          cp "$objcRoot/APPLE_LICENSE" \
            "$out/share/licenses/darwin-sdk/ObjectiveC-LICENSE"
          cp "$libcRoot/APPLE_LICENSE" \
            "$out/share/licenses/darwin-sdk/Libc-LICENSE"
          cp "$libinfoRoot/APPLE_LICENSE" \
            "$out/share/licenses/darwin-sdk/Libinfo-LICENSE"
          cp "$libresolvRoot/APPLE_LICENSE" \
            "$out/share/licenses/darwin-sdk/libresolv-LICENSE"
          cp "$bootstrapCmdsRoot/APPLE_LICENSE" \
            "$out/share/licenses/darwin-sdk/bootstrap_cmds-LICENSE"
          cp "$hfsRoot/APPLE_LICENSE" \
            "$out/share/licenses/darwin-sdk/hfs-LICENSE"
          cp "$libnotifyRoot/APPLE_LICENSE" \
            "$out/share/licenses/darwin-sdk/Libnotify-LICENSE"

          cat > "$out/System/Library/Frameworks/Security.framework/Headers/SecBase.h" <<'EOF'
          #ifndef _SECURITY_SECBASE_H_
          #define _SECURITY_SECBASE_H_
          #include <CoreFoundation/CoreFoundation.h>
          #include <stdint.h>
          #include <sys/cdefs.h>
          __BEGIN_DECLS
          typedef int32_t OSStatus;
          typedef struct __SecCertificate *SecCertificateRef;
          typedef struct __SecIdentity *SecIdentityRef;
          typedef struct __SecKey *SecKeyRef;
          typedef struct __SecPolicy *SecPolicyRef;
          typedef struct __SecTrust *SecTrustRef;
          typedef OSType SecKeychainAttrType;
          typedef struct SecKeychainAttribute {
            SecKeychainAttrType tag;
            UInt32 length;
            void *data;
          } SecKeychainAttribute;
          typedef struct SecKeychainAttributeList {
            UInt32 count;
            SecKeychainAttribute *attr;
          } SecKeychainAttributeList;
          CFStringRef SecCopyErrorMessageString(OSStatus status, void *reserved);
          enum {
            errSecSuccess = 0,
            errSecAllocate = -108,
            errSecAuthFailed = -25293,
            errSecItemNotFound = -25300,
            errSSLProtocol = -9800,
            errSSLNegotiation = -9801,
            errSSLFatalAlert = -9802,
            errSSLWouldBlock = -9803,
            errSSLSessionNotFound = -9804,
            errSSLClosedGraceful = -9805,
            errSSLClosedAbort = -9806,
            errSSLXCertChainInvalid = -9807,
            errSSLBadCert = -9808,
            errSSLCrypto = -9809,
            errSSLInternal = -9810,
            errSSLModuleAttach = -9811,
            errSSLUnknownRootCert = -9812,
            errSSLNoRootCert = -9813,
            errSSLCertExpired = -9814,
            errSSLCertNotYetValid = -9815,
            errSSLClosedNoNotify = -9816,
            errSSLBufferOverflow = -9817,
            errSSLBadCipherSuite = -9818,
            errSSLPeerUnexpectedMsg = -9819,
            errSSLPeerBadRecordMac = -9820,
            errSSLPeerDecryptionFail = -9821,
            errSSLPeerRecordOverflow = -9822,
            errSSLPeerDecompressFail = -9823,
            errSSLPeerHandshakeFail = -9824,
            errSSLPeerBadCert = -9825,
            errSSLPeerUnsupportedCert = -9826,
            errSSLPeerCertRevoked = -9827,
            errSSLPeerCertExpired = -9828,
            errSSLPeerCertUnknown = -9829,
            errSSLIllegalParam = -9830,
            errSSLPeerUnknownCA = -9831,
            errSSLPeerAccessDenied = -9832,
            errSSLPeerDecodeError = -9833,
            errSSLPeerDecryptError = -9834,
            errSSLPeerExportRestriction = -9835,
            errSSLPeerProtocolVersion = -9836,
            errSSLPeerInsufficientSecurity = -9837,
            errSSLPeerInternalError = -9838,
            errSSLPeerUserCancelled = -9839,
            errSSLPeerNoRenegotiation = -9840,
            errSSLPeerAuthCompleted = -9841,
            errSSLServerAuthCompleted = errSSLPeerAuthCompleted,
            errSSLClientCertRequested = -9842,
            errSSLHostNameMismatch = -9843,
            errSSLConnectionRefused = -9844,
            errSSLDecryptionFail = -9845,
            errSSLBadRecordMac = -9846,
            errSSLRecordOverflow = -9847,
            errSSLBadConfiguration = -9848,
            errSSLUnexpectedRecord = -9849,
            errSSLWeakPeerEphemeralDHKey = -9850,
            errSSLClientHelloReceived = -9851
          };
          __END_DECLS
          #endif
          EOF

          # Apple's public AuthSession surface used by OpenJDK to distinguish
          # headless security sessions from WindowServer-capable sessions.
          cp ${./darwin-sdk-auth-session.h} \
            "$out/System/Library/Frameworks/Security.framework/Headers/AuthSession.h"

          cat > "$out/System/Library/Frameworks/Security.framework/Headers/SecCertificate.h" <<'EOF'
          #ifndef _SECURITY_SECCERTIFICATE_H_
          #define _SECURITY_SECCERTIFICATE_H_
          #include <Security/SecBase.h>
          #include <Security/cssmtype.h>
          __BEGIN_DECLS
          SecCertificateRef SecCertificateCreateWithData(CFAllocatorRef allocator, CFDataRef data);
          CFDataRef SecCertificateCopyData(SecCertificateRef certificate);
          CFStringRef SecCertificateCopySubjectSummary(SecCertificateRef certificate);
          OSStatus SecCertificateCopyCommonName(SecCertificateRef certificate, CFStringRef *commonName);
          CFStringRef SecCertificateCopyLongDescription(
            CFAllocatorRef allocator,
            SecCertificateRef certificate,
            CFErrorRef *error
          );
          OSStatus SecCertificateGetData(SecCertificateRef certificate, CSSM_DATA *data);
          CFTypeID SecCertificateGetTypeID(void);
          __END_DECLS
          #endif
          EOF

          cat > "$out/System/Library/Frameworks/Security.framework/Headers/SecItem.h" <<'EOF'
          #ifndef _SECURITY_SECITEM_H_
          #define _SECURITY_SECITEM_H_
          #include <Security/SecBase.h>
          __BEGIN_DECLS
          extern const CFStringRef kSecClass;
          extern const CFStringRef kSecClassCertificate;
          extern const CFStringRef kSecClassIdentity;
          extern const CFStringRef kSecAttrLabel;
          extern const CFStringRef kSecMatchLimit;
          extern const CFStringRef kSecMatchLimitAll;
          extern const CFStringRef kSecMatchSearchList;
          extern const CFStringRef kSecMatchPolicy;
          extern const CFStringRef kSecReturnRef;
          OSStatus SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result);
          __END_DECLS
          #endif
          EOF

          cat > "$out/System/Library/Frameworks/Security.framework/Headers/SecPolicy.h" <<'EOF'
          #ifndef _SECURITY_SECPOLICY_H_
          #define _SECURITY_SECPOLICY_H_
          #include <Security/SecBase.h>
          __BEGIN_DECLS
          extern const CFStringRef kSecPolicyAppleSSL;
          extern const CFStringRef kSecPolicyOid;
          CFDictionaryRef SecPolicyCopyProperties(SecPolicyRef policy);
          SecPolicyRef SecPolicyCreateSSL(Boolean server, CFStringRef hostname);
          __END_DECLS
          #endif
          EOF

          cat > "$out/System/Library/Frameworks/Security.framework/Headers/SecTrust.h" <<'EOF'
          #ifndef _SECURITY_SECTRUST_H_
          #define _SECURITY_SECTRUST_H_
          #include <Security/SecBase.h>
          #include <Security/cssmapple.h>
          __BEGIN_DECLS
          typedef enum {
            kSecTrustResultInvalid = 0,
            kSecTrustResultProceed = 1,
            kSecTrustResultConfirm = 2,
            kSecTrustResultDeny = 3,
            kSecTrustResultUnspecified = 4,
            kSecTrustResultRecoverableTrustFailure = 5,
            kSecTrustResultFatalTrustFailure = 6,
            kSecTrustResultOtherError = 7
          } SecTrustResultType;
          OSStatus SecTrustCreateWithCertificates(
            CFTypeRef certificates,
            CFTypeRef policies,
            SecTrustRef *trust
          );
          OSStatus SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result);
          OSStatus SecTrustCopyAnchorCertificates(CFArrayRef *anchors);
          OSStatus SecTrustSetAnchorCertificates(SecTrustRef trust, CFArrayRef anchors);
          OSStatus SecTrustSetAnchorCertificatesOnly(SecTrustRef trust, Boolean anchorCertificatesOnly);
          SecKeyRef SecTrustCopyPublicKey(SecTrustRef trust);
          CFIndex SecTrustGetCertificateCount(SecTrustRef trust);
          OSStatus SecTrustGetResult(
            SecTrustRef trust,
            SecTrustResultType *result,
            CFArrayRef *certChain,
            CSSM_TP_APPLE_EVIDENCE_INFO **evidenceInfo
          );
          bool SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error);
          SecCertificateRef SecTrustGetCertificateAtIndex(SecTrustRef trust, CFIndex index);
          __END_DECLS
          #endif
          EOF

          # Exact public subset from the pinned Apple Security
          # trust/headers/SecTrustSettings.h surface.
          cat > "$out/System/Library/Frameworks/Security.framework/Headers/SecTrustSettings.h" <<'EOF'
          #ifndef _SECURITY_SECTRUSTSETTINGS_H_
          #define _SECURITY_SECTRUSTSETTINGS_H_
          #include <Security/SecBase.h>

          #define kSecTrustSettingsPolicy CFSTR("kSecTrustSettingsPolicy")
          #define kSecTrustSettingsApplication CFSTR("kSecTrustSettingsApplication")
          #define kSecTrustSettingsPolicyString CFSTR("kSecTrustSettingsPolicyString")
          #define kSecTrustSettingsResult CFSTR("kSecTrustSettingsResult")

          typedef CF_ENUM(uint32_t, SecTrustSettingsResult) {
            kSecTrustSettingsResultInvalid = 0,
            kSecTrustSettingsResultTrustRoot = 1,
            kSecTrustSettingsResultTrustAsRoot = 2,
            kSecTrustSettingsResultDeny = 3,
            kSecTrustSettingsResultUnspecified = 4
          };

          typedef CF_ENUM(uint32_t, SecTrustSettingsDomain) {
            kSecTrustSettingsDomainUser = 0,
            kSecTrustSettingsDomainAdmin = 1,
            kSecTrustSettingsDomainSystem = 2
          };

          __BEGIN_DECLS
          OSStatus SecTrustSettingsCopyTrustSettings(
            SecCertificateRef certificate,
            SecTrustSettingsDomain domain,
            CFArrayRef *trustSettings
          );
          OSStatus SecTrustSettingsCopyCertificates(
            SecTrustSettingsDomain domain,
            CFArrayRef * __nullable CF_RETURNS_RETAINED certArray
          );
          __END_DECLS
          #endif
          EOF

          cp ${./darwin-sdk-secure-transport.h} \
            "$out/System/Library/Frameworks/Security.framework/Headers/SecureTransport.h"
          cp "$securityRoot/header_symlinks/Security/CipherSuite.h" \
            "$out/System/Library/Frameworks/Security.framework/Headers/CipherSuite.h"

          cp ${./darwin-sdk-sec-keychain.h} \
            "$out/System/Library/Frameworks/Security.framework/Headers/SecKeychain.h"
          cp ${./darwin-sdk-sec-identity.h} \
            "$out/System/Library/Frameworks/Security.framework/Headers/SecIdentity.h"
          cp ${./darwin-sdk-sec-key.h} \
            "$out/System/Library/Frameworks/Security.framework/Headers/SecKey.h"
          cp ${./darwin-sdk-sec-identity-search.h} \
            "$out/System/Library/Frameworks/Security.framework/Headers/SecIdentitySearch.h"
          cp ${./darwin-sdk-sec-policy-search.h} \
            "$out/System/Library/Frameworks/Security.framework/Headers/SecPolicySearch.h"

          # Apple's pinned public import/export ABI used by the macOS
          # KeychainStore implementation in OpenJDK 8.
          cp ${./darwin-sdk-cssmtype.h} \
            "$out/System/Library/Frameworks/Security.framework/Headers/cssmtype.h"
          cp ${./darwin-sdk-cssmapple.h} \
            "$out/System/Library/Frameworks/Security.framework/Headers/cssmapple.h"
          cp ${./darwin-sdk-oidsalg.h} \
            "$out/System/Library/Frameworks/Security.framework/Headers/oidsalg.h"
          cp ${./darwin-sdk-sec-access.h} \
            "$out/System/Library/Frameworks/Security.framework/Headers/SecAccess.h"
          cp ${./darwin-sdk-sec-import-export.h} \
            "$out/System/Library/Frameworks/Security.framework/Headers/SecImportExport.h"

          cat > "$out/System/Library/Frameworks/Security.framework/Headers/Security.h" <<'EOF'
          #ifndef _SECURITY_H_
          #define _SECURITY_H_
          #include <Security/AuthSession.h>
          #include <Security/SecBase.h>
          #include <Security/SecCertificate.h>
          #include <Security/SecImportExport.h>
          #include <Security/SecIdentity.h>
          #include <Security/SecIdentitySearch.h>
          #include <Security/SecItem.h>
          #include <Security/SecKey.h>
          #include <Security/SecKeychain.h>
          #include <Security/SecPolicy.h>
          #include <Security/SecPolicySearch.h>
          #include <Security/SecTask.h>
          #include <Security/SecTrust.h>
          #include <Security/SecTrustSettings.h>
          #include <Security/SecureTransport.h>
          #include <Security/cssmapple.h>
          #include <Security/oidsalg.h>
          #endif
          EOF

          cat > "$out/System/Library/Frameworks/Security.framework/Headers/SecTask.h" <<'EOF'
          #ifndef _SECURITY_SECTASK_H_
          #define _SECURITY_SECTASK_H_
          #include <CoreFoundation/CoreFoundation.h>
          #include <mach/message.h>
          #include <sys/cdefs.h>
          __BEGIN_DECLS
          typedef struct __SecTask *SecTaskRef;
          CFTypeID SecTaskGetTypeID(void);
          SecTaskRef SecTaskCreateWithAuditToken(CFAllocatorRef allocator, audit_token_t token);
          SecTaskRef SecTaskCreateFromSelf(CFAllocatorRef allocator);
          CFTypeRef SecTaskCopyValueForEntitlement(
            SecTaskRef task,
            CFStringRef entitlement,
            CFErrorRef *error
          );
          CFDictionaryRef SecTaskCopyValuesForEntitlements(
            SecTaskRef task,
            CFArrayRef entitlements,
            CFErrorRef *error
          );
          CFStringRef SecTaskCopySigningIdentifier(SecTaskRef task, CFErrorRef *error);
          __END_DECLS
          #endif
          EOF

          cat > "$out/System/Library/Frameworks/SystemConfiguration.framework/Headers/SystemConfiguration.h" <<'EOF'
          #ifndef _SYSTEMCONFIGURATION_H
          #define _SYSTEMCONFIGURATION_H
          #include <CoreFoundation/CoreFoundation.h>
          typedef const struct __SCPreferences *SCPreferencesRef;
          #include <SystemConfiguration/SCDynamicStore.h>
          #include <SystemConfiguration/SCDynamicStoreCopySpecific.h>
          #include <SystemConfiguration/SCNetwork.h>
          #include <SystemConfiguration/SCNetworkReachability.h>
          #include <SystemConfiguration/SCNetworkConfiguration.h>
          #include <SystemConfiguration/SCSchemaDefinitions.h>
          #endif
          EOF

          cat > "$out/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation'
          current-version: 3500.0.0
          compatibility-version: 150.0.0
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols:
                - _CFArrayGetCount
                - _CFArrayGetTypeID
                - _CFArrayGetValueAtIndex
                - _CFArrayAppendValue
                - _CFArrayCreate
                - _CFArrayCreateMutable
                - _CFArrayInsertValueAtIndex
                - _CFArrayRemoveAllValues
                - _CFArraySetValueAtIndex
                - _CFAttributedStringCreateMutable
                - _CFAttributedStringRemoveAttribute
                - _CFAttributedStringReplaceString
                - _CFAttributedStringSetAttribute
                - _CFBooleanGetTypeID
                - _CFBooleanGetValue
                - _CFBundleCopyExecutableURL
                - _CFBundleCreate
                - _CFBundleGetIdentifier
                - _CFBundleGetValueForInfoDictionaryKey
                - _CFBundleGetVersionNumber
                - _CFCopyTypeIDDescription
                - _CFDataGetBytePtr
                - _CFDataCreate
                - _CFDataGetBytes
                - _CFDataGetLength
                - _CFDataGetTypeID
                - _CFDictionaryAddValue
                - _CFDictionaryContainsKey
                - _CFDictionaryCreate
                - _CFDictionaryCreateMutable
                - _CFDictionaryGetValue
                - _CFDictionaryGetTypeID
                - _CFDictionaryGetValueIfPresent
                - _CFDictionarySetValue
                - _CFEqual
                - _CFGetTypeID
                - _CFLocaleCreateCanonicalLanguageIdentifierFromString
                - _CFLocaleCopyISOLanguageCodes
                - _CFMachPortCreateRunLoopSource
                - _CFMakeCollectable
                - _CFNumberCreate
                - _CFNumberGetTypeID
                - _CFNumberGetValue
                - _CFNumberIsFloatType
                - _CFPropertyListCreateWithStream
                - _CFReadStreamClose
                - _CFReadStreamCreateWithFile
                - _CFReadStreamOpen
                - _CFRelease
                - _CFRetain
                - _CFRunLoopAddSource
                - _CFRunLoopAddObserver
                - _CFRunLoopGetCurrent
                - _CFRunLoopGetMain
                - _CFRunLoopIsWaiting
                - _CFRunLoopRemoveSource
                - _CFRunLoopObserverCreate
                - _CFRunLoopRun
                - _CFRunLoopSourceCreate
                - _CFRunLoopSourceSignal
                - _CFRunLoopStop
                - _CFRunLoopWakeUp
                - _CFStringCreateWithCString
                - _CFStringCreateWithCStringNoCopy
                - _CFShow
                - _CFStringCreateWithBytes
                - _CFStringCreateCopy
                - _CFStringCreateMutableCopy
                - _CFStringCreateWithCharactersNoCopy
                - _CFStringCreateWithFileSystemRepresentation
                - _CFStringCompare
                - _CFStringGetBytes
                - _CFStringGetCString
                - _CFStringGetCStringPtr
                - _CFStringGetFileSystemRepresentation
                - _CFStringGetLength
                - _CFStringGetMaximumSizeForEncoding
                - _CFStringGetMaximumSizeOfFileSystemRepresentation
                - _CFStringGetTypeID
                - _CFStringHasPrefix
                - _CFStringNormalize
                - _CFTimeZoneCopyDefault
                - _CFTimeZoneCopySystem
                - _CFTimeZoneGetName
                - _CFTimeZoneResetSystem
                - _CFURLCreateFromFileSystemRepresentation
                - _CFURLCopyAbsoluteURL
                - _CFURLCopyFileSystemPath
                - _CFURLCopyLastPathComponent
                - _CFURLCreateCopyAppendingPathComponent
                - _CFURLCreateCopyDeletingLastPathComponent
                - _CFURLCreateFilePathURL
                - _CFURLCreateFileReferenceURL
                - _CFURLCreateWithString
                - _CFURLCreateWithFileSystemPath
                - _CFURLGetFileSystemRepresentation
                - _CFURLResourceIsReachable
                - _CFURLSetResourcePropertyForKey
                - _CFUUIDCreate
                - _CFUUIDCreateString
                - _CFUUIDGetConstantUUIDWithBytes
                - _CFUUIDGetUUIDBytes
                - __CFConstantStringClassReference
                - ___CFConstantStringClassReference
                - ___CFStringMakeConstantString
                - _kCFAllocatorDefault
                - _kCFAllocatorNull
                - _kCFAllocatorMalloc
                - _kCFAllocatorSystemDefault
                - _kCFBooleanTrue
                - _kCFBooleanFalse
                - _kCFBundleExecutableKey
                - _kCFBundleNameKey
                - _kCFRunLoopCommonModes
                - _kCFRunLoopDefaultMode
                - _kCFTypeArrayCallBacks
                - _kCFTypeDictionaryKeyCallBacks
                - _kCFTypeDictionaryValueCallBacks
          ...
          EOF
          sed -i \
            '/_CFArrayGetCount/r ${./darwin-sdk-corefoundation-jdk25.tbd-exports}' \
            "$out/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation.tbd"
          # Reexported framework install names include their versioned binary
          # path. ld64.lld resolves that path directly when following a TBD
          # reexport, so retain the canonical framework layout around the
          # release stub in addition to its top-level SDK lookup name.
          ln -s ../../CoreFoundation.tbd \
            "$out/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation.tbd"
          ln -s CoreFoundation.tbd \
            "$out/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"

          # CoreServices is a compatibility umbrella on current Darwin. Curl
          # uses it for proxy integration, while Git and Rust filesystem
          # clients consume its public FSEvents API. Publish both the umbrella
          # header and the real install name so those platform features remain
          # enabled without importing a binary framework from the build host.
          cp ${./darwin-sdk-core-services.h} \
            "$out/System/Library/Frameworks/CoreServices.framework/Headers/CoreServices.h"
          cp ${./darwin-sdk-core-services-jdk.h} \
            "$out/System/Library/Frameworks/CoreServices.framework/Headers/JDKSurface.h"
          cp ${./darwin-sdk-core-services.tbd} \
            "$out/System/Library/Frameworks/CoreServices.framework/CoreServices.tbd"
          ln -s ../../CoreServices.tbd \
            "$out/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices.tbd"
          ln -s CoreServices.tbd \
            "$out/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices"

          # CarbonCore owns the legacy File Manager entry points reexported by
          # CoreServices and, transitively, ApplicationServices.
          cp ${./darwin-sdk-carbon-core.tbd} \
            "$out/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/CarbonCore.framework/CarbonCore.tbd"
          ln -s ../../CarbonCore.tbd \
            "$out/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/CarbonCore.framework/Versions/A/CarbonCore.tbd"
          ln -s CarbonCore.tbd \
            "$out/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/CarbonCore.framework/Versions/A/CarbonCore"

          # Apple's CoreServices umbrella reexports its versioned, nested
          # LaunchServices framework. Keep the symbols in their canonical
          # owner so consumers such as OpenJDK's libnio can link only the
          # documented CoreServices umbrella without flattening the ABI.
          cp ${./darwin-sdk-launch-services.tbd} \
            "$out/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/LaunchServices.tbd"
          ln -s ../../LaunchServices.tbd \
            "$out/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/LaunchServices.tbd"
          ln -s LaunchServices.tbd \
            "$out/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/LaunchServices"

          # Dawn uses IOSurface-backed multiplanar Metal textures. Publish the
          # documented opaque reference, property keys, and geometry queries
          # as their own framework rather than treating them as IOKit symbols.
          cat > "$out/System/Library/Frameworks/IOSurface.framework/Headers/IOSurfaceRef.h" <<'EOF'
          #ifndef _AOS_IOSURFACE_REF_H_
          #define _AOS_IOSURFACE_REF_H_

          #include <CoreFoundation/CoreFoundation.h>

          CF_EXTERN_C_BEGIN

          typedef struct __IOSurface *IOSurfaceRef;

          extern const CFStringRef kIOSurfaceAllocSize;
          extern const CFStringRef kIOSurfaceWidth;
          extern const CFStringRef kIOSurfaceHeight;
          extern const CFStringRef kIOSurfacePixelFormat;
          extern const CFStringRef kIOSurfacePlaneInfo;
          extern const CFStringRef kIOSurfacePlaneWidth;
          extern const CFStringRef kIOSurfacePlaneHeight;
          extern const CFStringRef kIOSurfacePlaneBytesPerElement;
          extern const CFStringRef kIOSurfacePlaneBytesPerRow;
          extern const CFStringRef kIOSurfacePlaneSize;
          extern const CFStringRef kIOSurfacePlaneOffset;

          IOSurfaceRef IOSurfaceCreate(CFDictionaryRef properties);
          size_t IOSurfaceAlignProperty(CFStringRef property, size_t value);
          size_t IOSurfaceGetWidth(IOSurfaceRef buffer);
          size_t IOSurfaceGetHeight(IOSurfaceRef buffer);
          OSType IOSurfaceGetPixelFormat(IOSurfaceRef buffer);
          size_t IOSurfaceGetPlaneCount(IOSurfaceRef buffer);
          size_t IOSurfaceGetWidthOfPlane(IOSurfaceRef buffer, size_t planeIndex);
          size_t IOSurfaceGetHeightOfPlane(IOSurfaceRef buffer, size_t planeIndex);

          CF_EXTERN_C_END

          #endif
          EOF
          cat > "$out/System/Library/Frameworks/IOSurface.framework/Headers/IOSurface.h" <<'EOF'
          #ifndef _AOS_IOSURFACE_H_
          #define _AOS_IOSURFACE_H_
          #include <IOSurface/IOSurfaceRef.h>
          #endif
          EOF
          cat > "$out/System/Library/Frameworks/IOSurface.framework/IOSurface.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/System/Library/Frameworks/IOSurface.framework/Versions/A/IOSurface'
          current-version: 372.0.0
          compatibility-version: 1.0.0
          reexported-libraries:
            - targets: [ x86_64-macos, arm64-macos ]
              libraries: [ '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation' ]
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols:
                - _IOSurfaceAlignProperty
                - _IOSurfaceCreate
                - _IOSurfaceGetHeight
                - _IOSurfaceGetHeightOfPlane
                - _IOSurfaceGetPixelFormat
                - _IOSurfaceGetPlaneCount
                - _IOSurfaceGetWidth
                - _IOSurfaceGetWidthOfPlane
                - _kIOSurfaceAllocSize
                - _kIOSurfaceHeight
                - _kIOSurfacePixelFormat
                - _kIOSurfacePlaneBytesPerElement
                - _kIOSurfacePlaneBytesPerRow
                - _kIOSurfacePlaneHeight
                - _kIOSurfacePlaneInfo
                - _kIOSurfacePlaneOffset
                - _kIOSurfacePlaneSize
                - _kIOSurfacePlaneWidth
                - _kIOSurfaceWidth
          ...
          EOF
          ln -s ../../IOSurface.tbd \
            "$out/System/Library/Frameworks/IOSurface.framework/Versions/A/IOSurface.tbd"
          ln -s IOSurface.tbd \
            "$out/System/Library/Frameworks/IOSurface.framework/Versions/A/IOSurface"

          . ${qemuCocoaSdkFragment}
          . ${coreVideoFragment}

          # Dawn's macOS backend is part of Workerd's normal source build.  Use
          # Darling's independently implemented public Metal declarations so
          # the open SDK retains that backend without importing an Xcode SDK.
          cp -R "$darlingMetalRoot/include/Metal/." \
            "$out/System/Library/Frameworks/Metal.framework/Headers/"
          sed -i 's/NS_ENUM(uint8,/NS_ENUM(uint8_t,/' \
            "$out/System/Library/Frameworks/Metal.framework/Headers/MTLTexture.h"
          # MTLColorWriteMask is a bitmask in Apple's public API. Darling's
          # independently implemented declaration used NS_ENUM, which makes
          # ordinary flag accumulation ill-typed in Objective-C++.
          sed -i 's/typedef NS_ENUM(NSUInteger, MTLColorWriteMask)/typedef NS_OPTIONS(NSUInteger, MTLColorWriteMask)/' \
            "$out/System/Library/Frameworks/Metal.framework/Headers/MTLRenderPipeline.h"
          # The independently implemented Metal headers intentionally grow in
          # small API slices. Dawn also names these modern state/encoder types;
          # keep their Objective-C identities available even where no method
          # declaration is needed for static dispatch.
          cat > "$out/System/Library/Frameworks/Metal.framework/Headers/MTLAOSDeviceTypes.h" <<'EOF'
          #ifndef _METAL_AOS_DEVICE_TYPES_H_
          #define _METAL_AOS_DEVICE_TYPES_H_

          #import <Foundation/Foundation.h>
          #import <Metal/MTLResource.h>
          #include <stdint.h>

          typedef NSUInteger MTLTimestamp;

          typedef NS_ENUM(NSUInteger, MTLFeatureSet) {
            MTLFeatureSet_iOS_GPUFamily1_v1 = 0,
            MTLFeatureSet_iOS_GPUFamily2_v1 = 1,
            MTLFeatureSet_iOS_GPUFamily3_v1 = 4,
            MTLFeatureSet_iOS_GPUFamily3_v2 = 7,
            MTLFeatureSet_iOS_GPUFamily4_v1 = 11,
            MTLFeatureSet_tvOS_GPUFamily2_v1 = 30003,
          };

          typedef NS_ENUM(NSInteger, MTLGPUFamily) {
            MTLGPUFamilyApple1 = 1001,
            MTLGPUFamilyApple2 = 1002,
            MTLGPUFamilyApple3 = 1003,
            MTLGPUFamilyApple4 = 1004,
            MTLGPUFamilyApple5 = 1005,
            MTLGPUFamilyApple6 = 1006,
            MTLGPUFamilyApple7 = 1007,
            MTLGPUFamilyMac2 = 2002,
            MTLGPUFamilyCommon1 = 3001,
            MTLGPUFamilyCommon2 = 3002,
            MTLGPUFamilyCommon3 = 3003,
            MTLGPUFamilyMetal3 = 5001,
          };

          typedef NS_ENUM(NSUInteger, MTLCounterSamplingPoint) {
            MTLCounterSamplingPointAtStageBoundary = 0,
            MTLCounterSamplingPointAtDrawBoundary = 1,
            MTLCounterSamplingPointAtDispatchBoundary = 2,
            MTLCounterSamplingPointAtTileDispatchBoundary = 3,
            MTLCounterSamplingPointAtBlitBoundary = 4,
          };

          typedef NSString * const MTLCommonCounter;
          extern MTLCommonCounter MTLCommonCounterTimestamp;
          typedef NSString * const MTLCommonCounterSet;
          extern MTLCommonCounterSet MTLCommonCounterSetTimestamp;

          @protocol MTLDevice;
          @protocol MTLCounter <NSObject>
          @property(readonly, copy) NSString *name;
          @end

          @protocol MTLCounterSet <NSObject>
          @property(readonly, copy) NSString *name;
          @property(readonly, copy) NSArray<id<MTLCounter>> *counters;
          @end

          @interface MTLCounterSampleBufferDescriptor : NSObject <NSCopying>
          @property(retain) id<MTLCounterSet> counterSet;
          @property(copy) NSString *label;
          @property MTLStorageMode storageMode;
          @property NSUInteger sampleCount;
          @end

          @protocol MTLCounterSampleBuffer <NSObject>
          @property(readonly) id<MTLDevice> device;
          @property(readonly) NSString *label;
          @property(readonly) NSUInteger sampleCount;
          @end

          #endif
          EOF
          cat > "$out/System/Library/Frameworks/Metal.framework/Headers/MTLAOSDeviceMethods.h" <<'EOF'
          @property(readonly, copy) NSString *name;
          @property(readonly) uint64_t registryID;
          @property(readonly) NSUInteger maxBufferLength;
          @property(readonly) BOOL hasUnifiedMemory;
          @property(readonly) uint64_t recommendedMaxWorkingSetSize;
          @property(readonly) NSArray<id<MTLCounterSet>> *counterSets;
          - (BOOL)supportsFeatureSet:(MTLFeatureSet)featureSet;
          - (BOOL)supportsFamily:(MTLGPUFamily)gpuFamily;
          - (BOOL)supportsCounterSampling:(MTLCounterSamplingPoint)samplingPoint;
          - (id<MTLCounterSampleBuffer>)newCounterSampleBufferWithDescriptor:(MTLCounterSampleBufferDescriptor *)descriptor
                                                                        error:(NSError **)error;
          - (void)sampleTimestamps:(MTLTimestamp *)cpuTimestamp
                       gpuTimestamp:(MTLTimestamp *)gpuTimestamp;
          EOF
          sed -i '/^@protocol MTLDevice <NSObject>$/i #import <Metal/MTLAOSDeviceTypes.h>' \
            "$out/System/Library/Frameworks/Metal.framework/Headers/MTLDevice.h"
          sed -i '/^@protocol MTLDevice <NSObject>$/a #import <Metal/MTLAOSDeviceMethods.h>' \
            "$out/System/Library/Frameworks/Metal.framework/Headers/MTLDevice.h"

          cat > "$out/System/Library/Frameworks/Metal.framework/Headers/MTLAOSAdditionalTypes.h" <<'EOF'
          #ifndef _METAL_AOS_ADDITIONAL_TYPES_H_
          #define _METAL_AOS_ADDITIONAL_TYPES_H_

          #import <Metal/MTLCommandEncoder.h>
          #import <Metal/MTLDevice.h>
          #import <Metal/MTLPixelFormat.h>
          #import <Metal/MTLTexture.h>

          typedef NS_OPTIONS(NSUInteger, MTLBlitOption) {
            MTLBlitOptionNone = 0,
            MTLBlitOptionDepthFromDepthStencil = 1 << 0,
            MTLBlitOptionStencilFromDepthStencil = 1 << 1,
          };

          typedef NS_ENUM(NSUInteger, MTLCompareFunction) {
            MTLCompareFunctionNever = 0,
            MTLCompareFunctionLess = 1,
            MTLCompareFunctionEqual = 2,
            MTLCompareFunctionLessEqual = 3,
            MTLCompareFunctionGreater = 4,
            MTLCompareFunctionNotEqual = 5,
            MTLCompareFunctionGreaterEqual = 6,
            MTLCompareFunctionAlways = 7,
          };

          typedef NS_ENUM(NSUInteger, MTLStencilOperation) {
            MTLStencilOperationKeep = 0,
            MTLStencilOperationZero = 1,
            MTLStencilOperationReplace = 2,
            MTLStencilOperationIncrementClamp = 3,
            MTLStencilOperationDecrementClamp = 4,
            MTLStencilOperationInvert = 5,
            MTLStencilOperationIncrementWrap = 6,
            MTLStencilOperationDecrementWrap = 7,
          };

          typedef NS_ENUM(NSUInteger, MTLSamplerMinMagFilter) {
            MTLSamplerMinMagFilterNearest = 0,
            MTLSamplerMinMagFilterLinear = 1,
          };

          typedef NS_ENUM(NSUInteger, MTLSamplerMipFilter) {
            MTLSamplerMipFilterNotMipmapped = 0,
            MTLSamplerMipFilterNearest = 1,
            MTLSamplerMipFilterLinear = 2,
          };

          typedef NS_ENUM(NSUInteger, MTLSamplerAddressMode) {
            MTLSamplerAddressModeClampToEdge = 0,
            MTLSamplerAddressModeMirrorClampToEdge = 1,
            MTLSamplerAddressModeRepeat = 2,
            MTLSamplerAddressModeMirrorRepeat = 3,
            MTLSamplerAddressModeClampToZero = 4,
            MTLSamplerAddressModeClampToBorderColor = 5,
          };

          typedef NS_ENUM(NSUInteger, MTLVertexFormat) {
            MTLVertexFormatInvalid = 0,
            MTLVertexFormatUChar2 = 1,
            MTLVertexFormatUChar3 = 2,
            MTLVertexFormatUChar4 = 3,
            MTLVertexFormatChar2 = 4,
            MTLVertexFormatChar3 = 5,
            MTLVertexFormatChar4 = 6,
            MTLVertexFormatUChar2Normalized = 7,
            MTLVertexFormatUChar3Normalized = 8,
            MTLVertexFormatUChar4Normalized = 9,
            MTLVertexFormatChar2Normalized = 10,
            MTLVertexFormatChar3Normalized = 11,
            MTLVertexFormatChar4Normalized = 12,
            MTLVertexFormatUShort2 = 13,
            MTLVertexFormatUShort3 = 14,
            MTLVertexFormatUShort4 = 15,
            MTLVertexFormatShort2 = 16,
            MTLVertexFormatShort3 = 17,
            MTLVertexFormatShort4 = 18,
            MTLVertexFormatUShort2Normalized = 19,
            MTLVertexFormatUShort3Normalized = 20,
            MTLVertexFormatUShort4Normalized = 21,
            MTLVertexFormatShort2Normalized = 22,
            MTLVertexFormatShort3Normalized = 23,
            MTLVertexFormatShort4Normalized = 24,
            MTLVertexFormatHalf2 = 25,
            MTLVertexFormatHalf3 = 26,
            MTLVertexFormatHalf4 = 27,
            MTLVertexFormatFloat = 28,
            MTLVertexFormatFloat2 = 29,
            MTLVertexFormatFloat3 = 30,
            MTLVertexFormatFloat4 = 31,
            MTLVertexFormatInt = 32,
            MTLVertexFormatInt2 = 33,
            MTLVertexFormatInt3 = 34,
            MTLVertexFormatInt4 = 35,
            MTLVertexFormatUInt = 36,
            MTLVertexFormatUInt2 = 37,
            MTLVertexFormatUInt3 = 38,
            MTLVertexFormatUInt4 = 39,
            MTLVertexFormatInt1010102Normalized = 40,
            MTLVertexFormatUInt1010102Normalized = 41,
          };

          typedef NS_ENUM(NSUInteger, MTLVertexStepFunction) {
            MTLVertexStepFunctionConstant = 0,
            MTLVertexStepFunctionPerVertex = 1,
            MTLVertexStepFunctionPerInstance = 2,
            MTLVertexStepFunctionPerPatch = 3,
            MTLVertexStepFunctionPerPatchControlPoint = 4,
          };

          typedef NS_ENUM(NSUInteger, MTLDepthClipMode) {
            MTLDepthClipModeClip = 0,
            MTLDepthClipModeClamp = 1,
          };

          typedef NS_ENUM(NSUInteger, MTLVisibilityResultMode) {
            MTLVisibilityResultModeDisabled = 0,
            MTLVisibilityResultModeBoolean = 1,
            MTLVisibilityResultModeCounting = 2,
          };

          typedef NS_ENUM(NSUInteger, MTLLibraryError) {
            MTLLibraryErrorUnsupported = 1,
            MTLLibraryErrorInternal = 2,
            MTLLibraryErrorCompileFailure = 3,
            MTLLibraryErrorCompileWarning = 4,
            MTLLibraryErrorFunctionNotFound = 5,
            MTLLibraryErrorFileNotFound = 6,
          };

          @protocol MTLBlitCommandEncoder <MTLCommandEncoder>
          @end

          @protocol MTLDepthStencilState <NSObject>
          @end

          @protocol MTLSamplerState <NSObject>
          @end

          @protocol MTLSharedEvent <NSObject>
          @end

          @interface MTLTextureDescriptor (AOSDawn)
          + (MTLTextureDescriptor *)texture2DDescriptorWithPixelFormat:(MTLPixelFormat)pixelFormat
                                                                 width:(NSUInteger)width
                                                                height:(NSUInteger)height
                                                             mipmapped:(BOOL)mipmapped;
          @property MTLTextureType textureType;
          @property MTLPixelFormat pixelFormat;
          @property NSUInteger width;
          @property NSUInteger height;
          @property NSUInteger depth;
          @property NSUInteger mipmapLevelCount;
          @property NSUInteger sampleCount;
          @property NSUInteger arrayLength;
          @property MTLResourceOptions resourceOptions;
          @property MTLCPUCacheMode cpuCacheMode;
          @property MTLStorageMode storageMode;
          @property MTLHazardTrackingMode hazardTrackingMode;
          @property MTLTextureUsage usage;
          @end

          @interface MTLSamplerDescriptor (AOSDawn)
          @property MTLSamplerMinMagFilter minFilter;
          @property MTLSamplerMinMagFilter magFilter;
          @property MTLSamplerMipFilter mipFilter;
          @property NSUInteger maxAnisotropy;
          @property MTLSamplerAddressMode sAddressMode;
          @property MTLSamplerAddressMode tAddressMode;
          @property MTLSamplerAddressMode rAddressMode;
          @property BOOL normalizedCoordinates;
          @property float lodMinClamp;
          @property float lodMaxClamp;
          @property MTLCompareFunction compareFunction;
          @property(copy) NSString *label;
          @end

          @interface MTLStencilDescriptor (AOSDawn)
          @property MTLCompareFunction stencilCompareFunction;
          @property MTLStencilOperation stencilFailureOperation;
          @property MTLStencilOperation depthFailureOperation;
          @property MTLStencilOperation depthStencilPassOperation;
          @property uint32_t readMask;
          @property uint32_t writeMask;
          @end

          @interface MTLDepthStencilDescriptor (AOSDawn)
          @property MTLCompareFunction depthCompareFunction;
          @property(getter=isDepthWriteEnabled) BOOL depthWriteEnabled;
          @property(copy) MTLStencilDescriptor *frontFaceStencil;
          @property(copy) MTLStencilDescriptor *backFaceStencil;
          @property(copy) NSString *label;
          @end

          @interface MTLCompileOptions (AOSDawn)
          @property BOOL fastMathEnabled;
          @property BOOL preserveInvariance;
          @end

          @interface MTLVertexBufferLayoutDescriptor : NSObject <NSCopying>
          @property NSUInteger stride;
          @property MTLVertexStepFunction stepFunction;
          @property NSUInteger stepRate;
          @end

          @interface MTLVertexBufferLayoutDescriptorArray : NSObject
          - (MTLVertexBufferLayoutDescriptor *)objectAtIndexedSubscript:(NSUInteger)index;
          - (void)setObject:(MTLVertexBufferLayoutDescriptor *)descriptor
                atIndexedSubscript:(NSUInteger)index;
          @end

          @interface MTLVertexAttributeDescriptor : NSObject <NSCopying>
          @property MTLVertexFormat format;
          @property NSUInteger offset;
          @property NSUInteger bufferIndex;
          @end

          @interface MTLVertexAttributeDescriptorArray : NSObject
          - (MTLVertexAttributeDescriptor *)objectAtIndexedSubscript:(NSUInteger)index;
          - (void)setObject:(MTLVertexAttributeDescriptor *)descriptor
                atIndexedSubscript:(NSUInteger)index;
          @end

          @interface MTLVertexDescriptor (AOSDawn)
          + (MTLVertexDescriptor *)vertexDescriptor;
          @property(readonly) MTLVertexBufferLayoutDescriptorArray *layouts;
          @property(readonly) MTLVertexAttributeDescriptorArray *attributes;
          - (void)reset;
          @end

          @interface MTLRenderPassSampleBufferAttachmentDescriptor : NSObject <NSCopying>
          @property(retain) id<MTLCounterSampleBuffer> sampleBuffer;
          @property NSUInteger startOfVertexSampleIndex;
          @property NSUInteger endOfVertexSampleIndex;
          @property NSUInteger startOfFragmentSampleIndex;
          @property NSUInteger endOfFragmentSampleIndex;
          @end

          @interface MTLRenderPassSampleBufferAttachmentDescriptorArray : NSObject
          - (MTLRenderPassSampleBufferAttachmentDescriptor *)objectAtIndexedSubscript:(NSUInteger)index;
          - (void)setObject:(MTLRenderPassSampleBufferAttachmentDescriptor *)descriptor
                atIndexedSubscript:(NSUInteger)index;
          @end

          @interface MTLBlitPassSampleBufferAttachmentDescriptor : NSObject <NSCopying>
          @property(retain) id<MTLCounterSampleBuffer> sampleBuffer;
          @property NSUInteger startOfEncoderSampleIndex;
          @property NSUInteger endOfEncoderSampleIndex;
          @end

          @interface MTLBlitPassSampleBufferAttachmentDescriptorArray : NSObject
          - (MTLBlitPassSampleBufferAttachmentDescriptor *)objectAtIndexedSubscript:(NSUInteger)index;
          - (void)setObject:(MTLBlitPassSampleBufferAttachmentDescriptor *)descriptor
                atIndexedSubscript:(NSUInteger)index;
          @end

          @interface MTLBlitPassDescriptor : NSObject <NSCopying>
          + (MTLBlitPassDescriptor *)blitPassDescriptor;
          @property(readonly) MTLBlitPassSampleBufferAttachmentDescriptorArray *sampleBufferAttachments;
          @end

          #endif
          EOF
          sed -i '/^#endif \/\/ _METAL_METAL_H_$/i #import <Metal/MTLAOSAdditionalTypes.h>' \
            "$out/System/Library/Frameworks/Metal.framework/Headers/Metal.h"
          mkdir -p "$out/share/licenses/darwin-sdk/darling-metal"
          cp -R "$darlingMetalRoot/LICENSES/." \
            "$out/share/licenses/darwin-sdk/darling-metal/"

          cat > "$out/System/Library/Frameworks/Metal.framework/Metal.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/System/Library/Frameworks/Metal.framework/Versions/A/Metal'
          current-version: 367.4.0
          compatibility-version: 1.0.0
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols:
                - _MTLCopyAllDevices
                - _MTLCopyAllDevicesWithObserver
                - _MTLCreateSystemDefaultDevice
                - _MTLCommonCounterSetTimestamp
                - _MTLCommonCounterTimestamp
                - _MTLDeviceRemovalRequestedNotification
                - _MTLDeviceWasAddedNotification
                - _MTLDeviceWasRemovedNotification
                - _MTLRemoveDeviceObserver
                - '_OBJC_CLASS_$_MTLCaptureManager'
                - '_OBJC_CLASS_$_MTLBlitPassDescriptor'
                - '_OBJC_CLASS_$_MTLCompileOptions'
                - '_OBJC_CLASS_$_MTLComputePassDescriptor'
                - '_OBJC_CLASS_$_MTLComputePassSampleBufferAttachmentDescriptor'
                - '_OBJC_CLASS_$_MTLComputePassSampleBufferAttachmentDescriptorArray'
                - '_OBJC_CLASS_$_MTLComputePipelineDescriptor'
                - '_OBJC_CLASS_$_MTLCounterSampleBufferDescriptor'
                - '_OBJC_CLASS_$_MTLDepthStencilDescriptor'
                - '_OBJC_CLASS_$_MTLPipelineBufferDescriptor'
                - '_OBJC_CLASS_$_MTLPipelineBufferDescriptorArray'
                - '_OBJC_CLASS_$_MTLRenderPassAttachmentDescriptor'
                - '_OBJC_CLASS_$_MTLRenderPassColorAttachmentDescriptor'
                - '_OBJC_CLASS_$_MTLRenderPassColorAttachmentDescriptorArray'
                - '_OBJC_CLASS_$_MTLRenderPassDepthAttachmentDescriptor'
                - '_OBJC_CLASS_$_MTLRenderPassDescriptor'
                - '_OBJC_CLASS_$_MTLRenderPassStencilAttachmentDescriptor'
                - '_OBJC_CLASS_$_MTLRenderPipelineColorAttachmentDescriptor'
                - '_OBJC_CLASS_$_MTLRenderPipelineColorAttachmentDescriptorArray'
                - '_OBJC_CLASS_$_MTLRenderPipelineDescriptor'
                - '_OBJC_CLASS_$_MTLSamplerDescriptor'
                - '_OBJC_CLASS_$_MTLStencilDescriptor'
                - '_OBJC_CLASS_$_MTLTextureDescriptor'
                - '_OBJC_CLASS_$_MTLVertexAttributeDescriptor'
                - '_OBJC_CLASS_$_MTLVertexBufferLayoutDescriptor'
                - '_OBJC_CLASS_$_MTLVertexDescriptor'
                - '_OBJC_METACLASS_$_MTLDepthStencilDescriptor'
                - '_OBJC_METACLASS_$_MTLRenderPassDescriptor'
                - '_OBJC_METACLASS_$_MTLRenderPipelineDescriptor'
                - '_OBJC_METACLASS_$_MTLSamplerDescriptor'
                - '_OBJC_METACLASS_$_MTLTextureDescriptor'
                - '_OBJC_METACLASS_$_MTLVertexDescriptor'
          ...
          EOF
          ln -s ../../Metal.tbd \
            "$out/System/Library/Frameworks/Metal.framework/Versions/A/Metal.tbd"
          ln -s Metal.tbd \
            "$out/System/Library/Frameworks/Metal.framework/Versions/A/Metal"

          # QuartzCore owns the layers which present both Metal drawables and
          # QEMU's Cocoa scanout. Keep their shared geometry tied to
          # CoreGraphics rather than introducing a second CGSize definition.
          cat > "$out/System/Library/Frameworks/QuartzCore.framework/Headers/CALayer.h" <<'EOF'
          #ifndef _AOS_QUARTZCORE_CALAYER_H_
          #define _AOS_QUARTZCORE_CALAYER_H_

          #import <Foundation/Foundation.h>
          #import <CoreGraphics/CoreGraphics.h>

          typedef NSUInteger CAAutoresizingMask;
          typedef NSString *CALayerContentsGravity;
          extern CALayerContentsGravity const kCAGravityTopLeft;
          enum {
            kCALayerMinXMargin = 1U << 0,
            kCALayerWidthSizable = 1U << 1,
            kCALayerMaxXMargin = 1U << 2,
            kCALayerMinYMargin = 1U << 3,
            kCALayerHeightSizable = 1U << 4,
            kCALayerMaxYMargin = 1U << 5
          };

          @protocol CAMediaTiming
          @end

          @interface CALayer : NSObject <NSCoding, CAMediaTiming>
          + (instancetype)layer;
          @property(getter=isOpaque) BOOL opaque;
          @property CGPoint anchorPoint;
          @property CAAutoresizingMask autoresizingMask;
          @property CGPoint position;
          @property(getter=isHidden) BOOL hidden;
          @property CGRect bounds;
          @property CGRect frame;
          @property(copy) NSArray *sublayers;
          @property(retain) id contents;
          @property CGFloat contentsScale;
          @property(copy) CALayerContentsGravity contentsGravity;
          @property(copy) NSDictionary *actions;
          - (void)addSublayer:(CALayer *)layer;
          - (void)removeFromSuperlayer;
          - (void)setNeedsDisplay;
          @end

          @interface CATransaction : NSObject
          + (void)begin;
          + (void)commit;
          + (void)setDisableActions:(BOOL)flag;
          @end

          #endif
          EOF
          cat > "$out/System/Library/Frameworks/QuartzCore.framework/Headers/CAMetalLayer.h" <<'EOF'
          #ifndef _AOS_QUARTZCORE_CAMETALLAYER_H_
          #define _AOS_QUARTZCORE_CAMETALLAYER_H_

          #import <QuartzCore/CALayer.h>
          #import <Metal/Metal.h>

          @protocol CAMetalDrawable <MTLDrawable>
          @property(readonly) id<MTLTexture> texture;
          @end

          @interface CAMetalLayer : CALayer
          @property CGSize drawableSize;
          @property BOOL framebufferOnly;
          @property(retain) id<MTLDevice> device;
          @property MTLPixelFormat pixelFormat;
          @property BOOL displaySyncEnabled;
          - (id<CAMetalDrawable>)nextDrawable;
          @end

          #endif
          EOF
          cat > "$out/System/Library/Frameworks/QuartzCore.framework/Headers/QuartzCore.h" <<'EOF'
          #ifndef _AOS_QUARTZCORE_H_
          #define _AOS_QUARTZCORE_H_
          #import <QuartzCore/CALayer.h>
          #import <QuartzCore/CAMetalLayer.h>
          #import <QuartzCore/CAOpenGLLayer.h>
          #endif
          EOF
          cp ${./darwin-sdk-quartzcore-catransaction.h} \
            "$out/System/Library/Frameworks/QuartzCore.framework/Headers/CATransaction.h"
          cp ${./darwin-sdk-quartzcore-caopengl.h} \
            "$out/System/Library/Frameworks/QuartzCore.framework/Headers/CAOpenGLLayer.h"
          cat > "$out/System/Library/Frameworks/QuartzCore.framework/QuartzCore.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/System/Library/Frameworks/QuartzCore.framework/Versions/A/QuartzCore'
          current-version: 1151.6.0
          compatibility-version: 1.2.0
          reexported-libraries:
            - targets: [ x86_64-macos, arm64-macos ]
              libraries:
                - '/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation'
                - '/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics'
                - '/System/Library/Frameworks/CoreVideo.framework/Versions/A/CoreVideo'
                - '/System/Library/Frameworks/Metal.framework/Versions/A/Metal'
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols:
                - '_OBJC_CLASS_$_CALayer'
                - '_OBJC_CLASS_$_CAOpenGLLayer'
                - '_OBJC_CLASS_$_CAMetalLayer'
                - '_OBJC_CLASS_$_CATransaction'
                - '_OBJC_METACLASS_$_CATransaction'
                - '_OBJC_METACLASS_$_CALayer'
                - '_OBJC_METACLASS_$_CAOpenGLLayer'
                - '_OBJC_METACLASS_$_CAMetalLayer'
                - _kCAGravityTopLeft
          ...
          EOF
          ln -s ../../QuartzCore.tbd \
            "$out/System/Library/Frameworks/QuartzCore.framework/Versions/A/QuartzCore.tbd"
          ln -s QuartzCore.tbd \
            "$out/System/Library/Frameworks/QuartzCore.framework/Versions/A/QuartzCore"

          # GLib uses Foundation's filesystem lookup API and AppKit's native
          # notification backend, while other consumers import both through
          # Cocoa. Publish the documented command-line Objective-C subset as
          # separate frameworks so Meson can discover each module normally.
          cat > "$out/System/Library/Frameworks/Foundation.framework/Headers/Foundation.h" <<'EOF'
          #ifndef _AOS_FOUNDATION_H_
          #define _AOS_FOUNDATION_H_
          #import <objc/NSObject.h>
          #import <CoreFoundation/CFAvailability.h>
          #import <CoreGraphics/CoreGraphics.h>
          #include <dispatch/dispatch.h>

          #define NS_ENUM(_type, _name) CF_ENUM(_type, _name)
          #define NS_OPTIONS(_type, _name) CF_OPTIONS(_type, _name)
          #define NS_INLINE static inline
          #ifdef __cplusplus
          #define FOUNDATION_EXPORT extern "C"
          #else
          #define FOUNDATION_EXPORT extern
          #endif

          typedef struct _NSRange {
            NSUInteger location;
            NSUInteger length;
          } NSRange;
          NS_INLINE NSRange NSMakeRange(NSUInteger location, NSUInteger length) {
            NSRange range = {location, length};
            return range;
          }
          typedef double CFTimeInterval;

          @protocol NSCopying
          @end
          @protocol NSCoding
          @end

          typedef double NSTimeInterval;
          #define NSTimeIntervalSince1970 978307200.0

          @interface NSDate : NSObject <NSCopying>
          + (instancetype)dateWithTimeIntervalSince1970:(NSTimeInterval)seconds;
          - (NSTimeInterval)timeIntervalSince1970;
          @end

          @class NSString;
          @interface NSError : NSObject
          @property(readonly) NSInteger code;
          @property(readonly, copy) NSString *localizedDescription;
          @end

          typedef NSInteger NSComparisonResult;
          enum { NSOrderedAscending = -1, NSOrderedSame = 0, NSOrderedDescending = 1 };

          typedef struct {
            unsigned long state;
            id *itemsPtr;
            unsigned long *mutationsPtr;
            unsigned long extra[5];
          } NSFastEnumerationState;

          @protocol NSFastEnumeration
          - (NSUInteger)countByEnumeratingWithState:(NSFastEnumerationState *)state
                                            objects:(id [])buffer
                                              count:(NSUInteger)len;
          @end

          @class NSData;
          typedef unsigned short unichar;
          typedef NSUInteger NSStringEncoding;
          enum {
            NSASCIIStringEncoding = 1,
            NSUTF8StringEncoding = 4,
            NSUnicodeStringEncoding = 10,
            NSUTF16StringEncoding = NSUnicodeStringEncoding
          };

          @interface NSString : NSObject
          + (NSStringEncoding)defaultCStringEncoding;
          + (instancetype)stringWithCString:(const char *)bytes encoding:(NSStringEncoding)encoding;
          + (instancetype)stringWithCharacters:(const unichar *)characters length:(NSUInteger)length;
          + (instancetype)stringWithFormat:(NSString *)format, ...;
          + (instancetype)stringWithUTF8String:(const char *)bytes;
          - (instancetype)initWithUTF8String:(const char *)bytes;
          - (instancetype)initWithData:(NSData *)data encoding:(NSStringEncoding)encoding;
          - (const char *)UTF8String;
          - (const char *)cStringUsingEncoding:(NSStringEncoding)encoding;
          - (NSData *)dataUsingEncoding:(NSStringEncoding)encoding;
          @property(readonly) NSUInteger length;
          @property(readonly) int intValue;
          - (unichar)characterAtIndex:(NSUInteger)index;
          @property(readonly, copy) NSString *stringByDeletingLastPathComponent;
          - (NSComparisonResult)compare:(NSString *)string;
          - (NSComparisonResult)caseInsensitiveCompare:(NSString *)string;
          @end

          @interface NSData : NSObject
          - (instancetype)initWithBytes:(const void *)bytes length:(NSUInteger)length;
          @property(readonly) NSUInteger length;
          @property(readonly) const void *bytes;
          @end

          typedef CGPoint NSPoint;
          typedef CGSize NSSize;
          typedef CGRect NSRect;

          @interface NSValue : NSObject <NSCopying>
          @end

          @interface NSNumber : NSValue
          + (NSNumber *)numberWithBool:(BOOL)value;
          + (NSNumber *)numberWithInt:(int)value;
          + (NSNumber *)numberWithUnsignedChar:(unsigned char)value;
          + (NSNumber *)numberWithShort:(short)value;
          + (NSNumber *)numberWithUnsignedShort:(unsigned short)value;
          + (NSNumber *)numberWithLong:(long)value;
          + (NSNumber *)numberWithUnsignedLong:(unsigned long)value;
          + (NSNumber *)numberWithLongLong:(long long)value;
          + (NSNumber *)numberWithUnsignedLongLong:(unsigned long long)value;
          + (NSNumber *)numberWithDouble:(double)value;
          - (BOOL)boolValue;
          - (int)intValue;
          - (unsigned int)unsignedIntValue;
          - (unsigned char)unsignedCharValue;
          - (short)shortValue;
          - (unsigned short)unsignedShortValue;
          - (long)longValue;
          - (unsigned long)unsignedLongValue;
          - (long long)longLongValue;
          - (unsigned long long)unsignedLongLongValue;
          - (double)doubleValue;
          @end

          @interface NSEnumerator<ObjectType> : NSObject
          - (ObjectType)nextObject;
          @end

          @interface NSArray<ObjectType> : NSObject <NSFastEnumeration>
          + (instancetype)arrayWithObjects:(const ObjectType [])objects count:(NSUInteger)count;
          @property(readonly) ObjectType firstObject;
          - (ObjectType)objectAtIndex:(NSUInteger)index;
          @end

          @interface NSException : NSObject
          @property(readonly, copy) NSArray<NSString *> *callStackSymbols;
          @end

          FOUNDATION_EXPORT void NSLog(NSString *format, ...);

          @interface NSMutableArray<ObjectType> : NSArray<ObjectType>
          + (instancetype)arrayWithCapacity:(NSUInteger)numItems;
          - (void)addObject:(ObjectType)anObject;
          @end

          @interface NSDictionary<KeyType, ObjectType> : NSObject <NSFastEnumeration>
          + (instancetype)dictionaryWithObjects:(const ObjectType [])objects forKeys:(const KeyType [])keys count:(NSUInteger)count;
          - (ObjectType)objectForKey:(KeyType)aKey;
          - (ObjectType)objectForKeyedSubscript:(KeyType)key;
          - (NSEnumerator<KeyType> *)objectEnumerator;
          @end

          @interface NSMutableDictionary<KeyType, ObjectType> : NSDictionary<KeyType, ObjectType>
          + (instancetype)dictionaryWithCapacity:(NSUInteger)numItems;
          - (void)setObject:(ObjectType)anObject forKey:(KeyType)aKey;
          - (void)setObject:(ObjectType)object forKeyedSubscript:(KeyType)key;
          @end

          @interface NSAutoreleasePool : NSObject
          - (instancetype)init;
          - (void)drain;
          @end

          @interface NSOperation : NSObject
          - (void)start;
          @end

          @interface NSBlockOperation : NSOperation
          + (instancetype)blockOperationWithBlock:(void (^)(void))block;
          @end

          @interface NSUserDefaults : NSObject
          + (NSUserDefaults *)standardUserDefaults;
          - (id)objectForKey:(NSString *)defaultName;
          - (void)setObject:(id)value forKey:(NSString *)defaultName;
          - (void)removeObjectForKey:(NSString *)defaultName;
          - (BOOL)synchronize;
          @end

          @interface NSURL : NSObject
          + (NSURL *)fileURLWithPath:(NSString *)path;
          + (NSURL *)fileURLWithPath:(NSString *)path isDirectory:(BOOL)isDir;
          @property(readonly, copy) NSString *path;
          @end

          @interface NSBundle : NSObject
          + (NSBundle *)mainBundle;
          + (NSBundle *)bundleWithURL:(NSURL *)url;
          @property(readonly, copy) NSString *bundleIdentifier;
          @property(readonly, copy) NSString *bundlePath;
          @property(readonly, copy) NSString *executablePath;
          @property(readonly, copy) NSDictionary *infoDictionary;
          - (id)objectForInfoDictionaryKey:(NSString *)key;
          @end

          @interface NSMutableAttributedString : NSObject
          - (instancetype)initWithString:(NSString *)string;
          - (void)addAttribute:(NSString *)name value:(id)value range:(NSRange)range;
          @end

          @interface NSNotification : NSObject
          @property(nullable, readonly, copy) NSDictionary *userInfo;
          @end

          @interface NSThread : NSObject
          + (void)sleepForTimeInterval:(CFTimeInterval)timeInterval;
          @end

          typedef struct {
            NSInteger majorVersion;
            NSInteger minorVersion;
            NSInteger patchVersion;
          } NSOperatingSystemVersion;

          @interface NSProcessInfo : NSObject
          + (NSProcessInfo *)processInfo;
          @property(readonly, copy) NSString *processName;
          @property(readonly) unsigned long long physicalMemory;
          @property(readonly) NSOperatingSystemVersion operatingSystemVersion;
          @property(readonly, copy) NSString *operatingSystemVersionString;
          - (BOOL)isOperatingSystemAtLeastVersion:(NSOperatingSystemVersion)version;
          @end

          typedef NSUInteger NSSearchPathDirectory;
          enum {
            NSApplicationDirectory = 1,
            NSDemoApplicationDirectory = 2,
            NSDeveloperApplicationDirectory = 3,
            NSAdminApplicationDirectory = 4,
            NSLibraryDirectory = 5,
            NSDeveloperDirectory = 6,
            NSUserDirectory = 7,
            NSDocumentationDirectory = 8,
            NSDocumentDirectory = 9,
            NSCoreServiceDirectory = 10,
            NSAutosavedInformationDirectory = 11,
            NSDesktopDirectory = 12,
            NSCachesDirectory = 13,
            NSApplicationSupportDirectory = 14,
            NSDownloadsDirectory = 15,
            NSInputMethodsDirectory = 16,
            NSMoviesDirectory = 17,
            NSMusicDirectory = 18,
            NSPicturesDirectory = 19,
            NSPrinterDescriptionDirectory = 20,
            NSSharedPublicDirectory = 21,
            NSPreferencePanesDirectory = 22,
            NSApplicationScriptsDirectory = 23,
            NSItemReplacementDirectory = 99,
            NSAllApplicationsDirectory = 100,
            NSAllLibrariesDirectory = 101,
            NSTrashDirectory = 102
          };
          typedef NSUInteger NSSearchPathDomainMask;
          enum {
            NSUserDomainMask = 1,
            NSLocalDomainMask = 2,
            NSNetworkDomainMask = 4,
            NSSystemDomainMask = 8,
            NSAllDomainsMask = 0xffff
          };
          FOUNDATION_EXPORT NSArray<NSString *> *NSSearchPathForDirectoriesInDomains(
            NSSearchPathDirectory directory,
            NSSearchPathDomainMask domainMask,
            BOOL expandTilde
          );

          #import <Foundation/NSDate.h>
          #import <Foundation/NSString.h>
          #import <Foundation/NSValue.h>
          #import <Foundation/NSPathUtilities.h>
          #import <Foundation/NSJDKSurface.h>
          #import <Foundation/NSJDK25Surface.h>

          #endif
          EOF
          cp ${./darwin-sdk-foundation-nsdate.h} \
            "$out/System/Library/Frameworks/Foundation.framework/Headers/NSDate.h"
          cp ${./darwin-sdk-foundation-nsstring.h} \
            "$out/System/Library/Frameworks/Foundation.framework/Headers/NSString.h"
          cp ${./darwin-sdk-foundation-nsvalue.h} \
            "$out/System/Library/Frameworks/Foundation.framework/Headers/NSValue.h"
          cp ${./darwin-sdk-foundation-nspathutilities.h} \
            "$out/System/Library/Frameworks/Foundation.framework/Headers/NSPathUtilities.h"
          cp ${./darwin-sdk-foundation-jdk.h} \
            "$out/System/Library/Frameworks/Foundation.framework/Headers/NSJDKSurface.h"
          cp ${./darwin-sdk-foundation-jdk25.h} \
            "$out/System/Library/Frameworks/Foundation.framework/Headers/NSJDK25Surface.h"
          cat > "$out/System/Library/Frameworks/Foundation.framework/Headers/NSObject.h" <<'EOF'
          #ifndef _AOS_FOUNDATION_NSOBJECT_H_
          #define _AOS_FOUNDATION_NSOBJECT_H_
          #import <Foundation/Foundation.h>
          #endif
          EOF
          cat > "$out/System/Library/Frameworks/Foundation.framework/Headers/NSProcessInfo.h" <<'EOF'
          #ifndef _AOS_FOUNDATION_NSPROCESSINFO_H_
          #define _AOS_FOUNDATION_NSPROCESSINFO_H_
          #import <Foundation/Foundation.h>
          #endif
          EOF
          cat > "$out/System/Library/Frameworks/Foundation.framework/Headers/NSOperation.h" <<'EOF'
          #ifndef _AOS_FOUNDATION_NSOPERATION_H_
          #define _AOS_FOUNDATION_NSOPERATION_H_
          #import <Foundation/Foundation.h>
          #endif
          EOF

          cat > "$out/System/Library/Frameworks/AppKit.framework/Headers/AppKit.h" <<'EOF'
          #ifndef _AOS_APPKIT_H_
          #define _AOS_APPKIT_H_

          #import <Foundation/Foundation.h>
          #import <CoreVideo/CoreVideo.h>
          #import <QuartzCore/QuartzCore.h>

          #define IBAction void

          typedef CGPoint NSPoint;
          typedef CGSize NSSize;
          typedef CGRect NSRect;
          typedef struct NSEdgeInsets {
            CGFloat top;
            CGFloat left;
            CGFloat bottom;
            CGFloat right;
          } NSEdgeInsets;
          NS_INLINE NSPoint NSMakePoint(CGFloat x, CGFloat y) { return CGPointMake(x, y); }
          NS_INLINE NSSize NSMakeSize(CGFloat width, CGFloat height) {
            NSSize size = { width, height };
            return size;
          }
          NS_INLINE NSRect NSMakeRect(CGFloat x, CGFloat y, CGFloat width, CGFloat height) {
            NSRect rect = { { x, y }, { width, height } };
            return rect;
          }
          NS_INLINE CGRect NSRectToCGRect(NSRect rect) { return rect; }

          typedef NSUInteger NSWindowStyleMask;
          enum {
            NSWindowStyleMaskTitled = 1U << 0,
            NSWindowStyleMaskClosable = 1U << 1,
            NSWindowStyleMaskMiniaturizable = 1U << 2,
            NSWindowStyleMaskResizable = 1U << 3,
            NSWindowStyleMaskFullScreen = 1U << 14
          };
          typedef NSUInteger NSWindowCollectionBehavior;
          enum {
            NSWindowCollectionBehaviorFullScreenPrimary = 1U << 7,
            NSWindowCollectionBehaviorFullScreenAuxiliary = 1ULL << 8
          };
          typedef NSUInteger NSBackingStoreType;
          enum { NSBackingStoreBuffered = 2 };
          typedef NSUInteger NSTrackingAreaOptions;
          enum {
            NSTrackingMouseEnteredAndExited = 1U << 0,
            NSTrackingMouseMoved = 1U << 1,
            NSTrackingActiveInKeyWindow = 1U << 5,
            NSTrackingInVisibleRect = 1U << 9
          };
          typedef NSUInteger NSEventModifierFlags;
          enum {
            NSEventModifierFlagCapsLock = 1U << 16,
            NSEventModifierFlagShift = 1U << 17,
            NSEventModifierFlagControl = 1U << 18,
            NSEventModifierFlagOption = 1U << 19,
            NSEventModifierFlagCommand = 1U << 20
          };
          typedef NSUInteger NSEventType;
          enum {
            NSEventTypeKeyDown = 10,
            NSEventTypeKeyUp = 11,
            NSEventTypeFlagsChanged = 12,
            NSEventTypeScrollWheel = 22
          };
          typedef NSUInteger NSApplicationPresentationOptions;
          enum {
            NSApplicationPresentationAutoHideDock = 1U << 0,
            NSApplicationPresentationHideDock = 1U << 1,
            NSApplicationPresentationAutoHideMenuBar = 1U << 2,
            NSApplicationPresentationHideMenuBar = 1U << 3
          };
          typedef NSUInteger NSApplicationTerminateReply;
          typedef NSUInteger NSApplicationPrintReply;
          typedef NSInteger NSModalResponse;
          enum {
            NSPrintingCancelled = 0,
            NSPrintingSuccess = 1,
            NSPrintingReplyLater = 2,
            NSPrintingFailure = 3,
            NSTerminateCancel = 0,
            NSTerminateNow = 1,
            NSTerminateLater = 2,
            NSModalResponseOK = 1,
            NSAlertSecondButtonReturn = 1001,
            NSControlStateValueOff = 0,
            NSControlStateValueOn = 1,
            NSItalicFontMask = 1U << 0,
            NSBoldFontMask = 1U << 1
          };

          typedef NSString *NSPasteboardType;
          extern NSPasteboardType const NSPasteboardTypeString;
          extern NSString *const NSAboutPanelOptionApplicationIcon;
          extern NSString *const NSAboutPanelOptionApplicationVersion;
          extern NSString *const NSFontAttributeName;
          extern NSString *const NSForegroundColorAttributeName;
          extern NSString *const NSScreenNumber;
          extern NSString *const NSUnderlineStyleAttributeName;

          @class NSApplication;
          @class NSEvent;
          @class NSMenu;
          @class NSMenuItem;
          @class NSNotification;
          @class NSPasteboard;
          @class NSView;
          @class NSWindow;

          @protocol NSApplicationDelegate <NSObject>
          @optional
          - (void)applicationDidFinishLaunching:(NSNotification *)notification;
          - (void)application:(NSApplication *)sender openFiles:(NSArray<NSString *> *)filenames;
          - (NSApplicationPrintReply)application:(NSApplication *)application
                                      printFiles:(NSArray<NSString *> *)fileNames
                                    withSettings:(NSDictionary *)printSettings
                                 showPrintPanels:(BOOL)showPrintPanels;
          - (BOOL)applicationShouldHandleReopen:(NSApplication *)sender
                              hasVisibleWindows:(BOOL)flag;
          - (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender;
          - (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender;
          - (NSMenu *)applicationDockMenu:(NSApplication *)sender;
          @end

          @protocol NSWindowDelegate <NSObject>
          @optional
          - (void)windowDidResize:(NSNotification *)notification;
          - (void)windowDidEnterFullScreen:(NSNotification *)notification;
          - (void)windowDidExitFullScreen:(NSNotification *)notification;
          - (BOOL)windowShouldClose:(id)sender;
          - (BOOL)windowShouldZoom:(NSWindow *)window toFrame:(NSRect)newFrame;
          @end

          @protocol NSPasteboardTypeOwner <NSObject>
          @optional
          - (void)pasteboard:(NSPasteboard *)sender provideDataForType:(NSPasteboardType)type;
          @end

          @interface NSResponder : NSObject
          - (void)mouseDown:(NSEvent *)event;
          - (void)mouseUp:(NSEvent *)event;
          - (void)mouseMoved:(NSEvent *)event;
          - (void)mouseDragged:(NSEvent *)event;
          - (void)rightMouseDown:(NSEvent *)event;
          - (void)rightMouseUp:(NSEvent *)event;
          - (void)rightMouseDragged:(NSEvent *)event;
          - (void)otherMouseDown:(NSEvent *)event;
          - (void)otherMouseUp:(NSEvent *)event;
          - (void)otherMouseDragged:(NSEvent *)event;
          - (void)scrollWheel:(NSEvent *)event;
          - (void)keyDown:(NSEvent *)event;
          - (void)keyUp:(NSEvent *)event;
          - (void)flagsChanged:(NSEvent *)event;
          @end

          @interface NSTrackingArea : NSObject
          - (instancetype)initWithRect:(NSRect)rect
                               options:(NSTrackingAreaOptions)options
                                 owner:(id)owner
                              userInfo:(NSDictionary *)userInfo;
          @end

          @interface NSView : NSResponder
          - (instancetype)initWithFrame:(NSRect)frameRect;
          @property NSRect frame;
          @property NSSize boundsSize;
          @property(getter=wantsLayer) BOOL wantsLayer;
          @property(getter=isHidden) BOOL hidden;
          @property(readonly, retain) CALayer *layer;
          @property(readonly, assign) NSWindow *window;
          - (void)addSubview:(NSView *)view;
          - (void)removeFromSuperview;
          - (void)addTrackingArea:(NSTrackingArea *)trackingArea;
          - (void)setClipsToBounds:(BOOL)clipsToBounds;
          - (void)getRectsBeingDrawn:(const NSRect **)rects count:(NSInteger *)count;
          - (void)setNeedsDisplayInRect:(NSRect)invalidRect;
          @end

          @interface NSScreen : NSObject
          @property(readonly) NSRect frame;
          @property(readonly) NSEdgeInsets safeAreaInsets;
          @property(readonly, copy) NSDictionary *deviceDescription;
          @end

          @interface NSWindow : NSResponder
          - (instancetype)initWithContentRect:(NSRect)contentRect
                                    styleMask:(NSWindowStyleMask)style
                                      backing:(NSBackingStoreType)backingStoreType
                                        defer:(BOOL)flag;
          @property(copy) NSString *title;
          @property(strong, nullable) __kindof NSView *contentView;
          @property(assign) id<NSWindowDelegate> delegate;
          @property NSWindowStyleMask styleMask;
          @property NSWindowCollectionBehavior collectionBehavior;
          @property BOOL acceptsMouseMovedEvents;
          @property NSSize contentAspectRatio;
          @property NSSize contentMinSize;
          @property(readonly, retain) NSScreen *screen;
          - (void)makeKeyAndOrderFront:(id)sender;
          - (void)orderFront:(id)sender;
          - (void)center;
          - (void)setContentSize:(NSSize)size;
          - (void)toggleFullScreen:(id)sender;
          @end

          @interface NSEvent : NSObject
          + (NSEvent *)eventWithCGEvent:(CGEventRef)cgEvent;
          @property(readonly) NSEventType type;
          @property(readonly) unsigned short keyCode;
          @property(readonly) NSEventModifierFlags modifierFlags;
          @property(readonly, copy) NSString *characters;
          @property(readonly, copy) NSString *charactersIgnoringModifiers;
          @property(readonly) CGFloat deltaX;
          @property(readonly) CGFloat deltaY;
          @property(readonly) NSPoint locationInWindow;
          @end

          @interface NSApplication : NSResponder
          + (NSApplication *)sharedApplication;
          @property(assign) id<NSApplicationDelegate> delegate;
          @property(retain) NSMenu *mainMenu;
          @property(retain) NSMenu *servicesMenu;
          @property(retain) NSMenu *windowsMenu;
          @property NSApplicationPresentationOptions presentationOptions;
          - (void)run;
          - (void)sendEvent:(NSEvent *)event;
          - (void)terminate:(id)sender;
          - (void)orderFrontStandardAboutPanelWithOptions:(NSDictionary *)optionsDictionary;
          @end
          extern NSApplication *NSApp;

          @interface NSImage : NSObject
          - (instancetype)initByReferencingFile:(NSString *)fileName;
          - (instancetype)initWithContentsOfFile:(NSString *)fileName;
          @end

          @interface NSAlert : NSObject
          @property(copy) NSString *messageText;
          - (void)addButtonWithTitle:(NSString *)title;
          - (NSModalResponse)runModal;
          @end

          @protocol NSOpenSavePanelDelegate <NSObject>
          @optional
          - (BOOL)panel:(id)sender shouldEnableURL:(NSURL *)url;
          @end

          @interface NSPanel : NSWindow
          @end

          @interface NSSavePanel : NSPanel
          + (NSSavePanel *)savePanel;
          - (void)setAllowsOtherFileTypes:(BOOL)flag;
          - (void)setTitle:(NSString *)title;
          - (void)setTreatsFilePackagesAsDirectories:(BOOL)flag;
          - (void)setCanCreateDirectories:(BOOL)flag;
          - (void)setDelegate:(id<NSOpenSavePanelDelegate>)delegate;
          - (NSInteger)runModalForDirectory:(NSString *)path file:(NSString *)name;
          - (NSURL *)URL;
          @end

          @interface NSOpenPanel : NSSavePanel
          + (NSOpenPanel *)openPanel;
          @property BOOL canChooseFiles;
          @property BOOL canChooseDirectories;
          @property BOOL allowsMultipleSelection;
          @property(readonly, copy) NSArray<NSURL *> *URLs;
          - (NSModalResponse)runModal;
          @end

          @interface NSMenu : NSObject
          - (instancetype)initWithTitle:(NSString *)title;
          @property(copy) NSString *title;
          @property BOOL autoenablesItems;
          @property(readonly, copy) NSArray<NSMenuItem *> *itemArray;
          - (void)addItem:(NSMenuItem *)newItem;
          - (NSMenuItem *)addItemWithTitle:(NSString *)string action:(SEL)selector keyEquivalent:(NSString *)charCode;
          - (NSMenuItem *)itemWithTitle:(NSString *)title;
          @end

          @interface NSMenuItem : NSObject
          + (NSMenuItem *)separatorItem;
          - (instancetype)initWithTitle:(NSString *)string action:(SEL)selector keyEquivalent:(NSString *)charCode;
          @property(retain) NSMenu *submenu;
          @property NSEventModifierFlags keyEquivalentModifierMask;
          @property(getter=isEnabled) BOOL enabled;
          @property NSInteger state;
          @property NSInteger tag;
          @property(readonly, assign) NSMenu *menu;
          @property(retain) id representedObject;
          @property(copy) NSMutableAttributedString *attributedTitle;
          @end

          @interface NSColor : NSObject
          + (NSColor *)whiteColor;
          + (NSColor *)blackColor;
          @end

          @interface NSFont : NSObject
          + (NSFont *)fontWithName:(NSString *)fontName size:(CGFloat)fontSize;
          @end

          @interface NSFontManager : NSObject
          + (NSFontManager *)sharedFontManager;
          - (NSFont *)convertFont:(NSFont *)font toHaveTrait:(NSUInteger)trait;
          - (NSFont *)fontWithFamily:(NSString *)family
                              traits:(NSUInteger)traits
                              weight:(NSInteger)weight
                                size:(CGFloat)size;
          @end

          @interface NSTextField : NSView
          @property(copy) NSString *stringValue;
          @property(copy) NSMutableAttributedString *attributedStringValue;
          @property BOOL editable;
          @property BOOL selectable;
          @property BOOL bezeled;
          @property BOOL drawsBackground;
          @property(retain) NSColor *textColor;
          @property(retain) NSColor *backgroundColor;
          @property(retain) NSFont *font;
          - (void)sizeToFit;
          @end

          @interface NSGraphicsContext : NSObject
          + (NSGraphicsContext *)currentContext;
          @property(readonly) CGContextRef CGContext;
          @end

          @interface NSCursor : NSObject
          + (void)hide;
          + (void)unhide;
          @end

          @interface NSPasteboard : NSObject
          + (NSPasteboard *)generalPasteboard;
          @property(readonly) NSInteger changeCount;
          - (NSInteger)declareTypes:(NSArray<NSPasteboardType> *)newTypes owner:(id)newOwner;
          - (BOOL)setData:(NSData *)data forType:(NSPasteboardType)dataType;
          - (NSData *)dataForType:(NSPasteboardType)dataType;
          - (NSPasteboardType)availableTypeFromArray:(NSArray<NSPasteboardType> *)types;
          @end

          @interface NSWorkspace : NSObject
          + (NSWorkspace *)sharedWorkspace;
          - (BOOL)openURL:(NSURL *)url;
          @end

          void NSBeep(void);

          typedef NSInteger NSUserNotificationActivationType;
          enum {
            NSUserNotificationActivationTypeNone = 0,
            NSUserNotificationActivationTypeContentsClicked = 1,
            NSUserNotificationActivationTypeActionButtonClicked = 2,
            NSUserNotificationActivationTypeReplied = 3,
            NSUserNotificationActivationTypeAdditionalActionClicked = 4
          };

          @interface NSUserNotification : NSObject
          @property(copy) NSString *title;
          @property(copy) NSString *informativeText;
          @property(copy) NSString *identifier;
          @property(retain) NSImage *contentImage;
          @property(copy) NSString *actionButtonTitle;
          @property(copy) NSDictionary *userInfo;
          @property(readonly) NSUserNotificationActivationType activationType;
          @end

          @class NSUserNotificationCenter;
          @protocol NSUserNotificationCenterDelegate <NSObject>
          @optional
          - (void)userNotificationCenter:(NSUserNotificationCenter *)center
                 didActivateNotification:(NSUserNotification *)notification;
          @end

          @interface NSUserNotificationCenter : NSObject
          + (NSUserNotificationCenter *)defaultUserNotificationCenter;
          @property(assign) id<NSUserNotificationCenterDelegate> delegate;
          @property(readonly, copy) NSArray<NSUserNotification *> *deliveredNotifications;
          - (void)deliverNotification:(NSUserNotification *)notification;
          - (void)removeDeliveredNotification:(NSUserNotification *)notification;
          @end

          #import <AppKit/NSOpenGL.h>
          #import <AppKit/NSAccessibility.h>
          #import <AppKit/NSJDKSurface.h>
          #import <AppKit/NSJDK25Surface.h>

          #endif
          EOF
          cp ${./darwin-sdk-appkit-jdk.h} \
            "$out/System/Library/Frameworks/AppKit.framework/Headers/NSJDKSurface.h"
          cp ${./darwin-sdk-appkit-nsfont.h} \
            "$out/System/Library/Frameworks/AppKit.framework/Headers/NSFont.h"
          cp ${./darwin-sdk-appkit-nsaccessibility.h} \
            "$out/System/Library/Frameworks/AppKit.framework/Headers/NSAccessibility.h"
          cp ${./darwin-sdk-appkit-jdk25.h} \
            "$out/System/Library/Frameworks/AppKit.framework/Headers/NSJDK25Surface.h"
          cp ${./darwin-sdk-appkit-wrapper.h} \
            "$out/System/Library/Frameworks/AppKit.framework/Headers/NSTrackingArea.h"
          cp ${./darwin-sdk-appkit-nsopengl.h} \
            "$out/System/Library/Frameworks/AppKit.framework/Headers/NSOpenGL.h"
          cp ${./darwin-sdk-appkit-nsrunningapplication.h} \
            "$out/System/Library/Frameworks/AppKit.framework/Headers/NSRunningApplication.h"

          cp ${./darwin-sdk-opengl.h} \
            "$out/System/Library/Frameworks/OpenGL.framework/Headers/OpenGL.h"
          cp ${./darwin-sdk-opengl.tbd} \
            "$out/System/Library/Frameworks/OpenGL.framework/OpenGL.tbd"
          ln -s ../../OpenGL.tbd \
            "$out/System/Library/Frameworks/OpenGL.framework/Versions/A/OpenGL.tbd"
          ln -s OpenGL.tbd \
            "$out/System/Library/Frameworks/OpenGL.framework/Versions/A/OpenGL"

          cat > "$out/System/Library/Frameworks/Cocoa.framework/Headers/Cocoa.h" <<'EOF'
          #ifndef _AOS_COCOA_H_
          #define _AOS_COCOA_H_
          #import <Foundation/Foundation.h>
          #import <AppKit/AppKit.h>
          #endif
          EOF

          cp ${./darwin-sdk-foundation.tbd} \
            "$out/System/Library/Frameworks/Foundation.framework/Foundation.tbd"
          sed -i \
            '/_NSLog/r ${./darwin-sdk-foundation-jdk.tbd-exports}' \
            "$out/System/Library/Frameworks/Foundation.framework/Foundation.tbd"
          sed -i \
            '/_NSLog/r ${./darwin-sdk-foundation-jdk25.tbd-exports}' \
            "$out/System/Library/Frameworks/Foundation.framework/Foundation.tbd"
          ln -s ../../Foundation.tbd \
            "$out/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation.tbd"
          ln -s Foundation.tbd \
            "$out/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation"

          cp ${./darwin-sdk-appkit.tbd} \
            "$out/System/Library/Frameworks/AppKit.framework/AppKit.tbd"
          sed -i \
            '/_NSBeep/r ${./darwin-sdk-appkit-jdk.tbd-exports}' \
            "$out/System/Library/Frameworks/AppKit.framework/AppKit.tbd"
          sed -i \
            '/_NSBeep/r ${./darwin-sdk-appkit-jdk25.tbd-exports}' \
            "$out/System/Library/Frameworks/AppKit.framework/AppKit.tbd"
          ln -s ../../AppKit.tbd \
            "$out/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit.tbd"
          ln -s AppKit.tbd \
            "$out/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit"
          cat > "$out/System/Library/Frameworks/Cocoa.framework/Cocoa.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa'
          current-version: 24.0.0
          compatibility-version: 1.0.0
          reexported-libraries:
            - targets: [ x86_64-macos, arm64-macos ]
              libraries:
                - '/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit'
                - '/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation'
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols:
                - '_OBJC_CLASS_$_NSArray'
                - '_OBJC_CLASS_$_NSBundle'
                - '_OBJC_CLASS_$_NSDictionary'
                - '_OBJC_CLASS_$_NSImage'
                - '_OBJC_CLASS_$_NSMutableDictionary'
                - '_OBJC_CLASS_$_NSObject'
                - '_OBJC_CLASS_$_NSString'
                - '_OBJC_CLASS_$_NSUserNotification'
                - '_OBJC_CLASS_$_NSUserNotificationCenter'
                - '_OBJC_METACLASS_$_NSObject'
                - '_OBJC_PROTOCOL_$_NSUserNotificationCenterDelegate'
          ...
          EOF

          # Publish the source-backed public ApplicationServices ABI without
          # embedding another large static framework fragment in the builder argv.
          cp ${./darwin-sdk-application-services.h} \
            "$out/System/Library/Frameworks/ApplicationServices.framework/Headers/ApplicationServices.h"
          cp ${./darwin-sdk-application-services.tbd} \
            "$out/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices.tbd"
          ln -s ../../ApplicationServices.tbd \
            "$out/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices.tbd"
          ln -s ApplicationServices.tbd \
            "$out/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices"
          # Carbon is a public compatibility umbrella. Keep its exact source
          # contract in a source-backed asset so the SDK builder remains well
          # below Linux's per-argument execve limit.
          cp ${./darwin-sdk-carbon.h} \
            "$out/System/Library/Frameworks/Carbon.framework/Headers/Carbon.h"
          cp ${./darwin-sdk-carbon-ae.h} \
            "$out/System/Library/Frameworks/Carbon.framework/Headers/AEDataModel.h"
          cp ${./darwin-sdk-carbon-jdk.h} \
            "$out/System/Library/Frameworks/Carbon.framework/Headers/JDKSurface.h"
          cp ${./darwin-sdk-carbon.tbd} \
            "$out/System/Library/Frameworks/Carbon.framework/Carbon.tbd"
          ln -s ../../Carbon.tbd \
            "$out/System/Library/Frameworks/Carbon.framework/Versions/A/Carbon.tbd"
          ln -s Carbon.tbd \
            "$out/System/Library/Frameworks/Carbon.framework/Versions/A/Carbon"

          # OpenJDK 8 still consumes Apple's public JavaRuntimeSupport ABI.
          # Publish only the exact linked SDK contract verified against the
          # historical Apple SDK and current OpenJDK consumers; no framework
          # implementation or proprietary header payload is included.
          "$CONFIG_SHELL" ${javaRuntimeSupportFragment}

          # Hypervisor.framework is a public system ABI with distinct ARM and
          # x86 interfaces.  Publish the factual declarations and constants
          # used by open-source virtual-machine monitors without importing an
          # Xcode SDK or weakening QEMU's native-HVF feature set.
          cat > "$out/System/Library/Frameworks/Hypervisor.framework/Headers/Hypervisor.h" <<'EOF'
          #ifndef AOS_HYPERVISOR_H
          #define AOS_HYPERVISOR_H

          #include <stdbool.h>
          #include <stddef.h>
          #include <stdint.h>
          #include <os/object.h>

          #if defined(__aarch64__) || defined(__arm64__)

          typedef int32_t hv_return_t;
          #define HV_SUCCESS ((hv_return_t)0)
          #define HV_ERROR ((hv_return_t)0xfae94001u)
          #define HV_BUSY ((hv_return_t)0xfae94002u)
          #define HV_BAD_ARGUMENT ((hv_return_t)0xfae94003u)
          #define HV_NO_RESOURCES ((hv_return_t)0xfae94005u)
          #define HV_NO_DEVICE ((hv_return_t)0xfae94006u)
          #define HV_DENIED ((hv_return_t)0xfae94007u)
          #define HV_UNSUPPORTED ((hv_return_t)0xfae9400fu)

          typedef uint64_t hv_memory_flags_t;
          enum {
            HV_MEMORY_READ = 1ull << 0,
            HV_MEMORY_WRITE = 1ull << 1,
            HV_MEMORY_EXEC = 1ull << 2,
          };

          typedef struct hv_vm_config_s *hv_vm_config_t;
          typedef struct hv_vcpu_config_s *hv_vcpu_config_t;
          typedef uint64_t hv_ipa_t;
          typedef uint64_t hv_vcpu_t;
          typedef uint32_t hv_exit_reason_t;
          enum {
            HV_EXIT_REASON_CANCELED,
            HV_EXIT_REASON_EXCEPTION,
            HV_EXIT_REASON_VTIMER_ACTIVATED,
            HV_EXIT_REASON_UNKNOWN,
          };

          typedef struct {
            uint64_t syndrome;
            uint64_t virtual_address;
            hv_ipa_t physical_address;
          } hv_vcpu_exit_exception_t;

          typedef struct {
            hv_exit_reason_t reason;
            hv_vcpu_exit_exception_t exception;
          } hv_vcpu_exit_t;

          typedef __attribute__((ext_vector_type(16))) uint8_t hv_simd_fp_uchar16_t;

          typedef uint32_t hv_reg_t;
          enum {
            HV_REG_X0,
            HV_REG_X1,
            HV_REG_X2,
            HV_REG_X3,
            HV_REG_X4,
            HV_REG_X5,
            HV_REG_X6,
            HV_REG_X7,
            HV_REG_X8,
            HV_REG_X9,
            HV_REG_X10,
            HV_REG_X11,
            HV_REG_X12,
            HV_REG_X13,
            HV_REG_X14,
            HV_REG_X15,
            HV_REG_X16,
            HV_REG_X17,
            HV_REG_X18,
            HV_REG_X19,
            HV_REG_X20,
            HV_REG_X21,
            HV_REG_X22,
            HV_REG_X23,
            HV_REG_X24,
            HV_REG_X25,
            HV_REG_X26,
            HV_REG_X27,
            HV_REG_X28,
            HV_REG_X29,
            HV_REG_X30,
            HV_REG_PC,
            HV_REG_FPCR,
            HV_REG_FPSR,
            HV_REG_CPSR,
          };

          typedef uint32_t hv_simd_fp_reg_t;
          enum {
            HV_SIMD_FP_REG_Q0,
            HV_SIMD_FP_REG_Q1,
            HV_SIMD_FP_REG_Q2,
            HV_SIMD_FP_REG_Q3,
            HV_SIMD_FP_REG_Q4,
            HV_SIMD_FP_REG_Q5,
            HV_SIMD_FP_REG_Q6,
            HV_SIMD_FP_REG_Q7,
            HV_SIMD_FP_REG_Q8,
            HV_SIMD_FP_REG_Q9,
            HV_SIMD_FP_REG_Q10,
            HV_SIMD_FP_REG_Q11,
            HV_SIMD_FP_REG_Q12,
            HV_SIMD_FP_REG_Q13,
            HV_SIMD_FP_REG_Q14,
            HV_SIMD_FP_REG_Q15,
            HV_SIMD_FP_REG_Q16,
            HV_SIMD_FP_REG_Q17,
            HV_SIMD_FP_REG_Q18,
            HV_SIMD_FP_REG_Q19,
            HV_SIMD_FP_REG_Q20,
            HV_SIMD_FP_REG_Q21,
            HV_SIMD_FP_REG_Q22,
            HV_SIMD_FP_REG_Q23,
            HV_SIMD_FP_REG_Q24,
            HV_SIMD_FP_REG_Q25,
            HV_SIMD_FP_REG_Q26,
            HV_SIMD_FP_REG_Q27,
            HV_SIMD_FP_REG_Q28,
            HV_SIMD_FP_REG_Q29,
            HV_SIMD_FP_REG_Q30,
            HV_SIMD_FP_REG_Q31,
          };

          typedef uint16_t hv_sys_reg_t;
          enum {
            HV_SYS_REG_DBGBVR0_EL1 = 0x8004,
            HV_SYS_REG_DBGBCR0_EL1 = 0x8005,
            HV_SYS_REG_DBGWVR0_EL1 = 0x8006,
            HV_SYS_REG_DBGWCR0_EL1 = 0x8007,
            HV_SYS_REG_DBGBVR1_EL1 = 0x800c,
            HV_SYS_REG_DBGBCR1_EL1 = 0x800d,
            HV_SYS_REG_DBGWVR1_EL1 = 0x800e,
            HV_SYS_REG_DBGWCR1_EL1 = 0x800f,
            HV_SYS_REG_MDCCINT_EL1 = 0x8010,
            HV_SYS_REG_MDSCR_EL1 = 0x8012,
            HV_SYS_REG_DBGBVR2_EL1 = 0x8014,
            HV_SYS_REG_DBGBCR2_EL1 = 0x8015,
            HV_SYS_REG_DBGWVR2_EL1 = 0x8016,
            HV_SYS_REG_DBGWCR2_EL1 = 0x8017,
            HV_SYS_REG_DBGBVR3_EL1 = 0x801c,
            HV_SYS_REG_DBGBCR3_EL1 = 0x801d,
            HV_SYS_REG_DBGWVR3_EL1 = 0x801e,
            HV_SYS_REG_DBGWCR3_EL1 = 0x801f,
            HV_SYS_REG_DBGBVR4_EL1 = 0x8024,
            HV_SYS_REG_DBGBCR4_EL1 = 0x8025,
            HV_SYS_REG_DBGWVR4_EL1 = 0x8026,
            HV_SYS_REG_DBGWCR4_EL1 = 0x8027,
            HV_SYS_REG_DBGBVR5_EL1 = 0x802c,
            HV_SYS_REG_DBGBCR5_EL1 = 0x802d,
            HV_SYS_REG_DBGWVR5_EL1 = 0x802e,
            HV_SYS_REG_DBGWCR5_EL1 = 0x802f,
            HV_SYS_REG_DBGBVR6_EL1 = 0x8034,
            HV_SYS_REG_DBGBCR6_EL1 = 0x8035,
            HV_SYS_REG_DBGWVR6_EL1 = 0x8036,
            HV_SYS_REG_DBGWCR6_EL1 = 0x8037,
            HV_SYS_REG_DBGBVR7_EL1 = 0x803c,
            HV_SYS_REG_DBGBCR7_EL1 = 0x803d,
            HV_SYS_REG_DBGWVR7_EL1 = 0x803e,
            HV_SYS_REG_DBGWCR7_EL1 = 0x803f,
            HV_SYS_REG_DBGBVR8_EL1 = 0x8044,
            HV_SYS_REG_DBGBCR8_EL1 = 0x8045,
            HV_SYS_REG_DBGWVR8_EL1 = 0x8046,
            HV_SYS_REG_DBGWCR8_EL1 = 0x8047,
            HV_SYS_REG_DBGBVR9_EL1 = 0x804c,
            HV_SYS_REG_DBGBCR9_EL1 = 0x804d,
            HV_SYS_REG_DBGWVR9_EL1 = 0x804e,
            HV_SYS_REG_DBGWCR9_EL1 = 0x804f,
            HV_SYS_REG_DBGBVR10_EL1 = 0x8054,
            HV_SYS_REG_DBGBCR10_EL1 = 0x8055,
            HV_SYS_REG_DBGWVR10_EL1 = 0x8056,
            HV_SYS_REG_DBGWCR10_EL1 = 0x8057,
            HV_SYS_REG_DBGBVR11_EL1 = 0x805c,
            HV_SYS_REG_DBGBCR11_EL1 = 0x805d,
            HV_SYS_REG_DBGWVR11_EL1 = 0x805e,
            HV_SYS_REG_DBGWCR11_EL1 = 0x805f,
            HV_SYS_REG_DBGBVR12_EL1 = 0x8064,
            HV_SYS_REG_DBGBCR12_EL1 = 0x8065,
            HV_SYS_REG_DBGWVR12_EL1 = 0x8066,
            HV_SYS_REG_DBGWCR12_EL1 = 0x8067,
            HV_SYS_REG_DBGBVR13_EL1 = 0x806c,
            HV_SYS_REG_DBGBCR13_EL1 = 0x806d,
            HV_SYS_REG_DBGWVR13_EL1 = 0x806e,
            HV_SYS_REG_DBGWCR13_EL1 = 0x806f,
            HV_SYS_REG_DBGBVR14_EL1 = 0x8074,
            HV_SYS_REG_DBGBCR14_EL1 = 0x8075,
            HV_SYS_REG_DBGWVR14_EL1 = 0x8076,
            HV_SYS_REG_DBGWCR14_EL1 = 0x8077,
            HV_SYS_REG_DBGBVR15_EL1 = 0x807c,
            HV_SYS_REG_DBGBCR15_EL1 = 0x807d,
            HV_SYS_REG_DBGWVR15_EL1 = 0x807e,
            HV_SYS_REG_DBGWCR15_EL1 = 0x807f,
            HV_SYS_REG_MIDR_EL1 = 0xc000,
            HV_SYS_REG_MPIDR_EL1 = 0xc005,
            HV_SYS_REG_ID_AA64PFR0_EL1 = 0xc020,
            HV_SYS_REG_ID_AA64PFR1_EL1 = 0xc021,
            HV_SYS_REG_ID_AA64DFR0_EL1 = 0xc028,
            HV_SYS_REG_ID_AA64DFR1_EL1 = 0xc029,
            HV_SYS_REG_ID_AA64ISAR0_EL1 = 0xc030,
            HV_SYS_REG_ID_AA64ISAR1_EL1 = 0xc031,
            HV_SYS_REG_ID_AA64MMFR0_EL1 = 0xc038,
            HV_SYS_REG_ID_AA64MMFR1_EL1 = 0xc039,
            HV_SYS_REG_ID_AA64MMFR2_EL1 = 0xc03a,
            HV_SYS_REG_SCTLR_EL1 = 0xc080,
            HV_SYS_REG_CPACR_EL1 = 0xc082,
            HV_SYS_REG_TTBR0_EL1 = 0xc100,
            HV_SYS_REG_TTBR1_EL1 = 0xc101,
            HV_SYS_REG_TCR_EL1 = 0xc102,
            HV_SYS_REG_APIAKEYLO_EL1 = 0xc108,
            HV_SYS_REG_APIAKEYHI_EL1 = 0xc109,
            HV_SYS_REG_APIBKEYLO_EL1 = 0xc10a,
            HV_SYS_REG_APIBKEYHI_EL1 = 0xc10b,
            HV_SYS_REG_APDAKEYLO_EL1 = 0xc110,
            HV_SYS_REG_APDAKEYHI_EL1 = 0xc111,
            HV_SYS_REG_APDBKEYLO_EL1 = 0xc112,
            HV_SYS_REG_APDBKEYHI_EL1 = 0xc113,
            HV_SYS_REG_APGAKEYLO_EL1 = 0xc118,
            HV_SYS_REG_APGAKEYHI_EL1 = 0xc119,
            HV_SYS_REG_SPSR_EL1 = 0xc200,
            HV_SYS_REG_ELR_EL1 = 0xc201,
            HV_SYS_REG_SP_EL0 = 0xc208,
            HV_SYS_REG_AFSR0_EL1 = 0xc288,
            HV_SYS_REG_AFSR1_EL1 = 0xc289,
            HV_SYS_REG_ESR_EL1 = 0xc290,
            HV_SYS_REG_FAR_EL1 = 0xc300,
            HV_SYS_REG_PAR_EL1 = 0xc3a0,
            HV_SYS_REG_MAIR_EL1 = 0xc510,
            HV_SYS_REG_AMAIR_EL1 = 0xc518,
            HV_SYS_REG_VBAR_EL1 = 0xc600,
            HV_SYS_REG_CONTEXTIDR_EL1 = 0xc681,
            HV_SYS_REG_TPIDR_EL1 = 0xc684,
            HV_SYS_REG_CNTKCTL_EL1 = 0xc708,
            HV_SYS_REG_CSSELR_EL1 = 0xd000,
            HV_SYS_REG_TPIDR_EL0 = 0xde82,
            HV_SYS_REG_TPIDRRO_EL0 = 0xde83,
            HV_SYS_REG_CNTV_CTL_EL0 = 0xdf19,
            HV_SYS_REG_CNTV_CVAL_EL0 = 0xdf1a,
            HV_SYS_REG_SP_EL1 = 0xe208,
          };

          typedef uint32_t hv_interrupt_type_t;
          enum {
            HV_INTERRUPT_TYPE_IRQ,
            HV_INTERRUPT_TYPE_FIQ,
          };

          typedef uint32_t hv_feature_reg_t;
          enum {
            HV_FEATURE_REG_ID_AA64DFR0_EL1,
            HV_FEATURE_REG_ID_AA64DFR1_EL1,
            HV_FEATURE_REG_ID_AA64ISAR0_EL1,
            HV_FEATURE_REG_ID_AA64ISAR1_EL1,
            HV_FEATURE_REG_ID_AA64MMFR0_EL1,
            HV_FEATURE_REG_ID_AA64MMFR1_EL1,
            HV_FEATURE_REG_ID_AA64MMFR2_EL1,
            HV_FEATURE_REG_ID_AA64PFR0_EL1,
            HV_FEATURE_REG_ID_AA64PFR1_EL1,
          };

          hv_vm_config_t hv_vm_config_create(void);
          hv_return_t hv_vm_config_get_default_ipa_size(uint32_t *ipa_bit_length);
          hv_return_t hv_vm_config_get_max_ipa_size(uint32_t *ipa_bit_length);
          hv_return_t hv_vm_config_set_ipa_size(hv_vm_config_t config, uint32_t ipa_bit_length);
          hv_return_t hv_vm_create(hv_vm_config_t config);
          hv_return_t hv_vm_destroy(void);
          hv_return_t hv_vm_map(void *address, hv_ipa_t ipa, size_t size, hv_memory_flags_t flags);
          hv_return_t hv_vm_unmap(hv_ipa_t ipa, size_t size);
          hv_return_t hv_vm_protect(hv_ipa_t ipa, size_t size, hv_memory_flags_t flags);

          hv_vcpu_config_t hv_vcpu_config_create(void);
          hv_return_t hv_vcpu_config_get_feature_reg(hv_vcpu_config_t config, hv_feature_reg_t reg, uint64_t *value);
          hv_return_t hv_vcpu_create(hv_vcpu_t *vcpu, hv_vcpu_exit_t **exit, hv_vcpu_config_t config);
          hv_return_t hv_vcpu_destroy(hv_vcpu_t vcpu);
          hv_return_t hv_vcpu_get_reg(hv_vcpu_t vcpu, hv_reg_t reg, uint64_t *value);
          hv_return_t hv_vcpu_set_reg(hv_vcpu_t vcpu, hv_reg_t reg, uint64_t value);
          hv_return_t hv_vcpu_get_simd_fp_reg(hv_vcpu_t vcpu, hv_simd_fp_reg_t reg, hv_simd_fp_uchar16_t *value);
          hv_return_t hv_vcpu_set_simd_fp_reg(hv_vcpu_t vcpu, hv_simd_fp_reg_t reg, hv_simd_fp_uchar16_t value);
          hv_return_t hv_vcpu_get_sys_reg(hv_vcpu_t vcpu, hv_sys_reg_t reg, uint64_t *value);
          hv_return_t hv_vcpu_set_sys_reg(hv_vcpu_t vcpu, hv_sys_reg_t reg, uint64_t value);
          hv_return_t hv_vcpu_set_pending_interrupt(hv_vcpu_t vcpu, hv_interrupt_type_t type, bool pending);
          hv_return_t hv_vcpu_set_trap_debug_exceptions(hv_vcpu_t vcpu, bool enabled);
          hv_return_t hv_vcpu_set_trap_debug_reg_accesses(hv_vcpu_t vcpu, bool enabled);
          hv_return_t hv_vcpu_run(hv_vcpu_t vcpu);
          hv_return_t hv_vcpus_exit(hv_vcpu_t *vcpus, uint32_t count);
          hv_return_t hv_vcpu_set_vtimer_mask(hv_vcpu_t vcpu, bool masked);
          hv_return_t hv_vcpu_set_vtimer_offset(hv_vcpu_t vcpu, uint64_t offset);

          #else
          #include <Hypervisor/hv.h>
          #include <Hypervisor/hv_vmx.h>
          #endif

          #endif
          EOF

          cat > "$out/System/Library/Frameworks/Hypervisor.framework/Headers/hv.h" <<'EOF'
          #ifndef AOS_HYPERVISOR_HV_H
          #define AOS_HYPERVISOR_HV_H

          #include <stdbool.h>
          #include <stddef.h>
          #include <stdint.h>

          typedef int32_t hv_return_t;
          #define HV_SUCCESS ((hv_return_t)0)
          #define HV_ERROR ((hv_return_t)0xfae94001u)
          #define HV_BUSY ((hv_return_t)0xfae94002u)
          #define HV_BAD_ARGUMENT ((hv_return_t)0xfae94003u)
          #define HV_NO_RESOURCES ((hv_return_t)0xfae94005u)
          #define HV_NO_DEVICE ((hv_return_t)0xfae94006u)
          #define HV_DENIED ((hv_return_t)0xfae94007u)
          #define HV_UNSUPPORTED ((hv_return_t)0xfae9400fu)

          typedef uint64_t hv_memory_flags_t;
          typedef uint64_t hv_vm_options_t;
          typedef uint64_t hv_vcpu_options_t;
          typedef unsigned int hv_vcpuid_t;
          typedef const void *hv_uvaddr_t;
          typedef uint64_t hv_gpaddr_t;
          enum {
            HV_MEMORY_READ = 1ull << 0,
            HV_MEMORY_WRITE = 1ull << 1,
            HV_MEMORY_EXEC = 1ull << 2,
            HV_VM_DEFAULT = 0,
            HV_VCPU_DEFAULT = 0,
            HV_DEADLINE_FOREVER = ~0ull,
          };

          typedef enum {
            HV_X86_RIP,
            HV_X86_RFLAGS,
            HV_X86_RAX,
            HV_X86_RCX,
            HV_X86_RDX,
            HV_X86_RBX,
            HV_X86_RSI,
            HV_X86_RDI,
            HV_X86_RSP,
            HV_X86_RBP,
            HV_X86_R8,
            HV_X86_R9,
            HV_X86_R10,
            HV_X86_R11,
            HV_X86_R12,
            HV_X86_R13,
            HV_X86_R14,
            HV_X86_R15,
            HV_X86_CS,
            HV_X86_SS,
            HV_X86_DS,
            HV_X86_ES,
            HV_X86_FS,
            HV_X86_GS,
            HV_X86_IDT_BASE,
            HV_X86_IDT_LIMIT,
            HV_X86_GDT_BASE,
            HV_X86_GDT_LIMIT,
            HV_X86_LDTR,
            HV_X86_LDT_BASE,
            HV_X86_LDT_LIMIT,
            HV_X86_LDT_AR,
            HV_X86_TR,
            HV_X86_TSS_BASE,
            HV_X86_TSS_LIMIT,
            HV_X86_TSS_AR,
            HV_X86_CR0,
            HV_X86_CR1,
            HV_X86_CR2,
            HV_X86_CR3,
            HV_X86_CR4,
            HV_X86_DR0,
            HV_X86_DR1,
            HV_X86_DR2,
            HV_X86_DR3,
            HV_X86_DR4,
            HV_X86_DR5,
            HV_X86_DR6,
            HV_X86_DR7,
            HV_X86_TPR,
            HV_X86_XCR0,
          } hv_x86_reg_t;

          hv_return_t hv_vm_create(hv_vm_options_t flags);
          hv_return_t hv_vm_destroy(void);
          hv_return_t hv_vm_map(hv_uvaddr_t address, hv_gpaddr_t gpa, size_t size, hv_memory_flags_t flags);
          hv_return_t hv_vm_unmap(hv_gpaddr_t gpa, size_t size);
          hv_return_t hv_vm_protect(hv_gpaddr_t gpa, size_t size, hv_memory_flags_t flags);
          hv_return_t hv_vcpu_create(hv_vcpuid_t *vcpu, hv_vcpu_options_t flags);
          hv_return_t hv_vcpu_destroy(hv_vcpuid_t vcpu);
          hv_return_t hv_vcpu_read_register(hv_vcpuid_t vcpu, hv_x86_reg_t reg, uint64_t *value);
          hv_return_t hv_vcpu_write_register(hv_vcpuid_t vcpu, hv_x86_reg_t reg, uint64_t value);
          hv_return_t hv_vcpu_read_fpstate(hv_vcpuid_t vcpu, void *buffer, size_t size);
          hv_return_t hv_vcpu_write_fpstate(hv_vcpuid_t vcpu, void *buffer, size_t size);
          hv_return_t hv_vcpu_enable_native_msr(hv_vcpuid_t vcpu, uint32_t msr, bool enabled);
          hv_return_t hv_vcpu_read_msr(hv_vcpuid_t vcpu, uint32_t msr, uint64_t *value);
          hv_return_t hv_vcpu_write_msr(hv_vcpuid_t vcpu, uint32_t msr, uint64_t value);
          hv_return_t hv_vcpu_invalidate_tlb(hv_vcpuid_t vcpu);
          hv_return_t hv_vcpu_run(hv_vcpuid_t vcpu);
          hv_return_t hv_vcpu_run_until(hv_vcpuid_t vcpu, uint64_t deadline);
          hv_return_t hv_vcpu_interrupt(hv_vcpuid_t *vcpus, unsigned int count);

          #endif
          EOF

          cat > "$out/System/Library/Frameworks/Hypervisor.framework/Headers/hv_vmx.h" <<'EOF'
          #ifndef AOS_HYPERVISOR_HV_VMX_H
          #define AOS_HYPERVISOR_HV_VMX_H

          #include <Hypervisor/hv.h>

          typedef enum {
            HV_VMX_CAP_PINBASED = 0,
            HV_VMX_CAP_PROCBASED = 1,
            HV_VMX_CAP_PROCBASED2 = 2,
            HV_VMX_CAP_ENTRY = 3,
          } hv_vmx_capability_t;

          enum {
            CPU_BASED_TSC_OFFSET = 1u << 3,
            CPU_BASED2_RDTSCP = 1u << 3,
            CPU_BASED2_INVPCID = 1u << 12,
            CPU_BASED2_XSAVES_XRSTORS = 1u << 20,
            VMX_REASON_VMCALL = 18,
          };

          hv_return_t hv_vmx_read_capability(hv_vmx_capability_t capability, uint64_t *value);
          hv_return_t hv_vmx_vcpu_read_vmcs(hv_vcpuid_t vcpu, uint32_t field, uint64_t *value);
          hv_return_t hv_vmx_vcpu_write_vmcs(hv_vcpuid_t vcpu, uint32_t field, uint64_t value);

          #endif
          EOF

          cat > "$out/System/Library/Frameworks/Hypervisor.framework/Hypervisor.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/System/Library/Frameworks/Hypervisor.framework/Versions/A/Hypervisor'
          current-version: 1.0.0
          compatibility-version: 1.0.0
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols:
                - _hv_vcpu_create
                - _hv_vcpu_destroy
                - _hv_vcpu_run
                - _hv_vm_create
                - _hv_vm_destroy
                - _hv_vm_map
                - _hv_vm_protect
                - _hv_vm_unmap
            - targets: [ x86_64-macos ]
              symbols:
                - _hv_vcpu_enable_native_msr
                - _hv_vcpu_interrupt
                - _hv_vcpu_invalidate_tlb
                - _hv_vcpu_read_fpstate
                - _hv_vcpu_read_msr
                - _hv_vcpu_read_register
                - _hv_vcpu_run_until
                - _hv_vcpu_write_fpstate
                - _hv_vcpu_write_msr
                - _hv_vcpu_write_register
                - _hv_vmx_read_capability
                - _hv_vmx_vcpu_read_vmcs
                - _hv_vmx_vcpu_write_vmcs
            - targets: [ arm64-macos ]
              symbols:
                - _hv_vcpu_config_create
                - _hv_vcpu_config_get_feature_reg
                - _hv_vcpu_get_reg
                - _hv_vcpu_get_simd_fp_reg
                - _hv_vcpu_get_sys_reg
                - _hv_vcpu_set_pending_interrupt
                - _hv_vcpu_set_reg
                - _hv_vcpu_set_simd_fp_reg
                - _hv_vcpu_set_sys_reg
                - _hv_vcpu_set_trap_debug_exceptions
                - _hv_vcpu_set_trap_debug_reg_accesses
                - _hv_vcpu_set_vtimer_mask
                - _hv_vcpu_set_vtimer_offset
                - _hv_vcpus_exit
                - _hv_vm_config_create
                - _hv_vm_config_get_default_ipa_size
                - _hv_vm_config_get_max_ipa_size
                - _hv_vm_config_set_ipa_size
          ...
          EOF
          ln -s ../../Hypervisor.tbd \
            "$out/System/Library/Frameworks/Hypervisor.framework/Versions/A/Hypervisor.tbd"
          ln -s Hypervisor.tbd \
            "$out/System/Library/Frameworks/Hypervisor.framework/Versions/A/Hypervisor"

          cat > "$out/System/Library/Frameworks/IOKit.framework/IOKit.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit'
          current-version: 275.0.0
          compatibility-version: 1.0.0
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols:
                - _IOBSDNameMatching
                - _IOCreatePlugInInterfaceForService
                - _IODestroyPlugInInterface
                - _IOIteratorNext
                - _IOIteratorReset
                - _IOKitWaitQuiet
                - _IOMainPort
                - _IONotificationPortCreate
                - _IONotificationPortDestroy
                - _IONotificationPortGetRunLoopSource
                - _IOObjectConformsTo
                - _IOObjectRelease
                - _IOObjectRetain
                - _IORegistryEntryCreateCFProperty
                - _IORegistryEntryFromPath
                - _IORegistryEntryGetChildEntry
                - _IORegistryEntryIDMatching
                - _IORegistryEntryGetParentEntry
                - _IORegistryEntryGetPath
                - _IORegistryEntrySearchCFProperty
                - _IORegistryEntrySetCFProperty
                - _IOServiceAddMatchingNotification
                - _IOServiceAuthorize
                - _IOServiceGetMatchingService
                - _IOServiceGetMatchingServices
                - _IOServiceMatching
                - _kIOMainPortDefault
                - _kIOMasterPortDefault
          ...
          EOF

          cp ${./darwin-sdk-security.tbd} \
            "$out/System/Library/Frameworks/Security.framework/Security.tbd"

          # OpenJDK's native proxy selector consumes CFNetwork's documented
          # system-proxy API. These source-backed assets describe only that
          # public ABI; the target host provides the framework implementation.
          cp ${./darwin-sdk-cfnetwork.h} \
            "$out/System/Library/Frameworks/CFNetwork.framework/Headers/CFNetwork.h"
          cp ${./darwin-sdk-cf-proxy-support.h} \
            "$out/System/Library/Frameworks/CFNetwork.framework/Headers/CFProxySupport.h"
          cp ${./darwin-sdk-cfnetwork.tbd} \
            "$out/System/Library/Frameworks/CFNetwork.framework/CFNetwork.tbd"
          ln -s ../../CFNetwork.tbd \
            "$out/System/Library/Frameworks/CFNetwork.framework/Versions/A/CFNetwork.tbd"
          ln -s CFNetwork.tbd \
            "$out/System/Library/Frameworks/CFNetwork.framework/Versions/A/CFNetwork"

          cat > "$out/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration'
          current-version: 1400.0.0
          compatibility-version: 1.0.0
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols:
                - _SCDynamicStoreCopyValue
                - _SCDynamicStoreCopyProxies
                - _SCDynamicStoreCreate
                - _SCDynamicStoreCreateRunLoopSource
                - _SCDynamicStoreSetNotificationKeys
                - _kSCPropNetProxiesExcludeSimpleHostnames
                - _kSCPropNetProxiesExceptionsList
                - _kSCPropNetProxiesFTPEnable
                - _kSCPropNetProxiesFTPPort
                - _kSCPropNetProxiesFTPProxy
                - _kSCPropNetProxiesGopherEnable
                - _kSCPropNetProxiesGopherPort
                - _kSCPropNetProxiesGopherProxy
                - _kSCPropNetProxiesHTTPEnable
                - _kSCPropNetProxiesHTTPPort
                - _kSCPropNetProxiesHTTPProxy
                - _kSCPropNetProxiesHTTPSEnable
                - _kSCPropNetProxiesHTTPSPort
                - _kSCPropNetProxiesHTTPSProxy
                - _kSCPropNetProxiesSOCKSEnable
                - _kSCPropNetProxiesSOCKSPort
                - _kSCPropNetProxiesSOCKSProxy
          ...
          EOF

          cat > "$out/usr/lib/libobjc.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/usr/lib/libobjc.A.dylib'
          current-version: 228.0.0
          compatibility-version: 1.0.0
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols:
                - ___objc_personality_v0
                - __objc_empty_cache
                - _class_addIvar
                - _class_addMethod
                - _class_conformsToProtocol
                - _class_copyIvarList
                - _class_copyMethodList
                - _class_copyPropertyList
                - _class_copyProtocolList
                - _class_getClassMethod
                - _class_getInstanceMethod
                - _class_getInstanceSize
                - _class_getInstanceVariable
                - _class_getName
                - _class_getProperty
                - _class_getSuperclass
                - _class_isMetaClass
                - _class_createInstance
                - _class_respondsToSelector
                - _ivar_getName
                - _ivar_getOffset
                - _ivar_getTypeEncoding
                - _method_copyArgumentType
                - _method_copyReturnType
                - _method_getImplementation
                - _method_getName
                - _method_getTypeEncoding
                - _method_setImplementation
                - _objc_alloc
                - _objc_alloc_init
                - _objc_allocateClassPair
                - _objc_autorelease
                - _objc_autoreleasePoolPop
                - _objc_autoreleasePoolPush
                - _objc_autoreleaseReturnValue
                - _objc_begin_catch
                - _objc_copyClassList
                - _objc_copyProtocolList
                - _objc_copyStruct
                - _objc_copyWeak
                - _objc_destroyWeak
                - _objc_disposeClassPair
                - _objc_enumerationMutation
                - _objc_end_catch
                - _objc_ehtype_vtable
                - _objc_exception_throw
                # objc4's pinned public exception ABI declares this as
                # `OBJC_EXPORT OBJC_NORETURN void objc_exception_rethrow(void)`.
                - _objc_exception_rethrow
                - _objc_getClass
                - _objc_getProperty
                - _objc_getMetaClass
                - _objc_getProtocol
                - _objc_initWeak
                - _objc_loadWeakRetained
                - _objc_lookUpClass
                - _objc_msgSend
                - _objc_msgSendSuper
                - _objc_msgSendSuper2
                - _objc_moveWeak
                - _objc_registerClassPair
                - _objc_registerProtocol
                - _objc_release
                - _objc_retain
                - _objc_retainAutoreleaseReturnValue
                - _objc_retainAutoreleasedReturnValue
                - _objc_storeStrong
                - _objc_storeWeak
                - _objc_setProperty_nonatomic
                - _objc_setProperty_atomic
                - _objc_sync_enter
                - _objc_sync_exit
                - _objc_terminate
                - _object_getClass
                - _object_getInstanceVariable
                - _object_setClass
                - _object_setInstanceVariable
                - _protocol_addMethodDescription
                - _protocol_addProtocol
                - _protocol_copyProtocolList
                - _protocol_getName
                - _sel_getName
                - _sel_getUid
                - _sel_registerName
            - targets: [ x86_64-macos ]
              symbols:
                - _objc_msgSend_stret
                - _objc_msgSendSuper2_stret
          ...
          EOF

          # Darwin's libc, libdl, libm, pthread, resolv, and libutil symbols
          # are all re-exported by libSystem.  Make the traditional linker
          # names resolve to the same textual stub without shipping binaries.
          for library in c dl m pthread resolv util; do
            ln -s libSystem.tbd "$out/usr/lib/lib$library.tbd"
          done
          # Mach-O load commands retain Apple's versioned dylib install names.
          # Flat-namespace links follow those transitive names through the SDK,
          # so provide canonical aliases to the corresponding textual stubs.
          ln -s libSystem.tbd "$out/usr/lib/libSystem.B.dylib"
          ln -s libobjc.tbd "$out/usr/lib/libobjc.A.dylib"
        '';
      }
    ];

    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;

    meta = {
      description = "Redistributable Darwin headers and system link stubs";
      homepage = "https://ziglang.org/";
      license = "APSL-1.1 AND APSL-2.0 AND BSD-3-Clause AND MIT AND (Apache-2.0 WITH Swift-exception)";
      platforms = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
    };
  }
