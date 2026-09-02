# Dawn maps WebGPU multiplanar formats to CoreVideo's public pixel format
# codes. OpenJDK additionally consumes the public display-link ABI.
cat > "$out/System/Library/Frameworks/CoreVideo.framework/Headers/CVPixelBuffer.h" <<'EOF'
#ifndef _AOS_COREVIDEO_CVPIXELBUFFER_H_
#define _AOS_COREVIDEO_CVPIXELBUFFER_H_

#include <CoreFoundation/CoreFoundation.h>

#ifdef __cplusplus
enum : OSType
#else
enum
#endif
{
  kCVPixelFormatType_32BGRA = 'BGRA',
  kCVPixelFormatType_32RGBA = 'RGBA',
  kCVPixelFormatType_OneComponent8 = 'L008',
  kCVPixelFormatType_TwoComponent8 = '2C08',
  kCVPixelFormatType_ARGB2101010LEPacked = 'l10r',
  kCVPixelFormatType_OneComponent16 = 'L016',
  kCVPixelFormatType_TwoComponent16 = '2C16',
  kCVPixelFormatType_OneComponent16Half = 'L00h',
  kCVPixelFormatType_TwoComponent16Half = '2C0h',
  kCVPixelFormatType_64RGBAHalf = 'RGhA',
  kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange = '420v',
  kCVPixelFormatType_422YpCbCr8BiPlanarVideoRange = '422v',
  kCVPixelFormatType_444YpCbCr8BiPlanarVideoRange = '444v',
  kCVPixelFormatType_420YpCbCr10BiPlanarVideoRange = 'x420',
  kCVPixelFormatType_422YpCbCr10BiPlanarVideoRange = 'x422',
  kCVPixelFormatType_444YpCbCr10BiPlanarVideoRange = 'x444',
  kCVPixelFormatType_420YpCbCr8VideoRange_8A_TriPlanar = 'v0a8',
};

#endif
EOF
cat > "$out/System/Library/Frameworks/CoreVideo.framework/Headers/CVDisplayLink.h" <<'EOF'
#ifndef _AOS_COREVIDEO_CVDISPLAYLINK_H_
#define _AOS_COREVIDEO_CVDISPLAYLINK_H_
#include <CoreGraphics/CoreGraphics.h>
#include <stdint.h>
typedef int32_t CVReturn;
typedef uint64_t CVOptionFlags;
typedef struct __CVDisplayLink *CVDisplayLinkRef;
typedef struct CVSMPTETime {
  SInt16 subframes;
  SInt16 subframeDivisor;
  UInt32 counter;
  UInt32 type;
  UInt32 flags;
  SInt16 hours;
  SInt16 minutes;
  SInt16 seconds;
  SInt16 frames;
} CVSMPTETime;
typedef struct CVTimeStamp {
  uint32_t version;
  int32_t videoTimeScale;
  int64_t videoTime;
  uint64_t hostTime;
  double rateScalar;
  int64_t videoRefreshPeriod;
  CVSMPTETime smpteTime;
  uint64_t flags;
  uint64_t reserved;
} CVTimeStamp;
typedef CVReturn (*CVDisplayLinkOutputCallback)(
  CVDisplayLinkRef,
  const CVTimeStamp *,
  const CVTimeStamp *,
  CVOptionFlags,
  CVOptionFlags *,
  void *
);
typedef struct {
  int64_t timeValue;
  int32_t timeScale;
  int32_t flags;
} CVTime;
enum { kCVTimeIsIndefinite = 1 << 0 };
enum { kCVReturnSuccess = 0 };
CVReturn CVDisplayLinkCreateWithCGDisplay(CGDirectDisplayID displayID, CVDisplayLinkRef *displayLinkOut);
CVReturn CVDisplayLinkCreateWithActiveCGDisplays(CVDisplayLinkRef *displayLinkOut);
CVTime CVDisplayLinkGetNominalOutputVideoRefreshPeriod(CVDisplayLinkRef displayLink);
Boolean CVDisplayLinkIsRunning(CVDisplayLinkRef displayLink);
CVReturn CVDisplayLinkSetOutputCallback(CVDisplayLinkRef displayLink, CVDisplayLinkOutputCallback callback, void *userInfo);
CVReturn CVDisplayLinkStart(CVDisplayLinkRef displayLink);
CVReturn CVDisplayLinkStop(CVDisplayLinkRef displayLink);
void CVDisplayLinkRelease(CVDisplayLinkRef displayLink);
#endif
EOF
cat > "$out/System/Library/Frameworks/CoreVideo.framework/Headers/CoreVideo.h" <<'EOF'
#ifndef _AOS_COREVIDEO_H_
#define _AOS_COREVIDEO_H_
#include <CoreVideo/CVPixelBuffer.h>
#include <CoreVideo/CVDisplayLink.h>
#endif
EOF
cat > "$out/System/Library/Frameworks/CoreVideo.framework/CoreVideo.tbd" <<'EOF'
--- !tapi-tbd
tbd-version: 4
targets: [ x86_64-macos, arm64-macos ]
install-name: '/System/Library/Frameworks/CoreVideo.framework/Versions/A/CoreVideo'
current-version: 1.5.0
compatibility-version: 1.2.0
reexported-libraries:
  - targets: [ x86_64-macos, arm64-macos ]
    libraries:
      - '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation'
      - '/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics'
exports:
  - targets: [ x86_64-macos, arm64-macos ]
    symbols:
      - _CVDisplayLinkCreateWithCGDisplay
      - _CVDisplayLinkCreateWithActiveCGDisplays
      - _CVDisplayLinkGetNominalOutputVideoRefreshPeriod
      - _CVDisplayLinkIsRunning
      - _CVDisplayLinkRelease
      - _CVDisplayLinkSetOutputCallback
      - _CVDisplayLinkStart
      - _CVDisplayLinkStop
...
EOF
ln -s ../../CoreVideo.tbd \
  "$out/System/Library/Frameworks/CoreVideo.framework/Versions/A/CoreVideo.tbd"
ln -s CoreVideo.tbd \
  "$out/System/Library/Frameworks/CoreVideo.framework/Versions/A/CoreVideo"
