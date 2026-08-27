# Build-only smoke coverage for the Linux-hosted Darwin C/C++ toolchains.
{pkgs}: let
  buildSystem = pkgs.stdenv.buildPlatform.system;

  mkTargetSmoke = targetSystem: expectedCpu: expectedDarwinArch: let
    cross = import ../.. {
      system = buildSystem;
      crossSystem = targetSystem;
    };
  in
    cross.stdenv.mkDerivation {
      pname = "darwin-cross-smoke-${targetSystem}";
      version = "0";
      src = null;
      outputs = ["c" "cxx"];
      buildDeps = [
        cross.buildPackages.cmake
        cross.buildPackages.ninja
      ];
      runtimeDeps = [cross.stdenv.darwinRuntimes];
      dontNukeRefs = true;

      phases = [
        {
          name = "build-and-verify";
          script = ''
            mkdir -p "$c/bin" "$c/lib" "$cxx/bin"

            printf '%s\n' \
              'extern int puts(const char *);' \
              'int main(void) { return puts("aos Darwin C smoke") < 0; }' \
              > smoke.c
            "$CC" smoke.c -o "$c/bin/aos-darwin-c-smoke"

            # Dependency-only preprocessing must not receive Darwin linker
            # flags; configure probes commonly combine this mode with -Werror.
            "$CC" -Werror -MM smoke.c > smoke.d
            grep -Fq 'smoke.o: smoke.c' smoke.d

            printf '%s\n' \
              '#include <ApplicationServices/ApplicationServices.h>' \
              '#include <CoreFoundation/CoreFoundation.h>' \
              '#include <CoreServices/CoreServices.h>' \
              '#include <sys/ioctl.h>' \
              '#include <net/bpf.h>' \
              '#include <net/ethernet.h>' \
              '#include <net/if_media.h>' \
              '#include <netinet/tcp_fsm.h>' \
              '#include <netinet/tcp_timer.h>' \
              '#include <rpc/pmap_prot.h>' \
              '#include <rpc/rpc.h>' \
              '#include <sys/syscall.h>' \
              '#include <sys/ttydev.h>' \
              '#include <sys/xattr.h>' \
              '#include <SystemConfiguration/SCNetworkConfiguration.h>' \
              '#include <SystemConfiguration/SystemConfiguration.h>' \
              '_Static_assert(kSCNetworkFlagsReachable == (1u << 1), "legacy reachability flag");' \
              '_Static_assert(kSCNetworkReachabilityFlagsConnectionOnTraffic == (1u << 3), "on-traffic reachability flag");' \
              '_Static_assert(BPF_MAJOR_VERSION == 1, "BPF ABI major version");' \
              '_Static_assert(BPF_MINOR_VERSION == 1, "BPF ABI minor version");' \
              'int main(void) {' \
              '  CFStringRef label = CFSTR("aos Darwin SDK");' \
              '  CFStringRef canonicalLanguage = CFLocaleCreateCanonicalLanguageIdentifierFromString(kCFAllocatorDefault, label);' \
              '  CFIndex maximum = CFStringGetMaximumSizeForEncoding(CFStringGetLength(label), kCFStringEncodingUTF8);' \
              '  UInt8 stringBuffer[32];' \
              '  CFIndex usedStringBytes = 0;' \
              '  CFIndex convertedCharacters = CFStringGetBytes(label, CFRangeMake(0, CFStringGetLength(label)), kCFStringEncodingUTF8, 0, false, stringBuffer, sizeof(stringBuffer), &usedStringBytes);' \
              '  CFTimeZoneRef zone = CFTimeZoneCopyDefault();' \
              '  CFTimeZoneRef systemZone = CFTimeZoneCopySystem();' \
              '  CFTimeZoneResetSystem();' \
              '  CFStringRef zoneName = zone == NULL ? NULL : CFTimeZoneGetName(zone);' \
              '  CFStringRef path = CFStringCreateWithCString(kCFAllocatorDefault, ".", kCFStringEncodingUTF8);' \
              '  CFStringRef pathCopy = path == NULL ? NULL : CFStringCreateCopy(kCFAllocatorDefault, path);' \
              '  CFComparisonResult pathComparison = pathCopy == NULL ? kCFCompareLessThan : CFStringCompare(pathCopy, path, 0);' \
              '  Boolean pathHasPrefix = pathCopy != NULL && CFStringHasPrefix(pathCopy, CFSTR("."));' \
              '  CFURLRef pathURL = path == NULL ? NULL : CFURLCreateWithFileSystemPath(kCFAllocatorDefault, path, kCFURLPOSIXPathStyle, true);' \
              '  UInt8 pathBuffer[32];' \
              '  Boolean represented = pathURL != NULL && CFURLGetFileSystemRepresentation(pathURL, true, pathBuffer, sizeof(pathBuffer));' \
              '  CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)".", 1, false);' \
              '  CFBundleRef bundle = url == NULL ? NULL : CFBundleCreate(kCFAllocatorDefault, url);' \
              '  CFURLRef executable = bundle == NULL ? NULL : CFBundleCopyExecutableURL(bundle);' \
              '  CFStringRef identifier = bundle == NULL ? NULL : CFBundleGetIdentifier(bundle);' \
              '  CFTypeRef value = bundle == NULL ? NULL : CFBundleGetValueForInfoDictionaryKey(bundle, CFSTR("CFBundleIdentifier"));' \
              '  CFUUIDRef uuid = CFUUIDCreate(kCFAllocatorDefault);' \
              '  CFStringRef uuidString = uuid == NULL ? NULL : CFUUIDCreateString(kCFAllocatorDefault, uuid);' \
              '  CFStringRef typeDescription = CFCopyTypeIDDescription(CFStringGetTypeID());' \
              '  CFDictionaryRef proxies = SCDynamicStoreCopyProxies(NULL);' \
              '  OSStatus launchStatus = LSOpenCFURLRef(url, NULL);' \
              '  char attributes[32];' \
              '  ssize_t attributeSize = getxattr(".", "com.andyl.aos.smoke", attributes, sizeof(attributes), 0, XATTR_NOFOLLOW);' \
              '  ssize_t attributeListSize = listxattr(".", attributes, sizeof(attributes), XATTR_NOFOLLOW);' \
              '  int attributeSetStatus = setxattr(".", "com.andyl.aos.smoke", "aos", 3, 0, XATTR_CREATE);' \
              '  int attributeRemoveStatus = removexattr(".", "com.andyl.aos.smoke", XATTR_NOFOLLOW);' \
              '  if (proxies != NULL) CFRelease(proxies);' \
              '  if (typeDescription != NULL) CFRelease(typeDescription);' \
              '  if (uuidString != NULL) CFRelease(uuidString);' \
              '  if (uuid != NULL) CFRelease(uuid);' \
              '  if (executable != NULL) CFRelease(executable);' \
              '  if (bundle != NULL) CFRelease(bundle);' \
              '  if (url != NULL) CFRelease(url);' \
              '  if (pathURL != NULL) CFRelease(pathURL);' \
              '  if (pathCopy != NULL) CFRelease(pathCopy);' \
              '  if (path != NULL) CFRelease(path);' \
              '  if (systemZone != NULL) CFRelease(systemZone);' \
              '  if (zone != NULL) CFRelease(zone);' \
              '  if (canonicalLanguage != NULL) CFRelease(canonicalLanguage);' \
              '  struct ether_addr address = { { 0 } };' \
              '  struct bpf_hdr bpfHeader = { 0 };' \
              '  return label == NULL || canonicalLanguage == NULL || maximum < 0 || convertedCharacters < 0 || usedStringBytes < 0 || zoneName == NULL || systemZone == NULL || pathComparison != kCFCompareEqualTo || !pathHasPrefix || identifier == value || !represented || launchStatus == -1 || attributeSize < -1 || attributeListSize < -1 || attributeSetStatus < -1 || attributeRemoveStatus < -1 || address.octet[0] != 0 || bpfHeader.bh_hdrlen != 0 || ETHER_ADDR_LEN != 6 || XATTR_CREATE != 0x0002 || XATTR_REPLACE != 0x0004;' \
              '}' \
              > framework-smoke.c
            "$CC" framework-smoke.c \
              -framework CoreFoundation \
              -framework CoreServices \
              -framework SystemConfiguration \
              -lobjc \
              -o "$c/bin/aos-darwin-framework-smoke"

            # LLVM's dsymutil reads property lists through CoreFoundation
            # streams. Exercise the exact public declarations and ABI exports
            # directly so every supported target proves that link surface.
            printf '%s\n' \
              '#include <CoreFoundation/CoreFoundation.h>' \
              'int main(void) {' \
              '  CFURLRef fileURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, CFSTR("aos.plist"), kCFURLPOSIXPathStyle, false);' \
              '  CFReadStreamRef stream = CFReadStreamCreateWithFile(kCFAllocatorDefault, fileURL);' \
              '  Boolean opened = CFReadStreamOpen(stream);' \
              '  CFPropertyListFormat format = kCFPropertyListXMLFormat_v1_0;' \
              '  CFErrorRef error = NULL;' \
              '  CFPropertyListRef propertyList = CFPropertyListCreateWithStream(kCFAllocatorDefault, stream, 0, kCFPropertyListImmutable, &format, &error);' \
              '  CFReadStreamClose(stream);' \
              '  if (propertyList != NULL) CFRelease(propertyList);' \
              '  if (error != NULL) CFRelease(error);' \
              '  if (stream != NULL) CFRelease(stream);' \
              '  if (fileURL != NULL) CFRelease(fileURL);' \
              '  return opened && propertyList == NULL;' \
              '}' \
              > corefoundation-stream-smoke.c
            "$CC" corefoundation-stream-smoke.c \
              -framework CoreFoundation \
              -o "$c/bin/aos-darwin-corefoundation-stream-smoke"

            printf '%s\n' \
              '#include <Hypervisor/Hypervisor.h>' \
              '#if defined(__aarch64__) || defined(__arm64__)' \
              'int main(void) {' \
              '  uint32_t ipaSize = 0;' \
              '  uint64_t feature = 0;' \
              '  hv_vm_config_t vmConfig = hv_vm_config_create();' \
              '  hv_vcpu_config_t vcpuConfig = hv_vcpu_config_create();' \
              '  hv_return_t result = hv_vm_config_get_default_ipa_size(&ipaSize);' \
              '  result |= hv_vm_config_get_max_ipa_size(&ipaSize);' \
              '  result |= hv_vm_config_set_ipa_size(vmConfig, ipaSize);' \
              '  result |= hv_vcpu_config_get_feature_reg(vcpuConfig, HV_FEATURE_REG_ID_AA64DFR0_EL1, &feature);' \
              '  result |= hv_vm_create(vmConfig);' \
              '  os_release(vcpuConfig);' \
              '  os_release(vmConfig);' \
              '  return result == HV_SUCCESS && feature == 0;' \
              '}' \
              '#else' \
              '#include <Hypervisor/hv_vmx.h>' \
              '_Static_assert(CPU_BASED_TSC_OFFSET == (1u << 3), "primary TSC-offset capability");' \
              '_Static_assert(CPU_BASED2_RDTSCP == (1u << 3), "secondary RDTSCP capability");' \
              '_Static_assert(CPU_BASED2_INVPCID == (1u << 12), "secondary INVPCID capability");' \
              '_Static_assert(CPU_BASED2_XSAVES_XRSTORS == (1u << 20), "secondary XSAVES capability");' \
              '_Static_assert(VMX_REASON_VMCALL == 18, "VMCALL exit reason");' \
              'int main(void) {' \
              '  uint64_t capability = 0;' \
              '  hv_vcpuid_t vcpu = 0;' \
              '  hv_return_t result = hv_vm_create(HV_VM_DEFAULT);' \
              '  result |= hv_vcpu_create(&vcpu, HV_VCPU_DEFAULT);' \
              '  result |= hv_vmx_read_capability(HV_VMX_CAP_PROCBASED, &capability);' \
              '  return result == HV_SUCCESS && capability == 0;' \
              '}' \
              '#endif' \
              > hypervisor-smoke.c
            "$CC" hypervisor-smoke.c -framework Hypervisor \
              -o "$c/bin/aos-darwin-hypervisor-smoke"

            printf '%s\n' \
              '#include <CoreFoundation/CoreFoundation.h>' \
              '#include <CoreServices/CoreServices.h>' \
              'static void aos_fsevent_callback(ConstFSEventStreamRef stream, void *info, size_t count, void *paths, const FSEventStreamEventFlags flags[], const FSEventStreamEventId ids[]) { (void)stream; (void)info; (void)count; (void)paths; (void)flags; (void)ids; }' \
              'int main(void) {' \
              '  const UInt8 textBytes[] = { 97, 111, 115 };' \
              '  CFStringRef text = CFStringCreateWithBytes(kCFAllocatorDefault, textBytes, 3, kCFStringEncodingUTF8, false);' \
              '  const UInt8 *dataBytes = CFDataGetBytePtr(NULL);' \
              '  const void *values[] = { text };' \
              '  CFArrayRef immutable = CFArrayCreate(kCFAllocatorDefault, values, 1, &kCFTypeArrayCallBacks);' \
              '  CFMutableArrayRef mutable = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);' \
              '  CFArrayAppendValue(mutable, values[0]);' \
              '  CFArrayInsertValueAtIndex(mutable, 0, values[0]);' \
              '  CFURLRef base = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, CFSTR("."), kCFURLPOSIXPathStyle, true);' \
              '  CFURLRef child = CFURLCreateCopyAppendingPathComponent(kCFAllocatorDefault, base, CFSTR("aos"), false);' \
              '  CFURLRef parent = CFURLCreateCopyDeletingLastPathComponent(kCFAllocatorDefault, child);' \
              '  CFURLRef absolute = CFURLCopyAbsoluteURL(parent);' \
              '  CFStringRef path = CFURLCopyFileSystemPath(absolute, kCFURLPOSIXPathStyle);' \
              '  CFStringRef last = CFURLCopyLastPathComponent(child);' \
              '  CFURLRef reference = CFURLCreateFileReferenceURL(kCFAllocatorDefault, child, NULL);' \
              '  CFURLRef filePath = CFURLCreateFilePathURL(kCFAllocatorDefault, reference, NULL);' \
              '  Boolean reachable = CFURLResourceIsReachable(filePath, NULL);' \
              '  Boolean propertySet = CFURLSetResourcePropertyForKey(filePath, CFSTR("aos"), kCFBooleanTrue, NULL);' \
              '  FSEventStreamContext context = { 0, NULL, NULL, NULL, NULL };' \
              '  FSEventStreamRef stream = FSEventStreamCreate(kCFAllocatorDefault, aos_fsevent_callback, &context, immutable, kFSEventStreamEventIdSinceNow, 0.1, kFSEventStreamCreateFlagFileEvents);' \
              '  CFRunLoopRef runLoop = CFRunLoopGetCurrent();' \
              '  Boolean waiting = CFRunLoopIsWaiting(runLoop);' \
              '  FSEventStreamScheduleWithRunLoop(stream, runLoop, kCFRunLoopDefaultMode);' \
              '  FSEventStreamSetDispatchQueue(stream, NULL);' \
              '  Boolean started = FSEventStreamStart(stream);' \
              '  dev_t device = FSEventStreamGetDeviceBeingWatched(stream);' \
              '  FSEventStreamEventId current = FSEventsGetCurrentEventId();' \
              '  Boolean purged = FSEventsPurgeEventsForDeviceUpToEventId(device, current);' \
              '  FSEventStreamStop(stream);' \
              '  FSEventStreamInvalidate(stream);' \
              '  FSEventStreamRelease(stream);' \
              '  if (filePath != NULL) CFRelease(filePath);' \
              '  if (reference != NULL) CFRelease(reference);' \
              '  if (last != NULL) CFRelease(last);' \
              '  if (path != NULL) CFRelease(path);' \
              '  if (absolute != NULL) CFRelease(absolute);' \
              '  if (parent != NULL) CFRelease(parent);' \
              '  if (child != NULL) CFRelease(child);' \
              '  if (base != NULL) CFRelease(base);' \
              '  if (mutable != NULL) CFRelease(mutable);' \
              '  if (immutable != NULL) CFRelease(immutable);' \
              '  if (text != NULL) CFRelease(text);' \
              '  return reachable && propertySet && started && purged && waiting && current == 0 && dataBytes == NULL;' \
              '}' \
              > coreservices-smoke.c
            # CoreServices is an umbrella and must carry its CoreFoundation
            # reexport without consumers repeating the underlying framework.
            "$CC" coreservices-smoke.c -framework CoreServices \
              -o "$c/bin/aos-darwin-coreservices-smoke"

            # Match Clang's plugin topology: a dylib records the versioned
            # CoreServices install name, then a flat-namespace bundle links
            # that dylib and makes ld64 follow the transitive framework edge.
            printf '%s\n' \
              '#include <CoreFoundation/CoreFoundation.h>' \
              '#include <CoreServices/CoreServices.h>' \
              'int aos_core_services_reexport(void) {' \
              '  const UInt8 textBytes[] = { 97, 111, 115 };' \
              '  CFStringRef text = CFStringCreateWithBytes(kCFAllocatorDefault, textBytes, 3, kCFStringEncodingUTF8, false);' \
              '  if (text != NULL) CFRelease(text);' \
              '  return text == NULL;' \
              '}' \
              > coreservices-reexport.c
            "$CC" -dynamiclib coreservices-reexport.c -framework CoreServices \
              -Wl,-install_name,"$c/lib/libaos-darwin-coreservices-reexport.dylib" \
              -o "$c/lib/libaos-darwin-coreservices-reexport.dylib"
            # The generic fixup phase uses the GNU --strip-unneeded spelling.
            # Darwin's wrapper must translate it to a supported Mach-O
            # operation and remove dead N_OSO/string-table build paths.
            "$STRIP" --strip-unneeded \
              "$c/lib/libaos-darwin-coreservices-reexport.dylib"
            printf '%s\n' \
              'extern int aos_core_services_reexport(void);' \
              'int aos_core_services_plugin(void) { return aos_core_services_reexport(); }' \
              > coreservices-plugin.c
            "$CC" -bundle coreservices-plugin.c \
              -Wl,-flat_namespace -Wl,-undefined -Wl,dynamic_lookup \
              "$c/lib/libaos-darwin-coreservices-reexport.dylib" \
              -o "$c/lib/aos-darwin-coreservices-plugin.bundle"

            printf '%s\n' \
              '#import <Cocoa/Cocoa.h>' \
              '@interface AosNotificationDelegate : NSObject<NSUserNotificationCenterDelegate> @end' \
              '@implementation AosNotificationDelegate @end' \
              'int main(void) {' \
              '  NSString *text = [[NSString alloc] initWithUTF8String:"aos"];' \
              '  NSMutableDictionary *info = [NSMutableDictionary new];' \
              '  info[@"aos"] = text;' \
              '  NSImage *image = [[NSImage alloc] initByReferencingFile:text];' \
              '  NSUserNotification *notification = [NSUserNotification new];' \
              '  notification.title = text;' \
              '  notification.informativeText = text;' \
              '  notification.identifier = text;' \
              '  notification.contentImage = image;' \
              '  notification.userInfo = info;' \
              '  AosNotificationDelegate *delegate = [AosNotificationDelegate new];' \
              '  NSUserNotificationCenter *center = [NSUserNotificationCenter defaultUserNotificationCenter];' \
              '  center.delegate = delegate;' \
              '  [center deliverNotification:notification];' \
              '  NSBundle *bundle = [NSBundle mainBundle];' \
              '  return bundle.bundleIdentifier == nil || notification.activationType < NSUserNotificationActivationTypeNone;' \
              '}' \
              > cocoa-smoke.m
            "$CC" cocoa-smoke.m \
              -framework Cocoa \
              -framework CoreFoundation \
              -lobjc \
              -o "$c/bin/aos-darwin-cocoa-smoke"

            printf '%s\n' \
              '#import <ApplicationServices/ApplicationServices.h>' \
              '#import <CoreServices/CoreServices.h>' \
              '#import <Foundation/Foundation.h>' \
              '#import <AppKit/AppKit.h>' \
              'int main(void) {' \
              '  NSSearchPathDirectory mediaDirectories[] = { NSMoviesDirectory, NSMusicDirectory, NSPicturesDirectory, NSSharedPublicDirectory };' \
              '  NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, true);' \
              '  NSString *path = paths.firstObject;' \
              '  NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];' \
              '  NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];' \
              '  [defaults setObject:path forKey:@"aos"];' \
              '  id defaultValue = [defaults objectForKey:@"aos"];' \
              '  [defaults removeObjectForKey:@"aos"];' \
              '  BOOL synchronized = [defaults synchronize];' \
              '  NSData *pathData = [path dataUsingEncoding:NSUTF8StringEncoding];' \
              '  NSString *decodedPath = [[NSString alloc] initWithData:pathData encoding:NSUTF8StringEncoding];' \
              '  NSNumber *number = [NSNumber numberWithUnsignedLongLong:42];' \
              '  NSMutableArray *values = [NSMutableArray arrayWithCapacity:2];' \
              '  [values addObject:number];' \
              '  NSMutableDictionary *dictionary = [NSMutableDictionary dictionaryWithCapacity:1];' \
              '  [dictionary setObject:number forKey:@"aos"];' \
              '  NSEnumerator *enumerator = [dictionary objectEnumerator];' \
              '  id enumeratedValue = [enumerator nextObject];' \
              '  NSImage *image = [[NSImage alloc] initByReferencingFile:path];' \
              '  NSURL *url = [NSURL fileURLWithPath:path];' \
              '  NSBundle *bundle = [NSBundle bundleWithURL:url];' \
              '  const char *bundlePath = [bundle.bundlePath cStringUsingEncoding:NSUTF8StringEncoding];' \
              '  CFArrayRef handlers = LSCopyAllHandlersForURLScheme(CFSTR("aos"));' \
              '  CFArrayRef roleHandlers = LSCopyAllRoleHandlersForContentType(CFSTR("public.data"), kLSRolesAll);' \
              '  CFURLRef application = LSCopyDefaultApplicationURLForContentType(CFSTR("public.data"), kLSRolesAll, NULL);' \
              '  CFStringRef roleHandler = LSCopyDefaultRoleHandlerForContentType(CFSTR("public.data"), kLSRolesAll);' \
              '  CFStringRef schemeHandler = LSCopyDefaultHandlerForURLScheme(CFSTR("aos"));' \
              '  CFStringRef uti = UTTypeCreatePreferredIdentifierForTag(kUTTagClassMIMEType, CFSTR("application/xml"), kUTTypeXML);' \
              '  CFStringRef tag = UTTypeCopyPreferredTagWithClass(uti, kUTTagClassFilenameExtension);' \
              '  CFStringRef utiDescription = UTTypeCopyDescription(kUTTypeApplication);' \
              '  Boolean utiMatches = UTTypeEqual(kUTTypeFolder, kUTTypeVolume);' \
              '  Boolean utiConforms = UTTypeConformsTo(uti, kUTTypeXML);' \
              '  CFArrayRef applications = LSCopyApplicationURLsForBundleIdentifier(CFSTR("com.andyl.aos"), NULL);' \
              '  LSLaunchURLSpec spec = { application, applications, NULL, kLSLaunchDefaults, NULL };' \
              '  OSStatus launchStatus = LSOpenFromURLSpec(&spec, NULL);' \
              '  FSRef legacyApplication;' \
              '  OSStatus findStatus = LSFindApplicationForInfo(kLSUnknownCreator, CFSTR("com.andyl.aos"), NULL, &legacyApplication, NULL);' \
              '  [pool drain];' \
              '  return image == nil || defaultValue == nil || !synchronized || decodedPath == nil || number.unsignedLongLongValue != 42 || enumeratedValue == nil || path.UTF8String == NULL || bundlePath == NULL || mediaDirectories[0] == 0 || handlers == NULL || roleHandlers == NULL || roleHandler == NULL || schemeHandler == NULL || uti == NULL || tag == NULL || utiDescription == NULL || utiMatches || !utiConforms || launchStatus == -1 || findStatus < kLSApplicationNotFoundErr;' \
              '}' \
              > foundation-appkit-smoke.m
            "$CC" foundation-appkit-smoke.m \
              -framework Foundation \
              -framework AppKit \
              -lobjc \
              -o "$c/bin/aos-darwin-foundation-appkit-smoke"

            printf '%s\n' \
              '#import <Foundation/NSObject.h>' \
              '#import <Foundation/NSProcessInfo.h>' \
              '#import <CoreVideo/CVPixelBuffer.h>' \
              '#import <IOSurface/IOSurfaceRef.h>' \
              '#import <Metal/Metal.h>' \
              '#import <QuartzCore/CAMetalLayer.h>' \
              'int main(void) {' \
              '  id<MTLDevice> device = MTLCreateSystemDefaultDevice();' \
              '  NSArray<id<MTLDevice>> *devices = MTLCopyAllDevices();' \
              '  MTLTextureDescriptor *descriptor = [MTLTextureDescriptor new];' \
              '  descriptor.textureType = MTLTextureType2D;' \
              '  descriptor.width = 1;' \
              '  descriptor.height = 1;' \
              '  descriptor.usage = MTLTextureUsageShaderRead;' \
              '  MTLSamplerDescriptor *sampler = [MTLSamplerDescriptor new];' \
              '  sampler.minFilter = MTLSamplerMinMagFilterLinear;' \
              '  sampler.compareFunction = MTLCompareFunctionAlways;' \
              '  MTLVertexDescriptor *vertex = [MTLVertexDescriptor vertexDescriptor];' \
              '  MTLVertexBufferLayoutDescriptor *vertexLayout = [MTLVertexBufferLayoutDescriptor new];' \
              '  MTLVertexAttributeDescriptor *vertexAttribute = [MTLVertexAttributeDescriptor new];' \
              '  vertex.attributes[0].format = MTLVertexFormatFloat4;' \
              '  vertex.layouts[0].stepFunction = MTLVertexStepFunctionPerVertex;' \
              '  MTLCounterSampleBufferDescriptor *counter = [MTLCounterSampleBufferDescriptor new];' \
              '  counter.storageMode = MTLStorageModeShared;' \
              '  MTLBlitPassDescriptor *blitDescriptor = [MTLBlitPassDescriptor new];' \
              '  id<MTLBlitCommandEncoder> blitEncoder = nil;' \
              '  id<MTLSharedEvent> sharedEvent = nil;' \
              '  NSProcessInfo *processInfo = [NSProcessInfo processInfo];' \
              '  NSOperatingSystemVersion version = processInfo.operatingSystemVersion;' \
              '  OSType pixelFormat = kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange;' \
              '  IOSurfaceRef surface = IOSurfaceCreate(NULL);' \
              '  size_t rowBytes = IOSurfaceAlignProperty(kIOSurfacePlaneBytesPerRow, 64);' \
              '  CAMetalLayer *layer = [CAMetalLayer layer];' \
              '  CGSize drawableSize = { 1.0, 1.0 };' \
              '  NSRange range = NSMakeRange(0, 1);' \
              '  layer.drawableSize = drawableSize;' \
              '  layer.device = device;' \
              '  MTLTimestamp timestamp = 0;' \
              '  MTLCommonCounterSet counterSet = MTLCommonCounterSetTimestamp;' \
              '  MTLCommonCounter counterName = MTLCommonCounterTimestamp;' \
              '  MTLColorWriteMask writeMask = MTLColorWriteMaskRed | MTLColorWriteMaskGreen;' \
              '  BOOL unified = device.hasUnifiedMemory;' \
              '  uint64_t workingSet = device.recommendedMaxWorkingSetSize;' \
              '  NSComparisonResult comparison = [counterName caseInsensitiveCompare:counterSet];' \
              '  return device == nil || devices == nil || descriptor == nil || sampler == nil || vertex == nil || vertexLayout == nil || vertexAttribute == nil || counter == nil || blitDescriptor == nil || blitEncoder != nil || sharedEvent != nil || processInfo == nil || version.majorVersion < 0 || pixelFormat == 0 || surface == NULL || rowBytes == 0 || layer == nil || range.length != 1 || timestamp != 0 || counterSet == nil || counterName == nil || writeMask == MTLColorWriteMaskNone || unified > 1 || workingSet == UINT64_MAX || comparison < NSOrderedAscending;' \
              '}' \
              > metal-smoke.m
            "$CC" metal-smoke.m \
              -framework Foundation \
              -framework CoreVideo \
              -framework IOSurface \
              -framework Metal \
              -framework QuartzCore \
              -lobjc \
              -o "$c/bin/aos-darwin-metal-smoke"

            printf '%s\n' \
              '#include <arpa/nameser.h>' \
              '#include <dns.h>' \
              '#include <resolv.h>' \
              '#include <tzfile.h>' \
              'int main(void) {' \
              '  unsigned char answer[NS_PACKETSZ];' \
              '  char expanded[NS_MAXDNAME];' \
              '  struct __res_state state = { 0 };' \
              '  union res_sockaddr_union servers[1];' \
              '  int initialized = res_ninit(&state);' \
              '  int serverCount = res_getservers(&state, servers, 1);' \
              '  res_ndestroy(&state);' \
              '  int query = res_query("localhost", ns_c_in, ns_t_a, answer, sizeof(answer));' \
              '  int expansion = dn_expand(answer, answer + sizeof(answer), answer, expanded, sizeof(expanded));' \
              '  return initialized < -1 || serverCount < 0 || query < -1 || expansion < -1 || sizeof(struct tzhead) != 44;' \
              '}' \
              > resolver-smoke.c
            "$CC" resolver-smoke.c -o "$c/bin/aos-darwin-resolver-smoke"

            printf '%s\n' \
              '#include <rpcsvc/yp_prot.h>' \
              '#include <rpcsvc/ypclnt.h>' \
              'int main(void) {' \
              '  char *domain = 0;' \
              '  char *value = 0;' \
              '  int valueLength = 0;' \
              '  int domainStatus = yp_get_default_domain(&domain);' \
              '  int matchStatus = yp_match("aos", "aos", "aos", 3, &value, &valueLength);' \
              '  return domainStatus < 0 || matchStatus < 0 || valueLength < 0;' \
              '}' \
              > nis-smoke.c
            "$CC" nis-smoke.c -o "$c/bin/aos-darwin-nis-smoke"

            printf '%s\n' \
              '#include <iconv.h>' \
              'int main(void) {' \
              '  iconv_t converter = iconv_open("UTF-8", "UTF-8");' \
              '  if (converter != (iconv_t)-1) iconv_close(converter);' \
              '  return converter == (iconv_t)0;' \
              '}' \
              > iconv-smoke.c
            "$CC" iconv-smoke.c -liconv \
              -o "$c/bin/aos-darwin-iconv-smoke"

            printf '%s\n' \
              '#include <mach/mach.h>' \
              '#include <mach/mach_vm.h>' \
              '#include <membership.h>' \
              '#include <notify.h>' \
              '#include <os/log.h>' \
              '#include <readpassphrase.h>' \
              '#include <fstab.h>' \
              '#include <hfs/hfs_mount.h>' \
              '#include <servers/bootstrap.h>' \
              '#include <sys/socket.h>' \
              '#include <utmp.h>' \
              '#include <util.h>' \
              'static const void *const aos_darwin_symbols[] = {' \
              '  (const void *)&mach_vm_read_overwrite,' \
              '  (const void *)&mach_vm_region,' \
              '  (const void *)&openpty,' \
              '  (const void *)&login_tty,' \
              '  (const void *)&login,' \
              '  (const void *)&logout,' \
              '  (const void *)&forkpty,' \
              '  (const void *)&sendfile,' \
              '  (const void *)&readpassphrase,' \
              '  (const void *)&getfsent,' \
              '  (const void *)&getfsspec,' \
              '  (const void *)&getfsfile,' \
              '  (const void *)&setfsent,' \
              '  (const void *)&endfsent,' \
              '  (const void *)&bootstrap_look_up,' \
              '  (const void *)&bootstrap_check_in,' \
              '  (const void *)&bootstrap_status,' \
              '  (const void *)&mbr_uuid_to_id,' \
              '  (const void *)&mbr_uid_to_uuid,' \
              '  (const void *)&mbr_gid_to_uuid,' \
              '};' \
              'int main(void) {' \
              '  int notify_fd = -1;' \
              '  int notify_token = NOTIFY_TOKEN_INVALID;' \
              '  uint32_t notify_status = notify_register_file_descriptor("aos.cares.config", &notify_fd, 0, &notify_token);' \
              '  if (notify_status == NOTIFY_STATUS_OK) notify_cancel(notify_token);' \
              '  os_log(OS_LOG_DEFAULT, "aos Darwin command-line SDK smoke");' \
              '  return sizeof(struct utmp) == 0 || UNKNOWNUID != 99 || NOTIFY_STATUS_OK != 0 || aos_darwin_symbols[0] == 0;' \
              '}' \
              > command-line-sdk-smoke.c
            "$CC" command-line-sdk-smoke.c \
              -o "$c/bin/aos-darwin-command-line-sdk-smoke"

            # Match V8's Darwin system-instrumentation surface exactly: the
            # public macro must preserve its formatted payload and link the
            # libSystem trace exports without a private framework dependency.
            printf '%s\n' \
              '#include <os/signpost.h>' \
              'int main(void) {' \
              '  os_log_t provider = os_log_create("v8", "");' \
              '  bool enabled = os_log_type_enabled(provider, OS_LOG_TYPE_DEFAULT);' \
              '  os_signpost_event_emit(provider, OS_SIGNPOST_ID_EXCLUSIVE, "", "%s, cpu_duration: %d", "aos", 1);' \
              '  os_release(provider);' \
              '  return enabled && OS_SIGNPOST_ID_EXCLUSIVE == OS_SIGNPOST_ID_INVALID;' \
              '}' \
              > signpost-smoke.cc
            "$CXX" signpost-smoke.cc \
              -o "$cxx/bin/aos-darwin-signpost-smoke"

            printf '%s\n' \
              '#include <objc/runtime.h>' \
              'extern void *objc_autoreleasePoolPush(void);' \
              'extern void objc_autoreleasePoolPop(void *context);' \
              'extern void objc_enumerationMutation(id object);' \
              'static const void *aos_objc_runtime_symbols[] = {' \
              '  (const void *)&protocol_copyProtocolList,' \
              '  (const void *)&objc_copyProtocolList,' \
              '  (const void *)&class_getInstanceVariable,' \
              '  (const void *)&method_copyReturnType,' \
              '  (const void *)&method_copyArgumentType,' \
              '  (const void *)&method_setImplementation,' \
              '  (const void *)&class_copyProtocolList,' \
              '  (const void *)&objc_copyClassList,' \
              '  (const void *)&protocol_getName,' \
              '  (const void *)&ivar_getTypeEncoding,' \
              '  (const void *)&ivar_getOffset,' \
              '  (const void *)&ivar_getName,' \
              '  (const void *)&method_getTypeEncoding,' \
              '  (const void *)&protocol_addProtocol,' \
              '  (const void *)&protocol_addMethodDescription,' \
              '  (const void *)&objc_registerProtocol,' \
              '  (const void *)&class_respondsToSelector,' \
              '};' \
              '__attribute__((objc_root_class)) @interface AosRoot @end' \
              '@implementation AosRoot @end' \
              'int main(void) {' \
              '  void *pool = objc_autoreleasePoolPush();' \
              '  Class root = objc_getClass("AosRoot");' \
              '  int isMeta = class_isMetaClass(objc_getMetaClass("AosRoot"));' \
              '  if (root == Nil) objc_enumerationMutation(nil);' \
              '  objc_autoreleasePoolPop(pool);' \
              '  return root == 0 || isMeta < 0 || aos_objc_runtime_symbols[0] == 0;' \
              '}' \
              > objective-c-smoke.m
            "$CC" objective-c-smoke.m -lobjc \
              -o "$c/bin/aos-darwin-objective-c-smoke"

            printf '%s\n' \
              '#include <sandbox.h>' \
              'extern int sandbox_init_with_parameters(const char *profile, uint64_t flags, const char *const parameters[], char **errorbuf);' \
              'int main(void) {' \
              '  char *error = 0;' \
              '  const char *const parameters[] = { 0 };' \
              '  int named = sandbox_init(kSBXProfilePureComputation, SANDBOX_NAMED, &error);' \
              '  int parameterized = sandbox_init_with_parameters("(version 1) (allow default)", 0, parameters, &error);' \
              '  sandbox_free_error(error);' \
              '  return named == parameterized && SANDBOX_NAMED_EXTERNAL == 0;' \
              '}' \
              > sandbox-smoke.c
            "$CC" sandbox-smoke.c -lsandbox \
              -o "$c/bin/aos-darwin-sandbox-smoke"

            printf '%s\n' \
              '#include <IOKit/IOKitLib.h>' \
              '#include <IOKit/storage/IOBlockStorageDevice.h>' \
              '#include <IOKit/storage/IOCDMedia.h>' \
              '#include <IOKit/storage/IODVDMedia.h>' \
              '#include <IOKit/storage/IOMediaBSDClient.h>' \
              '#include <IOKit/storage/ata/ATASMARTLib.h>' \
              '#include <IOKit/usb/IOUSBHostFamilyDefinitions.h>' \
              '#include <IOKit/usb/IOUSBLib.h>' \
              '#include <Security/Security.h>' \
              'int main(void) {' \
              '  SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);' \
              '  if (task != NULL) CFRelease(task);' \
              '  CFMutableDictionaryRef matching = IOServiceMatching(kIOUSBDeviceClassName);' \
              '  CFDictionaryAddValue(matching, CFSTR("AOSKey"), CFSTR("AOSValue"));' \
              '  io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, matching);' \
              '  CFTypeRef property = IORegistryEntrySearchCFProperty(service, kIOServicePlane, CFSTR("IOClass"), kCFAllocatorDefault, 0);' \
              '  if (property != NULL) CFRelease(property);' \
              '  if (service != IO_OBJECT_NULL) IOObjectRelease(service);' \
              '  CFMutableDictionaryRef idMatching = IORegistryEntryIDMatching(0);' \
              '  if (idMatching != NULL) CFRelease(idMatching);' \
              '  host_basic_info_data_t hostInfo = { 0 };' \
              '  mach_msg_type_number_t hostInfoCount = HOST_BASIC_INFO_COUNT;' \
              '  kern_return_t hostStatus = host_info(mach_host_self(), HOST_BASIC_INFO, (host_info_t)&hostInfo, &hostInfoCount);' \
              '  unsigned long mediaIoctls[] = { DKIOCGETBLOCKSIZE, DKIOCGETBLOCKCOUNT };' \
              '  return kIOCDMediaClass[0] != 73 || kIODVDMediaClass[0] != 73 || mediaIoctls[0] == mediaIoctls[1] || (hostStatus != KERN_SUCCESS && hostStatus != KERN_FAILURE);' \
              '}' \
              > iokit-smoke.c
            "$CC" iokit-smoke.c \
              -framework IOKit \
              -framework CoreFoundation \
              -framework Security \
              -o "$c/bin/aos-darwin-iokit-smoke"

            printf '%s\n' \
              '#include <Security/Security.h>' \
              'static OSStatus aos_ssl_read(SSLConnectionRef connection, void *data, size_t *length) { (void)connection; (void)data; (void)length; return errSSLClosedGraceful; }' \
              'static OSStatus aos_ssl_write(SSLConnectionRef connection, const void *data, size_t *length) { (void)connection; (void)data; (void)length; return errSSLClosedGraceful; }' \
              'int main(void) {' \
              '  SSLContextRef context = SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);' \
              '  SSLSetIOFuncs(context, aos_ssl_read, aos_ssl_write);' \
              '  SSLSetConnection(context, NULL);' \
              '  SSLSetSessionOption(context, kSSLSessionOptionBreakOnServerAuth, true);' \
              '  SSLSetProtocolVersionMin(context, kTLSProtocol1);' \
              '  SSLSetProtocolVersionMax(context, kTLSProtocol12);' \
              '  SSLSetPeerDomainName(context, "localhost", 9);' \
              '  OSStatus handshake = SSLHandshake(context);' \
              '  SecTrustRef trust = NULL;' \
              '  SSLCopyPeerTrust(context, &trust);' \
              '  SecTrustResultType trustResult = kSecTrustResultInvalid;' \
              '  if (trust != NULL) SecTrustEvaluate(trust, &trustResult);' \
              '  SecCertificateRef certificate = trust == NULL ? NULL : SecTrustGetCertificateAtIndex(trust, 0);' \
              '  CFDataRef certificateData = certificate == NULL ? NULL : SecCertificateCopyData(certificate);' \
              '  SecPolicyRef policy = SecPolicyCreateSSL(false, NULL);' \
              '  CFDictionaryRef policyProperties = policy == NULL ? NULL : SecPolicyCopyProperties(policy);' \
              '  bool policyScoped = policyProperties != NULL && CFDictionaryContainsKey(policyProperties, kSecPolicyOid);' \
              '  bool sslPolicy = CFEqual(kSecPolicyAppleSSL, kSecPolicyAppleSSL);' \
              '  CFMutableArrayRef subjectCertificates = CFArrayCreateMutable(NULL, 1, &kCFTypeArrayCallBacks);' \
              '  CFArraySetValueAtIndex(subjectCertificates, 0, certificate);' \
              '  SecTrustRef certificateTrust = NULL;' \
              '  OSStatus createdTrust = SecTrustCreateWithCertificates(subjectCertificates, policy, &certificateTrust);' \
              '  bool trusted = certificateTrust != NULL && SecTrustEvaluateWithError(certificateTrust, NULL);' \
              '  CFArrayRef trustSettings = NULL;' \
              '  OSStatus copiedTrustSettings = SecTrustSettingsCopyTrustSettings(certificate, kSecTrustSettingsDomainUser, &trustSettings);' \
              '  const void *policyConstants[] = { kSecPolicyAppleSSL, kSecPolicyOid };' \
              '  const void *trustSettingKeys[] = { kSecTrustSettingsApplication, kSecTrustSettingsPolicy, kSecTrustSettingsPolicyString, kSecTrustSettingsResult };' \
              '  const void *queryKeys[] = { kSecClass, kSecMatchLimit, kSecReturnRef };' \
              '  const void *queryValues[] = { kSecClassCertificate, kSecMatchLimitAll, kCFBooleanTrue };' \
              '  CFDictionaryRef query = CFDictionaryCreate(kCFAllocatorDefault, queryKeys, queryValues, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);' \
              '  CFTypeRef queryResult = NULL;' \
              '  OSStatus copiedItems = SecItemCopyMatching(query, &queryResult);' \
              '  SecKeychainRef keychain = NULL;' \
              '  SecKeychainItemRef item = NULL;' \
              '  UInt32 passwordLength = 0;' \
              '  void *passwordData = NULL;' \
              '  OSStatus copiedKeychain = SecKeychainCopyDefault(&keychain);' \
              '  OSStatus addedPassword = SecKeychainAddGenericPassword(keychain, 3, "aos", 4, "user", 4, "pass", &item);' \
              '  OSStatus foundPassword = SecKeychainFindGenericPassword(keychain, 3, "aos", 4, "user", &passwordLength, &passwordData, &item);' \
              '  OSStatus modifiedPassword = SecKeychainItemModifyAttributesAndData(item, NULL, 4, "next");' \
              '  OSStatus freedPassword = SecKeychainItemFreeContent(NULL, passwordData);' \
              '  OSStatus deletedPassword = SecKeychainItemDelete(item);' \
              '  CFStringRef error = SecCopyErrorMessageString(handshake, NULL);' \
              '  size_t processed = 0;' \
              '  SSLWrite(context, "aos", 3, &processed);' \
              '  SSLRead(context, NULL, 0, &processed);' \
              '  SSLClose(context);' \
              '  if (queryResult != NULL) CFRelease(queryResult);' \
              '  if (query != NULL) CFRelease(query);' \
              '  if (trustSettings != NULL) CFRelease(trustSettings);' \
              '  if (certificateTrust != NULL) CFRelease(certificateTrust);' \
              '  if (subjectCertificates != NULL) CFRelease(subjectCertificates);' \
              '  if (policyProperties != NULL) CFRelease(policyProperties);' \
              '  if (policy != NULL) CFRelease(policy);' \
              '  if (error != NULL) CFRelease(error);' \
              '  if (certificateData != NULL) CFRelease(certificateData);' \
              '  if (trust != NULL) CFRelease(trust);' \
              '  if (context != NULL) CFRelease(context);' \
              '  return trustResult == kSecTrustResultOtherError && processed == (size_t)-1 && createdTrust == copiedTrustSettings && copiedItems == errSecItemNotFound && policyConstants[0] == NULL && trustSettingKeys[0] == NULL && policyScoped && sslPolicy && trusted && kSecTrustSettingsResultTrustRoot != 1 && kSecTrustSettingsResultTrustAsRoot != 2 && kSecTrustSettingsResultDeny != 3 && kSecTrustSettingsDomainAdmin != 1 && copiedKeychain == addedPassword && foundPassword == modifiedPassword && freedPassword == deletedPassword;' \
              '}' \
              > security-smoke.c
            "$CC" security-smoke.c \
              -framework CoreFoundation \
              -framework Security \
              -o "$c/bin/aos-darwin-security-smoke"

            printf '%s\n' \
              'extern "C" int puts(const char *);' \
              '#include <string>' \
              'constexpr int answer = 42;' \
              'int main() {' \
              '  std::string message = "aos Darwin C++ smoke";' \
              '  return answer == 42 && puts(message.c_str()) >= 0 ? 0 : 1;' \
              '}' \
              > smoke.cc
            "$CXX" -c smoke.cc -o smoke.o
            "$CXX" smoke.o -o "$cxx/bin/aos-darwin-cxx-smoke"

            test "$(sw_vers -productVersion)" = "11.0"
            mkdir cmake-smoke
            printf '%s\n' \
              'cmake_minimum_required(VERSION 3.20)' \
              'project(aos_darwin_cmake_smoke LANGUAGES C CXX)' \
              'add_library(aos-darwin-cmake-smoke SHARED ../smoke.c)' \
              'set_target_properties(aos-darwin-cmake-smoke PROPERTIES INSTALL_NAME_DIR "@rpath")' \
              'add_library(aos-darwin-cmake-cxx-smoke SHARED ../smoke.cc)' \
              'set_target_properties(aos-darwin-cmake-cxx-smoke PROPERTIES INSTALL_NAME_DIR "@rpath")' \
              'target_link_libraries(aos-darwin-cmake-cxx-smoke PRIVATE aos-darwin-cmake-smoke)' \
              'install(TARGETS aos-darwin-cmake-smoke aos-darwin-cmake-cxx-smoke LIBRARY DESTINATION lib)' \
              > cmake-smoke/CMakeLists.txt
            cmake -S cmake-smoke -B cmake-build -G Ninja \
              -DCMAKE_INSTALL_PREFIX="$PWD/cmake-installed" $cmakeFlags
            ninja -C cmake-build install
            cp cmake-installed/lib/libaos-darwin-cmake-smoke.dylib \
              "$c/lib/libaos-darwin-cmake-smoke.dylib"
            cp cmake-installed/lib/libaos-darwin-cmake-cxx-smoke.dylib \
              "$cxx/libaos-darwin-cmake-cxx-smoke.dylib"

            printf '%s\n' \
              'extern "C" int aos_darwin_plugin(void) { return 0; }' \
              > plugin.cc
            "$CXX" -c plugin.cc -o plugin.o
            "$CXX" -bundle \
              -Wl,-flat_namespace \
              -Wl,-undefined,dynamic_lookup \
              -Wl,-rpath,"$c/lib" \
              plugin.o "$cxx/libaos-darwin-cmake-cxx-smoke.dylib" \
              -o "$cxx/aos-darwin-flat-namespace.bundle"

            for executable in \
              "$c/bin/aos-darwin-c-smoke" \
              "$c/bin/aos-darwin-command-line-sdk-smoke" \
              "$c/bin/aos-darwin-corefoundation-stream-smoke" \
              "$c/bin/aos-darwin-coreservices-smoke" \
              "$c/bin/aos-darwin-cocoa-smoke" \
              "$c/bin/aos-darwin-framework-smoke" \
              "$c/bin/aos-darwin-foundation-appkit-smoke" \
              "$c/bin/aos-darwin-hypervisor-smoke" \
              "$c/bin/aos-darwin-iconv-smoke" \
              "$c/bin/aos-darwin-iokit-smoke" \
              "$c/bin/aos-darwin-metal-smoke" \
              "$c/bin/aos-darwin-nis-smoke" \
              "$c/bin/aos-darwin-objective-c-smoke" \
              "$c/bin/aos-darwin-resolver-smoke" \
              "$c/bin/aos-darwin-security-smoke" \
              "$c/lib/libaos-darwin-cmake-smoke.dylib" \
              "$cxx/libaos-darwin-cmake-cxx-smoke.dylib" \
              "$cxx/aos-darwin-flat-namespace.bundle" \
              "$cxx/bin/aos-darwin-cxx-smoke" \
              "$cxx/bin/aos-darwin-signpost-smoke"; do
              header=$("$OBJDUMP" --macho --private-header "$executable")
              if ! printf '%s\n' "$header" | grep -q '${expectedCpu}'; then
                echo "unexpected Mach-O architecture in $executable: expected ${expectedCpu}" >&2
                printf '%s\n' "$header" >&2
                exit 1
              fi
              strings_output=$("$STRINGS" "$executable")
              case "$strings_output" in
                *'/build/'*)
                  echo "build-directory debug path in $executable" >&2
                  exit 1
                  ;;
              esac
            done

            for library in ${cross.stdenv.darwinRuntimes}/lib/*.dylib; do
              headers=$("$OBJDUMP" --macho --all-headers "$library")
              case "$headers" in
                *'${expectedCpu}'*) ;;
                *)
                  echo "unexpected Mach-O architecture in $library: expected ${expectedCpu}" >&2
                  exit 1
                  ;;
              esac
              case "$headers" in
                *'name ${cross.stdenv.darwinRuntimes}/lib/'*) ;;
                *)
                  echo "unstable install name in $library" >&2
                  exit 1
                  ;;
              esac
              case "$headers" in
                *'/build'*)
                  echo "build-directory load command in $library" >&2
                  exit 1
                  ;;
              esac
              strings_output=$("$STRINGS" "$library")
              case "$strings_output" in
                *'/build/'*)
                  echo "build-directory debug path in $library" >&2
                  exit 1
                  ;;
              esac
            done

            for archive in ${cross.stdenv.darwinRuntimes}/lib/darwin/*.a; do
              headers=$("$OBJDUMP" --macho --universal-headers "$archive")
              case "$headers" in
                *'nfat_arch 1'*) ;;
                *)
                  echo "compiler runtime archive is not single-architecture: $archive" >&2
                  exit 1
                  ;;
              esac
              case "$headers" in
                *'architecture ${expectedDarwinArch}'*) ;;
                *)
                  echo "unexpected compiler runtime architecture in $archive" >&2
                  exit 1
                  ;;
              esac
            done
          '';
        }
      ];
    };

  x86 = mkTargetSmoke "x86_64-darwin" "X86_64" "x86_64";
  arm = mkTargetSmoke "aarch64-darwin" "ARM64" "arm64";
in
  pkgs.mkDerivation {
    pname = "darwin-cross-smoke";
    version = "0";
    src = null;
    phases = [
      {
        name = "verify-target-metadata";
        script = ''
          test "$(cat ${x86.c}/nix-support/aos-target-platform)" = "x86_64-darwin"
          test "$(cat ${x86.cxx}/nix-support/aos-target-platform)" = "x86_64-darwin"
          test "$(cat ${arm.c}/nix-support/aos-target-platform)" = "aarch64-darwin"
          test "$(cat ${arm.cxx}/nix-support/aos-target-platform)" = "aarch64-darwin"

          mkdir -p "$out"
          printf 'PASS\n' > "$out/result"
        '';
      }
    ];
    passthru = {
      inherit x86 arm;
    };
  }
