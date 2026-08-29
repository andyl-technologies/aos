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
              '#include <sys/ptrace.h>' \
              '#include <sys/syscall.h>' \
              '#include <sys/ttydev.h>' \
              '#include <sys/xattr.h>' \
              '#include <SystemConfiguration/SCNetworkConfiguration.h>' \
              '#include <SystemConfiguration/SystemConfiguration.h>' \
              '_Static_assert(kSCNetworkFlagsReachable == (1u << 1), "legacy reachability flag");' \
              '_Static_assert(kSCNetworkReachabilityFlagsConnectionOnTraffic == (1u << 3), "on-traffic reachability flag");' \
              '_Static_assert(BPF_MAJOR_VERSION == 1, "BPF ABI major version");' \
              '_Static_assert(BPF_MINOR_VERSION == 1, "BPF ABI minor version");' \
              '_Static_assert(PT_CONTINUE == 7, "ptrace continue request");' \
              '_Static_assert(PT_ATTACH == 10, "ptrace attach request");' \
              '_Static_assert(PT_DETACH == 11, "ptrace detach request");' \
              'int main(void) {' \
              '  int (*ptraceFunction)(int, pid_t, caddr_t, int) = ptrace;' \
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
              '  CFMutableStringRef mutablePath = path == NULL ? NULL : CFStringCreateMutableCopy(kCFAllocatorDefault, 0, path);' \
              '  if (mutablePath != NULL) CFStringNormalize(mutablePath, kCFStringNormalizationFormC);' \
              '  const UniChar noCopyCharacters[] = { 65, 79, 83 };' \
              '  CFStringRef noCopyString = CFStringCreateWithCharactersNoCopy(kCFAllocatorMalloc, noCopyCharacters, 3, kCFAllocatorMalloc);' \
              '  int numberValue = 1;' \
              '  CFNumberRef number = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &numberValue);' \
              '  Boolean numberIsFloat = CFNumberIsFloatType(number);' \
              '  CFTypeRef collectable = CFMakeCollectable(noCopyString);' \
              '  CFComparisonResult pathComparison = pathCopy == NULL ? kCFCompareLessThan : CFStringCompare(pathCopy, path, 0);' \
              '  Boolean pathHasPrefix = pathCopy != NULL && CFStringHasPrefix(pathCopy, CFSTR("."));' \
              '  CFURLRef pathURL = path == NULL ? NULL : CFURLCreateWithFileSystemPath(kCFAllocatorDefault, path, kCFURLPOSIXPathStyle, true);' \
              '  UInt8 pathBuffer[32];' \
              '  Boolean represented = pathURL != NULL && CFURLGetFileSystemRepresentation(pathURL, true, pathBuffer, sizeof(pathBuffer));' \
              '  CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)".", 1, false);' \
              '  Boolean (*copyResource)(CFAllocatorRef, CFURLRef, CFDataRef *, CFDictionaryRef *, CFArrayRef, SInt32 *) = CFURLCreateDataAndPropertiesFromResource;' \
              '  const CFDictionaryKeyCallBacks *copyStringCallbacks = &kCFCopyStringDictionaryKeyCallBacks;' \
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
              '  if (mutablePath != NULL) CFRelease(mutablePath);' \
              '  if (number != NULL) CFRelease(number);' \
              '  if (path != NULL) CFRelease(path);' \
              '  if (systemZone != NULL) CFRelease(systemZone);' \
              '  if (zone != NULL) CFRelease(zone);' \
              '  if (canonicalLanguage != NULL) CFRelease(canonicalLanguage);' \
              '  struct ether_addr address = { { 0 } };' \
              '  struct bpf_hdr bpfHeader = { 0 };' \
              '  return ptraceFunction == NULL || label == NULL || canonicalLanguage == NULL || maximum < 0 || convertedCharacters < 0 || usedStringBytes < 0 || zoneName == NULL || systemZone == NULL || pathComparison != kCFCompareEqualTo || !pathHasPrefix || mutablePath == NULL || noCopyString == NULL || collectable == NULL || numberIsFloat || copyResource == NULL || copyStringCallbacks == NULL || identifier == value || !represented || launchStatus == -1 || attributeSize < -1 || attributeListSize < -1 || attributeSetStatus < -1 || attributeRemoveStatus < -1 || address.octet[0] != 0 || bpfHeader.bh_hdrlen != 0 || ETHER_ADDR_LEN != 6 || XATTR_CREATE != 0x0002 || XATTR_REPLACE != 0x0004;' \
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
              '#include <netinet/ip_icmp.h>' \
              '#include <netinet/icmp6.h>' \
              '#include <net/if_arp.h>' \
              'int main(void) {' \
              '  struct icmp echo4 = { 0 };' \
              '  echo4.icmp_type = ICMP_ECHO;' \
              '  echo4.icmp_code = 0;' \
              '  echo4.icmp_id = 1;' \
              '  echo4.icmp_seq = 2;' \
              '  echo4.icmp_data[0] = 3;' \
              '  struct icmp6_hdr echo6 = { 0 };' \
              '  echo6.icmp6_type = ICMP6_ECHO_REQUEST;' \
              '  echo6.icmp6_code = 0;' \
              '  echo6.icmp6_id = 4;' \
              '  echo6.icmp6_seq = 5;' \
              '  struct arphdr arp = { 0 };' \
              '  return sizeof(echo4) < ICMP_ADVLENMIN || sizeof(echo6) != 8 || echo4.icmp_type == ICMP_ECHOREPLY || echo6.icmp6_type == ICMP6_ECHO_REPLY || arp.ar_hrd != 0;' \
              '}' \
              > icmp-smoke.c
            "$CC" icmp-smoke.c -o "$c/bin/aos-darwin-icmp-smoke"

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
              '  LangCode language = 0;' \
              '  RegionCode region = 0;' \
              '  OSStatus localeStatus = LocaleStringToLangAndRegionCodes("en_US", &language, &region);' \
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
              '  return reachable && propertySet && started && purged && waiting && localeStatus == kLocalesTableFormatErr && language == 0 && region == 0 && current == 0 && dataBytes == NULL;' \
              '}' \
              > coreservices-smoke.c
            # CoreServices is an umbrella and must carry its CoreFoundation
            # reexport without consumers repeating the underlying framework.
            "$CC" coreservices-smoke.c -framework CoreServices \
              -o "$c/bin/aos-darwin-coreservices-smoke"

            # OpenJDK's libnet links the documented CoreServices umbrella,
            # whose CFNetwork import must also carry the framework reexport.
            "$CC" ${./darwin-coreservices-cfnetwork-smoke.c} \
              -framework CoreFoundation \
              -framework CoreServices \
              -o "$c/bin/aos-darwin-coreservices-cfnetwork-smoke"

            # OpenJDK's libnio likewise relies on CoreServices to carry the
            # canonical nested LaunchServices framework for legacy UTI APIs.
            "$CC" ${./darwin-coreservices-launchservices-smoke.c} \
              -framework CoreFoundation \
              -framework CoreServices \
              -o "$c/bin/aos-darwin-coreservices-launchservices-smoke"

            # OpenJDK links this public umbrella without repeating its
            # documented CoreText and CoreServices/CarbonCore dependencies.
            "$CC" ${./darwin-applicationservices-reexports-smoke.c} \
              -framework ApplicationServices \
              -o "$c/bin/aos-darwin-applicationservices-reexports-smoke"

            # The Java sound implementation is C++ but consumes these APIs
            # through their canonical C linkage.
            "$CXX" ${./darwin-audio-cxx-smoke.cc} \
              -framework AudioToolbox \
              -framework AudioUnit \
              -framework CoreAudio \
              -o "$cxx/bin/aos-darwin-audio-cxx-smoke"

            "$CC" ${./darwin-quartzcore-corevideo-smoke.c} \
              -framework QuartzCore \
              -o "$c/bin/aos-darwin-quartzcore-corevideo-smoke"

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

            # QEMU's Cocoa frontend includes Carbon only for HIToolbox's
            # stable virtual-key constants. Compile representatives from each
            # key family it consumes so a missing umbrella cannot pass SDK
            # validation; QEMU itself compiles the complete table.
            printf '%s\n' \
              '#include <Carbon/Carbon.h>' \
              '_Static_assert(kVK_ANSI_A == 0x00, "ANSI key ABI");' \
              '_Static_assert(kVK_ANSI_Keypad9 == 0x5c, "keypad ABI");' \
              '_Static_assert(kVK_RightCommand == 0x36, "modifier ABI");' \
              '_Static_assert(kVK_UpArrow == 0x7e, "navigation ABI");' \
              '_Static_assert(kVK_JIS_Kana == 0x68, "JIS key ABI");' \
              'int main(void) {' \
              '  int ansi = kVK_ANSI_A + kVK_ANSI_0 + kVK_ANSI_Grave + kVK_ANSI_Keypad9;' \
              '  int controls = kVK_Return + kVK_RightCommand + kVK_F1 + kVK_F15 + kVK_UpArrow;' \
              '  int jis = kVK_JIS_Yen + kVK_JIS_Underscore + kVK_JIS_KeypadComma + kVK_JIS_Eisu + kVK_JIS_Kana;' \
              '  AEDesc desc = { typeNull, NULL };' \
              '  char bytes[8] = { 0 };' \
              '  Size descSize = AEGetDescDataSize(&desc);' \
              '  OSErr descStatus = AEGetDescData(&desc, bytes, sizeof(bytes));' \
              '  FSRef ref = { { 0 } };' \
              '  LongDateTime longTime = 0;' \
              '  CFAbsoluteTime absoluteTime = 0;' \
              '  OSStatus folderStatus = FSFindFolder(0, kTemporaryFolderType, false, &ref);' \
              '  OSStatus pathStatus = FSRefMakePath(&ref, (UInt8 *)bytes, sizeof(bytes));' \
              '  OSStatus toLong = UCConvertCFAbsoluteTimeToLongDateTime(absoluteTime, &longTime);' \
              '  OSStatus toAbsolute = UCConvertLongDateTimeToCFAbsoluteTime(longTime, &absoluteTime);' \
              '  OSType constants = typeAEList + typeAERecord + typeBoolean + typeSInt64 + typeUnicodeText + typeUTF8Text + typeTIFF + typeJPEG + typeGIF + typePict + typeIconFamily + typeLongDateTime + typeKernelProcessID + keyASUserRecordFields + keyASSubroutineName + keyDirectObject + kASAppleScriptSuite + kASSubroutineEvent + kChewableItemsFolderType;' \
              '  return ansi + controls + jis == 0 || descSize < 0 || descStatus == -1 || folderStatus == pathStatus || toLong == toAbsolute || constants == 0 || kAutoGenerateReturnID != -1 || kAnyTransactionID != 0;' \
              '}' \
              > carbon-smoke.c
            "$CC" carbon-smoke.c -framework Carbon -o "$c/bin/aos-darwin-carbon-smoke"

            # QEMU's Cocoa UI combines AppKit objects with CoreGraphics
            # scanout/event APIs, CoreVideo display timing, QuartzCore layers,
            # and the surviving Carbon process transform. Compile and link
            # those framework boundaries directly so an umbrella-only header
            # stub or an incomplete TAPI export cannot pass this smoke.
            printf '%s\n' \
              '#import <Cocoa/Cocoa.h>' \
              '#import <Carbon/Carbon.h>' \
              '#import <CoreVideo/CoreVideo.h>' \
              '#import <QuartzCore/QuartzCore.h>' \
              'static CGEventRef aos_event_tap(CGEventTapProxy proxy, CGEventType type, CGEventRef event, void *info) {' \
              '  return proxy == NULL || info == NULL || type == kCGEventKeyDown ? event : event;' \
              '}' \
              '@interface AosCocoaView : NSView @end' \
              '@implementation AosCocoaView @end' \
              '@interface AosCocoaApplication : NSApplication<NSApplicationDelegate, NSWindowDelegate, NSPasteboardTypeOwner> @end' \
              '@implementation AosCocoaApplication @end' \
              'int main(void) {' \
              '  NSRect frame = NSMakeRect(0, 0, 64, 64);' \
              '  CGRect scanout = NSRectToCGRect(frame);' \
              '  AosCocoaView *view = [[AosCocoaView alloc] initWithFrame:frame];' \
              '  [view setWantsLayer:YES];' \
              '  [view addTrackingArea:[[NSTrackingArea alloc] initWithRect:frame options:NSTrackingMouseEnteredAndExited | NSTrackingMouseMoved | NSTrackingActiveInKeyWindow | NSTrackingInVisibleRect owner:view userInfo:nil]];' \
              '  CALayer *layer = [CALayer layer];' \
              '  layer.anchorPoint = CGPointMake(0, 0);' \
              '  layer.autoresizingMask = kCALayerMaxXMargin | kCALayerMinYMargin;' \
              '  layer.bounds = scanout;' \
              '  [CATransaction begin];' \
              '  [CATransaction setDisableActions:YES];' \
              '  [CATransaction commit];' \
              '  NSWindow *window = [[NSWindow alloc] initWithContentRect:frame styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable backing:NSBackingStoreBuffered defer:NO];' \
              '  window.collectionBehavior = NSWindowCollectionBehaviorFullScreenPrimary;' \
              '  window.contentView = view;' \
              '  [window makeKeyAndOrderFront:nil];' \
              '  NSTextField *field = [[NSTextField alloc] initWithFrame:frame];' \
              '  field.stringValue = [NSString stringWithCString:"aos" encoding:NSASCIIStringEncoding];' \
              '  [field sizeToFit];' \
              '  NSMutableAttributedString *title = [[NSMutableAttributedString alloc] initWithString:field.stringValue];' \
              '  [title addAttribute:NSFontAttributeName value:[NSFont fontWithName:@"Menlo" size:12] range:NSMakeRange(0, title.description.length)];' \
              '  [title addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:NSMakeRange(0, 0)];' \
              '  [title addAttribute:NSUnderlineStyleAttributeName value:[NSNumber numberWithInt:1] range:NSMakeRange(0, 0)];' \
              '  NSMenu *menu = [[NSMenu alloc] initWithTitle:@"AOS"];' \
              '  NSMenuItem *item = [menu addItemWithTitle:@"Open" action:NULL keyEquivalent:@"o"];' \
              '  item.keyEquivalentModifierMask = NSEventModifierFlagCommand | NSEventModifierFlagShift;' \
              '  item.attributedTitle = title;' \
              '  NSFont *panelFont = [[NSFontManager sharedFontManager] fontWithFamily:@"Helvetica" traits:NSBoldFontMask | NSItalicFontMask weight:0 size:14];' \
              '  NSAlert *alert = [NSAlert new];' \
              '  alert.messageText = @"AOS";' \
              '  [alert addButtonWithTitle:@"OK"];' \
              '  NSOpenPanel *panel = [NSOpenPanel openPanel];' \
              '  panel.canChooseFiles = YES;' \
              '  NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];' \
              '  [pasteboard declareTypes:@[ NSPasteboardTypeString ] owner:nil];' \
              '  [pasteboard setData:[[NSData alloc] initWithBytes:"aos" length:3] forType:NSPasteboardTypeString];' \
              '  [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:@"/" isDirectory:YES]];' \
              '  NSEvent *event = [NSEvent eventWithCGEvent:NULL];' \
              '  NSEventModifierFlags modifiers = event.modifierFlags | NSEventModifierFlagCapsLock | NSEventModifierFlagControl | NSEventModifierFlagOption;' \
              '  CGColorSpaceRef colorSpace = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);' \
              '  CGDataProviderRef provider = CGDataProviderCreateWithData(NULL, "aos", 3, NULL);' \
              '  CGImageRef image = CGImageCreate(1, 1, 8, 32, 4, colorSpace, kCGImageAlphaFirst | kCGBitmapByteOrder32Little, provider, NULL, false, kCGRenderingIntentDefault);' \
              '  CGImageRef cropped = CGImageCreateWithImageInRect(image, scanout);' \
              '  CGContextRef context = [NSGraphicsContext currentContext].CGContext;' \
              '  CGContextSetInterpolationQuality(context, kCGInterpolationNone);' \
              '  CGContextSetShouldAntialias(context, false);' \
              '  CGContextSetRGBFillColor(context, 0, 0, 0, 1);' \
              '  CGContextFillRect(context, scanout);' \
              '  CGContextDrawImage(context, scanout, image);' \
              '  CFMachPortRef tap = CGEventTapCreate(kCGHIDEventTap, kCGHeadInsertEventTap, kCGEventTapOptionDefault, CGEventMaskBit(kCGEventKeyDown) | CGEventMaskBit(kCGEventKeyUp) | CGEventMaskBit(kCGEventFlagsChanged), aos_event_tap, view);' \
              '  CFRunLoopSourceRef tapSource = CFMachPortCreateRunLoopSource(kCFAllocatorDefault, tap, 0);' \
              '  CGAssociateMouseAndMouseCursorPosition(true);' \
              '  CGSize screenSize = CGDisplayScreenSize(0);' \
              '  CVDisplayLinkRef displayLink = NULL;' \
              '  CVDisplayLinkCreateWithCGDisplay(0, &displayLink);' \
              '  CVTime refresh = CVDisplayLinkGetNominalOutputVideoRefreshPeriod(displayLink);' \
              '  if (displayLink != NULL) CVDisplayLinkRelease(displayLink);' \
              '  if (cropped != NULL) CGImageRelease(cropped);' \
              '  if (image != NULL) CGImageRelease(image);' \
              '  if (provider != NULL) CGDataProviderRelease(provider);' \
              '  if (colorSpace != NULL) CGColorSpaceRelease(colorSpace);' \
              '  ProcessSerialNumber process = { 0, kCurrentProcess };' \
              '  OSStatus transform = TransformProcessType(&process, kProcessTransformToForegroundApplication);' \
              '  NSDictionary *about = @{ NSAboutPanelOptionApplicationIcon: [NSImage new], NSAboutPanelOptionApplicationVersion: @"1" };' \
              '  [[NSApplication sharedApplication] orderFrontStandardAboutPanelWithOptions:about];' \
              '  [[NSApplication sharedApplication] sendEvent:event];' \
              '  NSBeep();' \
              '  return tap == NULL || tapSource == NULL || refresh.flags == kCVTimeIsIndefinite || screenSize.width < 0 || modifiers == 0 || panelFont == nil || [alert runModal] == NSAlertSecondButtonReturn || [panel runModal] != NSModalResponseOK || transform == -1;' \
              '}' \
              > qemu-cocoa-sdk-smoke.m
            "$CC" qemu-cocoa-sdk-smoke.m \
              -framework Cocoa \
              -framework CoreVideo \
              -framework QuartzCore \
              -o "$c/bin/aos-darwin-qemu-cocoa-sdk-smoke"

            printf '%s\n' \
              '#import <ApplicationServices/ApplicationServices.h>' \
              '#import <CoreServices/CoreServices.h>' \
              '#import <Foundation/Foundation.h>' \
              '#import <AppKit/AppKit.h>' \
              '@interface AOSFoundationSmokeException : NSException' \
              '@end' \
              '@implementation AOSFoundationSmokeException' \
              '@end' \
              '@interface AOSFoundationSmokeBlockOperation : NSBlockOperation' \
              '@end' \
              '@implementation AOSFoundationSmokeBlockOperation' \
              '@end' \
              'int main(void) {' \
              '  const unichar characters[] = { 0x41, 0x4f, 0x53 };' \
              '  NSString *characterString = [NSString stringWithCharacters:characters length:3];' \
              '  @try {' \
              '    NSLog(@"%@", characterString);' \
              '  } @catch (NSException *exception) {' \
              '    NSLog(@"%@", exception.callStackSymbols);' \
              '  } @finally {' \
              '    NSLog(@"Objective-C exception cleanup complete");' \
              '  }' \
              '  NSSearchPathDirectory mediaDirectories[] = { NSMoviesDirectory, NSMusicDirectory, NSPicturesDirectory, NSSharedPublicDirectory };' \
              '  NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, true);' \
              '  NSString *path = paths.firstObject;' \
              '  NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];' \
              '  NSBlockOperation *operation = [NSBlockOperation blockOperationWithBlock:(void (^)(void))nil];' \
              '  [operation start];' \
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
              '  return characterString == nil || operation == nil || image == nil || defaultValue == nil || !synchronized || decodedPath == nil || number.unsignedLongLongValue != 42 || enumeratedValue == nil || path.UTF8String == NULL || bundlePath == NULL || mediaDirectories[0] == 0 || handlers == NULL || roleHandlers == NULL || roleHandler == NULL || schemeHandler == NULL || uti == NULL || tag == NULL || utiDescription == NULL || utiMatches || !utiConforms || launchStatus == -1 || findStatus < kLSApplicationNotFoundErr;' \
              '}' \
              > foundation-appkit-smoke.m
            "$CC" -fblocks foundation-appkit-smoke.m \
              -framework Foundation \
              -framework AppKit \
              -lobjc \
              -o "$c/bin/aos-darwin-foundation-appkit-smoke"

            cp ${./darwin-jdk-sdk-smoke.m} jdk-sdk-smoke.m
            "$CC" jdk-sdk-smoke.m \
              -framework Foundation \
              -framework AppKit \
              -framework ApplicationServices \
              -lobjc \
              -o "$c/bin/aos-darwin-jdk-sdk-smoke"

            cp ${./darwin-jdk10-sdk-smoke.m} jdk10-sdk-smoke.mm
            "$CXX" jdk10-sdk-smoke.mm \
              -framework AppKit \
              -framework CoreGraphics \
              -framework CoreText \
              -framework OpenGL \
              -o "$cxx/bin/aos-darwin-jdk10-sdk-smoke"

            cp ${./darwin-jdk25-sdk-smoke.m} jdk25-sdk-smoke.m
            "$CC" jdk25-sdk-smoke.m \
              -framework Foundation \
              -framework AppKit \
              -framework ApplicationServices \
              -framework AudioToolbox \
              -framework AudioUnit \
              -framework CFNetwork \
              -framework CoreAudio \
              -framework CoreFoundation \
              -framework CoreGraphics \
              -framework CoreMIDI \
              -framework CoreText \
              -framework CoreVideo \
              -framework OpenGL \
              -framework QuartzCore \
              -framework Security \
              -lobjc \
              -o "$c/bin/aos-darwin-jdk25-sdk-smoke"

            # Apple's split Foundation headers are valid entry points, not
            # aliases that only work after the umbrella has established the
            # base type order. Compile and link each one first in an otherwise
            # independent translation unit to keep that include contract.
            for split_header in NSDate NSString NSValue; do
              cat > "foundation-$split_header-smoke.m" <<EOF
            #import <Foundation/$split_header.h>
            #import <Foundation/Foundation.h>
            int main(void) { return 0; }
            EOF
              "$CC" "foundation-$split_header-smoke.m" \
                -framework Foundation \
                -lobjc \
                -o "$c/bin/aos-darwin-foundation-$split_header-smoke"
            done

            cp ${./darwin-jrs-sdk-smoke.m} jrs-sdk-smoke.m
            "$CC" jrs-sdk-smoke.m \
              -framework JavaRuntimeSupport \
              -framework AppKit \
              -framework ApplicationServices \
              -lobjc \
              -o "$c/bin/aos-darwin-jrs-sdk-smoke"

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
              '#include <Security/AuthSession.h>' \
              '#include <Security/SecImportExport.h>' \
              '#include <Security/Security.h>' \
              '#if defined(__arm64__)' \
              '_Static_assert(sizeof(SSLCipherSuite) == 2, "arm64 SecureTransport cipher ABI");' \
              '#else' \
              '_Static_assert(sizeof(SSLCipherSuite) == 4, "x86_64 SecureTransport cipher ABI");' \
              '#endif' \
              'static OSStatus aos_ssl_read(SSLConnectionRef connection, void *data, size_t *length) { (void)connection; (void)data; (void)length; return errSSLClosedGraceful; }' \
              'static OSStatus aos_ssl_write(SSLConnectionRef connection, const void *data, size_t *length) { (void)connection; (void)data; (void)length; return errSSLClosedGraceful; }' \
              'int main(void) {' \
              '  SecuritySessionId session = 0;' \
              '  SessionAttributeBits attributes = 0;' \
              '  OSStatus sessionStatus = SessionGetInfo(callerSecuritySession, &session, &attributes);' \
              '  SecKeyImportExportParameters importParameters = {' \
              '    .version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION,' \
              '    .flags = 0,' \
              '    .keyUsage = CSSM_KEYUSE_ANY,' \
              '    .keyAttributes = CSSM_KEYATTR_RETURN_DEFAULT' \
              '  };' \
              '  SecExternalFormat externalFormat = kSecFormatWrappedPKCS8;' \
              '  SecExternalItemType externalType = kSecItemTypePrivateKey;' \
              '  CFDataRef exportedData = NULL;' \
              '  CFArrayRef importedItems = NULL;' \
              '  OSStatus exportStatus = SecKeychainItemExport(NULL, kSecFormatPKCS12, kSecItemPemArmour, &importParameters, &exportedData);' \
              '  OSStatus importStatus = SecKeychainItemImport(NULL, NULL, &externalFormat, &externalType, 0, &importParameters, NULL, &importedItems);' \
              '  SSLContextRef context = SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);' \
              '  SSLSetIOFuncs(context, aos_ssl_read, aos_ssl_write);' \
              '  SSLSetConnection(context, NULL);' \
              '  SSLSetSessionOption(context, kSSLSessionOptionBreakOnServerAuth, true);' \
              '  SSLSetProtocolVersionMin(context, kTLSProtocol1);' \
              '  SSLSetProtocolVersionMax(context, kTLSProtocol12);' \
              '  SSLSetPeerDomainName(context, "localhost", 9);' \
              '  SSLCipherSuite ciphers[1] = { TLS_RSA_WITH_AES_128_CBC_SHA };' \
              '  size_t cipherCount = 1;' \
              '  OSStatus countedCiphers = SSLGetNumberSupportedCiphers(context, &cipherCount);' \
              '  OSStatus copiedCiphers = SSLGetSupportedCiphers(context, ciphers, &cipherCount);' \
              '  OSStatus enabledCiphers = SSLSetEnabledCiphers(context, ciphers, cipherCount);' \
              '  OSStatus setCertificate = SSLSetCertificate(context, NULL);' \
              '  OSStatus setPeer = SSLSetPeerID(context, "aos", 3);' \
              '  OSStatus gotCipher = SSLGetNegotiatedCipher(context, ciphers);' \
              '  SSLProtocol negotiatedProtocol = kSSLProtocolUnknown;' \
              '  OSStatus gotProtocol = SSLGetNegotiatedProtocolVersion(context, &negotiatedProtocol);' \
              '  OSStatus setAlpn = SSLSetALPNProtocols(context, NULL);' \
              '  CFArrayRef alpn = NULL;' \
              '  OSStatus copiedAlpn = SSLCopyALPNProtocols(context, &alpn);' \
              '  size_t buffered = 0;' \
              '  OSStatus gotBuffered = SSLGetBufferedReadSize(context, &buffered);' \
              '  OSStatus handshake = SSLHandshake(context);' \
              '  SecTrustRef trust = NULL;' \
              '  SSLCopyPeerTrust(context, &trust);' \
              '  SecTrustResultType trustResult = kSecTrustResultInvalid;' \
              '  if (trust != NULL) SecTrustEvaluate(trust, &trustResult);' \
              '  SecCertificateRef certificate = trust == NULL ? NULL : SecTrustGetCertificateAtIndex(trust, 0);' \
              '  CFDataRef certificateData = certificate == NULL ? NULL : SecCertificateCopyData(certificate);' \
              '  SecCertificateRef createdCertificate = SecCertificateCreateWithData(kCFAllocatorDefault, certificateData);' \
              '  CFStringRef subjectSummary = SecCertificateCopySubjectSummary(certificate);' \
              '  CFStringRef commonName = NULL;' \
              '  OSStatus copiedCommonName = SecCertificateCopyCommonName(certificate, &commonName);' \
              '  CFStringRef longDescription = SecCertificateCopyLongDescription(kCFAllocatorDefault, certificate, NULL);' \
              '  SecPolicyRef policy = SecPolicyCreateSSL(false, NULL);' \
              '  CFDictionaryRef policyProperties = policy == NULL ? NULL : SecPolicyCopyProperties(policy);' \
              '  bool policyScoped = policyProperties != NULL && CFDictionaryContainsKey(policyProperties, kSecPolicyOid);' \
              '  bool sslPolicy = CFEqual(kSecPolicyAppleSSL, kSecPolicyAppleSSL);' \
              '  CFMutableArrayRef subjectCertificates = CFArrayCreateMutable(NULL, 1, &kCFTypeArrayCallBacks);' \
              '  CFArraySetValueAtIndex(subjectCertificates, 0, certificate);' \
              '  SecTrustRef certificateTrust = NULL;' \
              '  OSStatus createdTrust = SecTrustCreateWithCertificates(subjectCertificates, policy, &certificateTrust);' \
              '  bool trusted = certificateTrust != NULL && SecTrustEvaluateWithError(certificateTrust, NULL);' \
              '  const UInt8 securityTextBytes[] = { 97, 111, 115 };' \
              '  CFStringRef noCopyText = CFStringCreateWithBytesNoCopy(kCFAllocatorDefault, securityTextBytes, 3, kCFStringEncodingUTF8, false, kCFAllocatorNull);' \
              '  CFArrayRef trustSettings = NULL;' \
              '  OSStatus copiedTrustSettings = SecTrustSettingsCopyTrustSettings(certificate, kSecTrustSettingsDomainUser, &trustSettings);' \
              '  CFArrayRef trustCertificates = NULL;' \
              '  OSStatus copiedTrustCertificates = SecTrustSettingsCopyCertificates(kSecTrustSettingsDomainUser, &trustCertificates);' \
              '  OSStatus anchorsOnly = SecTrustSetAnchorCertificatesOnly(certificateTrust, true);' \
              '  SecKeyRef publicKey = SecTrustCopyPublicKey(certificateTrust);' \
              '  CFIndex trustCertificateCount = SecTrustGetCertificateCount(certificateTrust);' \
              '  CFDataRef publicKeyData = SecKeyCopyExternalRepresentation(publicKey, NULL);' \
              '  SecIdentityRef identity = NULL;' \
              '  OSStatus createdIdentity = SecIdentityCreateWithCertificate(NULL, certificate, &identity);' \
              '  SecItemImportExportKeyParameters itemImportParameters = { .version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION, .flags = 0 };' \
              '  CFArrayRef itemImports = NULL;' \
              '  OSStatus importedItem = SecItemImport(NULL, NULL, &externalFormat, &externalType, 0, &itemImportParameters, NULL, &itemImports);' \
              '  const void *policyConstants[] = { kSecPolicyAppleSSL, kSecPolicyOid };' \
              '  const void *trustSettingKeys[] = { kSecTrustSettingsApplication, kSecTrustSettingsPolicy, kSecTrustSettingsPolicyString, kSecTrustSettingsResult };' \
              '  const void *queryKeys[] = { kSecClass, kSecMatchLimit, kSecReturnRef };' \
              '  const void *queryValues[] = { kSecClassCertificate, kSecMatchLimitAll, kCFBooleanTrue };' \
              '  const void *curlSecurityData[] = { kSecClassIdentity, kSecAttrLabel, kSecMatchPolicy, kSecImportItemIdentity };' \
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
              '  if (itemImports != NULL) CFRelease(itemImports);' \
              '  if (identity != NULL) CFRelease(identity);' \
              '  if (publicKeyData != NULL) CFRelease(publicKeyData);' \
              '  if (publicKey != NULL) CFRelease(publicKey);' \
              '  if (longDescription != NULL) CFRelease(longDescription);' \
              '  if (commonName != NULL) CFRelease(commonName);' \
              '  if (subjectSummary != NULL) CFRelease(subjectSummary);' \
              '  if (createdCertificate != NULL) CFRelease(createdCertificate);' \
              '  if (alpn != NULL) CFRelease(alpn);' \
              '  if (queryResult != NULL) CFRelease(queryResult);' \
              '  if (query != NULL) CFRelease(query);' \
              '  if (trustCertificates != NULL) CFRelease(trustCertificates);' \
              '  if (trustSettings != NULL) CFRelease(trustSettings);' \
              '  if (noCopyText != NULL) CFRelease(noCopyText);' \
              '  if (certificateTrust != NULL) CFRelease(certificateTrust);' \
              '  if (subjectCertificates != NULL) CFRelease(subjectCertificates);' \
              '  if (policyProperties != NULL) CFRelease(policyProperties);' \
              '  if (policy != NULL) CFRelease(policy);' \
              '  if (error != NULL) CFRelease(error);' \
              '  if (certificateData != NULL) CFRelease(certificateData);' \
              '  if (trust != NULL) CFRelease(trust);' \
              '  if (context != NULL) CFRelease(context);' \
              '  return trustResult == kSecTrustResultOtherError && processed == (size_t)-1 && sessionStatus == errSecItemNotFound && exportStatus == errSecItemNotFound && importStatus == errSecItemNotFound && externalFormat == kSecFormatX509Cert && externalType == kSecItemTypeCertificate && exportedData == NULL && importedItems == NULL && session == callerSecuritySession && attributes == sessionHasGraphicAccess && createdTrust == copiedTrustSettings && copiedTrustCertificates == errSecItemNotFound && noCopyText == NULL && copiedItems == errSecItemNotFound && policyConstants[0] == NULL && trustSettingKeys[0] == NULL && curlSecurityData[0] == NULL && policyScoped && sslPolicy && trusted && kSecTrustSettingsResultTrustRoot != 1 && kSecTrustSettingsResultTrustAsRoot != 2 && kSecTrustSettingsResultDeny != 3 && kSecTrustSettingsDomainAdmin != 1 && copiedKeychain == addedPassword && foundPassword == modifiedPassword && freedPassword == deletedPassword && countedCiphers == copiedCiphers && enabledCiphers == setCertificate && setPeer == gotCipher && gotProtocol == setAlpn && copiedAlpn == gotBuffered && copiedCommonName == anchorsOnly && createdIdentity == importedItem && trustCertificateCount == -1 && errSecAllocate == errSecAuthFailed && errSSLProtocol == errSSLClientHelloReceived;' \
              '}' \
              > security-smoke.c
            "$CC" security-smoke.c \
              -framework CoreFoundation \
              -framework Security \
              -o "$c/bin/aos-darwin-security-smoke"

            printf '%s\n' \
              '#include <Security/Security.h>' \
              'int main(void) {' \
              '  SecIdentityRef identity = NULL;' \
              '  SecCertificateRef certificate = NULL;' \
              '  SecKeyRef privateKey = NULL;' \
              '  SecIdentitySearchRef identitySearch = NULL;' \
              '  SecPolicySearchRef policySearch = NULL;' \
              '  SecPolicyRef policy = NULL;' \
              '  SecTrustRef trust = NULL;' \
              '  SecKeychainSearchRef keychainSearch = NULL;' \
              '  SecKeychainItemRef item = NULL;' \
              '  SecKeychainAttribute attribute = { kSecLabelItemAttr, 0, NULL };' \
              '  SecKeychainAttributeList attributes = { 1, &attribute };' \
              '  CSSM_DATA certificateData = { 0, NULL };' \
              '  CSSM_TP_APPLE_EVIDENCE_INFO *evidence = NULL;' \
              '  CFArrayRef anchors = NULL;' \
              '  CFArrayRef chain = NULL;' \
              '  SecTrustResultType result = kSecTrustResultInvalid;' \
              '  OSStatus status = SecIdentityCopyCertificate(identity, &certificate);' \
              '  status += SecIdentityCopyPrivateKey(identity, &privateKey);' \
              '  status += SecIdentitySearchCreate(NULL, CSSM_KEYUSE_ANY, &identitySearch);' \
              '  status += SecIdentitySearchCopyNext(identitySearch, &identity);' \
              '  status += SecPolicySearchCreate(CSSM_CERT_X_509v3, &CSSMOID_APPLE_X509_BASIC, NULL, &policySearch);' \
              '  status += SecPolicySearchCopyNext(policySearch, &policy);' \
              '  status += SecCertificateGetData(certificate, &certificateData);' \
              '  CFTypeID typeID = SecCertificateGetTypeID();' \
              '  status += SecKeychainItemCopyContent(item, NULL, &attributes, NULL, NULL);' \
              '  status += SecKeychainItemModifyContent(item, &attributes, 0, NULL);' \
              '  status += SecKeychainSearchCreateFromAttributes(NULL, kSecCertificateItemClass, &attributes, &keychainSearch);' \
              '  status += SecKeychainSearchCopyNext(keychainSearch, &item);' \
              '  status += SecTrustCopyAnchorCertificates(&anchors);' \
              '  status += SecTrustSetAnchorCertificates(trust, anchors);' \
              '  status += SecTrustGetResult(trust, &result, &chain, &evidence);' \
              '  cssmPerror("aos", status);' \
              '  return status == 0 || typeID == 0 || attribute.tag == kSecModDateItemAttr;' \
              '}' \
              > security-jdk-smoke.c
            "$CC" security-jdk-smoke.c \
              -framework CoreFoundation \
              -framework Security \
              -o "$c/bin/aos-darwin-security-jdk-smoke"

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
              "$c/bin/aos-darwin-applicationservices-reexports-smoke" \
              "$c/bin/aos-darwin-c-smoke" \
              "$c/bin/aos-darwin-carbon-smoke" \
              "$c/bin/aos-darwin-command-line-sdk-smoke" \
              "$c/bin/aos-darwin-corefoundation-stream-smoke" \
              "$c/bin/aos-darwin-coreservices-smoke" \
              "$c/bin/aos-darwin-cocoa-smoke" \
              "$c/bin/aos-darwin-framework-smoke" \
              "$c/bin/aos-darwin-foundation-appkit-smoke" \
              "$c/bin/aos-darwin-hypervisor-smoke" \
              "$c/bin/aos-darwin-iconv-smoke" \
              "$c/bin/aos-darwin-jdk-sdk-smoke" \
              "$c/bin/aos-darwin-jdk25-sdk-smoke" \
              "$c/bin/aos-darwin-foundation-NSDate-smoke" \
              "$c/bin/aos-darwin-foundation-NSString-smoke" \
              "$c/bin/aos-darwin-foundation-NSValue-smoke" \
              "$c/bin/aos-darwin-jrs-sdk-smoke" \
              "$c/bin/aos-darwin-iokit-smoke" \
              "$c/bin/aos-darwin-metal-smoke" \
              "$c/bin/aos-darwin-nis-smoke" \
              "$c/bin/aos-darwin-objective-c-smoke" \
              "$c/bin/aos-darwin-quartzcore-corevideo-smoke" \
              "$c/bin/aos-darwin-resolver-smoke" \
              "$c/bin/aos-darwin-security-smoke" \
              "$c/bin/aos-darwin-security-jdk-smoke" \
              "$c/lib/libaos-darwin-cmake-smoke.dylib" \
              "$cxx/libaos-darwin-cmake-cxx-smoke.dylib" \
              "$cxx/aos-darwin-flat-namespace.bundle" \
              "$cxx/bin/aos-darwin-audio-cxx-smoke" \
              "$cxx/bin/aos-darwin-jdk10-sdk-smoke" \
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
