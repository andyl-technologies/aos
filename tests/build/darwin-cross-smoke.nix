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
              '#include <net/ethernet.h>' \
              '#include <netinet/tcp_fsm.h>' \
              '#include <netinet/tcp_timer.h>' \
              '#include <rpc/pmap_prot.h>' \
              '#include <rpc/rpc.h>' \
              '#include <sys/syscall.h>' \
              '#include <sys/ttydev.h>' \
              '#include <sys/xattr.h>' \
              '#include <SystemConfiguration/SystemConfiguration.h>' \
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
              '  if (path != NULL) CFRelease(path);' \
              '  if (systemZone != NULL) CFRelease(systemZone);' \
              '  if (zone != NULL) CFRelease(zone);' \
              '  if (canonicalLanguage != NULL) CFRelease(canonicalLanguage);' \
              '  struct ether_addr address = { { 0 } };' \
              '  return label == NULL || canonicalLanguage == NULL || maximum < 0 || convertedCharacters < 0 || usedStringBytes < 0 || zoneName == NULL || systemZone == NULL || identifier == value || !represented || launchStatus == -1 || attributeSize < -1 || attributeListSize < -1 || attributeSetStatus < -1 || attributeRemoveStatus < -1 || address.octet[0] != 0 || ETHER_ADDR_LEN != 6 || XATTR_CREATE != 0x0002 || XATTR_REPLACE != 0x0004;' \
              '}' \
              > framework-smoke.c
            "$CC" framework-smoke.c \
              -framework CoreFoundation \
              -framework CoreServices \
              -framework SystemConfiguration \
              -lobjc \
              -o "$c/bin/aos-darwin-framework-smoke"

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
              '#include <arpa/nameser.h>' \
              '#include <dns.h>' \
              '#include <resolv.h>' \
              'int main(void) {' \
              '  unsigned char answer[NS_PACKETSZ];' \
              '  char expanded[NS_MAXDNAME];' \
              '  int query = res_query("localhost", ns_c_in, ns_t_a, answer, sizeof(answer));' \
              '  int expansion = dn_expand(answer, answer + sizeof(answer), answer, expanded, sizeof(expanded));' \
              '  return query < -1 || expansion < -1;' \
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
              '  os_log(OS_LOG_DEFAULT, "aos Darwin command-line SDK smoke");' \
              '  return sizeof(struct utmp) == 0 || UNKNOWNUID != 99 || aos_darwin_symbols[0] == 0;' \
              '}' \
              > command-line-sdk-smoke.c
            "$CC" command-line-sdk-smoke.c \
              -o "$c/bin/aos-darwin-command-line-sdk-smoke"

            printf '%s\n' \
              '#include <objc/runtime.h>' \
              'extern void *objc_autoreleasePoolPush(void);' \
              'extern void objc_autoreleasePoolPop(void *context);' \
              '__attribute__((objc_root_class)) @interface AosRoot @end' \
              '@implementation AosRoot @end' \
              'int main(void) {' \
              '  void *pool = objc_autoreleasePoolPush();' \
              '  Class root = objc_getClass("AosRoot");' \
              '  int isMeta = class_isMetaClass(objc_getMetaClass("AosRoot"));' \
              '  objc_autoreleasePoolPop(pool);' \
              '  return root == 0 || isMeta < 0;' \
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
              '#include <IOKit/storage/ata/ATASMARTLib.h>' \
              '#include <IOKit/usb/IOUSBHostFamilyDefinitions.h>' \
              '#include <IOKit/usb/IOUSBLib.h>' \
              '#include <Security/Security.h>' \
              'int main(void) {' \
              '  SecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);' \
              '  if (task != NULL) CFRelease(task);' \
              '  CFMutableDictionaryRef matching = IOServiceMatching(kIOUSBDeviceClassName);' \
              '  io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, matching);' \
              '  if (service != IO_OBJECT_NULL) IOObjectRelease(service);' \
              '  return 0;' \
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
              '  if (error != NULL) CFRelease(error);' \
              '  if (certificateData != NULL) CFRelease(certificateData);' \
              '  if (trust != NULL) CFRelease(trust);' \
              '  if (context != NULL) CFRelease(context);' \
              '  return trustResult == kSecTrustResultOtherError && processed == (size_t)-1 && copiedKeychain == addedPassword && foundPassword == modifiedPassword && freedPassword == deletedPassword;' \
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
              "$c/bin/aos-darwin-coreservices-smoke" \
              "$c/bin/aos-darwin-cocoa-smoke" \
              "$c/bin/aos-darwin-framework-smoke" \
              "$c/bin/aos-darwin-foundation-appkit-smoke" \
              "$c/bin/aos-darwin-iconv-smoke" \
              "$c/bin/aos-darwin-iokit-smoke" \
              "$c/bin/aos-darwin-nis-smoke" \
              "$c/bin/aos-darwin-objective-c-smoke" \
              "$c/bin/aos-darwin-resolver-smoke" \
              "$c/bin/aos-darwin-security-smoke" \
              "$c/lib/libaos-darwin-cmake-smoke.dylib" \
              "$cxx/libaos-darwin-cmake-cxx-smoke.dylib" \
              "$cxx/aos-darwin-flat-namespace.bundle" \
              "$cxx/bin/aos-darwin-cxx-smoke"; do
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
