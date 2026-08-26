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

            printf '%s\n' \
              '#include <CoreFoundation/CoreFoundation.h>' \
              '#include <netinet/tcp_fsm.h>' \
              '#include <netinet/tcp_timer.h>' \
              '#include <sys/ttydev.h>' \
              '#include <SystemConfiguration/SystemConfiguration.h>' \
              'int main(void) {' \
              '  CFStringRef label = CFSTR("aos Darwin SDK");' \
              '  CFIndex maximum = CFStringGetMaximumSizeForEncoding(CFStringGetLength(label), kCFStringEncodingUTF8);' \
              '  CFTimeZoneRef zone = CFTimeZoneCopyDefault();' \
              '  CFStringRef zoneName = zone == NULL ? NULL : CFTimeZoneGetName(zone);' \
              '  CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)".", 1, false);' \
              '  CFBundleRef bundle = url == NULL ? NULL : CFBundleCreate(kCFAllocatorDefault, url);' \
              '  CFStringRef identifier = bundle == NULL ? NULL : CFBundleGetIdentifier(bundle);' \
              '  CFTypeRef value = bundle == NULL ? NULL : CFBundleGetValueForInfoDictionaryKey(bundle, CFSTR("CFBundleIdentifier"));' \
              '  CFStringRef typeDescription = CFCopyTypeIDDescription(CFStringGetTypeID());' \
              '  CFDictionaryRef proxies = SCDynamicStoreCopyProxies(NULL);' \
              '  if (proxies != NULL) CFRelease(proxies);' \
              '  if (typeDescription != NULL) CFRelease(typeDescription);' \
              '  if (bundle != NULL) CFRelease(bundle);' \
              '  if (url != NULL) CFRelease(url);' \
              '  if (zone != NULL) CFRelease(zone);' \
              '  return label == NULL || maximum < 0 || zoneName == NULL || identifier == value;' \
              '}' \
              > framework-smoke.c
            "$CC" framework-smoke.c \
              -framework SystemConfiguration \
              -framework CoreFoundation \
              -lobjc \
              -o "$c/bin/aos-darwin-framework-smoke"

            printf '%s\n' \
              '#include <arpa/nameser.h>' \
              '#include <resolv.h>' \
              'int main(void) {' \
              '  unsigned char answer[NS_PACKETSZ];' \
              '  return res_query("localhost", ns_c_in, ns_t_a, answer, sizeof(answer)) < -1;' \
              '}' \
              > resolver-smoke.c
            "$CC" resolver-smoke.c -o "$c/bin/aos-darwin-resolver-smoke"

            printf '%s\n' \
              '#include <objc/runtime.h>' \
              '__attribute__((objc_root_class)) @interface AosRoot @end' \
              '@implementation AosRoot @end' \
              'int main(void) { return objc_getClass("AosRoot") == 0; }' \
              > objective-c-smoke.m
            "$CC" objective-c-smoke.m -lobjc \
              -o "$c/bin/aos-darwin-objective-c-smoke"

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
              "$c/bin/aos-darwin-framework-smoke" \
              "$c/bin/aos-darwin-iokit-smoke" \
              "$c/bin/aos-darwin-objective-c-smoke" \
              "$c/bin/aos-darwin-resolver-smoke" \
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
