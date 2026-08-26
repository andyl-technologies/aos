##! Open Darwin SDK surface used by the Linux-hosted cross toolchain.
##!
##! Zig maintains a redistributable aggregation of Apple open-source libc,
##! XNU, libdispatch, and related public headers together with a textual TAPI
##! description of libSystem.  This derivation installs only those source/data
##! inputs; it does not contain or extract an Xcode SDK.
{
  mkDerivation,
  fetchurl,
}: let
  version = "0.16.0";
  coreFoundationRevision = "761b621da93a856a48995efc29ed11028c283306";
  systemConfigurationRevision = "585b7f2fca293f4642d21d15c5daf187f63c4796";

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

    runtimeDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf "$src"
          tar xf ${coreFoundationSrc}
          tar xf ${systemConfigurationSrc}
          cd "zig-${version}"
        '';
      }
      {
        name = "install";
        script = ''
          coreFoundationRoot="../swift-corelibs-foundation-${coreFoundationRevision}"
          systemConfigurationRoot="../configd-${systemConfigurationRevision}"

          mkdir -p \
            "$out/usr/include/c++/v1" \
            "$out/usr/include/libunwind" \
            "$out/usr/lib" \
            "$out/System/Library/Frameworks/CoreFoundation.framework/Headers" \
            "$out/System/Library/Frameworks/SystemConfiguration.framework/Headers" \
            "$out/share/licenses/darwin-sdk"

          cp -R lib/libc/include/any-darwin-any/. "$out/usr/include/"
          cp -R lib/libcxx/include/. "$out/usr/include/c++/v1/"
          cp -R lib/libcxxabi/include/. "$out/usr/include/c++/v1/"
          cp -R lib/libunwind/include/. "$out/usr/include/libunwind/"
          cp lib/libc/darwin/libSystem.tbd "$out/usr/lib/libSystem.tbd"
          cp lib/libc/darwin/SDKSettings.json "$out/SDKSettings.json"
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
          cp \
            "$systemConfigurationRoot/SystemConfiguration.fproj/SCDynamicStore.h" \
            "$systemConfigurationRoot/SystemConfiguration.fproj/SCDynamicStoreCopySpecific.h" \
            "$systemConfigurationRoot/SystemConfiguration.fproj/SCSchemaDefinitions.h" \
            "$out/System/Library/Frameworks/SystemConfiguration.framework/Headers/"
          cp "$coreFoundationRoot/LICENSE" \
            "$out/share/licenses/darwin-sdk/CoreFoundation-LICENSE"
          cp "$systemConfigurationRoot/APPLE_LICENSE" \
            "$out/share/licenses/darwin-sdk/SystemConfiguration-LICENSE"

          cat > "$out/System/Library/Frameworks/SystemConfiguration.framework/Headers/SystemConfiguration.h" <<'EOF'
          #ifndef _SYSTEMCONFIGURATION_H
          #define _SYSTEMCONFIGURATION_H
          #include <SystemConfiguration/SCDynamicStore.h>
          #include <SystemConfiguration/SCDynamicStoreCopySpecific.h>
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
                - _CFArrayGetValueAtIndex
                - _CFDictionaryGetValue
                - _CFNumberGetValue
                - _CFRelease
                - _CFStringGetCString
                - _CFStringGetCStringPtr
                - _CFStringGetLength
          ...
          EOF

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
                - _SCDynamicStoreCopyProxies
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

          # Darwin's libc, libdl, libm, pthread, resolv, and libutil symbols
          # are all re-exported by libSystem.  Make the traditional linker
          # names resolve to the same textual stub without shipping binaries.
          for library in c dl m pthread resolv util; do
            ln -s libSystem.tbd "$out/usr/lib/lib$library.tbd"
          done
        '';
      }
    ];

    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;

    meta = {
      description = "Redistributable Darwin headers and system link stubs";
      homepage = "https://ziglang.org/";
      license = "APSL-2.0 AND BSD-3-Clause AND MIT AND (Apache-2.0 WITH Swift-exception)";
      platforms = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
    };
  }
