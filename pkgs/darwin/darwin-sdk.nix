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

          mkdir -p \
            "$out/usr/include/c++/v1" \
            "$out/usr/include/hfs" \
            "$out/usr/include/libunwind" \
            "$out/usr/include/objc" \
            "$out/usr/include/os" \
            "$out/usr/include/rpc" \
            "$out/usr/include/servers" \
            "$out/usr/lib" \
            "$out/System/Library/Frameworks/ApplicationServices.framework/Headers" \
            "$out/System/Library/Frameworks/Cocoa.framework/Headers" \
            "$out/System/Library/Frameworks/CoreFoundation.framework/Headers" \
            "$out/System/Library/Frameworks/CoreFoundation.framework/Versions/A" \
            "$out/System/Library/Frameworks/CoreServices.framework/Headers" \
            "$out/System/Library/Frameworks/CoreServices.framework/Versions/A" \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/storage/ata" \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/storage" \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/usb" \
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
          # Darwin's Rust target specification and ordinary Autoconf clients
          # link iconv through its historical compatibility install name even
          # though the POSIX entry points are also exported by libSystem.
          # Publish that command-line SDK alias so `-liconv` records the same
          # dylib contract as Apple's SDK.
          cat > "$out/usr/lib/libiconv.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/usr/lib/libiconv.2.dylib'
          current-version: 7.0.0
          compatibility-version: 7.0.0
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols:
                - ___iconv
                - ___iconv_free_list
                - ___iconv_get_list
                - __libiconv_version
                - _iconv
                - _iconv_canonicalize
                - _iconv_close
                - _iconv_open
                - _iconv_open_into
                - _iconvctl
                - _iconvlist
                - _libiconv_set_relocation_prefix
          ...
          EOF
          ln -s libiconv.tbd "$out/usr/lib/libiconv.2.tbd"
          # Current Apple resolver headers bind the established public entry
          # points to their BIND 9 symbol names. Zig's older libSystem surface
          # describes only the unversioned aliases, so publish the matching
          # ABI exported by modern Darwin libSystem as well.
          sed -i '$i\  - targets: [ x86_64-macos, arm64-macos ]\n    symbols: [ _res_9_close, _res_9_dn_expand, _res_9_init, _res_9_isourserver, _res_9_mkquery, _res_9_query, _res_9_querydomain, _res_9_search, _res_9_send, _res_9_sendsigned ]' \
            "$out/usr/lib/libSystem.tbd"
          cp "$xnuRoot/bsd/netinet/tcp_fsm.h" "$out/usr/include/netinet/"
          cp "$xnuRoot/bsd/netinet/tcp_timer.h" "$out/usr/include/netinet/"
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
          cp "$libcRoot/include/fstab.h" "$out/usr/include/"
          # launchd publishes the userspace Mach bootstrap interface at the
          # traditional SDK path consumed by Kerberos KCM and other clients.
          cp "$launchdRoot/liblaunch/bootstrap.h" \
            "$out/usr/include/servers/bootstrap.h"
          cp "$hfsRoot/core/hfs_mount.h" "$out/usr/include/hfs/"
          cp "$xnuRoot/libkern/os/log.h" "$out/usr/include/os/"
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
            "$ioStorageFamilyRoot/IOStorage.h" \
            "$ioStorageFamilyRoot/IOStorageControllerCharacteristics.h" \
            "$ioStorageFamilyRoot/IOStorageDeviceCharacteristics.h" \
            "$ioStorageFamilyRoot/IOStorageProtocolCharacteristics.h" \
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

          # The command-line packages in this tree use only Security's SecTask
          # API to query their own entitlements.  Publish that documented ABI
          # without pulling in the unrelated keychain, codesigning, and CDSA
          # header graph from the full framework umbrella.
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

          cat > "$out/System/Library/Frameworks/Security.framework/Headers/Security.h" <<'EOF'
          #ifndef _SECURITY_H_
          #define _SECURITY_H_
          #include <Security/SecTask.h>
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
                - _CFArrayAppendValue
                - _CFArrayCreate
                - _CFArrayCreateMutable
                - _CFArrayInsertValueAtIndex
                - _CFBooleanGetTypeID
                - _CFBooleanGetValue
                - _CFBundleCopyExecutableURL
                - _CFBundleCreate
                - _CFBundleGetIdentifier
                - _CFBundleGetValueForInfoDictionaryKey
                - _CFCopyTypeIDDescription
                - _CFDataGetBytes
                - _CFDataGetLength
                - _CFDataGetTypeID
                - _CFDictionaryCreateMutable
                - _CFDictionaryGetValue
                - _CFDictionaryGetValueIfPresent
                - _CFDictionarySetValue
                - _CFGetTypeID
                - _CFLocaleCreateCanonicalLanguageIdentifierFromString
                - _CFNumberCreate
                - _CFNumberGetTypeID
                - _CFNumberGetValue
                - _CFRelease
                - _CFRetain
                - _CFRunLoopAddSource
                - _CFRunLoopGetCurrent
                - _CFRunLoopRemoveSource
                - _CFRunLoopRun
                - _CFRunLoopSourceCreate
                - _CFRunLoopSourceSignal
                - _CFRunLoopStop
                - _CFRunLoopWakeUp
                - _CFStringCreateWithCString
                - _CFStringCreateWithBytes
                - _CFStringGetBytes
                - _CFStringGetCString
                - _CFStringGetCStringPtr
                - _CFStringGetLength
                - _CFStringGetMaximumSizeForEncoding
                - _CFStringGetTypeID
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
                - _CFURLCreateWithFileSystemPath
                - _CFURLGetFileSystemRepresentation
                - _CFURLResourceIsReachable
                - _CFUUIDCreate
                - _CFUUIDCreateString
                - _CFUUIDGetConstantUUIDWithBytes
                - _CFUUIDGetUUIDBytes
                - ___CFConstantStringClassReference
                - ___CFStringMakeConstantString
                - _kCFAllocatorDefault
                - _kCFAllocatorSystemDefault
                - _kCFRunLoopCommonModes
                - _kCFRunLoopDefaultMode
                - _kCFTypeArrayCallBacks
                - _kCFTypeDictionaryKeyCallBacks
                - _kCFTypeDictionaryValueCallBacks
          ...
          EOF
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
          cat > "$out/System/Library/Frameworks/CoreServices.framework/Headers/CoreServices.h" <<'EOF'
          #ifndef __CORESERVICES__
          #define __CORESERVICES__

          #include <CoreFoundation/CoreFoundation.h>
          #include <dispatch/dispatch.h>
          #include <stdint.h>
          #include <sys/types.h>

          CF_EXTERN_C_BEGIN

          typedef uint64_t FSEventStreamEventId;
          typedef uint32_t FSEventStreamCreateFlags;
          typedef uint32_t FSEventStreamEventFlags;
          typedef struct __FSEventStream *FSEventStreamRef;
          typedef const struct __FSEventStream *ConstFSEventStreamRef;
          typedef void (*FSEventStreamCallback)(
            ConstFSEventStreamRef streamRef,
            void *clientCallBackInfo,
            size_t numEvents,
            void *eventPaths,
            const FSEventStreamEventFlags eventFlags[],
            const FSEventStreamEventId eventIds[]
          );
          typedef struct {
            CFIndex version;
            void *info;
            const void *(*retain)(const void *info);
            void (*release)(const void *info);
            CFStringRef (*copyDescription)(const void *info);
          } FSEventStreamContext;

          enum {
            kFSEventStreamCreateFlagNone = 0x00000000,
            kFSEventStreamCreateFlagUseCFTypes = 0x00000001,
            kFSEventStreamCreateFlagNoDefer = 0x00000002,
            kFSEventStreamCreateFlagWatchRoot = 0x00000004,
            kFSEventStreamCreateFlagIgnoreSelf = 0x00000008,
            kFSEventStreamCreateFlagFileEvents = 0x00000010,
            kFSEventStreamCreateFlagMarkSelf = 0x00000020,
            kFSEventStreamCreateFlagUseExtendedData = 0x00000040,
            kFSEventStreamCreateFlagFullHistory = 0x00000080,
            kFSEventStreamCreateFlagWithDocID = 0x00000100
          };
          enum {
            kFSEventStreamEventFlagNone = 0x00000000,
            kFSEventStreamEventFlagMustScanSubDirs = 0x00000001,
            kFSEventStreamEventFlagUserDropped = 0x00000002,
            kFSEventStreamEventFlagKernelDropped = 0x00000004,
            kFSEventStreamEventFlagEventIdsWrapped = 0x00000008,
            kFSEventStreamEventFlagHistoryDone = 0x00000010,
            kFSEventStreamEventFlagRootChanged = 0x00000020,
            kFSEventStreamEventFlagMount = 0x00000040,
            kFSEventStreamEventFlagUnmount = 0x00000080,
            kFSEventStreamEventFlagItemCreated = 0x00000100,
            kFSEventStreamEventFlagItemRemoved = 0x00000200,
            kFSEventStreamEventFlagItemInodeMetaMod = 0x00000400,
            kFSEventStreamEventFlagItemRenamed = 0x00000800,
            kFSEventStreamEventFlagItemModified = 0x00001000,
            kFSEventStreamEventFlagItemFinderInfoMod = 0x00002000,
            kFSEventStreamEventFlagItemChangeOwner = 0x00004000,
            kFSEventStreamEventFlagItemXattrMod = 0x00008000,
            kFSEventStreamEventFlagItemIsFile = 0x00010000,
            kFSEventStreamEventFlagItemIsDir = 0x00020000,
            kFSEventStreamEventFlagItemIsSymlink = 0x00040000,
            kFSEventStreamEventFlagOwnEvent = 0x00080000,
            kFSEventStreamEventFlagItemIsHardlink = 0x00100000,
            kFSEventStreamEventFlagItemIsLastHardlink = 0x00200000,
            kFSEventStreamEventFlagItemCloned = 0x00400000
          };

          #define kFSEventStreamEventIdSinceNow ((FSEventStreamEventId)UINT64_MAX)

          FSEventStreamRef FSEventStreamCreate(
            CFAllocatorRef allocator,
            FSEventStreamCallback callback,
            FSEventStreamContext *context,
            CFArrayRef pathsToWatch,
            FSEventStreamEventId sinceWhen,
            CFTimeInterval latency,
            FSEventStreamCreateFlags flags
          );
          void FSEventStreamSetDispatchQueue(FSEventStreamRef streamRef, dispatch_queue_t queue);
          Boolean FSEventStreamStart(FSEventStreamRef streamRef);
          void FSEventStreamStop(FSEventStreamRef streamRef);
          void FSEventStreamInvalidate(FSEventStreamRef streamRef);
          void FSEventStreamRelease(FSEventStreamRef streamRef);
          dev_t FSEventStreamGetDeviceBeingWatched(ConstFSEventStreamRef streamRef);
          FSEventStreamEventId FSEventsGetCurrentEventId(void);
          Boolean FSEventsPurgeEventsForDeviceUpToEventId(dev_t device, FSEventStreamEventId eventId);

          CF_EXTERN_C_END

          #endif
          EOF
          cat > "$out/System/Library/Frameworks/CoreServices.framework/CoreServices.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices'
          current-version: 1228.0.0
          compatibility-version: 1.0.0
          reexported-libraries:
            - targets: [ x86_64-macos, arm64-macos ]
              libraries: [ '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation' ]
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols:
                - _FSEventStreamCreate
                - _FSEventStreamGetDeviceBeingWatched
                - _FSEventStreamInvalidate
                - _FSEventStreamRelease
                - _FSEventStreamSetDispatchQueue
                - _FSEventStreamStart
                - _FSEventStreamStop
                - _FSEventsGetCurrentEventId
                - _FSEventsPurgeEventsForDeviceUpToEventId
                - _LSOpenCFURLRef
          ...
          EOF
          ln -s ../../CoreServices.tbd \
            "$out/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices.tbd"
          ln -s CoreServices.tbd \
            "$out/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices"

          # GLib's native Darwin notification backend uses the long-standing
          # AppKit classes re-exported by Cocoa. The implementation is supplied
          # by the target macOS system; the cross SDK needs only the public
          # Objective-C declarations and link-time class/protocol surface.
          cat > "$out/System/Library/Frameworks/Cocoa.framework/Headers/Cocoa.h" <<'EOF'
          #ifndef _AOS_COCOA_H_
          #define _AOS_COCOA_H_

          #import <objc/NSObject.h>

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

          @interface NSString : NSObject
          - (instancetype)initWithUTF8String:(const char *)bytes;
          - (const char *)UTF8String;
          - (NSComparisonResult)compare:(NSString *)string;
          @end

          @interface NSArray<ObjectType> : NSObject <NSFastEnumeration>
          @end

          @interface NSDictionary<KeyType, ObjectType> : NSObject
          - (ObjectType)objectForKeyedSubscript:(KeyType)key;
          @end

          @interface NSMutableDictionary<KeyType, ObjectType> : NSDictionary<KeyType, ObjectType>
          - (void)setObject:(ObjectType)object forKeyedSubscript:(KeyType)key;
          @end

          @interface NSBundle : NSObject
          + (NSBundle *)mainBundle;
          @property(readonly, copy) NSString *bundleIdentifier;
          @end

          @interface NSImage : NSObject
          - (instancetype)initByReferencingFile:(NSString *)fileName;
          @end

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

          #endif
          EOF
          cat > "$out/System/Library/Frameworks/Cocoa.framework/Cocoa.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa'
          current-version: 24.0.0
          compatibility-version: 1.0.0
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

          # CMake's Darwin Xcode generator includes the public
          # ApplicationServices umbrella and calls LaunchServices through
          # CoreServices. Keep that command-line development surface in the
          # SDK without importing a binary Apple framework.
          cat > "$out/System/Library/Frameworks/ApplicationServices.framework/Headers/ApplicationServices.h" <<'EOF'
          #ifndef __APPLICATIONSERVICES__
          #define __APPLICATIONSERVICES__

          #include <CoreFoundation/CoreFoundation.h>

          CF_EXTERN_C_BEGIN
          CF_EXPORT OSStatus LSOpenCFURLRef(CFURLRef inURL, CFURLRef *outLaunchedURL);
          CF_EXTERN_C_END

          #endif
          EOF
          cat > "$out/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices'
          current-version: 64.0.0
          compatibility-version: 1.0.0
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols: [ _LSOpenCFURLRef ]
          ...
          EOF

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
                - _IORegistryEntryGetParentEntry
                - _IORegistryEntryGetPath
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

          cat > "$out/System/Library/Frameworks/Security.framework/Security.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/System/Library/Frameworks/Security.framework/Versions/A/Security'
          current-version: 61123.0.0
          compatibility-version: 1.0.0
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols:
                - _SecTaskCopySigningIdentifier
                - _SecTaskCopyValueForEntitlement
                - _SecTaskCopyValuesForEntitlements
                - _SecTaskCreateFromSelf
                - _SecTaskCreateWithAuditToken
                - _SecTaskGetTypeID
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
                - _class_getClassMethod
                - _class_getInstanceMethod
                - _class_getInstanceSize
                - _class_getName
                - _class_getProperty
                - _class_getSuperclass
                - _method_getImplementation
                - _method_getName
                - _objc_alloc
                - _objc_allocateClassPair
                - _objc_autorelease
                - _objc_autoreleaseReturnValue
                - _objc_copyWeak
                - _objc_destroyWeak
                - _objc_disposeClassPair
                - _objc_getClass
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
                - _objc_release
                - _objc_retain
                - _objc_retainAutoreleaseReturnValue
                - _objc_retainAutoreleasedReturnValue
                - _objc_storeStrong
                - _objc_storeWeak
                - _object_getClass
                - _object_setClass
                - _sel_getName
                - _sel_getUid
                - _sel_registerName
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
