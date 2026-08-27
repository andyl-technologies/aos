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
            "$out/System/Library/Frameworks/ApplicationServices.framework/Headers" \
            "$out/System/Library/Frameworks/ApplicationServices.framework/Versions/A" \
            "$out/System/Library/Frameworks/AppKit.framework/Headers" \
            "$out/System/Library/Frameworks/AppKit.framework/Versions/C" \
            "$out/System/Library/Frameworks/Cocoa.framework/Headers" \
            "$out/System/Library/Frameworks/CoreFoundation.framework/Headers" \
            "$out/System/Library/Frameworks/CoreFoundation.framework/Versions/A" \
            "$out/System/Library/Frameworks/CoreServices.framework/Headers" \
            "$out/System/Library/Frameworks/CoreServices.framework/Versions/A" \
            "$out/System/Library/Frameworks/CoreVideo.framework/Headers" \
            "$out/System/Library/Frameworks/CoreVideo.framework/Versions/A" \
            "$out/System/Library/Frameworks/Foundation.framework/Headers" \
            "$out/System/Library/Frameworks/Foundation.framework/Versions/C" \
            "$out/System/Library/Frameworks/Hypervisor.framework/Headers" \
            "$out/System/Library/Frameworks/Hypervisor.framework/Versions/A" \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/storage/ata" \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/storage" \
            "$out/System/Library/Frameworks/IOKit.framework/Headers/usb" \
            "$out/System/Library/Frameworks/IOSurface.framework/Headers" \
            "$out/System/Library/Frameworks/IOSurface.framework/Versions/A" \
            "$out/System/Library/Frameworks/Metal.framework/Headers" \
            "$out/System/Library/Frameworks/Metal.framework/Versions/A" \
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
          cat > "$out/usr/lib/libsandbox.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/usr/lib/libsandbox.1.dylib'
          current-version: 300.0.0
          compatibility-version: 1.0.0
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols:
                - _kSBXProfileNoInternet
                - _kSBXProfileNoNetwork
                - _kSBXProfileNoWrite
                - _kSBXProfileNoWriteExceptTemporary
                - _kSBXProfilePureComputation
                - _sandbox_free_error
                - _sandbox_init
                - _sandbox_init_with_parameters
          ...
          EOF
          ln -s libsandbox.tbd "$out/usr/lib/libsandbox.1.tbd"
          # Current Apple resolver headers bind the established public entry
          # points to their BIND 9 symbol names. Zig's older libSystem surface
          # describes only the unversioned aliases, so publish the matching
          # ABI exported by modern Darwin libSystem as well.
          sed -i '$i\  - targets: [ x86_64-macos, arm64-macos ]\n    symbols: [ _res_9_close, _res_9_dn_expand, _res_9_getservers, _res_9_init, _res_9_isourserver, _res_9_mkquery, _res_9_ndestroy, _res_9_ninit, _res_9_query, _res_9_querydomain, _res_9_search, _res_9_send, _res_9_sendsigned ]' \
            "$out/usr/lib/libSystem.tbd"
          cp "$xnuRoot/bsd/netinet/tcp_fsm.h" "$out/usr/include/netinet/"
          cp "$xnuRoot/bsd/netinet/tcp_timer.h" "$out/usr/include/netinet/"
          cp "$xnuRoot/bsd/net/ethernet.h" "$out/usr/include/net/"
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
          typedef struct __SecPolicy *SecPolicyRef;
          typedef struct __SecTrust *SecTrustRef;
          CFStringRef SecCopyErrorMessageString(OSStatus status, void *reserved);
          enum {
            errSecSuccess = 0,
            errSecItemNotFound = -25300,
            errSSLClosedGraceful = -9805,
            errSSLPeerAuthCompleted = -9841,
            errSSLServerAuthCompleted = errSSLPeerAuthCompleted
          };
          __END_DECLS
          #endif
          EOF

          cat > "$out/System/Library/Frameworks/Security.framework/Headers/SecCertificate.h" <<'EOF'
          #ifndef _SECURITY_SECCERTIFICATE_H_
          #define _SECURITY_SECCERTIFICATE_H_
          #include <Security/SecBase.h>
          __BEGIN_DECLS
          CFDataRef SecCertificateCopyData(SecCertificateRef certificate);
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
          extern const CFStringRef kSecMatchLimit;
          extern const CFStringRef kSecMatchLimitAll;
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
          bool SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error);
          SecCertificateRef SecTrustGetCertificateAtIndex(SecTrustRef trust, CFIndex index);
          __END_DECLS
          #endif
          EOF

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
          __END_DECLS
          #endif
          EOF

          cat > "$out/System/Library/Frameworks/Security.framework/Headers/SecureTransport.h" <<'EOF'
          #ifndef _SECURITY_SECURETRANSPORT_H_
          #define _SECURITY_SECURETRANSPORT_H_
          #include <Security/SecTrust.h>
          #include <stddef.h>
          __BEGIN_DECLS
          struct SSLContext;
          typedef struct SSLContext *SSLContextRef;
          typedef const void *SSLConnectionRef;
          typedef OSStatus (*SSLReadFunc)(SSLConnectionRef connection, void *data, size_t *dataLength);
          typedef OSStatus (*SSLWriteFunc)(SSLConnectionRef connection, const void *data, size_t *dataLength);
          typedef enum {
            kSSLSessionOptionBreakOnServerAuth = 0
          } SSLSessionOption;
          typedef enum {
            kSSLServerSide = 0,
            kSSLClientSide = 1
          } SSLProtocolSide;
          typedef enum {
            kSSLStreamType = 0,
            kSSLDatagramType = 1
          } SSLConnectionType;
          typedef enum {
            kSSLProtocolUnknown = 0,
            kSSLProtocol2 = 1,
            kSSLProtocol3 = 2,
            kSSLProtocol3Only = 3,
            kTLSProtocol1 = 4,
            kTLSProtocol1Only = 5,
            kSSLProtocolAll = 6,
            kTLSProtocol11 = 7,
            kTLSProtocol12 = 8,
            kDTLSProtocol1 = 9,
            kTLSProtocol13 = 10,
            kDTLSProtocol12 = 11,
            kTLSProtocolMaxSupported = 999
          } SSLProtocol;
          SSLContextRef SSLCreateContext(
            CFAllocatorRef allocator,
            SSLProtocolSide protocolSide,
            SSLConnectionType connectionType
          );
          OSStatus SSLSetIOFuncs(SSLContextRef context, SSLReadFunc readFunc, SSLWriteFunc writeFunc);
          OSStatus SSLSetConnection(SSLContextRef context, SSLConnectionRef connection);
          OSStatus SSLSetSessionOption(SSLContextRef context, SSLSessionOption option, Boolean value);
          OSStatus SSLSetProtocolVersionMin(SSLContextRef context, SSLProtocol minVersion);
          OSStatus SSLSetProtocolVersionMax(SSLContextRef context, SSLProtocol maxVersion);
          OSStatus SSLSetPeerDomainName(SSLContextRef context, const char *peerName, size_t peerNameLength);
          OSStatus SSLHandshake(SSLContextRef context);
          OSStatus SSLCopyPeerTrust(SSLContextRef context, SecTrustRef *trust);
          OSStatus SSLWrite(SSLContextRef context, const void *data, size_t dataLength, size_t *processed);
          OSStatus SSLRead(SSLContextRef context, void *data, size_t dataLength, size_t *processed);
          OSStatus SSLClose(SSLContextRef context);
          __END_DECLS
          #endif
          EOF

          cat > "$out/System/Library/Frameworks/Security.framework/Headers/SecKeychain.h" <<'EOF'
          #ifndef _SECURITY_SECKEYCHAIN_H_
          #define _SECURITY_SECKEYCHAIN_H_
          #include <Security/SecBase.h>
          __BEGIN_DECLS
          typedef struct __SecKeychain *SecKeychainRef;
          typedef struct __SecKeychainItem *SecKeychainItemRef;
          typedef struct SecKeychainAttributeList SecKeychainAttributeList;
          OSStatus SecKeychainCopyDefault(SecKeychainRef *keychain);
          OSStatus SecKeychainAddGenericPassword(
            SecKeychainRef keychain,
            UInt32 serviceNameLength,
            const char *serviceName,
            UInt32 accountNameLength,
            const char *accountName,
            UInt32 passwordLength,
            const void *passwordData,
            SecKeychainItemRef *itemRef
          );
          OSStatus SecKeychainFindGenericPassword(
            CFTypeRef keychainOrArray,
            UInt32 serviceNameLength,
            const char *serviceName,
            UInt32 accountNameLength,
            const char *accountName,
            UInt32 *passwordLength,
            void **passwordData,
            SecKeychainItemRef *itemRef
          );
          OSStatus SecKeychainItemModifyAttributesAndData(
            SecKeychainItemRef itemRef,
            const SecKeychainAttributeList *attributeList,
            UInt32 length,
            const void *data
          );
          OSStatus SecKeychainItemDelete(SecKeychainItemRef itemRef);
          OSStatus SecKeychainItemFreeContent(SecKeychainAttributeList *attributeList, void *data);
          __END_DECLS
          #endif
          EOF

          cat > "$out/System/Library/Frameworks/Security.framework/Headers/Security.h" <<'EOF'
          #ifndef _SECURITY_H_
          #define _SECURITY_H_
          #include <Security/SecBase.h>
          #include <Security/SecCertificate.h>
          #include <Security/SecItem.h>
          #include <Security/SecKeychain.h>
          #include <Security/SecPolicy.h>
          #include <Security/SecTask.h>
          #include <Security/SecTrust.h>
          #include <Security/SecTrustSettings.h>
          #include <Security/SecureTransport.h>
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
                - _CFArrayGetValueAtIndex
                - _CFArrayAppendValue
                - _CFArrayCreate
                - _CFArrayCreateMutable
                - _CFArrayInsertValueAtIndex
                - _CFArrayRemoveAllValues
                - _CFArraySetValueAtIndex
                - _CFBooleanGetTypeID
                - _CFBooleanGetValue
                - _CFBundleCopyExecutableURL
                - _CFBundleCreate
                - _CFBundleGetIdentifier
                - _CFBundleGetValueForInfoDictionaryKey
                - _CFCopyTypeIDDescription
                - _CFDataGetBytePtr
                - _CFDataGetBytes
                - _CFDataGetLength
                - _CFDataGetTypeID
                - _CFDictionaryAddValue
                - _CFDictionaryContainsKey
                - _CFDictionaryCreate
                - _CFDictionaryCreateMutable
                - _CFDictionaryGetValue
                - _CFDictionaryGetValueIfPresent
                - _CFDictionarySetValue
                - _CFEqual
                - _CFGetTypeID
                - _CFLocaleCreateCanonicalLanguageIdentifierFromString
                - _CFNumberCreate
                - _CFNumberGetTypeID
                - _CFNumberGetValue
                - _CFRelease
                - _CFRetain
                - _CFRunLoopAddSource
                - _CFRunLoopGetCurrent
                - _CFRunLoopIsWaiting
                - _CFRunLoopRemoveSource
                - _CFRunLoopRun
                - _CFRunLoopSourceCreate
                - _CFRunLoopSourceSignal
                - _CFRunLoopStop
                - _CFRunLoopWakeUp
                - _CFStringCreateWithCString
                - _CFStringCreateWithBytes
                - _CFStringCreateCopy
                - _CFStringCompare
                - _CFStringGetBytes
                - _CFStringGetCString
                - _CFStringGetCStringPtr
                - _CFStringGetLength
                - _CFStringGetMaximumSizeForEncoding
                - _CFStringGetTypeID
                - _CFStringHasPrefix
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
                - _kCFAllocatorSystemDefault
                - _kCFBooleanTrue
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

          Boolean UTTypeEqual(CFStringRef inUTI1, CFStringRef inUTI2);
          Boolean UTTypeConformsTo(CFStringRef inUTI, CFStringRef inConformsToUTI);
          CFStringRef UTTypeCopyDescription(CFStringRef inUTI);
          CFStringRef UTTypeCreatePreferredIdentifierForTag(
            CFStringRef inTagClass,
            CFStringRef inTag,
            CFStringRef inConformingToUTI
          );
          CFStringRef UTTypeCopyPreferredTagWithClass(
            CFStringRef inUTI,
            CFStringRef inTagClass
          );
          CF_EXPORT const CFStringRef kUTTypeApplication;
          CF_EXPORT const CFStringRef kUTTypeVolume;
          CF_EXPORT const CFStringRef kUTTypeFolder;
          CF_EXPORT const CFStringRef kUTTypeXML;
          CF_EXPORT const CFStringRef kUTTagClassMIMEType;
          CF_EXPORT const CFStringRef kUTTagClassFilenameExtension;

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
          void FSEventStreamScheduleWithRunLoop(
            FSEventStreamRef streamRef,
            CFRunLoopRef runLoop,
            CFStringRef runLoopMode
          );
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
                - _FSEventStreamScheduleWithRunLoop
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

          # Dawn maps WebGPU multiplanar formats to CoreVideo's public pixel
          # format codes. The production sources use only these ABI constants,
          # but Bazel still links the framework as part of the Apple backend.
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
          cat > "$out/System/Library/Frameworks/CoreVideo.framework/Headers/CoreVideo.h" <<'EOF'
          #ifndef _AOS_COREVIDEO_H_
          #define _AOS_COREVIDEO_H_
          #include <CoreVideo/CVPixelBuffer.h>
          #endif
          EOF
          cat > "$out/System/Library/Frameworks/CoreVideo.framework/CoreVideo.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/System/Library/Frameworks/CoreVideo.framework/Versions/A/CoreVideo'
          current-version: 1.8.0
          compatibility-version: 1.2.0
          reexported-libraries:
            - targets: [ x86_64-macos, arm64-macos ]
              libraries: [ '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation' ]
          ...
          EOF
          ln -s ../../CoreVideo.tbd \
            "$out/System/Library/Frameworks/CoreVideo.framework/Versions/A/CoreVideo.tbd"
          ln -s CoreVideo.tbd \
            "$out/System/Library/Frameworks/CoreVideo.framework/Versions/A/CoreVideo"

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
          ...
          EOF
          ln -s ../../Metal.tbd \
            "$out/System/Library/Frameworks/Metal.framework/Versions/A/Metal.tbd"
          ln -s Metal.tbd \
            "$out/System/Library/Frameworks/Metal.framework/Versions/A/Metal"

          # QuartzCore owns the layer which presents Metal drawables. Dawn's
          # backend needs only the public CALayer/CAMetalLayer contract, while
          # all GPU objects remain declared and linked by Metal itself.
          cat > "$out/System/Library/Frameworks/QuartzCore.framework/Headers/CALayer.h" <<'EOF'
          #ifndef _AOS_QUARTZCORE_CALAYER_H_
          #define _AOS_QUARTZCORE_CALAYER_H_

          #import <Foundation/Foundation.h>

          typedef struct CGSize {
            double width;
            double height;
          } CGSize;

          @interface CALayer : NSObject
          + (instancetype)layer;
          @property(getter=isOpaque) BOOL opaque;
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
          #endif
          EOF
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
                - '/System/Library/Frameworks/Metal.framework/Versions/A/Metal'
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols:
                - '_OBJC_CLASS_$_CALayer'
                - '_OBJC_CLASS_$_CAMetalLayer'
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
          #include <dispatch/dispatch.h>

          #define NS_ENUM(_type, _name) CF_ENUM(_type, _name)
          #define NS_OPTIONS(_type, _name) CF_OPTIONS(_type, _name)
          #define NS_INLINE static inline

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
          typedef NSUInteger NSStringEncoding;
          enum { NSUTF8StringEncoding = 4 };

          @interface NSString : NSObject
          + (instancetype)stringWithUTF8String:(const char *)bytes;
          - (instancetype)initWithUTF8String:(const char *)bytes;
          - (instancetype)initWithData:(NSData *)data encoding:(NSStringEncoding)encoding;
          - (const char *)UTF8String;
          - (const char *)cStringUsingEncoding:(NSStringEncoding)encoding;
          - (NSData *)dataUsingEncoding:(NSStringEncoding)encoding;
          - (NSComparisonResult)compare:(NSString *)string;
          - (NSComparisonResult)caseInsensitiveCompare:(NSString *)string;
          @end

          @interface NSData : NSObject
          @end

          @interface NSNumber : NSObject
          + (NSNumber *)numberWithBool:(BOOL)value;
          + (NSNumber *)numberWithUnsignedChar:(unsigned char)value;
          + (NSNumber *)numberWithShort:(short)value;
          + (NSNumber *)numberWithUnsignedShort:(unsigned short)value;
          + (NSNumber *)numberWithLong:(long)value;
          + (NSNumber *)numberWithUnsignedLong:(unsigned long)value;
          + (NSNumber *)numberWithLongLong:(long long)value;
          + (NSNumber *)numberWithUnsignedLongLong:(unsigned long long)value;
          + (NSNumber *)numberWithDouble:(double)value;
          - (BOOL)boolValue;
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
          @property(readonly) ObjectType firstObject;
          @end

          @interface NSMutableArray<ObjectType> : NSArray<ObjectType>
          + (instancetype)arrayWithCapacity:(NSUInteger)numItems;
          - (void)addObject:(ObjectType)anObject;
          @end

          @interface NSDictionary<KeyType, ObjectType> : NSObject
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

          @interface NSUserDefaults : NSObject
          + (NSUserDefaults *)standardUserDefaults;
          - (id)objectForKey:(NSString *)defaultName;
          - (void)setObject:(id)value forKey:(NSString *)defaultName;
          - (void)removeObjectForKey:(NSString *)defaultName;
          - (BOOL)synchronize;
          @end

          @interface NSURL : NSObject
          + (NSURL *)fileURLWithPath:(NSString *)path;
          @end

          @interface NSBundle : NSObject
          + (NSBundle *)mainBundle;
          + (NSBundle *)bundleWithURL:(NSURL *)url;
          @property(readonly, copy) NSString *bundleIdentifier;
          @property(readonly, copy) NSString *bundlePath;
          - (id)objectForInfoDictionaryKey:(NSString *)key;
          @end

          typedef struct {
            NSInteger majorVersion;
            NSInteger minorVersion;
            NSInteger patchVersion;
          } NSOperatingSystemVersion;

          @interface NSProcessInfo : NSObject
          + (NSProcessInfo *)processInfo;
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
          NSArray<NSString *> *NSSearchPathForDirectoriesInDomains(
            NSSearchPathDirectory directory,
            NSSearchPathDomainMask domainMask,
            BOOL expandTilde
          );

          #endif
          EOF
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

          cat > "$out/System/Library/Frameworks/AppKit.framework/Headers/AppKit.h" <<'EOF'
          #ifndef _AOS_APPKIT_H_
          #define _AOS_APPKIT_H_

          #import <Foundation/Foundation.h>

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

          cat > "$out/System/Library/Frameworks/Cocoa.framework/Headers/Cocoa.h" <<'EOF'
          #ifndef _AOS_COCOA_H_
          #define _AOS_COCOA_H_
          #import <Foundation/Foundation.h>
          #import <AppKit/AppKit.h>
          #endif
          EOF

          cat > "$out/System/Library/Frameworks/Foundation.framework/Foundation.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation'
          current-version: 3100.0.0
          compatibility-version: 300.0.0
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols:
                - _NSSearchPathForDirectoriesInDomains
                - '_OBJC_CLASS_$_NSArray'
                - '_OBJC_CLASS_$_NSData'
                - '_OBJC_CLASS_$_NSBundle'
                - '_OBJC_CLASS_$_NSDictionary'
                - '_OBJC_CLASS_$_NSEnumerator'
                - '_OBJC_CLASS_$_NSAutoreleasePool'
                - '_OBJC_CLASS_$_NSMutableArray'
                - '_OBJC_CLASS_$_NSMutableDictionary'
                - '_OBJC_CLASS_$_NSNumber'
                - '_OBJC_CLASS_$_NSObject'
                - '_OBJC_CLASS_$_NSProcessInfo'
                - '_OBJC_CLASS_$_NSString'
                - '_OBJC_CLASS_$_NSURL'
                - '_OBJC_CLASS_$_NSUserDefaults'
                - '_OBJC_METACLASS_$_NSObject'
          ...
          EOF
          ln -s ../../Foundation.tbd \
            "$out/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation.tbd"
          ln -s Foundation.tbd \
            "$out/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation"

          cat > "$out/System/Library/Frameworks/AppKit.framework/AppKit.tbd" <<'EOF'
          --- !tapi-tbd
          tbd-version: 4
          targets: [ x86_64-macos, arm64-macos ]
          install-name: '/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit'
          current-version: 2600.0.0
          compatibility-version: 45.0.0
          reexported-libraries:
            - targets: [ x86_64-macos, arm64-macos ]
              libraries: [ '/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation' ]
            - targets: [ x86_64-macos, arm64-macos ]
              libraries: [ '/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices' ]
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols:
                - '_OBJC_CLASS_$_NSImage'
                - '_OBJC_CLASS_$_NSUserNotification'
                - '_OBJC_CLASS_$_NSUserNotificationCenter'
                - '_OBJC_PROTOCOL_$_NSUserNotificationCenterDelegate'
          ...
          EOF
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

          # GLib and other command-line clients use the public LaunchServices
          # API through the ApplicationServices umbrella. Keep the canonical
          # source and ABI surface, including the compatibility declarations
          # retained by Apple's SDK, without importing a binary framework.
          cat > "$out/System/Library/Frameworks/ApplicationServices.framework/Headers/ApplicationServices.h" <<'EOF'
          #ifndef __APPLICATIONSERVICES__
          #define __APPLICATIONSERVICES__

          #include <CoreFoundation/CoreFoundation.h>

          CF_EXTERN_C_BEGIN
          typedef UInt32 LSLaunchFlags;
          enum { kLSLaunchDefaults = 0x00000001 };

          typedef UInt32 LSRolesMask;
          enum { kLSRolesAll = 0xffffffffU };

          enum {
            kLSUnknownCreator = 0,
            kLSApplicationNotFoundErr = -10814
          };

          typedef struct AEDesc AEDesc;
          typedef struct FSRef { UInt8 hidden[80]; } FSRef;

          typedef struct LSLaunchURLSpec {
            CFURLRef appURL;
            CFArrayRef itemURLs;
            const AEDesc *passThruParams;
            LSLaunchFlags launchFlags;
            void *asyncRefCon;
          } LSLaunchURLSpec;

          CFArrayRef LSCopyApplicationURLsForBundleIdentifier(
            CFStringRef bundleIdentifier,
            CFErrorRef *error
          );
          OSStatus LSFindApplicationForInfo(
            OSType creator,
            CFStringRef bundleIdentifier,
            CFStringRef name,
            FSRef *applicationRef,
            CFURLRef *applicationURL
          );
          OSStatus LSOpenFromURLSpec(const LSLaunchURLSpec *urlSpec, CFURLRef *launchedURL);
          CF_EXPORT OSStatus LSOpenCFURLRef(CFURLRef inURL, CFURLRef *outLaunchedURL);
          CFArrayRef LSCopyAllHandlersForURLScheme(CFStringRef scheme);
          CFArrayRef LSCopyAllRoleHandlersForContentType(
            CFStringRef contentType,
            LSRolesMask roles
          );
          CFURLRef LSCopyDefaultApplicationURLForContentType(
            CFStringRef contentType,
            LSRolesMask roles,
            CFErrorRef *error
          );
          CFStringRef LSCopyDefaultRoleHandlerForContentType(
            CFStringRef contentType,
            LSRolesMask roles
          );
          CFStringRef LSCopyDefaultHandlerForURLScheme(CFStringRef scheme);
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
          reexported-libraries:
            - targets: [ x86_64-macos, arm64-macos ]
              libraries: [ '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation' ]
          exports:
            - targets: [ x86_64-macos, arm64-macos ]
              symbols:
                - _LSCopyAllHandlersForURLScheme
                - _LSCopyAllRoleHandlersForContentType
                - _LSCopyApplicationURLsForBundleIdentifier
                - _LSCopyDefaultApplicationURLForContentType
                - _LSCopyDefaultHandlerForURLScheme
                - _LSCopyDefaultRoleHandlerForContentType
                - _LSFindApplicationForInfo
                - _LSOpenCFURLRef
                - _LSOpenFromURLSpec
                - _UTTypeConformsTo
                - _UTTypeCopyDescription
                - _UTTypeCopyPreferredTagWithClass
                - _UTTypeCreatePreferredIdentifierForTag
                - _UTTypeEqual
                - _kUTTagClassFilenameExtension
                - _kUTTagClassMIMEType
                - _kUTTypeApplication
                - _kUTTypeFolder
                - _kUTTypeVolume
                - _kUTTypeXML
          ...
          EOF
          ln -s ../../ApplicationServices.tbd \
            "$out/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices.tbd"
          ln -s ApplicationServices.tbd \
            "$out/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices"

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
                - _SSLClose
                - _SSLCopyPeerTrust
                - _SSLCreateContext
                - _SSLHandshake
                - _SSLRead
                - _SSLSetConnection
                - _SSLSetIOFuncs
                - _SSLSetPeerDomainName
                - _SSLSetProtocolVersionMax
                - _SSLSetProtocolVersionMin
                - _SSLSetSessionOption
                - _SSLWrite
                - _SecCertificateCopyData
                - _SecCopyErrorMessageString
                - _SecItemCopyMatching
                - _SecKeychainAddGenericPassword
                - _SecKeychainCopyDefault
                - _SecKeychainFindGenericPassword
                - _SecKeychainItemDelete
                - _SecKeychainItemFreeContent
                - _SecKeychainItemModifyAttributesAndData
                - _SecTaskCopySigningIdentifier
                - _SecTaskCopyValueForEntitlement
                - _SecTaskCopyValuesForEntitlements
                - _SecTaskCreateFromSelf
                - _SecTaskCreateWithAuditToken
                - _SecTaskGetTypeID
                - _SecPolicyCopyProperties
                - _SecPolicyCreateSSL
                - _SecTrustCreateWithCertificates
                - _SecTrustEvaluate
                - _SecTrustEvaluateWithError
                - _SecTrustGetCertificateAtIndex
                - _SecTrustSettingsCopyTrustSettings
                - _kSecClass
                - _kSecClassCertificate
                - _kSecMatchLimit
                - _kSecMatchLimitAll
                - _kSecPolicyAppleSSL
                - _kSecPolicyOid
                - _kSecReturnRef
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
                - _class_copyProtocolList
                - _class_getClassMethod
                - _class_getInstanceMethod
                - _class_getInstanceSize
                - _class_getInstanceVariable
                - _class_getName
                - _class_getProperty
                - _class_getSuperclass
                - _class_isMetaClass
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
                - _objc_copyClassList
                - _objc_copyProtocolList
                - _objc_copyWeak
                - _objc_destroyWeak
                - _objc_disposeClassPair
                - _objc_enumerationMutation
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
                - _objc_registerProtocol
                - _objc_release
                - _objc_retain
                - _objc_retainAutoreleaseReturnValue
                - _objc_retainAutoreleasedReturnValue
                - _objc_storeStrong
                - _objc_storeWeak
                - _object_getClass
                - _object_setClass
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
