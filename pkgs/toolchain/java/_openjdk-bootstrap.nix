##! Shared builder for intermediate OpenJDK bootstrap compilers.
##! Underscore prefix = not auto-discovered. Imported by openjdk-N.nix files.
{
  stdenv,
  buildPackages,
  fetchurl,
  mkDerivation,
  gnumake,
  autoconf,
  bash,
  which,
  zip,
  unzip,
  gawk,
  coreutils,
  zlib,
  alsa-lib,
  binutils,
  cups,
  file,
  fontconfig,
  freetype,
  xorg-stubs,
  bootstrapTools,
  krb5 ? null,
}: {
  major,
  version,
  build,
  srcHash,
  prevJdk,
  repoSuffix ? "u",
  extraConfigureFlags ? [],
  extraBuildDeps ? [],
  extraDarwinFrameworks ? [],
  extraPatches ? [],
  # Override build parallelism (defaults to $NIX_BUILD_CORES).
  # Useful when the boot JDK has javac concurrency bugs.
  buildJobs ? null,
}: let
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  buildTools =
    if isDarwinCross
    then buildPackages
    else {
      inherit
        gnumake
        autoconf
        bash
        which
        zip
        unzip
        gawk
        coreutils
        binutils
        file
        ;
    };
  bootJdk =
    if isDarwinCross
    then builtins.getAttr "openjdk-${toString (major - 1)}" buildPackages
    else prevJdk;
  buildJdk =
    if isDarwinCross
    then builtins.getAttr "openjdk-${toString major}" buildPackages
    else null;
  nativeMig =
    if isDarwinCross
    then
      import ./_darwin-mig.nix {
        inherit fetchurl buildPackages;
      }
    else null;
  tag = "jdk-${version}+${build}";
  repo = "jdk${toString major}${repoSuffix}";
  jobsExpr =
    if buildJobs != null
    then toString buildJobs
    else "$NIX_BUILD_CORES";
  # JDK 9/10 interpret --with-freetype as a filesystem prefix; the bundled/system
  # selector was introduced in JDK 11. Use the target AOS library on older ports.
  darwinFreetypeFlags =
    if major <= 10
    then "--with-freetype-include=${freetype}/include/freetype2 --with-freetype-lib=${freetype}/lib"
    else "--with-freetype=bundled";
  # Their Clang setup predates the compiler's C++17 default and requires the
  # same GNU C++98 dialect that the GCC path already selects upstream.
  darwinLegacyCxxFlag =
    if major <= 10
    then "-std=gnu++98"
    else "";
  darwinFrameworkFlags = builtins.concatStringsSep " " (
    builtins.map (
      framework: "-F${framework}/Library/Frameworks"
    )
    extraDarwinFrameworks
  );
  darwinFrameworkRpathFlags = builtins.concatStringsSep " " (
    builtins.map (
      framework: "-Wl,-rpath,${framework}/Library/Frameworks"
    )
    extraDarwinFrameworks
  );
  darwinKrb5 =
    if isDarwinCross
    then assert krb5 != null; krb5
    else "";
  jdkTreePrefix =
    if major == 9
    then "jdk/"
    else "";
  hotspotTreePrefix =
    if major == 9
    then "hotspot/"
    else "";
  autoconfDir =
    if major == 9
    then "common/autoconf"
    else "make/autoconf";
  buildFlagsCpuDepAnchor =
    if major == 12
    then "\\[BUILD\\], \\[OPENJDK_BUILD_\\]"
    else "\\[BUILD\\], \\[OPENJDK_BUILD_\\], \\[BUILD_\\]";
  osxuiModernGuardPattern =
    if major == 12
    then "^ifeq ($(OPENJDK_TARGET_OS), macosx)$"
    else "^ifeq ($(call isTargetOs, macosx), true)$";
  osxuiModernGuardReplacement =
    if major == 12
    then "ifeq ($(OPENJDK_TARGET_OS)+$(ENABLE_HEADLESS_ONLY), macosx+false)"
    else "ifeq ($(call isTargetOs, macosx)+$(ENABLE_HEADLESS_ONLY), true+false)";
  osxuiModernGuardSedPattern = builtins.replaceStrings ["$("] ["\\$("] osxuiModernGuardPattern;
  osxuiModernGuardSedReplacement = builtins.replaceStrings ["$("] ["\\$("] osxuiModernGuardReplacement;
  jdk9AvailabilityMaximumNormalization =
    if isDarwinCross && major == 9
    then
      "\n"
      + ''
            # Older JDK 9 make logic encodes 10.x deployment versions by
            # removing dots. macOS 11 switched AvailabilityMacros to the
            # six-digit encoding used by Clang's deployment macro.
        test "$(grep -Fc -- \
          '-DMAC_OS_X_VERSION_MAX_ALLOWED=\$(subst .,,\$(MACOSX_VERSION_MIN))' \
          "$flagsM4")" -eq 1
        sed -i \
          's|\\\$(subst .,,\\\$(MACOSX_VERSION_MIN))|110000|' \
          "$flagsM4"
        test "$(grep -Fc -- \
          '-DMAC_OS_X_VERSION_MAX_ALLOWED=\$(subst .,,\$(MACOSX_VERSION_MIN))' \
          "$flagsM4")" -eq 0
        test "$(grep -Fc -- \
          '-DMAC_OS_X_VERSION_MAX_ALLOWED=110000' \
          "$flagsM4")" -eq 1
      ''
    else "";
  osxSecurityFoundationLink =
    if isDarwinCross && major == 12
    then
      "\n"
      + ''
          # JDK 12 asks Clang to infer the Objective-C runtime libraries.
          # With its 10.9 deployment target, current Clang consequently asks
          # for Apple's source-unavailable libarclite compatibility archive.
          # The object uses the public libobjc ABI and Foundation directly, so
          # name those canonical owners instead of invoking that inference.
        baseNativeLibraries=${jdkTreePrefix}make/lib/Lib-java.base.gmk
        test -f "$baseNativeLibraries"
        test "$(grep -Fc \
          'SetupJdkLibrary, BUILD_LIBOSXSECURITY' \
          "$baseNativeLibraries")" -eq 1
        test "$(sed -n \
          '/SetupJdkLibrary, BUILD_LIBOSXSECURITY/,/    ))/p' \
          "$baseNativeLibraries" | grep -Fc \
          '            -fobjc-link-runtime,')" -eq 1
        test "$(sed -n \
          '/SetupJdkLibrary, BUILD_LIBOSXSECURITY/,/    ))/p' \
          "$baseNativeLibraries" | grep -Fc \
          '            -lobjc -framework Foundation,')" -eq 0
        sed -i \
          '/SetupJdkLibrary, BUILD_LIBOSXSECURITY/,/    ))/ s|            -fobjc-link-runtime,|            -lobjc -framework Foundation,|' \
          "$baseNativeLibraries"
        test "$(sed -n \
          '/SetupJdkLibrary, BUILD_LIBOSXSECURITY/,/    ))/p' \
          "$baseNativeLibraries" | grep -Fc \
          '            -lobjc -framework Foundation,')" -eq 1
      ''
    else if isDarwinCross && (major == 14 || major == 16)
    then
      "\n"
      + ''
          # JDK 14 and 16's osxsecurity Objective-C object catches
          # NSException but their library lists only C frameworks. Link its
          # canonical Foundation owner directly.
        baseNativeLibraries=
        for candidate in \
          ${jdkTreePrefix}make/lib/Lib-java.base.gmk \
          ${jdkTreePrefix}make/modules/java.base/Lib.gmk; do
          if [ -f "$candidate" ] \
            && grep -Fq 'SetupJdkLibrary, BUILD_LIBOSXSECURITY' \
              "$candidate"; then
            baseNativeLibraries=$candidate
            break
          fi
        done
        test -n "$baseNativeLibraries"
        test "$(grep -Fc \
          'SetupJdkLibrary, BUILD_LIBOSXSECURITY' \
          "$baseNativeLibraries")" -eq 1
        test "$(sed -n \
          '/SetupJdkLibrary, BUILD_LIBOSXSECURITY/,/    ))/p' \
          "$baseNativeLibraries" | grep -Fc \
          '            -framework JavaNativeFoundation \')" -eq 1
        test "$(sed -n \
          '/SetupJdkLibrary, BUILD_LIBOSXSECURITY/,/    ))/p' \
          "$baseNativeLibraries" | grep -Fc \
          '            -framework Foundation \')" -eq 0
        sed -i \
          '/SetupJdkLibrary, BUILD_LIBOSXSECURITY/,/    ))/ {
            /            -framework JavaNativeFoundation \\/a\            -framework Foundation \\
          }' \
          "$baseNativeLibraries"
        test "$(sed -n \
          '/SetupJdkLibrary, BUILD_LIBOSXSECURITY/,/    ))/p' \
          "$baseNativeLibraries" | grep -Fc \
          '            -framework Foundation \')" -eq 1
      ''
    else "";
  modernPackMaskNormalization =
    if isDarwinCross && (major == 12 || major == 13)
    then ''
      packConstants=${jdkTreePrefix}src/jdk.pack/share/native/common-unpack/constants.h
      test "$(grep -Fc \
        'AO_UNUSED_MBZ             = (int)((~0U)<<13),' \
        "$packConstants")" -eq 1
      sed -i \
        's/AO_UNUSED_MBZ             = (int)((~0U)<<13),/AO_UNUSED_MBZ             = ~((1 << 13) - 1),/' \
        "$packConstants"
    ''
    else "";
  extraCfgStr = builtins.concatStringsSep " " extraConfigureFlags;
in
  mkDerivation {
    pname = "openjdk-${toString major}";
    inherit version;

    src = fetchurl {
      urls = [
        "https://github.com/openjdk/${repo}/archive/refs/tags/${tag}.tar.gz"
      ];
      hash = srcHash;
    };

    buildDeps =
      [
        buildTools.gnumake
        buildTools.autoconf
        buildTools.bash
        buildTools.which
        buildTools.zip
        buildTools.unzip
        buildTools.gawk
        buildTools.coreutils
        buildTools.binutils
        buildTools.file
        xorg-stubs
      ]
      ++ (
        if isDarwinCross
        then [nativeMig buildTools.python3 buildJdk]
        else []
      )
      ++ extraBuildDeps;
    runtimeDeps =
      [
        zlib
        fontconfig
        freetype
      ]
      ++ (
        if isDarwinCross
        then
          extraDarwinFrameworks
          ++ [darwinKrb5]
        else []
      );

    patches = extraPatches;

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd jdk*-*

          # GCC 14 makes "ordered comparison of pointer with integer zero" a hard
          # error in C++.  Fix the two occurrences in JDK 9 hotspot source.
          for f in hotspot/src/share/vm/opto/lcm.cpp src/hotspot/share/opto/lcm.cpp; do
            if [ -f "$f" ]; then
              sed -i 's/narrow_oop_base() > 0/narrow_oop_base() != (address)0/' "$f"
            fi
          done
          for f in hotspot/src/share/vm/memory/virtualspace.cpp src/hotspot/share/gc/shared/virtualspace.cpp; do
            if [ -f "$f" ]; then
              sed -i 's/base() > 0/base() != (char*)0/' "$f"
            fi
          done
          # Fix os_linux.cpp: "if (p < 0)" where p is char*
          for f in hotspot/src/os/linux/vm/os_linux.cpp src/hotspot/os/linux/os_linux.cpp; do
            if [ -f "$f" ]; then
              sed -i 's/if (p < 0)/if (p == NULL)/' "$f"
            fi
          done

          # Extend currency date range check from 10 to 20 years (builds break
          # when currency data entries exceed 10 years from build date).
          for f in \
            jdk/make/src/classes/build/tools/generatecurrencydata/GenerateCurrencyData.java \
            make/jdk/src/classes/build/tools/generatecurrencydata/GenerateCurrencyData.java; do
            if [ -f "$f" ]; then
              sed -i 's/((long) 10) \* 365/((long) 20) * 365/; s/more than 10 years/more than 20 years/' "$f"
            fi
          done

          # Fix DependOnVariable for GNU Make 4.3+ compatibility (JDK-8237879).
          # Replace $(eval -include ...) with $(if $(wildcard ...),$(eval include ...))
          # This was fixed upstream in JDK 11.0.8+ but never backported to JDK 9/10.
          if [ -f make/common/MakeBase.gmk ]; then
            sed -i 's/$(eval -include $(call DependOnVariableFileName, $1, $2))/$(if $(wildcard $(call DependOnVariableFileName, $1, $2)),$(eval include $(call DependOnVariableFileName, $1, $2)))/' make/common/MakeBase.gmk
          fi
        '';
      }
      {
        name = "configure";
        script =
          if isDarwinCross
          then ''
                        # flags-cflags computes OS definitions once from the Darwin target,
                        # then reuses them while compiling the native Linux BuildJDK. Keep
                        # the upstream build/target source split and correct the build-side
                        # definitions before its BUILD flag set is materialized.
                        flagsCflags=${autoconfDir}/flags-cflags.m4
                        if [ -f "$flagsCflags" ]; then
                          sed -i \
                            '/^  FLAGS_SETUP_CFLAGS_CPU_DEP(${buildFlagsCpuDepAnchor})$/i\
              if test "x$OPENJDK_BUILD_OS" = xlinux; then\
                CFLAGS_OS_DEF_JVM="-DLINUX -D_FILE_OFFSET_BITS=64"\
                CFLAGS_OS_DEF_JDK="-D_GNU_SOURCE -D_REENTRANT -D_FILE_OFFSET_BITS=64 -DLINUX"\
              else\
                AC_MSG_ERROR([AOS Darwin cross BuildJDK requires a Linux build OS])\
              fi\
            ' "$flagsCflags"
                          test "$(grep -c 'AOS Darwin cross BuildJDK requires' "$flagsCflags")" -eq 1
                        else
                          # JDK 10 keeps the equivalent flag setup in flags.m4.
                          # Its helper is parameterized by BUILD/TARGET and already
                          # derives the Linux BuildJDK definitions from
                          # OPENJDK_BUILD_OS, so no target-definition override is
                          # needed. Fail closed if that source contract changes.
                          flagsM4=${autoconfDir}/flags.m4
                          test -f "$flagsM4"
                          test "$(grep -Fc \
                            'FLAGS_SETUP_COMPILER_FLAGS_FOR_JDK_HELPER([BUILD], [OPENJDK_BUILD_])' \
                            "$flagsM4")" -eq 1
                          test "$(grep -Fc \
                            'if test "x$OPENJDK_$1_OS" = xlinux; then' \
                            "$flagsM4")" -ge 1
                          # These releases do not select a C++ dialect for the
                          # Clang HotSpot path. Keep their pre-C++11 source in
                          # the dialect used by their upstream GCC path.
                          test "$(grep -Fc \
                            '$2JVM_CFLAGS="[$]$2JVM_CFLAGS -flimit-debug-info"' \
                            "$flagsM4")" -eq 1
                          sed -i \
                            '/\$2JVM_CFLAGS="\[\$\]\$2JVM_CFLAGS -flimit-debug-info"/a\    $2JVM_CFLAGS="[$]$2JVM_CFLAGS -std=gnu++98"' \
                            "$flagsM4"
                          test "$(grep -Fc \
                            '$2JVM_CFLAGS="[$]$2JVM_CFLAGS -std=gnu++98"' \
                            "$flagsM4")" -eq 1
                          # JDK 9/10 still select Apple's removed libstdc++ for
                          # every Clang link. Retain it for the native Linux
                          # BuildJDK, but use Darwin's libc++ ABI for the target.
                          test "$(grep -Fc \
                            '$2JVM_LDFLAGS="[$]$2JVM_LDFLAGS -mno-omit-leaf-frame-pointer -mstack-alignment=16 -stdlib=libstdc++ -fPIC"' \
                            "$flagsM4")" -eq 1
                    sed -i \
                      '/\$2JVM_LDFLAGS="\[\$\]\$2JVM_LDFLAGS -mno-omit-leaf-frame-pointer -mstack-alignment=16 -stdlib=libstdc++ -fPIC"/c\      if test "x$OPENJDK_$1_OS" = xmacosx; then $2JVM_LDFLAGS="[$]$2JVM_LDFLAGS -mno-omit-leaf-frame-pointer -mstack-alignment=16 -stdlib=libc++ -fPIC"; else $2JVM_LDFLAGS="[$]$2JVM_LDFLAGS -mno-omit-leaf-frame-pointer -mstack-alignment=16 -stdlib=libstdc++ -fPIC"; fi' \
                      "$flagsM4"
                          test "$(grep -Fc -- '-stdlib=libc++ -fPIC' "$flagsM4")" -eq 1
                          test "$(grep -Fc -- '-stdlib=libstdc++ -fPIC' "$flagsM4")" -eq 1
                          # Match the public SDK/runtime deployment baseline.
                          # The obsolete 10.7 setting asks modern Clang for
                          # crt1.10.6.o, which Apple no longer ships.
                          test "$(grep -Fc 'MACOSX_VERSION_MIN=10.7.0' "$flagsM4")" -eq 1
                          sed -i 's/MACOSX_VERSION_MIN=10.7.0/MACOSX_VERSION_MIN=11.0.0/' \
                            "$flagsM4"
                          test "$(grep -Fc 'MACOSX_VERSION_MIN=11.0.0' "$flagsM4")" -eq 1${jdk9AvailabilityMaximumNormalization}
                        fi
                        # Older source archives include a generated configure script,
                        # but their wrapper only refreshes it inside a Mercurial checkout.
                        # Newer archives removed autogen.sh and their top-level configure
                        # generates build/.configure-support/generated-configure.sh on
                        # every clean build. In both layouts, ensure the cross-role flag
                        # fixes above are represented in the configure result.
                        if [ -f ${autoconfDir}/autogen.sh ]; then
                          $CONFIG_SHELL ${autoconfDir}/autogen.sh
                        else
                          test -f ${autoconfDir}/configure
                          test -f ${autoconfDir}/configure.ac
                          test ! -e build/.configure-support/generated-configure.sh
                        fi

                        # Modern Clang rejects the legacy implicit signed-to-
                        # unsigned narrowing in the retained HotSpot gtest.
                        # Keep the test enabled and make its intended all-ones
                        # value explicit.
                        alignTest=test/hotspot/gtest/utilities/test_align.cpp
                        if [ -f "$alignTest" ]; then
                          if grep -Fq ', -1 };' "$alignTest"; then
                            test "$(grep -Fc ', -1 };' "$alignTest")" -eq 1
                            sed -i 's/, -1 };/, uint64_t(-1) };/' "$alignTest"
                            test "$(grep -Fc ', uint64_t(-1) };' "$alignTest")" -eq 1
                          else
                            test "$(grep -Fc 'uint64_t(-1)' "$alignTest")" -ge 1
                          fi
                        fi

                        # The serviceability agent runs MIG over XNU's source
                        # definition, which is not an installed SDK header.
                        # Consume the exact pinned copy carried by the private
                        # native MIG package without publishing that build tool.
                        saGensrc=
                        for candidate in \
                          ${jdkTreePrefix}make/modules/jdk.hotspot.agent/Gensrc.gmk \
                          ${hotspotTreePrefix}make/gensrc/Gensrc-jdk.hotspot.agent.gmk; do
                          if [ -f "$candidate" ]; then
                            test -z "$saGensrc"
                            saGensrc=$candidate
                          fi
                        done
                        if [ -n "$saGensrc" ]; then
                          expectedMigDefs=2
                          sysrootMachDefs=$(grep -Fc \
                            '$(SYSROOT)/usr/include/mach/mach_exc.defs' \
                            "$saGensrc" || true)
                          sdkrootMachDefs=$(grep -Fc \
                            '$(SDKROOT)/usr/include/mach/mach_exc.defs' \
                            "$saGensrc" || true)
                          if [ "$sysrootMachDefs" -eq 2 ] \
                            && [ "$sdkrootMachDefs" -eq 0 ]; then
                            sed -i \
                              's|$(SYSROOT)/usr/include/mach/mach_exc.defs|${nativeMig}/share/mig/mach/mach_exc.defs|g' \
                              "$saGensrc"
                          elif [ "$sysrootMachDefs" -eq 0 ] \
                            && [ "$sdkrootMachDefs" -eq 2 ]; then
                            sed -i \
                              's|$(SDKROOT)/usr/include/mach/mach_exc.defs|${nativeMig}/share/mig/mach/mach_exc.defs|g' \
                              "$saGensrc"
                          elif [ "$sysrootMachDefs" -eq 0 ] \
                            && [ "$sdkrootMachDefs" -eq 0 ]; then
                            # JDK 9/10 carry this generated-source file but do
                            # not invoke MIG at all. Accept that older source
                            # contract only while neither a MIG command nor a
                            # mach_exc input has appeared.
                            ! grep -Eq '\$\(MIG\)|mach_exc\.defs' "$saGensrc"
                            expectedMigDefs=0
                          else
                            echo "OpenJDK ${toString major} has an unknown Darwin MIG input" >&2
                            exit 1
                          fi
                          test "$(grep -Fc \
                            '${nativeMig}/share/mig/mach/mach_exc.defs' \
                            "$saGensrc")" -eq "$expectedMigDefs"
                        fi

                        # OpenJDK's macOS credential-cache bridge uses the
                        # public MIT krb5 and com_err APIs, but upstream selects
                        # them through Apple's legacy Kerberos umbrella. Use the
                        # target AOS krb5 headers and libraries on every release
                        # while retaining the native credential-cache bridge.
                        nativeCcache=${jdkTreePrefix}src/java.security.jgss/macosx/native/libosxkrb5/nativeccache.c
                        test "$(grep -Fc '#import <Kerberos/Kerberos.h>' \
                          "$nativeCcache")" -eq 1
                        sed -i \
                          's|#import <Kerberos/Kerberos.h>|#include <krb5.h>\n#include <com_err.h>|' \
                          "$nativeCcache"
                        test "$(grep -Fc '#include <krb5.h>' "$nativeCcache")" -eq 1
                        test "$(grep -Fc '#include <com_err.h>' "$nativeCcache")" -eq 1

                        legacySecurityLibraries=${jdkTreePrefix}make/lib/Lib-java.security.jgss.gmk
                        modernSecurityLibraries=${jdkTreePrefix}make/modules/java.security.jgss/Lib.gmk
                        if [ -f "$legacySecurityLibraries" ] \
                          && grep -Fq 'BUILD_LIBKRB5_NAME := osxkrb5' \
                            "$legacySecurityLibraries"; then
                          securityLibraries=$legacySecurityLibraries
                          test "$(grep -Fc '    BUILD_LIBKRB5_NAME := osxkrb5' \
                            "$securityLibraries")" -eq 1
                          test "$(grep -Fc -- '-framework Kerberos' \
                            "$securityLibraries")" -eq 1
                          sed -i \
                            's|-framework Kerberos|-L${darwinKrb5}/lib -lkrb5 -lk5crypto -lcom_err|' \
                            "$securityLibraries"
                        else
                          securityLibraries=
                          for candidate in \
                            "$modernSecurityLibraries" \
                            "$legacySecurityLibraries"; do
                            if [ -f "$candidate" ] \
                              && grep -Fq 'SetupJdkLibrary, BUILD_LIBOSXKRB5' \
                                "$candidate"; then
                              securityLibraries=$candidate
                              break
                            fi
                          done
                          if [ -z "$securityLibraries" ]; then
                            echo "OpenJDK ${toString major} has no Darwin GSS native library definition" >&2
                            exit 1
                          fi
                          test "$(grep -Fc '        NAME := osxkrb5,' \
                            "$securityLibraries")" -eq 1
                          test "$(grep -Fc -- '-framework Kerberos' \
                            "$securityLibraries")" -eq 1
                          sed -i \
                            '/SetupJdkLibrary, BUILD_LIBOSXKRB5/,/    ))/ s|-framework Kerberos|-L${darwinKrb5}/lib -lkrb5 -lk5crypto -lcom_err|' \
                            "$securityLibraries"
                        fi
                        test "$(grep -Fc -- \
                          '-L${darwinKrb5}/lib -lkrb5 -lk5crypto -lcom_err' \
                          "$securityLibraries")" -eq 1
                        if grep -Fq \
                          '            $(addprefix -I, $(BUILD_LIBKRB5_SRC)) \' \
                          "$securityLibraries"; then
                          test "$(grep -Fc \
                            '            $(addprefix -I, $(BUILD_LIBKRB5_SRC)) \' \
                            "$securityLibraries")" -eq 1
                          sed -i \
                            '/            $(addprefix -I, $(BUILD_LIBKRB5_SRC)) \\/a\            -I${darwinKrb5}/include \\' \
                            "$securityLibraries"
                        elif grep -Fq '        CFLAGS := $(CFLAGS_JDKLIB),' \
                          "$securityLibraries"; then
                          sed -i \
                            '/SetupJdkLibrary, BUILD_LIBOSXKRB5/,/    ))/ s|CFLAGS := $(CFLAGS_JDKLIB),|CFLAGS := $(CFLAGS_JDKLIB) -I${darwinKrb5}/include,|' \
                            "$securityLibraries"
                        else
                          sed -i \
                            '/SetupJdkLibrary, BUILD_LIBOSXKRB5/,/    ))/ {
                              /        OPTIMIZATION := LOW, \\/a\        CFLAGS := $(CFLAGS_JDKLIB) -I${darwinKrb5}/include, \\
                            }' \
                            "$securityLibraries"
                        fi
                        test "$(grep -Fc -- '-I${darwinKrb5}/include' \
                          "$securityLibraries")" -eq 1${osxSecurityFoundationLink}

                        # macOS always implements JAWT through libawt_lwawt;
                        # it deliberately does not build the Unix
                        # libawt_headless. Upstream nevertheless adds the Unix
                        # dependency when a headless image is selected.
                        awtLibraries=
                        for candidate in \
                          ${jdkTreePrefix}make/modules/java.desktop/lib/AwtLibraries.gmk \
                          ${jdkTreePrefix}make/modules/java.desktop/lib/Awt2dLibraries.gmk \
                          ${jdkTreePrefix}make/lib/Awt2dLibraries.gmk; do
                          if [ -f "$candidate" ]; then
                            awtLibraries=$candidate
                            break
                          fi
                        done
                        test -n "$awtLibraries"
                        if grep -Fq \
                          '    $(BUILD_LIBJAWT): $(call FindLib, $(MODULE), awt_headless)' \
                          "$awtLibraries"; then
                          test "$(grep -Fc \
                            '    $(BUILD_LIBJAWT): $(call FindLib, $(MODULE), awt_headless)' \
                            "$awtLibraries")" -eq 1
                          sed -i \
                            '/$(BUILD_LIBJAWT): $(BUILD_LIBAWT_XAWT)/,/^  endif$/ s/^  else$/  else ifeq ($(call isTargetOs, macosx), false)/' \
                            "$awtLibraries"
                          test "$(grep -Fc \
                            '  else ifeq ($(call isTargetOs, macosx), false)' \
                            "$awtLibraries")" -eq 1
                        elif grep -Fq \
                          '    $(BUILD_LIBJAWT): $(INSTALL_LIBRARIES_HERE)/$(LIBRARY_PREFIX)awt_headless$(SHARED_LIBRARY_SUFFIX)' \
                          "$awtLibraries"; then
                          test "$(grep -Fc \
                            '    $(BUILD_LIBJAWT): $(INSTALL_LIBRARIES_HERE)/$(LIBRARY_PREFIX)awt_headless$(SHARED_LIBRARY_SUFFIX)' \
                            "$awtLibraries")" -eq 1
                          sed -i \
                            's|    $(BUILD_LIBJAWT): $(INSTALL_LIBRARIES_HERE)/$(LIBRARY_PREFIX)awt_headless$(SHARED_LIBRARY_SUFFIX)|    $(BUILD_LIBJAWT): $(if $(filter macosx,$(OPENJDK_TARGET_OS)),,$(INSTALL_LIBRARIES_HERE)/$(LIBRARY_PREFIX)awt_headless$(SHARED_LIBRARY_SUFFIX))|' \
                            "$awtLibraries"
                          test "$(grep -Fc \
                            '    $(BUILD_LIBJAWT): $(if $(filter macosx,$(OPENJDK_TARGET_OS)),,$(INSTALL_LIBRARIES_HERE)/$(LIBRARY_PREFIX)awt_headless$(SHARED_LIBRARY_SUFFIX))' \
                            "$awtLibraries")" -eq 1
                        fi

                        # The macOS AWT library compiles the shared Unix CUPS
                        # bridge, but does not consume the configured CUPS flags.
                        # Keep printing enabled with the explicit target package.
                        awtNativeLibraries=
                        for candidate in \
                          ${jdkTreePrefix}make/modules/java.desktop/lib/AwtLibraries.gmk \
                          ${jdkTreePrefix}make/modules/java.desktop/lib/Awt2dLibraries.gmk \
                          ${jdkTreePrefix}make/lib/Awt2dLibraries.gmk; do
                          if [ -f "$candidate" ] \
                            && grep -Eq \
                              '^  LIBAWT_LWAWT_CFLAGS .*=|SetupJdkLibrary, BUILD_LIBAWT_LWAWT' \
                              "$candidate"; then
                            awtNativeLibraries=$candidate
                            break
                          fi
                        done
                        test -n "$awtNativeLibraries"
                        if grep -Fq '  LIBAWT_LWAWT_CFLAGS := \' \
                          "$awtNativeLibraries"; then
                          test "$(grep -Fc '  LIBAWT_LWAWT_CFLAGS := \' \
                            "$awtNativeLibraries")" -eq 1
                          if ! grep -Fq '      -I${cups}/include \' \
                            "$awtNativeLibraries"; then
                            sed -i \
                              '/^  LIBAWT_LWAWT_CFLAGS := \\$/a\      -I${cups}/include \\' \
                              "$awtNativeLibraries"
                          fi
                          test "$(grep -Fc '      -I${cups}/include \' \
                            "$awtNativeLibraries")" -eq 1
                        elif grep -Eq '^  LIBAWT_LWAWT_CFLAGS .*=' \
                          "$awtNativeLibraries"; then
                          if ! grep -Eq \
                            '^  LIBAWT_LWAWT_CFLAGS .*=.*\$\(CUPS_CFLAGS\)' \
                            "$awtNativeLibraries"; then
                            sed -i \
                              '/^  LIBAWT_LWAWT_CFLAGS .*=/ s|$| $(CUPS_CFLAGS)|' \
                              "$awtNativeLibraries"
                          fi
                          test "$(grep -Ec \
                            '^  LIBAWT_LWAWT_CFLAGS .*=.*\$\(CUPS_CFLAGS\)' \
                            "$awtNativeLibraries")" -eq 1
                        else
                          # JDK 23/24 inline all libawt_lwawt flags in the
                          # SetupJdkLibrary call and have no intermediate flag
                          # variable. Add the configured target CUPS include
                          # flags to that exact library only.
                          test "$(grep -Fc \
                            '      EXTRA_HEADER_DIRS := $(LIBAWT_LWAWT_EXTRA_HEADER_DIRS), \' \
                            "$awtNativeLibraries")" -eq 1
                          sed -i \
                            '/SetupJdkLibrary, BUILD_LIBAWT_LWAWT/,/^  ))/ {
                              /EXTRA_HEADER_DIRS := $(LIBAWT_LWAWT_EXTRA_HEADER_DIRS), \\/a\      CFLAGS := $(CUPS_CFLAGS), \\
                            }' \
                            "$awtNativeLibraries"
                          test "$(grep -Fc \
                            '      CFLAGS := $(CUPS_CFLAGS), \' \
                            "$awtNativeLibraries")" -eq 1
                        fi

                        # JDK 23/24 retained an obsolete ExceptionHandling
                        # framework link despite using only Foundation's
                        # NSSetUncaughtExceptionHandler. Do not require the
                        # unrelated legacy framework when no native source
                        # consumes its header or NSExceptionHandler class.
                        if grep -Fq \
                          'SetupJdkLibrary, BUILD_LIBAWT_LWAWT' \
                          "$awtNativeLibraries" \
                          && grep -Fq -- '-framework ExceptionHandling' \
                            "$awtNativeLibraries"; then
                          test "$(grep -Fc -- '-framework ExceptionHandling' \
                            "$awtNativeLibraries")" -eq 1
                          if grep -REq \
                            '<ExceptionHandling/|NSExceptionHandler' \
                            ${jdkTreePrefix}src/java.desktop/macosx/native; then
                            echo "OpenJDK ${toString major} consumes ExceptionHandling APIs" >&2
                            exit 1
                          fi
                          sed -i \
                            '/SetupJdkLibrary, BUILD_LIBAWT_LWAWT/,/^  ))/ {
                              /-framework ExceptionHandling/d
                            }' \
                            "$awtNativeLibraries"
                          test "$(grep -Fc -- '-framework ExceptionHandling' \
                            "$awtNativeLibraries")" -eq 0
                        fi

                        # These sources use public IOKit pixel encodings and
                        # Blocks runtime macros directly. Include their
                        # canonical headers instead of relying on umbrella
                        # side effects from a full proprietary SDK.
                        graphicsDevice=${jdkTreePrefix}src/java.desktop/macosx/native/libawt_lwawt/awt/CGraphicsDevice.m
                        if ! grep -Fq \
                          '#import <IOKit/graphics/IOGraphicsTypes.h>' \
                          "$graphicsDevice"; then
                          test "$(grep -Fc '#import "ThreadUtilities.h"' \
                            "$graphicsDevice")" -eq 1
                          sed -i \
                            '/#import "ThreadUtilities.h"/a\#import <IOKit/graphics/IOGraphicsTypes.h>' \
                            "$graphicsDevice"
                        fi
                        test "$(grep -Fc \
                          '#import <IOKit/graphics/IOGraphicsTypes.h>' \
                          "$graphicsDevice")" -eq 1

                        threadUtilities=${jdkTreePrefix}src/java.desktop/macosx/native/libosxapp/ThreadUtilities.m
                        if ! grep -Fq '#include <Block.h>' "$threadUtilities"; then
                          test "$(grep -Fc '#import <objc/message.h>' \
                            "$threadUtilities")" -eq 1
                          sed -i \
                            '/#import <objc\/message.h>/a\#include <Block.h>' \
                            "$threadUtilities"
                        fi
                        test "$(grep -Fc '#include <Block.h>' \
                          "$threadUtilities")" -eq 1

                        # Backport the OpenJDK 20 compatibility definition.
                        # Some Darwin headers can include
                        # netinet/in.h before this source enables RFC 3542,
                        # leaving the public IPV6_DONTFRAG value hidden behind
                        # the header guard. Retain the socket option on those
                        # SDKs instead of disabling IPv6 fragmentation support.
                        socketOptions=${jdkTreePrefix}src/jdk.net/macosx/native/libextnet/MacOSXSocketOptions.c
                        if [ -f "$socketOptions" ] \
                          && grep -Fq 'IPV6_DONTFRAG' "$socketOptions" \
                          && ! grep -Fq '#ifndef IPV6_DONTFRAG' "$socketOptions"; then
                          test "$(grep -Fc 'IPV6_DONTFRAG' "$socketOptions")" -eq 3
                          test "$(grep -Fc '#ifndef IP_DONTFRAG' "$socketOptions")" -eq 1
                          sed -i \
                '/#ifndef IP_DONTFRAG/,/#endif/{
                  /#endif/a\
                  #ifndef IPV6_DONTFRAG\
                  #define IPV6_DONTFRAG           62\
                  #endif
                }' "$socketOptions"
                          test "$(grep -Fc '#ifndef IPV6_DONTFRAG' \
                            "$socketOptions")" -eq 1
                          test "$(grep -Fc '#define IPV6_DONTFRAG           62' \
                            "$socketOptions")" -eq 1
                        fi

                        # Backport JDK-8257148 to source releases which still
                        # probe for macOS 10.6. The supported Darwin deployment
                        # baseline is 11.0, where press-and-hold is always
                        # available, so retain that feature while removing the
                        # obsolete JRSCopyOSVersion dependency exactly as
                        # upstream did.
                        osVersion=${jdkTreePrefix}src/java.desktop/macosx/native/libawt_lwawt/awt/OSVersion.m
                        if [ -f "$osVersion" ]; then
                          awtView=${jdkTreePrefix}src/java.desktop/macosx/native/libawt_lwawt/awt/AWTView.m
                          test "$(grep -Fc '#import "OSVersion.h"' \
                            "$awtView")" -eq 1
                          test "$(grep -Fc \
                            '    shouldUsePressAndHold = !isSnowLeopardOrLower();' \
                            "$awtView")" -eq 1
                          sed -i \
                            -e '/#import "OSVersion.h"/d' \
                            -e '/static BOOL shouldUsePressAndHold()/,/^}/c\static BOOL shouldUsePressAndHold() {\n    return YES;\n}' \
                            "$awtView"
                          test "$(grep -Fc 'static BOOL shouldUsePressAndHold() {' \
                            "$awtView")" -eq 1
                          test "$(sed -n \
                            '/static BOOL shouldUsePressAndHold()/,/^}/p' \
                            "$awtView" | grep -Fc '    return YES;')" -eq 1
                          ! grep -Fq 'isSnowLeopardOrLower' "$awtView"

                          rm -f \
                            ${jdkTreePrefix}src/java.desktop/macosx/native/libawt_lwawt/awt/OSVersion.h \
                            "$osVersion"
                          test ! -e "$osVersion"
                        fi

                        # The macOS library lists the obsolete
                        # ExceptionHandling framework even though no native
                        # source consumes that framework's API. Modern public
                        # SDKs no longer ship it. Remove only the unused link
                        # input, and fail closed if a release starts using the
                        # API or changes the library definitions.
                        if grep -R -Eq \
                          'NSExceptionHandler|ExceptionHandling/' \
                          ${jdkTreePrefix}src/java.desktop/macosx/native; then
                          echo "OpenJDK ${toString major} consumes the ExceptionHandling API" >&2
                          exit 1
                        fi
                        for candidate in \
                          ${jdkTreePrefix}make/lib/Awt2dLibraries.gmk \
                          ${jdkTreePrefix}make/lib/Lib-java.desktop.gmk \
                          ${jdkTreePrefix}make/lib/PlatformLibraries.gmk \
                          ${jdkTreePrefix}make/modules/java.desktop/Lib.gmk \
                          ${jdkTreePrefix}make/modules/java.desktop/lib/Awt2dLibraries.gmk \
                          ${jdkTreePrefix}make/modules/java.desktop/lib/ClientLibraries.gmk; do
                          if [ -f "$candidate" ]; then
                            candidateLinks=$(grep -Fc -- \
                              '-framework ExceptionHandling' "$candidate" || true)
                            if [ "$candidateLinks" -gt 0 ]; then
                              sed -i \
                                '/-framework ExceptionHandling/d' \
                                "$candidate"
                            fi
                          fi
                        done
                        # Some maintained releases already removed the stale
                        # link input. The source API scan above is the contract:
                        # an absent framework is valid only while no source
                        # consumes it, and any remaining link is removed below.
                        for frameworkRoot in \
                          ${jdkTreePrefix}make/lib ${jdkTreePrefix}make/modules/java.desktop; do
                          if [ -d "$frameworkRoot" ]; then
                            ! grep -R -q -- '-framework ExceptionHandling' \
                              "$frameworkRoot"
                          fi
                        done

                        # Apple's linker historically supported `ld -r` for a
                        # partial Mach-O link. LLVM's ld64 does not implement
                        # that mode. These two results are immediately copied
                        # and consumed as .a files, so create real archives
                        # from the same complete object sets instead.
                        ${modernPackMaskNormalization}# The pack200 option mask intentionally selects every
                        # bit above bit 12. Releases through JDK 11 retain a
                        # signed negative shift that modern Clang correctly
                        # rejects as a non-constant expression. Spell the same
                        # mask as the complement of its low bits whenever that
                        # source is present.
                        packConstants=${jdkTreePrefix}src/jdk.pack/share/native/common-unpack/constants.h
                        if [ -f "$packConstants" ]; then
                          oldPackMask=$(grep -Fc \
                            'AO_UNUSED_MBZ             = (-1)<<13,' \
                            "$packConstants" || true)
                          newPackMask=$(grep -Fc \
                            'AO_UNUSED_MBZ             = ~((1 << 13) - 1),' \
                            "$packConstants" || true)
                          if [ "$oldPackMask" -eq 1 ] \
                            && [ "$newPackMask" -eq 0 ]; then
                            sed -i \
                              's/AO_UNUSED_MBZ             = (-1)<<13,/AO_UNUSED_MBZ             = ~((1 << 13) - 1),/' \
                              "$packConstants"
                          elif [ "$oldPackMask" -ne 0 ] \
                            || [ "$newPackMask" -ne 1 ]; then
                            echo "OpenJDK ${toString major} has an unknown pack200 option mask" >&2
                            exit 1
                          fi
                          test "$(grep -Fc \
                            'AO_UNUSED_MBZ             = ~((1 << 13) - 1),' \
                            "$packConstants")" -eq 1
                        fi

                        if [ ${
              if major <= 10
              then "true"
              else "false"
            } = true ]; then
                          coreLibraries=${jdkTreePrefix}make/lib/CoreLibraries.gmk
                          test "$(grep -Fc 'SetupNativeCompilation,BUILD_LIBFDLIBM_MAC' \
                            "$coreLibraries")" -eq 1
                          test "$(grep -Fc 'SetupNativeCompilation,BUILD_LIBJLI_STATIC' \
                            "$coreLibraries")" -ge 2
                          test "$(grep -Fc 'LDFLAGS := -nostdlib -r -arch x86_64,' \
                            "$coreLibraries")" -eq 1
                          test "$(grep -Fc 'LDFLAGS := -nostdlib -r,' \
                            "$coreLibraries")" -eq 1

                          sed -i \
                            '/SetupNativeCompilation,BUILD_LIBFDLIBM_MAC/,/^  ))/{
                              s/LIBRARY := fdlibm,/STATIC_LIBRARY := fdlibm,/
                              /LDFLAGS := -nostdlib -r -arch x86_64,/d
                            }' "$coreLibraries"
                          sed -i \
                            '/else ifeq ($(OPENJDK_TARGET_OS), macosx)/,/else ifeq ($(OPENJDK_TARGET_OS), aix)/{
                              /SetupNativeCompilation,BUILD_LIBJLI_STATIC/,/^  ))/{
                                s/LIBRARY := jli_static,/STATIC_LIBRARY := jli_static,/
                                s|OUTPUT_DIR := $(SUPPORT_OUTPUTDIR)/native/$(MODULE),|OUTPUT_DIR := $(SUPPORT_OUTPUTDIR)/native/$(MODULE)/libjli_static,|
                                /LDFLAGS := -nostdlib -r,/d
                              }
                            }' "$coreLibraries"
                          test "$(grep -Fc 'LDFLAGS := -nostdlib -r' \
                            "$coreLibraries")" -eq 0
                          test "$(grep -Fc 'STATIC_LIBRARY := fdlibm,' \
                            "$coreLibraries")" -ge 2
                          test "$(grep -Fc 'STATIC_LIBRARY := jli_static,' \
                            "$coreLibraries")" -ge 3
                        fi

            # OpenJDK generates its C++ precompiled header with CC plus
            # `-x c++-header`. AOS intentionally gives the CXX wrapper the
            # target libc++ isolation flags, so select that equivalent driver
            # role instead of falling through into native LLVM's libc++.
            if [ -f make/common/native/CompileFile.gmk ]; then
              pchGmk=make/common/native/CompileFile.gmk
              sed -i \
                's/$1_PCH_COMMAND := $$($1_CC)/$1_PCH_COMMAND := $$($1_CXX)/' \
                "$pchGmk"
              grep -q '^        $1_PCH_COMMAND := $$($1_CXX)' "$pchGmk"
            else
              pchGmk=make/common/NativeCompilation.gmk
              test "$(grep -Fc \
                '$$($1_CC) $$($1_CFLAGS) $$($1_EXTRA_CFLAGS) $$($1_SYSROOT_CFLAGS)' \
                "$pchGmk")" -eq 1
              sed -i \
                's/$$($1_CC) $$($1_CFLAGS) $$($1_EXTRA_CFLAGS) $$($1_SYSROOT_CFLAGS)/$$($1_CXX) $$($1_CFLAGS) $$($1_EXTRA_CFLAGS) $$($1_SYSROOT_CFLAGS)/' \
                "$pchGmk"
              test "$(grep -Fc \
                '$$($1_CXX) $$($1_CFLAGS) $$($1_EXTRA_CFLAGS) $$($1_SYSROOT_CFLAGS)' \
                "$pchGmk")" -eq 1
            fi

            # AOS deliberately builds the existing headless JDK variant. The
                        # macOS port otherwise probes Xcode's proprietary Metal tools and
                        # builds libosxui even when headless-only is enabled. Gate both
                        # together so this feature boundary is honored without fake tools.
                        toolchainM4=${autoconfDir}/toolchain.m4
                        if [ -f "$toolchainM4" ] \
                          && grep -q '^    UTIL_LOOKUP_TOOLCHAIN_PROGS(METAL, metal)$' "$toolchainM4"; then
                          sed -i \
                            '/^    UTIL_LOOKUP_TOOLCHAIN_PROGS(METAL, metal)$/i\    if test "x$ENABLE_HEADLESS_ONLY" = "xfalse"; then' \
                            "$toolchainM4"
                          sed -i \
                            '/^    UTIL_LOOKUP_TOOLCHAIN_PROGS(METALLIB, metallib)$/,/^  fi$/{
                              /^  fi$/i\    fi
                            }' \
                            "$toolchainM4"
                          grep -q '^    if test "x$ENABLE_HEADLESS_ONLY" = "xfalse"; then$' \
                            "$toolchainM4"
                        fi
                        clientLibraries=
                        for candidate in \
                          ${jdkTreePrefix}make/modules/java.desktop/lib/ClientLibraries.gmk \
                          ${jdkTreePrefix}make/modules/java.desktop/lib/Awt2dLibraries.gmk \
                          ${jdkTreePrefix}make/lib/Awt2dLibraries.gmk; do
                          if [ -f "$candidate" ] \
                            && grep -Eq \
                              'SetupJdkLibrary, BUILD_LIBOSXUI|SetupNativeCompilation,BUILD_LIBOSXUI' \
                              "$candidate"; then
                            clientLibraries=$candidate
                            break
                          fi
                        done
                        if [ -n "$clientLibraries" ]; then
                          modernOsxui=$(grep -Fc \
                            'SetupJdkLibrary, BUILD_LIBOSXUI' \
                            "$clientLibraries" || true)
                          legacyOsxui=$(grep -Fc \
                            'SetupNativeCompilation,BUILD_LIBOSXUI' \
                            "$clientLibraries" || true)
                          if [ "$modernOsxui" -eq 1 ] \
                            && [ "$legacyOsxui" -eq 0 ]; then
                            osxuiLine=$(grep -n \
                              'SetupJdkLibrary, BUILD_LIBOSXUI' \
                              "$clientLibraries" | cut -d: -f1)
                            osxuiGuardLine=$(head -n "$osxuiLine" "$clientLibraries" \
                              | grep -n '${osxuiModernGuardPattern}' \
                              | tail -n 1 | cut -d: -f1)
                            test -n "$osxuiGuardLine"
                            sed -i \
                              "''${osxuiGuardLine}s|${osxuiModernGuardSedPattern}|${osxuiModernGuardSedReplacement}|" \
                              "$clientLibraries"
                            test "$(sed -n "''${osxuiGuardLine}p" "$clientLibraries")" = \
                              '${osxuiModernGuardReplacement}'
                          elif [ "$modernOsxui" -eq 0 ] \
                            && [ "$legacyOsxui" -eq 1 ]; then
                            osxuiLine=$(grep -n \
                              'SetupNativeCompilation,BUILD_LIBOSXUI' \
                              "$clientLibraries" | cut -d: -f1)
                            osxuiGuardLine=$(head -n "$osxuiLine" "$clientLibraries" \
                              | grep -n '^ifeq ($(OPENJDK_TARGET_OS), macosx)$' \
                              | tail -n 1 | cut -d: -f1)
                            test -n "$osxuiGuardLine"
                            sed -i \
                              "''${osxuiGuardLine}s|^ifeq (\$(OPENJDK_TARGET_OS), macosx)$|ifeq (\$(OPENJDK_TARGET_OS)+\$(ENABLE_HEADLESS_ONLY), macosx+false)|" \
                              "$clientLibraries"
                            test "$(sed -n "''${osxuiGuardLine}p" "$clientLibraries")" = \
                              'ifeq ($(OPENJDK_TARGET_OS)+$(ENABLE_HEADLESS_ONLY), macosx+false)'
                          else
                            echo "OpenJDK ${toString major} has an unknown libosxui definition" >&2
                            exit 1
                          fi
                        fi

                        # OpenJDK clears Finder/resource-fork attributes from copied
                        # image files. The build runs on Linux, so implement the same
                        # list/clear operations through Python's native xattr API.
                        darwinTools=$TMPDIR/darwin-tools
                        mkdir -p "$darwinTools"
                        cat > "$darwinTools/xattr" <<'EOF'
            #!${buildTools.python3}/bin/python3
            import os
            import sys


            def main():
                flags = sys.argv[1] if len(sys.argv) > 1 else ""
                operations = set(flags[1:]) if flags.startswith("-") else set()
                if (
                    len(sys.argv) != 3
                    or not operations.intersection({"c", "l"})
                    or not operations.issubset({"c", "l", "s"})
                ):
                    print("usage: xattr -c|-l [-s] path", file=sys.stderr)
                    return 2

                path = sys.argv[2]
                follow_symlinks = "s" not in operations
                try:
                    names = os.listxattr(path, follow_symlinks=follow_symlinks)
                    if "l" in operations:
                        for name in names:
                            value = os.getxattr(
                                path, name, follow_symlinks=follow_symlinks
                            )
                            print(f"{name}: {value!r}")
                    else:
                        for name in names:
                            os.removexattr(
                                path, name, follow_symlinks=follow_symlinks
                            )
                except OSError as error:
                    print(f"xattr: {path}: {error}", file=sys.stderr)
                    return 1
                return 0


            if __name__ == "__main__":
                sys.exit(main())
            EOF
                        chmod +x "$darwinTools/xattr"

                        # OpenJDK marks its .app directories with Finder's bundle bit.
                        # Nix's Linux store serialization cannot represent macOS
                        # FinderInfo xattrs, while the complete .app directory layout is
                        # retained. Accept only that non-serializable metadata operation;
                        # fail closed if a future build needs any other SetFile behavior.
                        cat > "$darwinTools/SetFile" <<'EOF'
            #!${buildTools.bash}/bin/bash
            if [ "$#" -ne 3 ] || [ "$1" != "-a" ] || [ "$2" != "B" ]; then
              printf '%s\n' 'SetFile: only -a B <directory> is supported' >&2
              exit 2
            fi
            if [ ! -d "$3" ]; then
              printf 'SetFile: not a directory: %s\n' "$3" >&2
              exit 1
            fi
            exit 0
            EOF
                        chmod +x "$darwinTools/SetFile"

                        # OpenJDK requires its native BuildC compiler to match the target
                        # Clang toolchain. Wrap AOS Clang with the same hermetic glibc and
                        # GCC discovery that the native cc wrapper supplies to GCC.
                        for compiler in clang clang++; do
                          cat > "$darwinTools/build-$compiler" <<EOF
            #!${buildTools.bash}/bin/bash
            set -eu
            real_libc=\$(cat ${buildTools.bootstrapTools}/nix-support/orig-libc)
            real_libc_dev=\$(cat ${buildTools.bootstrapTools}/nix-support/orig-libc-dev)
            dynamic_linker=\$(cat ${buildTools.bootstrapTools}/nix-support/dynamic-linker)
            gcc_dir=\$(dirname "\$(${buildTools.gcc}/bin/gcc -print-libgcc-file-name)")
            compiler_flags=()
            if [ "$compiler" = clang++ ]; then
              compiler_flags=(${darwinLegacyCxxFlag})
            fi
            linking=true
            for arg in "\$@"; do
              case "\$arg" in
                -c|-E|-S|-fsyntax-only) linking=false ;;
              esac
            done
            link_flags=()
            if \$linking; then
              link_flags=(
                -L"\$real_libc/lib"
                -Wl,-dynamic-linker="\$dynamic_linker"
                -Wl,-rpath,"\$real_libc/lib"
              )
            fi
            exec ${buildTools.llvm}/bin/$compiler \
              --gcc-install-dir="\$gcc_dir" \
              -idirafter "\$real_libc_dev/include" \
              -B"\$real_libc/lib" -B"\$gcc_dir" \
              "\''${compiler_flags[@]}" "\''${link_flags[@]}" "\$@"
            EOF
                          chmod +x "$darwinTools/build-$compiler"
                        done

                        # LLVM supplies native inspectors/editors for emitted Mach-O files.
                        ln -s ${buildTools.llvm}/bin/llvm-otool "$darwinTools/otool"
                        ln -s ${buildTools.llvm}/bin/llvm-install-name-tool \
                          "$darwinTools/install_name_tool"
                        export PATH="$darwinTools:$PATH"

                        # The cross derivation contains both the previous boot
                        # JDK and the current native BuildJDK. A global library
                        # search path can mix their same-named JNI libraries
                        # (for example JDK 20 libnio with JDK 21 libnet). Every
                        # AOS native tool has a complete rpath, so isolate each
                        # JDK to its own adjacent libraries.
                        export LD_LIBRARY_PATH=

                        # The cross stdenv's global C++ search path describes the Darwin
                        # target. It must not leak into BuildJDK/ADLC, while target c++
                        # already receives its libc++ headers from the cc wrapper.
                        export CPLUS_INCLUDE_PATH=

                        # The native stdenv records -rpath-link for ELF linkers. Darwin's
                        # ld64 has no equivalent option, so retain the target library
                        # rpaths while removing only that Linux-specific search hint.
                        darwinLdflags=
                        for flag in ''${NIX_LDFLAGS:-}; do
                          case "$flag" in
                            -Wl,-rpath-link,*) ;;
                            *) darwinLdflags="$darwinLdflags $flag" ;;
                          esac
                        done

                        # Configure the emitted JDK for Darwin while retaining a native
                        # boot JDK. Darwin uses its CoreAudio port, so ALSA must not enter
                        # either the target inputs or configure result.
                        $CONFIG_SHELL configure \
                          BUILD_CC=$darwinTools/build-clang \
                          BUILD_CXX=$darwinTools/build-clang++ \
                          --openjdk-target=${stdenv.hostPlatform.config} \
                          --with-toolchain-type=clang \
                          --with-sysroot=${stdenv.sdk} \
                          --with-boot-jdk=${bootJdk} \
                          --with-build-jdk=${buildJdk} \
                          --enable-headless-only \
                          --with-native-debug-symbols=none \
                          --disable-warnings-as-errors \
                          --with-zlib=system \
                          --with-libjpeg=bundled \
                          --with-giflib=bundled \
                          --with-libpng=bundled \
                          --with-lcms=bundled \
                          ${darwinFreetypeFlags} \
                          --with-cups-include=${cups}/include \
                          --x-includes=${xorg-stubs}/include \
                          --x-libraries=${xorg-stubs}/lib \
                          --with-version-build=${build} \
                          --with-version-opt=aos \
                          --with-version-pre= \
                          --with-extra-cflags="-Wno-error -fcommon -fno-delete-null-pointer-checks ${darwinFrameworkFlags}" \
                          --with-extra-cxxflags="-Wno-error -fno-delete-null-pointer-checks ${darwinLegacyCxxFlag} ${darwinFrameworkFlags}" \
                          --with-extra-ldflags="$darwinLdflags ${darwinFrameworkFlags} ${darwinFrameworkRpathFlags}" \
                          --with-jobs=${jobsExpr} \
                          ${extraCfgStr}
                        grep -q '^ENABLE_HEADLESS_ONLY := true$' build/*/spec.gmk
          ''
          else ''
            $CONFIG_SHELL configure \
              --with-boot-jdk=${prevJdk} \
              --enable-headless-only \
              --with-native-debug-symbols=none \
              --disable-warnings-as-errors \
              --with-zlib=system \
              --with-libjpeg=bundled \
              --with-giflib=bundled \
              --with-libpng=bundled \
              --with-lcms=bundled \
              --with-cups-include=${cups}/include \
              --with-alsa=${alsa-lib} \
              --with-freetype-include=${freetype}/include/freetype2 \
              --with-freetype-lib=${freetype}/lib \
              --x-includes=${xorg-stubs}/include \
              --x-libraries=${xorg-stubs}/lib \
              --with-version-build=${build} \
              --with-version-opt=aos \
              --with-version-pre= \
              --with-extra-cflags="-Wno-error -fcommon -fno-lifetime-dse -fno-delete-null-pointer-checks" \
              --with-extra-cxxflags="-Wno-error -fno-lifetime-dse -fno-delete-null-pointer-checks" \
              --with-extra-ldflags="''${NIX_LDFLAGS:-}" \
              --with-jobs=${jobsExpr} \
              ${extraCfgStr}
          '';
      }
      {
        name = "build";
        script = ''
          # Disable AVX-512 in glibc to prevent SIGSEGV in memmove during JVM
          # bootstrap (older JDK hotspot code has alignment issues with AVX-512)
          export GLIBC_TUNABLES=glibc.cpu.hwcaps=-AVX512F

          # Remove -z defs from generated spec.gmk — our xorg-stubs don't
          # export all X11 symbols and some JDK libs use runtime-resolved deps
          find build -name 'spec.gmk' 2>/dev/null | while read f; do
            sed -i 's/-Xlinker -z -Xlinker defs//g; s/-Wl,-z,defs//g' "$f" 2>/dev/null || true
          done

          make images JOBS=${jobsExpr}
        '';
      }
      {
        name = "install";
        script =
          if isDarwinCross
          then ''
            mkdir -p $out
            cp -a build/*/images/jdk/* $out/
            test -x "$out/bin/java"
            test -x "$out/bin/javac"
            test -f "$out/lib/server/libjvm.dylib"
            test ! -e "$out/lib/libosxui.dylib"
            test ! -e "$out/lib/shaders.metallib"
          ''
          else ''
            mkdir -p $out
            cp -a build/*/images/jdk/* $out/

            # Patch ELF binaries with the correct dynamic linker and rpath
            INTERP=$(cat "${bootstrapTools}/nix-support/dynamic-linker")
            BT_LIB=$(dirname "$INTERP")

            # Find libstdc++ directory (nested under lib/gcc/...)
            STDCXX_FILE=$(find "$BT_LIB" -name 'libstdc++.so.6' -not -name '*.py' 2>/dev/null | head -1)
            STDCXX_DIR=""
            if [ -n "$STDCXX_FILE" ]; then
              STDCXX_DIR=$(dirname "$STDCXX_FILE")
            fi
            RPATH="$out/lib:$out/lib/jli:$out/lib/server:$BT_LIB"
            if [ -n "$STDCXX_DIR" ]; then
              RPATH="$RPATH:$STDCXX_DIR"
            fi
            # Add runtime dependency library paths
            RPATH="$RPATH:${zlib}/lib:${fontconfig}/lib:${freetype}/lib"

            # Patch executables
            for f in $out/bin/* $out/lib/jspawnhelper; do
              if [ -f "$f" ] && [ ! -L "$f" ]; then
                patchelf --set-interpreter "$INTERP" \
                         --set-rpath "$RPATH" \
                         "$f" 2>/dev/null || true
              fi
            done

            # Patch shared libraries
            find $out/lib -name '*.so' -o -name '*.so.*' | while read f; do
              if [ -f "$f" ] && [ ! -L "$f" ]; then
                patchelf --set-rpath "$RPATH" \
                         "$f" 2>/dev/null || true
              fi
            done
          '';
      }
    ];

    meta = {
      description = "OpenJDK ${toString major} — bootstrap chain intermediate";
      homepage = "https://openjdk.org";
      license = "GPL-2.0-with-classpath-exception";
    };
  }
