##! Node.js — JavaScript runtime built on V8.
##!
##! Built hermetically from source. Node bundles its own V8, ICU, zlib,
##! libuv, c-ares, nghttp2, and OpenSSL, so this package uses the bundled
##! dependencies exclusively (no `--shared-*` system libraries) to keep the
##! build self-contained. The build is python-driven (`configure.py` plus the
##! GYP-generated Makefiles); `PYTHON` is pinned to the AOS python3 so no host
##! interpreter is consulted.
{
  mkDerivation,
  fetchurl,
  python3,
  gnumake,
  stdenv,
  buildPackages,
}: let
  version = "22.22.3";
  isDarwinCross = stdenv.isCross && stdenv.hostPlatform.isDarwin;
  buildPython =
    if isDarwinCross
    then buildPackages.python3
    else python3;
  targetCpu =
    if stdenv.hostPlatform.isAarch64
    then "arm64"
    else "x64";
in
  mkDerivation {
    pname = "nodejs";
    inherit version;

    src = fetchurl {
      urls = [
        "https://nodejs.org/dist/v${version}/node-v${version}.tar.xz"
      ];
      hash = "sha256-8+aleNsaszWkpyeFweh60Yos9tL8JXR6HXQfs0rwvQ8=";
    };

    buildDeps =
      [
        python3
        gnumake
      ]
      ++ (
        if isDarwinCross
        then [buildPython]
        else []
      );
    runtimeDeps = [];
    propagatedDeps = [];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd node-v${version}
        '';
      }
      {
        name = "configure";
        script = ''
          # No /usr/bin/env in the sandbox: pin every python invocation to the
          # AOS interpreter. configure.py honors $PYTHON; the generated build
          # rules invoke it via the same variable through the Makefile.
          export PYTHON=${buildPython}/bin/python3
          ${
            if isDarwinCross
            then ''
              # GYP's Makefile generator asks xcodebuild only for Xcode
              # metadata, even though the Linux-hosted cross compiler and
              # SDKROOT provide every build input.  Supply deterministic
              # metadata rather than probing a nonexistent host Xcode.
              mkdir -p .aos-build-tools
              cat > .aos-build-tools/xcodebuild <<'SH'
              #!${buildPackages.bash}/bin/bash
              case "''${1:-}" in
                -version)
                  printf '%s\n' 'Xcode 16.0' 'Build version 16A242d'
                  ;;
                -showsdks)
                  printf '%s\n' 'macOS 15.0 -sdk macosx15.0'
                  ;;
                *)
                  exit 1
                  ;;
              esac
              SH
              chmod +x .aos-build-tools/xcodebuild
              export PATH="$PWD/.aos-build-tools:$PATH"

              # The macOS GYP generator archives both host and target static
              # libraries with Apple's `libtool -static`.  An ar archive has
              # the same portable container format, so translate the narrow
              # archive-mode interface to the native hermetic ar.  The final
              # Darwin linker reads the Mach-O members without the archiver
              # needing to execute or interpret them.
              cat > .aos-build-tools/libtool <<'SH'
              #!${buildPackages.bash}/bin/bash
              output=
              members=()
              while (( $# )); do
                case "$1" in
                  -static|-no_warning_for_no_symbols)
                    shift
                    ;;
                  -o)
                    output=$2
                    shift 2
                    ;;
                  *)
                    members+=("$1")
                    shift
                    ;;
                esac
              done
              if [[ -z "$output" ]]; then
                printf '%s\n' 'AOS libtool shim requires -static -o OUTPUT' >&2
                exit 2
              fi
              exec ${buildPackages.cc}/bin/ar rcs "$output" "''${members[@]}"
              SH
              chmod +x .aos-build-tools/libtool

              # libuv declares both host and target toolsets, but its OS
              # source conditions use only GYP's target OS.  Select Linux
              # sources for the generators that execute during this build and
              # retain Darwin sources for the installed target library.
              $PYTHON - <<'PY'
              import os
              from pathlib import Path

              uv_gyp = Path("deps/uv/uv.gyp")
              source = uv_gyp.read_text()
              replacements = {
                  "'OS == \"linux\" or OS==\"openharmony\"'":
                      "'OS == \"linux\" or OS==\"openharmony\" or _toolset==\"host\"'",
                  "'OS==\"linux\" or OS==\"openharmony\"'":
                      "'OS==\"linux\" or OS==\"openharmony\" or _toolset==\"host\"'",
                  "[ 'OS in \"mac ios\"', {\n          'sources': [":
                      "[ 'OS in \"mac ios\" and _toolset==\"target\"', {\n          'sources': [",
                  "[ 'OS in \"ios mac freebsd dragonflybsd openbsd netbsd\".split()', {":
                      "[ 'OS in \"ios mac freebsd dragonflybsd openbsd netbsd\".split() and _toolset==\"target\"', {",
                  "['OS!=\"mac\"', {": "['OS!=\"mac\" or _toolset==\"host\"', {",
              }
              for old, new in replacements.items():
                  if old not in source:
                      raise SystemExit(f"missing expected libuv GYP fragment: {old}")
                  source = source.replace(old, new)
              uv_gyp.write_text(source)

              # V8 also derives platform sources from the target OS for both
              # toolsets.  Its build-time generators must use the Linux base
              # implementation and must not acquire the target-only macOS
              # system-instrumentation recorder.
              v8_gyp = Path("tools/v8_gypfiles/v8.gyp")
              source = v8_gyp.read_text()
              replacements = {
                  "      'conditions': [\n        ['is_component_build', {":
                      """      'target_conditions': [
                      ['_toolset=="host"', {
                        'sources!': [
                          '<(V8_ROOT)/src/base/platform/platform-darwin.cc',
                        ],
                        'sources': [
                          '<(V8_ROOT)/src/base/platform/platform-linux.cc',
                        ],
                      }],
                    ],

                    'conditions': [
                      ['is_component_build', {""",
                  "      'conditions': [\n        ['component==\"shared_library\"', {\n          'direct_dependent_settings': {":
                      """      'target_conditions': [
                      ['_toolset=="host"', {
                        'defines!': ['V8_ENABLE_SYSTEM_INSTRUMENTATION'],
                        'sources!': [
                          '<(V8_ROOT)/src/libplatform/tracing/recorder.h',
                          '<(V8_ROOT)/src/libplatform/tracing/recorder-mac.cc',
                        ],
                      }],
                    ],

                    'conditions': [
                      ['component=="shared_library"', {
                        'direct_dependent_settings': {""",
              }
              for old, new in replacements.items():
                  if source.count(old) != 1:
                      raise SystemExit(f"unexpected V8 GYP fragment: {old}")
                  source = source.replace(old, new)
              v8_gyp.write_text(source)

              # Bundled OpenSSL otherwise bakes its temporary GYP product
              # directory into node as the default provider search path.
              # Keep that runtime setting stable and inside the package.
              openssl_gyp = Path("deps/openssl/openssl.gyp")
              source = openssl_gyp.read_text()
              old = "'modules_dir': '<(PRODUCT_DIR_ABS_CSTR)/obj.target/deps/openssl/lib/openssl-modules'"
              if source.count(old) != 2:
                  raise SystemExit("unexpected OpenSSL GYP modules_dir fragments")
              modules_dir = f"{os.environ['out']}/lib/openssl-modules"
              source = source.replace(old, f"'modules_dir': '{modules_dir}'")
              openssl_gyp.write_text(source)
              PY

              # GYP applies its macOS target flags to a number of host-tool
              # variants as well.  Keep those Linux executables on the native
              # compiler and remove target-only driver arguments and the
              # inherited cross environment.
              write_build_compiler() {
                native_compiler=$1
                wrapper=$2
                cat > "$wrapper" <<EOF
              #!${buildPackages.bash}/bin/bash
              native_hardening=
              for token in \$AOS_HARDENING_ENABLE; do
                case "\$token" in
                  pacret) ;;
                  *) native_hardening="\$native_hardening \$token" ;;
                esac
              done
              export AOS_HARDENING_ENABLE="\$native_hardening"
              unset AOS_TARGET_ARCH AOS_TARGET_PLATFORM
              unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH LIBRARY_PATH
              unset MACOSX_DEPLOYMENT_TARGET NIX_CFLAGS_COMPILE NIX_LDFLAGS SDKROOT

              native_args=()
              skip_next=false
              mksnapshot_link=false
              for arg in "\$@"; do
                if \$skip_next; then
                  skip_next=false
                  continue
                fi
                case "\$arg" in
                  -arch|-framework|-isysroot)
                    skip_next=true
                    ;;
                  -mmacosx-version-min=*|-mbranch-protection=pac-ret|-stdlib=libc++|--sysroot=*|-Werror=undefined-inline|-Werror=extra-semi|-Werror=ctad-maybe-unsupported|-Wno-nullability-completeness)
                    ;;
                  -Wl,-dead_strip|-Wl,-headerpad_max_install_names|-Wl,-search_paths_first|-Wl,-syslibroot,*)
                    ;;
                  *)
                    native_args+=("\$arg")
                    case "\$arg" in
                      */mksnapshot) mksnapshot_link=true ;;
                    esac
                    ;;
                esac
              done

              # GYP orders the macOS mksnapshot archives for ld64, which
              # resolves their cyclic V8 references.  The Linux-hosted GNU
              # linker needs the same archive set explicitly grouped.
              if \$mksnapshot_link; then
                grouped_args=()
                archive_group=false
                for arg in "\''${native_args[@]}"; do
                  if ! \$archive_group && [[ "\$arg" == *.a ]]; then
                    grouped_args+=(-Wl,--start-group)
                    archive_group=true
                  fi
                  grouped_args+=("\$arg")
                done
                if \$archive_group; then
                  grouped_args+=(-Wl,--end-group)
                  native_args=("\''${grouped_args[@]}")
                fi
              fi
              exec "$native_compiler" "\''${native_args[@]}"
              EOF
                chmod +x "$wrapper"
              }
              write_build_compiler ${buildPackages.cc}/bin/cc .aos-build-tools/cc-for-build
              write_build_compiler ${buildPackages.cc}/bin/c++ .aos-build-tools/cxx-for-build

              export CC_host="$PWD/.aos-build-tools/cc-for-build"
              export CXX_host="$PWD/.aos-build-tools/cxx-for-build"
            ''
            else ""
          }

          # V8 and Node embed an absolute RPATH-free shared object set; the
          # ccWrapper already injects -Wl,-rpath for runtime deps. Bundled
          # OpenSSL/ICU/zlib mean we link nothing from the system.
          # Omit --ninja: it is a store-true flag, and leaving it off makes
          # configure.py emit GYP Makefiles driven by AOS gnumake.
          $PYTHON configure.py \
            --prefix=$out \
            --with-intl=full-icu \
            ${
            if isDarwinCross
            then ''--cross-compiling --dest-os=mac --dest-cpu=${targetCpu}''
            else ""
          }
        '';
      }
      {
        name = "build";
        script = ''
          export PYTHON=${buildPython}/bin/python3
          ${
            if isDarwinCross
            then ''
              make -j$NIX_BUILD_CORES PYTHON=$PYTHON \
                CC.host="$PWD/.aos-build-tools/cc-for-build" \
                CXX.host="$PWD/.aos-build-tools/cxx-for-build" \
                LINK.host="$PWD/.aos-build-tools/cxx-for-build" \
                AR.host=${buildPackages.cc}/bin/ar
            ''
            else "make -j$NIX_BUILD_CORES PYTHON=$PYTHON"
          }
        '';
      }
      {
        name = "install";
        script =
          if isDarwinCross
          then ''
            export PYTHON=${buildPython}/bin/python3
            make install PYTHON=$PYTHON
            mkdir -p "$out/lib/openssl-modules"
          ''
          else ''
            export PYTHON=${buildPython}/bin/python3
            make install PYTHON=$PYTHON
          '';
      }
    ];

    meta = {
      description = "Node.js — JavaScript runtime built on V8";
      homepage = "https://nodejs.org/";
      license = "MIT";
    };
  }
