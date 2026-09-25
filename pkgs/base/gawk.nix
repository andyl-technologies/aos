{
  lib,
  mkDerivation,
  fetchurl,
  m4,
  flex,
  bison,
  autoconf,
  automake,
  texinfo,
  gnumake,
  sed,
  bash,
  stdenv,
}: let
  version = "5.4.1";
in
  mkDerivation {
    platformSupport = {
      build = [{abi = ["gnu"]; os = ["linux"];}];
      host = [{abi = ["gnu"]; cpu = ["x86_64" "aarch64"]; os = ["linux"];} {abi = ["darwin"]; cpu = ["x86_64" "aarch64"]; os = ["darwin"];}];
      target = [];
      role = "public-package";
    };
    pname = "gawk";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "Awk emits the exact aggregate.";
        "files" = {};
        "input" = "Two colon-delimited records.";
        "operation" = "Sum the numeric second fields with awk.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/awk"
              "-F:"
              "{ total += $2 } END { print total }"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdin" = "alpha:19\nbeta:23\n";
            "stdout" = {
              "exact" = "42\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "Awk rejects the syntax error with status 1.";
        "files" = {};
        "input" = "An awk program with an unterminated action.";
        "operation" = "Parse the malformed awk program.";
        "steps" = [
          {
            "argv" = [
              "@out@/bin/awk"
              "{ print $1"
            ];
            "exit_code" = 1;
            "observes_rejection" = true;
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = ["https://mirrors.kernel.org/gnu/gawk/gawk-${version}.tar.xz"];
      hash = "sha256-B/b3NCt/6+QxP8LCVCrZPWT+IK2HFyABCfEFqCb1/Tc=";
    };

    buildDeps = [m4 flex bison autoconf automake texinfo gnumake sed];
    runtimeDeps = [bash];
    # The Darwin SDK has uchar.h but lacks its C11 char32_t API.
    configureFlags =
      if stdenv.hostPlatform.isDarwin
      then "--disable-nls ac_cv_header_uchar_h=no"
      else "--disable-nls";
    postPatch = ''
      # Preserve uninitialized array strings when scalar conversion clears
      # metadata; GCC's option generator depends on this behavior.
      patch -p1 < ${../../stdenv/toolchains/gcc16/patches/gawk-5.4.1-preserve-scalar-format.patch}
    '';
    postInstall = ''
      [ -f "$out/bin/gawk" ] && [ ! -e "$out/bin/awk" ] && ln -s gawk "$out/bin/awk"
      if [ -f "$out/bin/gawkbug" ]; then
        sed -i \
          -e "1s|^#!.*|#!${bash}/bin/bash|" \
          -e 's|^CC=.*|CC="gcc"|' \
          -e 's|^CFLAGS=.*|CFLAGS=""|' \
          "$out/bin/gawkbug"
      fi
    '';

    meta = {
      description = "GNU pattern scanning and processing language";
      homepage = "https://www.gnu.org/software/gawk/";
      license = "GPL-3.0-or-later";
      platforms = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    };
  }
