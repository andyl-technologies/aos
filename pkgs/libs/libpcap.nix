##! libpcap — Packet Capture Library
{
  lib,
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  flex,
  bison,
  libnl,
  bash,
  stdenv,
}: let
  version = "1.10.7";
  captureBackend =
    if stdenv.hostPlatform.isDarwin
    then "bpf"
    else "linux";
in
  mkDerivation {
    pname = "libpcap";
    qualification.packageProbe = lib.qualification.commandProbe {
      "primary" = {
        "artifacts" = [];
        "expected" = "libpcap produces a nonempty BPF instruction program.";
        "files" = {
          "primary.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libpcap primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libpcap rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <pcap/pcap.h>\nint main(void) {\n    pcap_t *capture = pcap_open_dead(DLT_EN10MB, 65535); struct bpf_program program;\n    if (capture == NULL || pcap_compile(capture, &program, \"tcp port 443\", 1, PCAP_NETMASK_UNKNOWN) != 0) return 2;\n    int ok = program.bf_len > 0; pcap_freecode(&program); pcap_close(capture);\n    return ok ? pass() : 3;\n}\n\n";
        };
        "input" = "The packet-filter expression tcp port 443.";
        "operation" = "Compile the filter for a dead Ethernet capture handle.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "primary.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lpcap"
              "-o"
              "primary-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/primary/primary-check"
            ];
            "exit_code" = 0;
            "stderr" = {
              "exact" = "";
            };
            "stdout" = {
              "exact" = "libpcap primary passed\n";
            };
          }
        ];
      };
      "badInput" = {
        "artifacts" = [];
        "expected" = "libpcap reports a filter syntax error.";
        "files" = {
          "bad-input.c" = "#include <stdio.h>\nstatic int pass(void) { return puts(\"libpcap primary passed\") == EOF; }\nstatic int reject(void) {\n    fputs(\"libpcap rejected invalid input\\n\", stderr);\n    return 7;\n}\n#include <pcap/pcap.h>\nint main(void) {\n    pcap_t *capture = pcap_open_dead(DLT_EN10MB, 65535); struct bpf_program program;\n    if (capture == NULL) return 2;\n    int status = pcap_compile(capture, &program, \"tcp and\", 1, PCAP_NETMASK_UNKNOWN); pcap_close(capture);\n    if (status == 0) { pcap_freecode(&program); return 3; }\n    return reject();\n}\n\n";
        };
        "input" = "A packet-filter expression ending in an incomplete conjunction.";
        "operation" = "Compile the malformed expression through libpcap.";
        "steps" = [
          {
            "argv" = [
              "@cc@"
              "bad-input.c"
              "-I@out@/include"
              "-L@out@/lib"
              "-Wl,-rpath,@out@/lib"
              "-lpcap"
              "-o"
              "bad-input-check"
            ];
            "exit_code" = 0;
            "stdout" = {
              "exact" = "";
            };
          }
          {
            "argv" = [
              "@work@/bad-input/bad-input-check"
            ];
            "exit_code" = 7;
            "observes_rejection" = true;
            "stderr" = {
              "exact" = "libpcap rejected invalid input\n";
            };
            "stdout" = {
              "exact" = "";
            };
          }
        ];
      };
    };

    inherit version;

    src = fetchurl {
      urls = [
        "https://www.tcpdump.org/release/libpcap-${version}.tar.gz"
      ];
      hash = "sha256-CzlKyQ28Cpg4/5dGjgXJyaPoc97CUUzVjbZdhZ0pbjE=";
    };

    buildDeps = [
      gnumake
      pkg-config
      flex
      bison
    ];
    runtimeDeps =
      if stdenv.hostPlatform.isDarwin
      then [bash]
      else [libnl];
    propagatedDeps =
      if stdenv.hostPlatform.isDarwin
      then []
      else [libnl];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libpcap-${version}
        '';
      }
      {
        name = "configure";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --with-pcap=${captureBackend} \
              --disable-universal \
              --disable-static \
              --enable-shared
          ''
          else ''
            ./configure \
              $configureFlags \
              --prefix=$out \
              --with-pcap=${captureBackend} \
              --disable-static \
              --enable-shared
          '';
      }
      {
        name = "build";
        script = ''
          make -j$NIX_BUILD_CORES
        '';
      }
      {
        name = "install";
        script =
          if stdenv.hostPlatform.isDarwin
          then ''
            make install
            sed -i "1s|^#!.*|#!${bash}/bin/bash|" "$out/bin/pcap-config"
            rm -f $out/lib/libpcap.a
          ''
          else ''
            make install
            rm -f $out/lib/libpcap.a
          '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libpcap";
        library = self;
        libs = ["-lpcap"];
        testSource = ''
          #include <pcap/pcap.h>
          #include <stdio.h>
          int main() {
            printf("libpcap version: %s\n", pcap_lib_version());
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "libpcap — packet capture library";
      homepage = "https://www.tcpdump.org";
      license = "BSD-3-Clause";
    };
  }
