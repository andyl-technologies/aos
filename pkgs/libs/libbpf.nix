##! libbpf - userspace library for loading and managing BPF programs
{
  mkDerivation,
  mkGithubUpstream,
  gnumake,
  pkg-config,
  elfutils,
  zlib,
  zstd,
}: let
  upstream = mkGithubUpstream {
    unitId = "libbpf-1";
    family = "libbpf";
    stream = "1";
    owner = "pkgs/libs/libbpf.nix";
    version = "1.7.0";
    upstreamId = "v1.7.0";
    repository = "libbpf/libbpf";
    tagPrefix = "v";
    major = 1;
    source = {
      authority = "github.com";
      path = [
        "libbpf"
        "libbpf"
        "archive"
        "refs"
        "tags"
        {
          parts = [
            {literal = "v";}
            {
              componentField = {
                component = "main";
                field = "comparisonVersion";
              };
            }
            {literal = ".tar.gz";}
          ];
        }
      ];
      hash = "sha256-erX+/794VX9iby4+MgR4hSg5RJRxWjD8IHD83cIFG3s=";
    };
    riskFloor = "high";
  };
  inherit (upstream) version;
in
  mkDerivation {
    pname = "libbpf";
    inherit version;

    src = upstream.components.main.sources.source;
    update = upstream.update;

    buildDeps = [
      gnumake
      pkg-config
    ];
    runtimeDeps = [
      elfutils
      zlib
      zstd
    ];
    propagatedDeps = [
      elfutils
      zlib
      zstd
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          tar xf $src
          cd libbpf-${version}
        '';
      }
      {
        name = "build";
        script = ''
          make -C src -j$NIX_BUILD_CORES \
            PREFIX=$out \
            LIBDIR=$out/lib \
            INCLUDEDIR=$out/include \
            UAPIDIR=$out/include
        '';
      }
      {
        name = "install";
        script = ''
          make -C src install \
            PREFIX=$out \
            LIBDIR=$out/lib \
            INCLUDEDIR=$out/include \
            UAPIDIR=$out/include
        '';
      }
    ];

    checks = {
      testing,
      self,
      pkgs,
    }: {
      link = testing.mkLinkCheck {
        pname = "lib-libbpf";
        library = self;
        extraDeps = [
          elfutils
          zlib
          zstd
        ];
        libs = [
          "-lbpf"
          "-lelf"
          "-lz"
          "-lzstd"
        ];
        testSource = ''
          #include <bpf/libbpf.h>
          #include <stdio.h>
          int main() {
            printf("libbpf: %s\n", libbpf_version_string());
            return 0;
          }
        '';
      };
    };

    meta = {
      description = "libbpf - userspace library for loading and managing BPF programs";
      homepage = "https://github.com/libbpf/libbpf";
      license = "LGPL-2.1-only OR BSD-2-Clause";
    };
  }
