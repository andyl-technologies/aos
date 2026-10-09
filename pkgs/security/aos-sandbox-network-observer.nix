##! aos-sandbox-network-observer — Read-only fixed BPF graph observer
{
  lib,
  mkDerivation,
  stdenv,
  targetPackages,
  pkg-config,
  linux-headers,
  libbpf,
  aos-sandbox-network-lease-gate,
}: let
  source = ./aos-sandbox-network-observer.c;
  targetLinuxHeaders =
    if stdenv.isCross
    then targetPackages.linux-headers
    else linux-headers;
in
  mkDerivation {
    pname = "aos-sandbox-network-observer";
    version = "1";
    src = null;

    buildDeps =
      [pkg-config]
      ++ lib.optional (!stdenv.isCross) linux-headers;
    runtimeDeps = [
      libbpf
      aos-sandbox-network-lease-gate
    ];
    propagatedDeps = [];
    disallowedReferences = [source];

    phases = [
      {
        name = "build";
        script = ''
          $CC -std=c17 -O2 -Wall -Wextra -Werror \
            -I${aos-sandbox-network-lease-gate}/include \
            -I${targetLinuxHeaders}/include \
            ${source} \
            -o aos-sandbox-network-observer \
            $(pkg-config --cflags --libs libbpf)
        '';
      }
      {
        name = "install";
        script = ''
          mkdir -p $out/bin
          cp aos-sandbox-network-observer $out/bin/
        '';
      }
    ];

    passthru.evidenceSources = [
      (builtins.path {
        path = ./aos-sandbox-network-observer.nix;
        name = "aos-sandbox-network-observer.nix";
      })
      (builtins.path {
        path = source;
        name = "aos-sandbox-network-observer.c";
      })
    ];

    meta = {
      description = "Read-only exact BPF graph observer for sandbox networking";
      license = "Apache-2.0";
    };
  }
