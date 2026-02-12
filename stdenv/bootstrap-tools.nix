# stdenv/bootstrap-tools.nix — Pre-built bootstrap tools for building AOS packages
#
# Downloads the nixpkgs bootstrap-tools (busybox + gcc/glibc/coreutils tarball)
# from the public Nix tarballs server and unpacks them.  These provide everything
# needed to build packages from source:
#
#   bash, coreutils, findutils, diffutils, sed, grep, gawk, tar, gzip, bzip2,
#   make, patch, patchelf, gcc, g++, cpp, binutils (as/ld/ar/...), glibc
#
# This is the ONLY point where pre-built binaries from outside AOS enter the
# build chain.  In the future the mescc-tools/live-bootstrap chain
# (stdenv/bootstrap/) will replace this with a fully-auditable source build.
#
# The bootstrap files are the same ones used by nixpkgs' stdenv, hosted at
# tarballs.nixos.org.  They are content-addressed (verified by hash).

{ system ? "aarch64-linux" }:

let
  # Per-architecture download URLs and hashes.
  # Source: nixpkgs pkgs/stdenv/linux/bootstrap-files/*.nix
  archFiles = {
    "aarch64-linux" = {
      busyboxUrl  = "http://tarballs.nixos.org/stdenv-linux/aarch64/21ec906463ea8f11abf3f9091ddd4c3276516e58/busybox";
      busyboxHash = "sha256-0MuIeQlBUaeisqoFSu8y+8oB6K4ZG5Lhq8RcS9JqkFQ=";
      toolsUrl    = "http://tarballs.nixos.org/stdenv-linux/aarch64/21ec906463ea8f11abf3f9091ddd4c3276516e58/bootstrap-tools.tar.xz";
      toolsHash   = "sha256-aJvtsWeuQHbb14BGZ2EiOKzjQn46h3x3duuPEawG0eE=";
    };
    "x86_64-linux" = {
      busyboxUrl  = "http://tarballs.nixos.org/stdenv/x86_64-unknown-linux-gnu/82b583ba2ba2e5706b35dbe23f31362e62be2a9d/busybox";
      busyboxHash = "sha256-QrTEnQTBM1Y/qV9odq8irZkQSD9uOMbs2Q5NgCvKCNQ=";
      toolsUrl    = "http://tarballs.nixos.org/stdenv/x86_64-unknown-linux-gnu/82b583ba2ba2e5706b35dbe23f31362e62be2a9d/bootstrap-tools.tar.xz";
      toolsHash   = "sha256-YQlr088HPoVWBU2jpPhpIMyOyoEDZYDw1y60SGGbUM0=";
    };
  };

  files = archFiles.${system}
    or (throw "bootstrap-tools: unsupported system '${system}' (expected aarch64-linux or x86_64-linux)");

  # ---------------------------------------------------------------------------
  # Step 1: Fetch the static busybox binary.
  # This is the only binary we trust from outside — it's content-addressed.
  # busybox provides ash (shell), tar, xz, cp, mkdir, chmod, etc.
  # ---------------------------------------------------------------------------
  # system = "builtin" lets Nix run the fetch locally on any host, matching
  # the behaviour of <nix/fetchurl.nix> used by nixpkgs.
  busybox = builtins.derivation {
    name = "bootstrap-busybox";
    system = "builtin";
    builder = "builtin:fetchurl";
    url = files.busyboxUrl;
    executable = true;
    outputHash = files.busyboxHash;
    outputHashMode = "recursive";  # executable files need NAR hash
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };

  # ---------------------------------------------------------------------------
  # Step 2: Fetch the bootstrap-tools tarball.
  # Contains gcc, binutils, glibc, coreutils, tar, make, etc. with all
  # Nix store references stripped (nuke-refs'd).
  # ---------------------------------------------------------------------------
  tarball = builtins.derivation {
    name = "bootstrap-tools-tarball";
    system = "builtin";
    builder = "builtin:fetchurl";
    url = files.toolsUrl;
    outputHash = files.toolsHash;
    outputHashMode = "flat";
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };

  # ---------------------------------------------------------------------------
  # Step 3: Unpack the tarball and patch ELF binaries.
  # Uses busybox to unpack, then patchelf (from inside the tarball) to fix
  # the dynamic linker and RPATH in every binary.
  # ---------------------------------------------------------------------------
  bootstrapTools = builtins.derivation {
    name = "bootstrap-tools";
    inherit system tarball;
    builder = busybox;
    args = [ "ash" "-e" ./bootstrap-tools/unpack.sh ];
  };

in bootstrapTools
