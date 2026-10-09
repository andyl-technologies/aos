##! Fixed image-owned filesystem worker; no standalone activation authority.
{
  lib,
  mkCargoPackage,
  protobuf,
  pkg-config,
  elfutils,
  aos-fuse-transport,
  aos-sandbox-mountd,
}: let
  version = "0.1.0";
  src = import ../tools/aos/_workspace-source.nix {inherit lib;};
in
  mkCargoPackage {
    pname = "aos-filesystem-fuse-worker";
    inherit version src;
    # The complete workspace has one vendor input contract. Reuse Mount's
    # source-only vendor derivation rather than adding another divergent pin.
    cargoDeps = aos-sandbox-mountd.passthru.cargoDeps;
    cargoRoot = "crates";
    cargoFlags = "-p aos-filesystem-fuse --bin aos-filesystem-fuse-worker";
    cargoTestFlags = "-p aos-filesystem-fuse";
    # Protected journal fixtures are debug-only; the installed worker remains
    # a release build without fixture authority.
    checkType = "debug";
    cargoNextest = true;
    doCheck = true;
    buildDeps = [protobuf pkg-config elfutils];
    runtimeDeps = [aos-fuse-transport];
    cargoEnv = {
      PROTOC = "${protobuf}/bin/protoc";
      RUSTFLAGS = "-C link-arg=-Wl,--build-id=sha1";
    };

    postInstall = ''
      test -x "$out/bin/aos-filesystem-fuse-worker"
      notes=$(${elfutils}/bin/eu-readelf --notes "$out/bin/aos-filesystem-fuse-worker")
      printf '%s\n' "$notes" | grep -Fq 'GNU_BUILD_ID'
      printf '%s\n' "$notes" | grep -Eq 'Build ID: [0-9a-f]{40}$'
    '';

    meta = {
      description = "Closed image-owned immutable filesystem worker";
      homepage = "https://github.com/andyl/andyl-os";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }
