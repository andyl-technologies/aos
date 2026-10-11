##! uutils tar — Rust tar archiver.
{
  mkCargoPackage,
  fetchCargoVendor,
  fetchurl,
}: let
  version = "0.0.1";
  revision = "ad4ce760660ccbcb81b86dfc558e95fbc59c064f";
  src = fetchurl {
    urls = ["https://github.com/uutils/tar/archive/${revision}.tar.gz"];
    hash = "sha256-vk+e3ariK9iJOT5i81Jpe31+wGJm5lN23rF7TP9nzf8=";
  };
  cargoDeps = fetchCargoVendor {
    inherit src;
    hash = "sha256-RFGQsZVqk7PDT6qo+43lgC37VRhGVUn4QiXEjLdX35Q=";
  };
in
  mkCargoPackage {
    platformSupport = {
      build = [
        {
          abi = ["gnu"];
          os = ["linux"];
        }
      ];
      host = [
        {
          abi = ["gnu"];
          cpu = ["x86_64" "aarch64"];
          os = ["linux"];
        }
        {
          abi = ["darwin"];
          cpu = ["x86_64" "aarch64"];
          os = ["darwin"];
        }
      ];
      target = [];
      role = "public-package";
    };
    pname = "uutils-tar";
    inherit version src cargoDeps;

    cargoFlags = "--bin tarapp";
    doCheck = false;

    postInstall = ''
      ln -s tarapp "$out/bin/tar"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-uutils-tar";
        tool = self;
        command = ''
          cd /tmp
          printf 'payload' > uutils-tar-source
          ${self}/bin/tar -cf uutils-tar-archive.tar uutils-tar-source
          rm uutils-tar-source
          ${self}/bin/tar -xf uutils-tar-archive.tar
          cat uutils-tar-source
        '';
        expectedOutput = "payload";
      };
    };

    meta = {
      description = "Rust tar archiver";
      homepage = "https://github.com/uutils/tar";
      license = "MIT";
      mainProgram = "tar";
    };
  }
