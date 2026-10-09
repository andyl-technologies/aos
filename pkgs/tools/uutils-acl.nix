##! uutils acl — Rust ACL command suite.
{
  mkCargoPackage,
  fetchCargoDeps,
  fetchurl,
}: let
  version = "0.0.1";
  revision = "f99244539cb4ac4e1f7bfa86d8084d0569992aa5";
  src = fetchurl {
    urls = ["https://github.com/uutils/acl/archive/${revision}.tar.gz"];
    hash = "sha256-vHi2ll114gSPtGMM/5VeenvMg+VvgemVMqO0cSosoG4=";
  };
  cargoDeps = fetchCargoDeps {
    inherit src;
    hash = "sha256-5g3fwciZUhEi8wpPBAD8kwyNio35i5v6yT12vFKx5Ec=";
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
      ];
      target = [];
      role = "public-package";
    };
    pname = "uutils-acl";
    inherit version src cargoDeps;

    cargoFlags = "--bin acl";
    doCheck = false;

    postInstall = ''
      cargo tree --offline --depth 1 --edges normal,build --format '{p}' --prefix none \
        | sed -n 's/^uu_\([^ ]*\) .*/\1/p' \
        | while read -r utility; do
            ln -s acl "$out/bin/$utility"
          done

      test -L "$out/bin/getfacl"
      test -L "$out/bin/setfacl"
      test -L "$out/bin/chacl"
    '';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-uutils-acl";
        tool = self;
        command = ''
          printf 'probe' > /tmp/uutils-acl-probe
          entries=$(${self}/bin/getfacl -c /tmp/uutils-acl-probe)
          case "$entries" in
            *'user::rw-'*) printf 'acl-read\n' ;;
            *) exit 1 ;;
          esac
        '';
        expectedOutput = "acl-read";
      };
    };

    meta = {
      description = "Rust ACL command suite";
      homepage = "https://github.com/uutils/acl";
      license = "MIT";
      mainProgram = "getfacl";
    };
  }
