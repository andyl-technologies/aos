##! Native mkDerivation platform declaration checks.
{pkgs}: let
  declaration = {
    build = [
      {
        os = ["builder-os"];
        features = ["native-toolchain"];
      }
    ];
    host = [
      {
        cpu = [
          "host-a"
          "host-b"
        ];
        os = ["target-os"];
      }
    ];
    target = [];
    role = "public-package";
  };
  package = pkgs.mkDerivation {
    pname = "package-platform-declaration-probe";
    version = "0";
    src = null;
    platformSupport = declaration;
    outputChecks = {};
    phases = [
      {
        name = "install";
        script = ''
          mkdir -p "$out"
          printf 'PASS\n' > "$out/result"
        '';
      }
    ];
  };
  rejects = value: !(builtins.tryEval (builtins.deepSeq value true)).success;
  unknownConstraintRejected = rejects (pkgs.lib.packagePlatform.normalize "unknown-constraint" (
    declaration
    // {
      host = [{vendor = ["forged-vendor"];}];
    }
  ));
  missingAxisRejected = rejects (pkgs.lib.packagePlatform.normalize "missing-axis" (
    builtins.removeAttrs declaration ["target"]
  ));
  unknownRoleRejected = rejects (pkgs.lib.packagePlatform.normalize "unknown-role" (
    declaration // {role = "documentary-tag";}
  ));
  featurePlatform = {
    constraints = {
      cpu = "host-a";
      os = "target-os";
      abi = "target-abi";
      features = [
        "native-toolchain"
        "signed-sdk"
      ];
    };
  };
in
  assert package.platformSupport == pkgs.lib.packagePlatform.normalize "expected" declaration;
  assert pkgs.lib.packagePlatform.supports featurePlatform [
    {
      os = ["target-os"];
      features = ["signed-sdk"];
    }
  ];
  assert !(pkgs.lib.packagePlatform.supports featurePlatform [{features = ["missing-feature"];}]);
  assert unknownConstraintRejected;
  assert missingAxisRejected;
  assert unknownRoleRejected; package
