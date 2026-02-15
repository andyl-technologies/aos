##! Ignition — First-boot provisioning utility
##!
##! TODO: Build from source once Go is bootstrapped as an AOS package.
##! Go requires a multi-stage bootstrap (Go 1.4 from C, then modern Go).
##! For now, install a shell-script stub that logs and exits.
{ mkDerivation, fetchurl }:

let
  version = "2.19.0";
in
mkDerivation {
  pname = "ignition";
  inherit version;

  src = null;

  buildDeps = [ ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "install";
      script = ''
                mkdir -p $out/bin
                cat > $out/bin/ignition << 'STUB'
        #!/bin/sh
        echo "ignition: stub — Go bootstrap not yet implemented" >&2
        exit 1
        STUB
                chmod +x $out/bin/ignition
      '';
    }
  ];

  meta = {
    description = "Ignition — machine provisioning utility (stub)";
    homepage = "https://github.com/coreos/ignition";
    license = "Apache-2.0";
  };
}
