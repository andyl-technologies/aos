##! efibootmgr — EFI boot entry manager
{
  mkDerivation,
  fetchurl,
  gnumake,
  pkg-config,
  efivar,
  popt,
}: let
  version = "18";
in
  mkDerivation {
    pname = "efibootmgr";
    inherit version;

    src = fetchurl {
      urls = ["https://github.com/rhboot/efibootmgr/archive/refs/tags/${version}.tar.gz"];
      hash = "sha256-RChn0S+FJQNKQE/IrzA226jh/JcJmK8khsO5QN+tCHQ=";
    };

    buildDeps = [gnumake pkg-config];
    runtimeDeps = [efivar popt];
    propagatedDeps = [];

    makeFlags = "EFIDIR=aos PKG_CONFIG=pkg-config";
    installFlags = "EFIDIR=aos prefix=${builtins.placeholder "out"}";

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-efibootmgr";
        tool = self;
        command = "efibootmgr --version";
      };
    };

    meta = {
      description = "Userspace manager for UEFI boot entries";
      homepage = "https://github.com/rhboot/efibootmgr";
      license = "GPL-2.0-only";
      mainProgram = "efibootmgr";
    };
  }
