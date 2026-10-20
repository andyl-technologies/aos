##! Checks deterministic ESP population with the production helper and real FAT.
{pkgs, ...}:
pkgs.mkDerivation {
  pname = "esp-population-check";
  version = "1";
  src = null;
  buildDeps = [pkgs.bash pkgs.coreutils pkgs.findutils pkgs.mtools pkgs.dosfstools pkgs.python3];
  outputChecks.out = {};
  phases = [
    {
      name = "check";
      script = ''
        ${pkgs.python3}/bin/python3 ${./_esp-population.py} \
          --bash ${pkgs.bash}/bin/bash \
          --helper ${../../pkgs/system/_systemd-abilities/platform/_populate-esp.sh} \
          --mkfs ${pkgs.dosfstools}/sbin/mkfs.vfat \
          --mcopy ${pkgs.mtools}/bin/mcopy \
          --mshowfat ${pkgs.mtools}/bin/mshowfat \
          --tool-path ${pkgs.coreutils}/bin:${pkgs.findutils}/bin:${pkgs.mtools}/bin
        mkdir -p "$out"
        printf 'PASS\n' > "$out/result"
      '';
    }
  ];
}
