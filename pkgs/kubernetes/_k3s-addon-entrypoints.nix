##! Adapts the upstream Helm and service-load-balancer entrypoints to AOS paths.
{
  lib,
  pkgs,
  buildPackages,
  helmPrograms,
}: let
  scriptPackage = {
    pname,
    version,
    hash,
    runtime,
    patchScript ? "",
  }: let
    src = pkgs.fetchurl {
      name = "${pname}-v${version}.tar.gz";
      urls = ["https://github.com/k3s-io/${pname}/archive/refs/tags/v${version}.tar.gz"];
      inherit hash;
    };
    path = lib.concatMapStringsSep ":" (package: "${package}/bin:${package}/sbin") runtime;
  in
    pkgs.mkDerivation {
      inherit pname version src;
      buildDeps = [buildPackages.bash];
      runtimeDeps = [pkgs.bash] ++ runtime;
      phases = [
        {
          name = "unpack";
          script = ''
            mkdir source
            tar xf "$src" --strip-components=1 -C source
            cd source
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin" "$out/share/licenses/${pname}"
            sed -i '1c\#!${pkgs.bash}/bin/bash' entry
            sed -i '2i\export PATH="${path}"' entry
            ${patchScript}
            ${buildPackages.bash}/bin/bash -n entry
            install -m 0755 entry "$out/bin/${pname}"
            cp LICENSE "$out/share/licenses/${pname}/"
          '';
        }
      ];
      meta = {
        description = "${pname} entrypoint using source-built AOS runtime tools";
        license = "Apache-2.0";
      };
    };
in {
  helm = scriptPackage {
    pname = "klipper-helm";
    version = "0.9.14-build20260210";
    hash = "sha256-kTVRbG6/0a/SGJwu/l9AQDLIGoWdfCXWJ9lDnJ91Nk8=";
    runtime = [helmPrograms.helm pkgs.coreutils pkgs.grep pkgs.jq];
  };

  loadBalancer = scriptPackage {
    pname = "klipper-lb";
    version = "0.4.14";
    hash = "sha256-T5UmXlOomjqwhjAaRJ+EFf/zWo/GrGSK/Vxd+yR7ZQo=";
    runtime = [pkgs.iptables pkgs.coreutils pkgs.grep];
    patchScript = ''
      # Keep upstream's nft/legacy selection, but write aliases into /run.
      # Both backends are immutable AOS outputs, outside the writable directory.
      # Read lsmod's kernel source directly; this job never loads modules.
      sed -i \
        -e 's|lsmod [|] grep -qF nf_tables|grep -q "^nf_tables " /proc/modules|' \
        -e 's|^BIN_DIR=.*|BIN_DIR="/run/klipper-lb/bin"\nmkdir -p "$BIN_DIR"\nexport PATH="$BIN_DIR:$PATH"|' \
        -e 's|ln -sf xtables-nft-multi|ln -sf ${pkgs.iptables}/sbin/xtables-nft-multi|' \
        -e 's|ln -sf xtables-legacy-multi|ln -sf ${pkgs.iptables}/sbin/xtables-legacy-multi|' \
        entry
    '';
  };
}
