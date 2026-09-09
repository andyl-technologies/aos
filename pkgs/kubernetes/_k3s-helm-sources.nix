##! Pins Helm and the dependency updates used by K3s's Helm job plugins.
{
  mkDerivation,
  fetchurl,
}: let
  pluginSource = {
    pname,
    version,
    repository,
    hash,
    locks,
  }: let
    archive = fetchurl {
      name = "${pname}-v${version}.tar.gz";
      urls = ["https://github.com/${repository}/archive/refs/tags/v${version}.tar.gz"];
      inherit hash;
    };
  in
    mkDerivation {
      pname = "${pname}-source";
      inherit version;
      src = archive;
      buildDeps = [];
      runtimeDeps = [];
      passthru.evidenceSources = [archive locks];
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
            # Klipper Helm upgrades both plugins to the job's Helm library
            # before compiling them. Retain the resolved graph so the build
            # needs neither network access nor a new dependency resolution.
            cp ${locks}/go.mod ${locks}/go.sum .
            mkdir -p "$out"
            cp -R . "$out/"
          '';
        }
      ];
    };
in {
  helm = fetchurl {
    name = "helm-v3.19.5.tar.gz";
    urls = ["https://github.com/helm/helm/archive/refs/tags/v3.19.5.tar.gz"];
    hash = "sha256-z+9Gxgj5/3B0smTXvQUo3aTWxG/3pSXOOL40FEd7D3s=";
  };

  set-status = pluginSource {
    pname = "helm-set-status";
    version = "0.3.0";
    repository = "k3s-io/helm-set-status";
    hash = "sha256-Vt/qu4AmZLfGkmB+r8gj94RgUYFTkHCvqjaeYrTf0Ps=";
    locks = ./_k3s-helm-locks/set-status;
  };

  mapkubeapis = pluginSource {
    pname = "helm-mapkubeapis";
    version = "0.6.1";
    repository = "helm/helm-mapkubeapis";
    hash = "sha256-Jh9K2zoJpbfAajJGQFfG+TyPvenFd2vQexf9yq0Y7AI=";
    locks = ./_k3s-helm-locks/mapkubeapis;
  };
}
