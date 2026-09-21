##! Pins Helm and the dependency updates used by K3s's Helm job plugins.
{
  mkDerivation,
  fetchurl,
}: let
  sourceWithLocks = {
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
            # Keep Helm and its plugins on reviewed dependency graphs. Builds
            # consume the retained locks without network access or resolution.
            cp ${locks}/go.mod ${locks}/go.sum .
            mkdir -p "$out"
            cp -R . "$out/"
          '';
        }
      ];
    };
in {
  helm = sourceWithLocks {
    pname = "helm";
    version = "3.22.0";
    repository = "helm/helm";
    hash = "sha256-AqMklxy3CLfTKrdRdy+3Zbgd9tPpPAw+hFs/W6r4DGU=";
    locks = ./_k3s-helm-locks/helm;
  };

  set-status = sourceWithLocks {
    pname = "helm-set-status";
    version = "0.3.0";
    repository = "k3s-io/helm-set-status";
    hash = "sha256-Vt/qu4AmZLfGkmB+r8gj94RgUYFTkHCvqjaeYrTf0Ps=";
    locks = ./_k3s-helm-locks/set-status;
  };

  mapkubeapis = sourceWithLocks {
    pname = "helm-mapkubeapis";
    version = "0.6.1";
    repository = "helm/helm-mapkubeapis";
    hash = "sha256-Jh9K2zoJpbfAajJGQFfG+TyPvenFd2vQexf9yq0Y7AI=";
    locks = ./_k3s-helm-locks/mapkubeapis;
  };
}
