##! Builds Helm and both plugins used by the K3s Helm job lifecycle.
{
  mkDerivation,
  fetchurl,
  fetchGoModules,
  buildPackages,
  glibc,
}: let
  sources = import ./_k3s-helm-sources.nix {inherit mkDerivation fetchurl;};
  buildProgram = {
    pname,
    version,
    src,
    moduleHash,
    command,
    versionFlags,
    cgo ? false,
    tags ? "",
    prepare ? "",
  }: let
    modules = fetchGoModules {
      inherit src;
      name = "${pname}-go-modules";
      hash = moduleHash;
    };
  in
    mkDerivation {
      inherit pname version src;
      buildDeps = [buildPackages.go];
      runtimeDeps =
        if cgo
        then [glibc]
        else [];
      passthru.evidenceSources = [src modules];
      phases = [
        {
          name = "unpack";
          script = ''
            mkdir source
            if [ -d "$src" ]; then
              cp -R "$src"/. source/
              chmod -R u+w source
            else
              tar xf "$src" --strip-components=1 -C source
            fi
            cd source
          '';
        }
        {
          name = "build";
          script = ''
            export GOPATH="${modules}"
            export GOCACHE="$TMPDIR/go-cache"
            export GOPROXY=off
            export GOTOOLCHAIN=local
            export CGO_ENABLED=${
              if cgo
              then "1"
              else "0"
            }
            export GOMAXPROCS="$NIX_BUILD_CORES"
            if [ -n "''${AOS_CROSS_COMPILING:-}" ]; then
              export GOOS="$AOS_GOOS"
              export GOARCH="$AOS_GOARCH"
            fi

            ${prepare}
            go build -mod=readonly -p "$NIX_BUILD_CORES" -trimpath \
              -tags "${tags}" -ldflags "-s -w ${versionFlags}" \
              -o ${pname} ${command}
          '';
        }
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin" "$out/share/licenses/${pname}"
            install -m 0755 ${pname} "$out/bin/${pname}"
            cp LICENSE "$out/share/licenses/${pname}/"
          '';
        }
      ];
      meta = {
        description = "${pname} for the source-built K3s Helm job";
        license = "Apache-2.0";
      };
    };

  setStatus = buildProgram {
    pname = "helm-set-status";
    version = "0.3.0";
    src = sources.set-status;
    moduleHash = "sha256-+MIfOJl1fiFZ6XYXLqu5Er2klxd5+Tg1cB3dczX1D0Y=";
    command = "./cmd/helm-set-status";
    versionFlags = "-X main.version=0.3.0";
    cgo = true;
    tags = "static_build netcgo osusergo";
  };
  mapKubeApis = buildProgram {
    pname = "mapkubeapis";
    version = "0.6.1";
    src = sources.mapkubeapis;
    moduleHash = "sha256-TyJXqVTuIeVScGt6nueNwQ5OZkA5LSSl33eOu4bvoYo=";
    command = "./cmd/mapkubeapis";
    versionFlags = "-X main.version=0.6.1";
  };
in {
  helm = buildProgram {
    pname = "helm";
    version = "3.19.5";
    src = sources.helm;
    moduleHash = "sha256-AKelZroc7C1ii+cRPF+srKatW89ZjgoUpq9EycEdxi8=";
    command = "./cmd/helm";
    prepare = ''
      # Helm derives its offline Kubernetes capabilities from the module pin.
      kubernetes_minor=$(sed -n 's|^[[:space:]]*k8s.io/apimachinery v0\.\([0-9]*\)\..*|\1|p' go.mod)
      test -n "$kubernetes_minor"
    '';
    versionFlags = "-X helm.sh/helm/v3/internal/version.version=v3.19.5 -X helm.sh/helm/v3/pkg/lint/rules.k8sVersionMajor=1 -X helm.sh/helm/v3/pkg/lint/rules.k8sVersionMinor=$kubernetes_minor -X helm.sh/helm/v3/pkg/chartutil.k8sVersionMajor=1 -X helm.sh/helm/v3/pkg/chartutil.k8sVersionMinor=$kubernetes_minor";
  };

  plugins = mkDerivation {
    pname = "k3s-helm-plugins";
    version = "3.19.5";
    src = [sources.set-status sources.mapkubeapis];
    buildDeps = [];
    runtimeDeps = [setStatus mapKubeApis];
    passthru.evidenceSources =
      setStatus.passthru.evidenceSources
      ++ mapKubeApis.passthru.evidenceSources;
    phases = [
      {
        name = "install";
        script = ''
          plugins="$out/share/helm/plugins"
          mkdir -p "$plugins/helm-set-status" "$plugins/helm-mapkubeapis/bin"
          cp ${sources.set-status}/plugin.yaml "$plugins/helm-set-status/"
          ln -s ${setStatus}/bin/helm-set-status "$plugins/helm-set-status/helm-set-status"
          cp ${sources.mapkubeapis}/plugin.yaml "$plugins/helm-mapkubeapis/"
          cp -R ${sources.mapkubeapis}/config "$plugins/helm-mapkubeapis/"
          ln -s ${mapKubeApis}/bin/mapkubeapis "$plugins/helm-mapkubeapis/bin/mapkubeapis"
        '';
      }
    ];
    meta = {
      description = "Helm status recovery and Kubernetes API migration plugins for K3s";
      license = "Apache-2.0";
    };
  };
}
