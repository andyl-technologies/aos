# Helm — Kubernetes package manager
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "3.16.4";
in
mkDerivation {
  pname = "helm";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/helm/helm/archive/v${version}/helm-${version}.tar.gz"
    ];
    hash = "sha256-QooO0GE2zCAY/+KD9eT3+6TSo3vFZs0M9apVDEmF9bs=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd helm-${version}
      '';
    }
    {
      name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        go build -o helm \
          -ldflags "-s -w \
            -X helm.sh/helm/v3/internal/version.version=v${version} \
            -X helm.sh/helm/v3/internal/version.gitTreeState=clean" \
          ./cmd/helm
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 helm $out/bin/helm
      '';
    }
  ];

  meta = {
    description = "Helm — the Kubernetes package manager";
    homepage = "https://helm.sh";
    license = "Apache-2.0";
  };
}
