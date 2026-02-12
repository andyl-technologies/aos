# nerdctl — Docker-compatible CLI for containerd
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "1.7.7";
in
mkDerivation {
  pname = "nerdctl";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/containerd/nerdctl/archive/v${version}/nerdctl-${version}.tar.gz"
    ];
    hash = "sha256-vN3y7jrSvIStxeIH+XFXmY/pc5EsfR3ZVAvUu0oHaY0=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd nerdctl-${version}
      '';
    }
    {
      name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        go build -o nerdctl \
          -ldflags "-s -w -X github.com/containerd/nerdctl/pkg/version.Version=v${version}" \
          ./cmd/nerdctl
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 nerdctl $out/bin/nerdctl
      '';
    }
  ];

  meta = {
    description = "nerdctl — Docker-compatible CLI for containerd";
    homepage = "https://github.com/containerd/nerdctl";
    license = "Apache-2.0";
  };
}
