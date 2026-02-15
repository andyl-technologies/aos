##! nerdctl — Docker-compatible CLI for containerd
{
  mkDerivation,
  fetchurl,
  go,
  cni-plugins,
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

  buildDeps = [ go ];
  runtimeDeps = [ cni-plugins ];
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
      name = "configure";
      script = ''
        export GOPATH="$TMPDIR/go"
        export GOCACHE="$TMPDIR/go-cache"
        export GOFLAGS="-trimpath"
        export CGO_ENABLED=0
        mkdir -p "$GOPATH" "$GOCACHE"

        # Use vendored deps from source
        if [ -d vendor ]; then
          export GOFLAGS="$GOFLAGS -mod=vendor"
        fi
      '';
    }
    {
      name = "build";
      script = ''
        go build \
          -ldflags "-s -w -X github.com/containerd/nerdctl/pkg/version.Version=v${version}" \
          -o nerdctl \
          ./cmd/nerdctl
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p "$out/bin"
        install -m 755 nerdctl "$out/bin/.nerdctl-unwrapped"

        cat > "$out/bin/nerdctl" << WRAPPER
        #!/bin/sh
        export CNI_PATH="${cni-plugins}/bin"
        exec "\$(dirname "\$0")/.nerdctl-unwrapped" "\$@"
        WRAPPER
        chmod +x "$out/bin/nerdctl"
      '';
    }
  ];

  meta = {
    description = "nerdctl — Docker-compatible CLI for containerd";
    homepage = "https://github.com/containerd/nerdctl";
    license = "Apache-2.0";
  };
}
