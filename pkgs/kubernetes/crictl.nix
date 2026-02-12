# crictl — CLI for CRI-compatible container runtimes
{
  mkDerivation,
  fetchurl,
  make,
}:

let
  version = "1.31.1";
in
mkDerivation {
  pname = "crictl";
  inherit version;

  src = fetchurl {
    urls = [
      "https://github.com/kubernetes-sigs/cri-tools/archive/v${version}/cri-tools-${version}.tar.gz"
    ];
    hash = "sha256-RlvRR2ioangsbksVs2g8Sl79A2PWiyQdV1enutqbzSE=";
  };

  buildDeps = [ make ];
  runtimeDeps = [ ];
  propagatedDeps = [ ];

  phases = [
    {
      name = "unpack";
      script = ''
        tar xf $src
        cd cri-tools-${version}
      '';
    }
    {
      name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        go build -o crictl \
          -ldflags "-s -w -X github.com/kubernetes-sigs/cri-tools/pkg/version.Version=v${version}" \
          ./cmd/crictl
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        install -m 755 crictl $out/bin/crictl
      '';
    }
  ];

  meta = {
    description = "crictl — CLI for CRI-compatible container runtimes";
    homepage = "https://github.com/kubernetes-sigs/cri-tools";
    license = "Apache-2.0";
  };
}
