##! Shared KubeEdge source — used by cloudcore, edgecore
{ fetchurl }:
let
  version = "1.20.0";
in
{
  inherit version;
  src = fetchurl {
    urls = [
      "https://github.com/kubeedge/kubeedge/archive/v${version}/kubeedge-${version}.tar.gz"
    ];
    hash = "sha256-ITwaKM9riNEKqBt16A1aJnU2GCKIgwiumbiPUPVIH7k=";
  };
}
