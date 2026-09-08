##! iperf3 — Network throughput measurement tool
{
  mkDerivation,
  fetchurl,
  gnumake,
  openssl,
  lksctp-tools,
}: let
  version = "3.21";
in
  mkDerivation {
    pname = "iperf3";
    inherit version;

    src = fetchurl {
      urls = ["https://downloads.es.net/pub/iperf/iperf-${version}.tar.gz"];
      hash = "sha256-ZW5EBevWIBId587KPq9DqI956huFfQQaagsTFIAazdg=";
    };

    buildDeps = [gnumake];
    runtimeDeps = [openssl lksctp-tools];
    propagatedDeps = [];
    configureFlags = "--with-openssl=${openssl}";

    postInstall = ''ln -s iperf3 "$out/bin/iperf"'';

    checks = {
      testing,
      self,
      ...
    }: {
      tool = testing.mkToolCheck {
        pname = "tool-iperf3";
        tool = self;
        command = "iperf3 --version";
      };
    };

    meta = {
      description = "Measures TCP, UDP, and SCTP network throughput";
      homepage = "https://software.es.net/iperf/";
      license = "BSD-3-Clause";
      mainProgram = "iperf3";
    };
  }
