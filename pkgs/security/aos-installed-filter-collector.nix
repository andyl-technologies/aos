##! Private fixed specimen children; no caller-selected PID, path or command.
{
  mkDerivation,
  coreutils,
}: mkDerivation {
  pname = "aos-installed-filter-collector";
  version = "0.1.0";
  src = ./aos-installed-filter-collector;
  dontStrip = true;

  buildDeps = [coreutils];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    {
      name = "unpack";
      script = ''
        cp -R $src source
        chmod -R u+w source
        cd source
      '';
    }
    {
      name = "build";
      script = ''
        $CC -std=c17 -O2 -Wall -Wextra -Werror -static \
          reader.c -o aos-installed-filter-reader
        $CC -std=c17 -O2 -Wall -Wextra -Werror -static \
          network.c -o aos-deployment-specimen-network
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/libexec
        cp aos-installed-filter-reader $out/libexec/
        $STRIP -s $out/libexec/aos-installed-filter-reader
        chmod 0555 $out/libexec/aos-installed-filter-reader

        cp aos-deployment-specimen-network $out/libexec/
        $STRIP -s $out/libexec/aos-deployment-specimen-network
        chmod 0555 $out/libexec/aos-deployment-specimen-network
      '';
    }
  ];

  # Pins describe the final executable bytes after fixup and reference scrubbing.
  postFinalize = ''
    sha256sum $out/libexec/aos-installed-filter-reader | cut -d ' ' -f 1 \
      > $out/libexec/aos-installed-filter-reader.sha256
    chmod 0444 $out/libexec/aos-installed-filter-reader.sha256

    sha256sum $out/libexec/aos-deployment-specimen-network | cut -d ' ' -f 1 \
      > $out/libexec/aos-deployment-specimen-network.sha256
    chmod 0444 $out/libexec/aos-deployment-specimen-network.sha256
  '';

  passthru.evidenceSources = [
    ./aos-installed-filter-collector.nix
    ./aos-installed-filter-collector/reader.c
    ./aos-installed-filter-collector/collector_identity.h
    ./aos-installed-filter-collector/network.c
  ];

  meta = {
    description = "Confined private reader for the fixed deployment specimen filter stack";
    license = "Apache-2.0";
    platforms = ["x86_64-linux"];
  };
}
