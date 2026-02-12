# update-tool — ANDYL OS A/B update agent
{ mkDerivation, fetchurl, sources, versions, make }:

mkDerivation {
  name = "update-tool-${versions.update.update-tool}";
  version = versions.update.update-tool;

  src = fetchurl {
    inherit (sources.update-tool) url hash;
  };

  buildDeps = [ make ];
  runtimeDeps = [];
  propagatedDeps = [];

  phases = [
    { name = "unpack";
      script = ''
        tar xf $src
        cd update-tool-${versions.update.update-tool}
      '';
    }
    { name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        export CGO_ENABLED=0
        export GOFLAGS="-trimpath"
        go build -o update-tool \
          -ldflags "-s -w -X main.version=${versions.update.update-tool}" \
          ./cmd/update-tool
      '';
    }
    { name = "install";
      script = ''
        mkdir -p $out/bin $out/lib/systemd/system

        install -m 755 update-tool $out/bin/update-tool

        # Install systemd units for the update agent
        cat > $out/lib/systemd/system/aos-update.service <<'UNIT'
        [Unit]
        Description=ANDYL OS Update Agent
        After=network-online.target
        Wants=network-online.target

        [Service]
        Type=oneshot
        ExecStart=$out/bin/update-tool check-and-apply
        StandardOutput=journal
        StandardError=journal

        [Install]
        WantedBy=multi-user.target
        UNIT

        cat > $out/lib/systemd/system/aos-update.timer <<'TIMER'
        [Unit]
        Description=ANDYL OS Update Check Timer

        [Timer]
        OnCalendar=*-*-* 03:00:00
        RandomizedDelaySec=3600
        Persistent=true

        [Install]
        WantedBy=timers.target
        TIMER
      '';
    }
  ];

  meta = {
    description = "ANDYL OS update agent — A/B image-based OS updates";
    homepage = "https://github.com/andyl/andyl-os";
    license = "Apache-2.0";
  };
}
