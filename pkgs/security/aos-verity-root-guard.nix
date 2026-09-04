##! aos-verity-root-guard — Require a service RootImage to mount through dm-verity
{
  mkDerivation,
  bash,
  coreutils,
  efitools,
  openssl,
}:
mkDerivation {
  pname = "aos-verity-root-guard";
  version = "0";
  src = null;

  buildDeps = [];
  runtimeDeps = [
    bash
    coreutils
    efitools
    openssl
  ];
  propagatedDeps = [];

  phases = [
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        cat > $out/bin/aos-verity-root-guard <<'EOF'
        #!${bash}/bin/bash
        set -eu

        signature_only=0
        if [ "''${1:-}" = "--signature-only" ]; then
          signature_only=1
          shift
        fi

        expected="''${1:?missing expected dm-verity root hash}"
        signature="''${2:?missing dm-verity root hash signature}"
        db_guid="db-d719b2cb-3d3a-4596-a3bc-dad00e67656f"
        db_var=
        for candidate in \
          "/run/aos-secure-boot-efivars/$db_guid" \
          "/sys/firmware/efi/efivars/$db_guid"; do
          [ -z "$db_var" ] || break
          if [ -r "$candidate" ]; then
            db_var="$candidate"
            break
          fi
        done
        shift
        shift
        if [ "''${1:-}" = "--" ]; then
          shift
        fi
        cmd=()
        if [ "$#" -eq 0 ] && [ "$signature_only" != "1" ]; then
          echo "aos-verity-root-guard: missing command" >&2
          exit 226
        fi
        if [ "$#" -gt 0 ]; then
          cmd=("$@")
        fi

        if [ "$signature_only" != "1" ]; then
          root_dev=
          root_source=
          while IFS= read -r line; do
            set -- $line
            if [ "''${5:-}" = "/" ]; then
              root_dev="''${3:-}"
              after_separator="''${line#* - }"
              set -- $after_separator
              root_source="''${2:-}"
              break
            fi
          done < /proc/self/mountinfo

          dm_name=
          if [ -n "$root_dev" ] && [ -r "/sys/dev/block/$root_dev/dm/name" ]; then
            IFS= read -r dm_name < "/sys/dev/block/$root_dev/dm/name" || dm_name=
          fi

          if [ "$dm_name" != "$expected-verity" ]; then
            echo "aos-verity-root-guard: root is '$root_source' ($root_dev), not '$expected-verity'" >&2
            exit 226
          fi

          dm_uuid=
          if [ -r "/sys/dev/block/$root_dev/dm/uuid" ]; then
            IFS= read -r dm_uuid < "/sys/dev/block/$root_dev/dm/uuid" || dm_uuid=
          fi
          case "$dm_uuid" in
            CRYPT-VERITY-*-"$expected-verity") ;;
            *)
              echo "aos-verity-root-guard: root device '$dm_name' has unexpected dm uuid '$dm_uuid'" >&2
              exit 226
              ;;
          esac

          dm_suspended=
          if [ -r "/sys/dev/block/$root_dev/dm/suspended" ]; then
            IFS= read -r dm_suspended < "/sys/dev/block/$root_dev/dm/suspended" || dm_suspended=
          fi
          if [ "$dm_suspended" != "0" ]; then
            echo "aos-verity-root-guard: root device '$dm_name' is suspended" >&2
            exit 226
          fi

          slave_count=0
          for path in "/sys/dev/block/$root_dev/slaves/"*; do
            [ -e "$path" ] || continue
            slave_count=$((slave_count + 1))
          done
          if [ "$slave_count" -lt 2 ]; then
            echo "aos-verity-root-guard: root device '$dm_name' is not backed by data and hash devices" >&2
            exit 226
          fi
        fi

        if [ ! -r "$signature" ]; then
          echo "aos-verity-root-guard: root hash signature '$signature' is not readable" >&2
          exit 226
        fi
        if [ -z "$db_var" ]; then
          echo "aos-verity-root-guard: Secure Boot db is not readable" >&2
          exit 226
        fi

        work=$(${coreutils}/bin/mktemp -d "''${TMPDIR:-/tmp}/aos-verity-root-guard.XXXXXX")
        trap '${coreutils}/bin/rm -rf "$work"' EXIT
        printf '%s' "$expected" > "$work/root.roothash"
        if ! exec 3< "$db_var"; then
          echo "aos-verity-root-guard: Secure Boot db is not readable" >&2
          exit 226
        fi
        if ! ${coreutils}/bin/dd bs=4 count=1 iflag=fullblock of="$work/db.attrs" status=none <&3; then
          exec 3<&-
          echo "aos-verity-root-guard: cannot read Secure Boot db attributes" >&2
          exit 226
        fi
        if ! ${coreutils}/bin/cat <&3 > "$work/db.esl"; then
          exec 3<&-
          echo "aos-verity-root-guard: cannot read Secure Boot db" >&2
          exit 226
        fi
        exec 3<&-
        if ! ${efitools}/bin/sig-list-to-certs "$work/db.esl" "$work/db" > "$work/sig-list-to-certs.log" 2>&1; then
          echo "aos-verity-root-guard: cannot extract Secure Boot db certificates" >&2
          exit 226
        fi

        verified=0
        for cert in "$work"/db-*.der; do
          [ -e "$cert" ] || continue
          pem="$cert.pem"
          if ${openssl}/bin/openssl x509 -inform DER -in "$cert" -out "$pem" > "$work/openssl-x509.log" 2>&1 \
            && ${openssl}/bin/openssl cms -verify -binary \
              -inform DER \
              -in "$signature" \
              -content "$work/root.roothash" \
              -CAfile "$pem" \
              -purpose any \
              -no_check_time \
              -out "$work/cms.out" > "$work/openssl-cms.log" 2>&1; then
            verified=1
            break
          fi
        done
        if [ "$verified" != "1" ]; then
          echo "aos-verity-root-guard: root hash signature is not trusted by Secure Boot db" >&2
          exit 226
        fi

        if [ "''${#cmd[@]}" -eq 0 ]; then
          exit 0
        fi
        exec "''${cmd[@]}"
        EOF
        chmod +x $out/bin/aos-verity-root-guard
      '';
    }
  ];

  # The installed shell program is generated inline above, so the package
  # definition is its complete corresponding source.
  passthru.evidenceSources = [
    (builtins.path {
      path = ./aos-verity-root-guard.nix;
      name = "aos-verity-root-guard.nix";
    })
  ];

  meta = {
    description = "Require service RootImage mounts to use the expected dm-verity device";
    license = "MIT";
  };
}
