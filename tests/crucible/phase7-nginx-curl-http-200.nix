{
  pkgs,
  lib,
  attrPath ? "checks.crucible.phase7.nginxCurlHttp200",
}: let
  crucibleSrc = import ../../pkgs/tools/crucible/_source.nix {inherit lib;};
  cargoDeps = pkgs.fetchCargoDeps {
    src = crucibleSrc;
    sourceRoot = "source/crates";
    hash = import ../../pkgs/tools/crucible/_cargo-deps-hash.nix;
  };
  guest = import ./_nginx-curl-http-200-guest.nix {inherit pkgs;};
  scenario = ./fixtures/nginx-curl-http-200.scenario.toml;
in
  pkgs.mkDerivation {
    pname = "crucible-phase7-nginx-curl-http-200";
    version = "0";
    src = crucibleSrc;

    buildDeps = [
      pkgs.coreutils
      pkgs.crucible
      pkgs.crucible-qemu-plugin
      pkgs.diffutils
      pkgs.grep
      pkgs.qemu-crucible
      pkgs.rust
      pkgs.sed
      guest
    ];

    phases = [
      {
        name = "unpack";
        script = ''
          cp -R "$src" source
          chmod -R u+w source
          cd source
        '';
      }
      {
        name = "configure";
        script = ''
          export CARGO_HOME="$TMPDIR/cargo"
          mkdir -p "$CARGO_HOME" .cargo
          if [ -f "${cargoDeps}/.cargo/config.toml" ]; then
            sed "s|@vendor@|${cargoDeps}|g" "${cargoDeps}/.cargo/config.toml" \
              > .cargo/config.toml
          else
            printf '[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "${cargoDeps}"\n\n' \
              > .cargo/config.toml
          fi
        '';
      }
      {
        name = "run-nginx-curl-http-200";
        script = ''
          set -eu
          cargo build \
            --frozen \
            --offline \
            --target-dir "$TMPDIR/nginx-curl-target" \
            --manifest-path crates/Cargo.toml \
            -p crucible-api \
            --example crucible-nginx-curl-http-200

          runner="$TMPDIR/nginx-curl-target/debug/examples/crucible-nginx-curl-http-200"
          "$runner" --emit-scenario > "$TMPDIR/generated.scenario.toml"
          diff -u ${scenario} "$TMPDIR/generated.scenario.toml"
          grep -Fq 'white_box = "enabled"' "$TMPDIR/generated.scenario.toml"
          grep -Fq 'kind = "guest_marker"' "$TMPDIR/generated.scenario.toml"
          if grep -Fq 'kind = "console_match"' "$TMPDIR/generated.scenario.toml"; then
            echo "application result unexpectedly uses ConsoleMatch" >&2
            exit 1
          fi
          if grep -Eq 'HTTP/1\\.1 200|GET /|CURL_STATUS' "$TMPDIR/generated.scenario.toml"; then
            echo "application result unexpectedly parses protocol or console text" >&2
            exit 1
          fi

          vmlinuz=$(ls ${pkgs.linux}/boot/vmlinuz-* | head -1)
          test -n "$vmlinuz"
          report="$TMPDIR/nginx-curl-http-200.result"
          timeout -k 30 1500 \
            "$runner" \
            ${pkgs.qemu-crucible}/bin/qemu-system-x86_64 \
            ${pkgs.crucible-qemu-plugin}/lib/libcrucible_qemu_plugin.so \
            "$vmlinuz" \
            ${guest}/root.ext4 \
            ${scenario} \
            > "$report"

          cat "$report"
          grep -Fxq PASS "$report"
          grep -Fxq 'scenario=nginx-curl-http-200' "$report"
          grep -Fxq 'backend=production-qemu-lifecycle' "$report"
          grep -Fxq 'topology=two-vm-hostless-world-link' "$report"
          grep -Fxq 'server_workload=nginx' "$report"
          grep -Fxq 'client_workload=curl' "$report"
          grep -Fxq 'http_status=200' "$report"
          grep -Fxq 'assertion=curl-receives-http-200:satisfied' "$report"
          grep -Eq '^final_configuration=[0-9a-f]{64}$' "$report"

          cli_report="$TMPDIR/nginx-curl-http-200.cli.jsonl"
          CRUCIBLE_KERNEL="$vmlinuz" \
          CRUCIBLE_ROOT_IMAGE=${guest}/root.ext4 \
          CRUCIBLE_KERNEL_CMDLINE='console=ttyS0 net.ifnames=0 root=/dev/vda rw init=/init' \
            timeout -k 30 1500 \
            ${pkgs.crucible}/bin/crucible \
            --backend qemu \
            --seed 0x200 \
            --format jsonl \
            run ${scenario} \
            --max-quanta 30000 \
            > "$cli_report"
          grep -F '"kind":"final_outcome"' "$cli_report" \
            | grep -Fq 'status=passed exit_code=0'

          mkdir -p "$out"
          cp "$report" "$out/result"
          cp "$cli_report" "$out/cli.jsonl"
          cp ${scenario} "$out/nginx-curl-http-200.scenario.toml"
          {
            printf 'check=%s\n' '${attrPath}'
            printf 'validation=guest-curl-observed-http-200-from-guest-nginx\n'
            printf 'network=crucible-hostless-world-link\n'
          } >> "$out/result"
        '';
      }
    ];
  }
