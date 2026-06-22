# lib/testing/systemd-credentials.nix — systemd credential substrate check.
#
# Verifies the static systemd pieces RFC-0001's TPM2-sealed credential path
# needs before package-level provisioning work can depend on them.
{
  pkgs,
  lib,
}:
pkgs.mkDerivation {
  pname = "systemd-credentials-check";
  version = "0";
  src = null;

  buildDeps = [pkgs.grep];

  phases = [
    {
      name = "check";
      script = ''
        systemd=${pkgs.systemd}

        fail() {
          echo "FAIL: $*" >&2
          exit 1
        }

        test -x "$systemd/bin/systemd-creds" \
          || fail "systemd-creds is missing"
        test -x "$systemd/lib/systemd/systemd-measure" \
          || fail "systemd-measure is missing"
        test -x "$systemd/lib/systemd/system-generators/systemd-tpm2-generator" \
          || fail "systemd-tpm2-generator is missing"
        test -x "$systemd/lib/systemd/systemd-tpm2-setup" \
          || fail "systemd-tpm2-setup is missing"
        test -f "$systemd/lib/systemd/system/systemd-tpm2-setup.service" \
          || fail "systemd-tpm2-setup.service is missing"
        test -f "$systemd/lib/systemd/system/systemd-tpm2-setup-early.service" \
          || fail "systemd-tpm2-setup-early.service is missing"
        test -f "$systemd/lib/systemd/system/systemd-tpm2-clear.service" \
          || fail "systemd-tpm2-clear.service is missing"
        test -f "$systemd/lib/systemd/system/tpm2.target" \
          || fail "tpm2.target is missing"
        test -f "$systemd/lib/cryptsetup/libcryptsetup-token-systemd-tpm2.so" \
          || fail "cryptsetup TPM2 token plugin is missing"
        test -f "$systemd/lib/tmpfiles.d/credstore.conf" \
          || fail "credstore tmpfiles config is missing"

        "$systemd/bin/systemd-creds" --help > systemd-creds.help
        "$systemd/lib/systemd/systemd-measure" --help > systemd-measure.help

        grep -q -- '^  encrypt INPUT OUTPUT' systemd-creds.help \
          || fail "systemd-creds lacks encrypt subcommand"
        grep -q -- '--with-key=host|tpm2|host+tpm2|null|auto|auto-initrd' systemd-creds.help \
          || fail "systemd-creds lacks TPM2 key selector"
        grep -q -- '--tpm2-public-key=PATH' systemd-creds.help \
          || fail "systemd-creds lacks signed PCR public-key flag"
        grep -q -- '--tpm2-public-key-pcrs=' systemd-creds.help \
          || fail "systemd-creds lacks signed PCR selector flag"
        grep -q -- '^  sign ' systemd-measure.help \
          || fail "systemd-measure lacks sign subcommand"
        grep -q -- '^  policy-digest ' systemd-measure.help \
          || fail "systemd-measure lacks policy-digest subcommand"
        grep -q -- '--private-key=KEY' systemd-measure.help \
          || fail "systemd-measure lacks private-key signing option"
        grep -q -- '--public-key=KEY' systemd-measure.help \
          || fail "systemd-measure lacks public-key verification option"
        grep -q -- '--pcrpkey=PATH' systemd-measure.help \
          || fail "systemd-measure lacks UKI PCR public-key section option"
        grep -q -- "ExecStart=$systemd/lib/systemd/systemd-tpm2-setup --graceful" \
          "$systemd/lib/systemd/system/systemd-tpm2-setup.service" \
          || fail "systemd-tpm2-setup.service does not run systemd-tpm2-setup"
        grep -q -- "ExecStart=$systemd/lib/systemd/systemd-tpm2-setup --early=yes --graceful" \
          "$systemd/lib/systemd/system/systemd-tpm2-setup-early.service" \
          || fail "systemd-tpm2-setup-early.service does not run systemd-tpm2-setup"
        grep -q -- "ExecStart=$systemd/lib/systemd/systemd-tpm2-clear --graceful" \
          "$systemd/lib/systemd/system/systemd-tpm2-clear.service" \
          || fail "systemd-tpm2-clear.service does not run systemd-tpm2-clear"
        grep -q -- '^d /etc/credstore 0700 root root' "$systemd/lib/tmpfiles.d/credstore.conf" \
          || fail "credstore tmpfiles config lacks /etc/credstore"
        grep -q -- '^d /etc/credstore.encrypted 0700 root root' "$systemd/lib/tmpfiles.d/credstore.conf" \
          || fail "credstore tmpfiles config lacks /etc/credstore.encrypted"
        grep -q -- '^z /run/credstore 0700 root root' "$systemd/lib/tmpfiles.d/credstore.conf" \
          || fail "credstore tmpfiles config lacks /run/credstore"
        grep -q -- '^z /run/credstore.encrypted 0700 root root' "$systemd/lib/tmpfiles.d/credstore.conf" \
          || fail "credstore tmpfiles config lacks /run/credstore.encrypted"

        mkdir -p "$out"
        {
          echo "systemd=$systemd"
          echo "systemd-creds=$systemd/bin/systemd-creds"
          echo "systemd-measure=$systemd/lib/systemd/systemd-measure"
          echo "systemd-tpm2-setup-service=$systemd/lib/systemd/system/systemd-tpm2-setup.service"
          echo "systemd-tpm2-generator=$systemd/lib/systemd/system-generators/systemd-tpm2-generator"
          echo "cryptsetup-tpm2-plugin=$systemd/lib/cryptsetup/libcryptsetup-token-systemd-tpm2.so"
        } > "$out/result"
      '';
    }
  ];

  meta.description = "Static check for systemd credentials, credstore, and TPM2 support";
}
