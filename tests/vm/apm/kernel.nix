# tests/vm/apm/kernel.nix - Immutable system transition option contracts.
#
# The production system lifecycle stages a complete authenticated A/B image;
# it cannot replace only the running kernel or userspace. This test executes
# every public and retained compatibility transition flag and proves invalid
# combinations fail before registry or profile state is consulted. Successful
# staging and reboot behavior is owned by the image-backed fleet lifecycle.
{
  testing,
  apm,
  pkgs,
}: {
  system-transition-options = testing.mkVMTest {
    name = "apm-system-transition-options";
    rootfsDeps = [
      apm
      pkgs.coreutils
      pkgs.grep
    ];

    testScript = ''
      set -eu

      must_fail_with() {
        expected=$1
        shift
        output=/tmp/transition-output
        if "$@" >"$output" 2>&1; then
          echo "FAIL: command unexpectedly succeeded: $*" >&2
          cat "$output" >&2
          exit 1
        fi
        if ! grep -Fq -- "$expected" "$output"; then
          echo "FAIL: command did not report expected contract: $*" >&2
          echo "expected: $expected" >&2
          cat "$output" >&2
          exit 1
        fi
      }

      # The supported image transition controls remain discoverable.
      ${apm}/bin/apm install --help > /tmp/install-help
      grep -Fq -- "--reboot" /tmp/install-help
      grep -Fq -- "--drain" /tmp/install-help

      # Retained legacy spellings are accepted only to produce a precise
      # migration error; they are not advertised as production features.
      if grep -Fq -- "--kexec" /tmp/install-help; then
        echo "FAIL: --kexec must not be advertised" >&2
        exit 1
      fi
      if grep -Fq -- "--live" /tmp/install-help; then
        echo "FAIL: --live must not be advertised" >&2
        exit 1
      fi

      must_fail_with \
        "--kexec is not supported for immutable A/B image transitions" \
        ${apm}/bin/apm install server --system --kexec
      must_fail_with \
        "--live is not supported for immutable A/B image transitions" \
        ${apm}/bin/apm install server --system --live
      must_fail_with \
        "--drain requires --reboot" \
        ${apm}/bin/apm install server --system --drain
      must_fail_with \
        "system transition flags require --system" \
        ${apm}/bin/apm install server --reboot
      must_fail_with \
        "system transition flags cannot be used with --image download mode" \
        ${apm}/bin/apm install server --image raw --reboot

      must_fail_with \
        "--kexec is not supported for immutable A/B image transitions" \
        ${apm}/bin/apm upgrade --system --kexec
      must_fail_with \
        "--live is not supported for immutable A/B image transitions" \
        ${apm}/bin/apm upgrade --system --live
      must_fail_with \
        "--drain requires --reboot" \
        ${apm}/bin/apm upgrade --system --drain
      must_fail_with \
        "system transition flags require --system" \
        ${apm}/bin/apm upgrade --reboot

      # Configuration rollback never changes the booted image. Transition
      # controls belong only to the explicit image rollback axis.
      must_fail_with \
        "system transition flags apply only to rollback --system --image" \
        ${apm}/bin/apm rollback --system --reboot
      must_fail_with \
        "system transition flags require --system --image" \
        ${apm}/bin/apm rollback --reboot
      must_fail_with \
        "--kexec is not supported for immutable A/B image transitions" \
        ${apm}/bin/apm rollback --system --image --kexec
      must_fail_with \
        "--live is not supported for immutable A/B image transitions" \
        ${apm}/bin/apm rollback --system --image --live
      must_fail_with \
        "--drain requires --reboot" \
        ${apm}/bin/apm rollback --system --image --drain
      must_fail_with \
        "system transition flags cannot be used with rollback --list" \
        ${apm}/bin/apm rollback --system --image --list --reboot

      # Clap itself owns mutual exclusion between transition strategies.
      must_fail_with \
        "cannot be used with" \
        ${apm}/bin/apm install server --system --kexec --reboot

      echo "system transition option contracts passed"
    '';
  };
}
