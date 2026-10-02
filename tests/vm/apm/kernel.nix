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
      ${apm}/bin/apm image install --help > /tmp/install-help
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
        ${apm}/bin/apm image install server --kexec
      must_fail_with \
        "--live is not supported for immutable A/B image transitions" \
        ${apm}/bin/apm image install server --live
      must_fail_with \
        "--drain requires --reboot" \
        ${apm}/bin/apm image install server --drain
      must_fail_with \
        "unexpected argument '--reboot'" \
        ${apm}/bin/apm install server --reboot
      must_fail_with \
        "unexpected argument '--reboot'" \
        ${apm}/bin/apm image download server --format raw --reboot

      must_fail_with \
        "--kexec is not supported for immutable A/B image transitions" \
        ${apm}/bin/apm image upgrade --kexec
      must_fail_with \
        "--live is not supported for immutable A/B image transitions" \
        ${apm}/bin/apm image upgrade --live
      must_fail_with \
        "--drain requires --reboot" \
        ${apm}/bin/apm image upgrade --drain
      must_fail_with \
        "unexpected argument '--reboot'" \
        ${apm}/bin/apm upgrade --reboot

      # Configuration rollback never changes the booted image. Transition
      # controls belong only to the explicit image rollback axis.
      must_fail_with \
        "unexpected argument '--reboot'" \
        ${apm}/bin/apm config rollback --reboot
      must_fail_with \
        "unexpected argument '--reboot'" \
        ${apm}/bin/apm rollback --reboot
      must_fail_with \
        "--kexec is not supported for immutable A/B image transitions" \
        ${apm}/bin/apm image rollback --kexec
      must_fail_with \
        "--live is not supported for immutable A/B image transitions" \
        ${apm}/bin/apm image rollback --live
      must_fail_with \
        "--drain requires --reboot" \
        ${apm}/bin/apm image rollback --drain
      must_fail_with \
        "unexpected argument '--reboot'" \
        ${apm}/bin/apm image list --reboot

      # Package scope flags cannot select image or declarative workflows.
      must_fail_with \
        "unexpected argument '--reboot'" \
        ${apm}/bin/apm install server --system --reboot
      must_fail_with \
        "unexpected argument '--reboot'" \
        ${apm}/bin/apm upgrade --system --reboot
      must_fail_with \
        "unexpected argument '--reboot'" \
        ${apm}/bin/apm rollback --system --reboot
      must_fail_with \
        "unexpected argument '--image'" \
        ${apm}/bin/apm install server --system --image raw
      must_fail_with \
        "unexpected argument '--image'" \
        ${apm}/bin/apm rollback --system --image
      must_fail_with \
        "unexpected argument '--from'" \
        ${apm}/bin/apm install --system --from /tmp/desired.toml
      must_fail_with \
        "unexpected argument '--system'" \
        ${apm}/bin/apm image install server --system

      # Clap itself owns mutual exclusion between transition strategies.
      must_fail_with \
        "cannot be used with" \
        ${apm}/bin/apm image install server --kexec --reboot

      echo "system transition option contracts passed"
    '';
  };
}
