##! aos-sandbox-guest-root-template — exact AOS guest payload and closure
{
  mkDerivation,
  aos-sandbox-agent,
  openssh,
  systemd,
  coreutils,
  grep,
  sed,
  buildPackages,
}: let
  guestAgent = aos-sandbox-agent;
  rootBuilder = buildPackages.aos-sandbox-agent;
in
  mkDerivation {
    pname = "aos-sandbox-guest-root-template";
    version = "1";
    src = null;

    # Nix's reference graph is the complete, exact package closure. The
    # publisher copies this immutable template, never a controller path.
    exportReferencesGraph = [
      "closure-guest-agent" guestAgent
      "closure-openssh" openssh
      "closure-systemd" systemd
    ];
    buildDeps = [rootBuilder coreutils grep sed];
    runtimeDeps = [guestAgent openssh systemd];
    # The output deliberately embeds the complete reference graph, including
    # transitive ELF runtime paths. Generic fixup/scrub would mutate copied
    # package bytes after their digests and package binding were measured.
    dontStrip = true;
    dontPatchELF = true;
    dontNukeRefs = true;

    phases = [
      {
        name = "populate";
        script = ''
          set -eu

          mkdir -p "$out/root/nix/store" "$out/root/etc" \
            "$out/root/run" "$out/root/var/empty" \
            "$out/root/proc" "$out/root/sys" "$out/root/dev"
          grep -h '^/nix/store/' closure-guest-agent closure-openssh closure-systemd \
            | sort -u > closure-paths
          test -s closure-paths

          while IFS= read -r store_path; do
            test -d "$store_path"
            cp -a "$store_path" "$out/root/nix/store/"
          done < closure-paths

          # The package path is a build input, while the runtime credential
          # pins this complete closure set. The workspace assignment and
          # incarnation are separately authenticated in launch FD 4.
          { printf 'aos.sandbox.guest-root-package.v1\n'; cat closure-paths; } \
            | sha256sum | sed 's/ .*//' > "$out/package-binding"
          package_binding=$(cat "$out/package-binding")

          source_digest() {
            sha256sum "$1" | sed 's/ .*//'
          }
          ${rootBuilder}/bin/aos-sandbox-guest-root-builder \
            "$out/root" \
            ${guestAgent}/bin/aos-sandbox-guest-agent "$(source_digest ${guestAgent}/bin/aos-sandbox-guest-agent)" \
            ${guestAgent}/bin/aos-sandbox-guest-exec "$(source_digest ${guestAgent}/bin/aos-sandbox-guest-exec)" \
            ${guestAgent}/bin/aos-sandbox-exec-gate "$(source_digest ${guestAgent}/bin/aos-sandbox-exec-gate)" \
            ${guestAgent}/bin/aos-sandbox-guest-init "$(source_digest ${guestAgent}/bin/aos-sandbox-guest-init)" \
            ${openssh}/sbin/sshd "$(source_digest ${openssh}/sbin/sshd)" \
            ${openssh}/libexec/sshd-session "$(source_digest ${openssh}/libexec/sshd-session)" \
            ${systemd}/lib/systemd/systemd "$(source_digest ${systemd}/lib/systemd/systemd)" \
            "$package_binding"

          # OpenSSH's compiled helper path points into its own package.
          # Redirect only the copied guest closure so /proc/<pid>/exe resolves
          # to the fixed helper measured by the attach bridge.
          chmod u+w "$out/root${openssh}/libexec"
          rm "$out/root${openssh}/libexec/sshd-session"
          ln -s /usr/libexec/sshd-session \
            "$out/root${openssh}/libexec/sshd-session"
          chmod u-w "$out/root${openssh}/libexec"

          test -s "$out/root/etc/aos/sandbox-agent/guest-executable-v1"
          test -x "$out/root/usr/libexec/aos-sandbox-guest-init"
          test -x "$out/root/usr/lib/systemd/systemd"
        '';
      }
    ];

    meta = {
      description = "Immutable AOS-built sandbox guest root template and exact package closure";
      license = "Apache-2.0";
      platforms = ["x86_64-linux" "aarch64-linux"];
    };
  }
