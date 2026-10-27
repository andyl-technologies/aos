{
  pkgs,
  nonce,
}:
assert builtins.isString nonce && builtins.match "[a-zA-Z0-9_-]{16,128}" nonce != null; let
  marker = builtins.toFile "native-builder-probe-source" "terrane-native-builder-probe-v1\n";
in
  builtins.derivation {
    name = "terrane-native-builder-probe";
    system = builtins.currentSystem;
    builder = "${pkgs.bash}/bin/bash";
    qualificationNonce = nonce;
    args = [
      "-euxo"
      "pipefail"
      "-c"
      ''
        export PATH=${pkgs.coreutils}/bin:${pkgs.util-linux}/bin
        # Nix maps the original guest build identity into its user namespace.
        # Verify both kernel identities rather than treating namespace UID 1000
        # as evidence of the original guest credential.
        read -r namespace_uid guest_uid mapping_length < /proc/self/uid_map
        test "$(wc -l < /proc/self/uid_map)" = 1
        test "$(id -u)" = "$namespace_uid"
        test "$namespace_uid" = 1000
        test "$mapping_length" = 1
        test "$guest_uid" -ge 30001
        test "$guest_uid" -le 30016

        capabilities=$(while read -r key value rest; do
          if test "$key" = CapEff:; then printf '%s' "$value"; fi
        done < /proc/self/status)
        test "$capabilities" = 0000000000000000

        test "$(findmnt --noheadings --output FSTYPE --target "$PWD")" = ext4
        test "$(findmnt --noheadings --output FSTYPE --target "$TMPDIR")" = ext4
        test "$(findmnt --noheadings --output FSTYPE --target "$(dirname "$out")")" = ext4
        test "$(cat ${marker})" = terrane-native-builder-probe-v1

        mkdir "$out"
        cp ${marker} "$out/source"
        cp /proc/self/uid_map "$out/uid-map"
        printf 'uid=%s\nguest_uid=%s\ncapabilities=%s\nkernel=%s\nboot_id=%s\nbuild_filesystem=ext4\ntemporary_filesystem=ext4\noutput_filesystem=ext4\nsource_sha256=%s\nnonce=%s\n' \
          "$namespace_uid" "$guest_uid" "$capabilities" "$(uname -r)" \
          "$(cat /proc/sys/kernel/random/boot_id)" \
          "$(sha256sum ${marker} | cut -d ' ' -f 1)" "$qualificationNonce" > "$out/proof"
      ''
    ];
    requiredSystemFeatures = ["terrane-native-builder"];
    preferLocalBuild = false;
    allowSubstitutes = false;
  }
