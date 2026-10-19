# ARCH-8 combines actual role permissions, native descriptor handoff and the
# production publisher's confinement. It does not claim complete host recovery.
{
  pkgs,
  publisherLocalProof,
  hostCacheProof,
  publication,
}:
pkgs.mkDerivation {
  pname = "terrane-gate-publisher-sole-writer";
  version = "0.1.0";
  src = null;
  buildDeps = [pkgs.coreutils pkgs.python3];
  phases = [
    {
      name = "qualify";
      script = ''
        test -e ${publication}
        test -e ${publisherLocalProof.multiUid}
        test -e ${publisherLocalProof.native}
        test -e ${hostCacheProof.native}
        mkdir -p "$out"
        python3 ${./publisher_ownership.py} ${publisherLocalProof.image} \
          ${hostCacheProof.image} ${pkgs.terrane.src} > "$out/source-review.json"
        printf '%s\n' 'PASS ARCH-8: role permissions, read-only native handoff and confined production publisher' > "$out/result"
      '';
    }
  ];
}
