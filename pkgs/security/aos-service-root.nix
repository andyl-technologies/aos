##! aos-service-root — Prepare trusted per-unit overlay roots
{
  mkDerivation,
  bash,
  coreutils,
  util-linux,
}:
mkDerivation {
  pname = "aos-service-root";
  version = "0";
  src = null;

  buildDeps = [];
  runtimeDeps = [
    bash
    coreutils
    util-linux
  ];
  propagatedDeps = [];

  phases = [
    {
      name = "build";
      script = ''
        mkdir -p $out/bin
        $CC -O2 -Wall -Wextra -Werror \
          -o $out/bin/aos-service-root ${./aos-service-root.c}
      '';
    }
  ];

  checks = {
    testing,
    self,
    pkgs,
  }: let
    payload = pkgs.runCommand "aos-service-root-payload" {} ''
      mkdir -p $out/share
      printf immutable > $out/share/payload
    '';
    otherPayload = pkgs.runCommand "aos-service-root-other-payload" {} ''
      mkdir -p $out/share
      printf other > $out/share/payload
    '';
  in {
    overlay = testing.mkVMTest {
      name = "security-aos-service-root-overlay";
      rootfsDeps = [
        self
        otherPayload
        payload
        pkgs.coreutils
        pkgs.grep
        pkgs.util-linux
      ];
      testScript = ''
        helper=${self}/bin/aos-service-root
        fixture=${payload}
        other_fixture=${otherPayload}

        "$helper" prepare demo "$fixture" alpha.service beta.service
        grep -qx immutable /run/aos/service-roots/demo/alpha.service/merged/share/payload
        grep -qx immutable /run/aos/service-roots/demo/beta.service/merged/share/payload

        alpha_options=$(findmnt -n -o OPTIONS /run/aos/service-roots/demo/alpha.service/merged)
        case ",$alpha_options," in
          *,nodev,*) ;;
          *) echo "overlay is missing nodev" >&2; exit 1 ;;
        esac
        case ",$alpha_options," in
          *,nosuid,*) ;;
          *) echo "overlay is missing nosuid" >&2; exit 1 ;;
        esac
        alpha_super_options=$(findmnt -n -o FS-OPTIONS /run/aos/service-roots/demo/alpha.service/merged)
        case ",$alpha_super_options," in
          *,upperdir=/run/aos/service-roots/demo/alpha.service/upper/root,*) ;;
          *) echo "overlay does not use the private nested upper root" >&2; exit 1 ;;
        esac
        test "$(stat -c %a /run/aos/service-roots/demo/alpha.service/upper)" = 700
        test "$(stat -c %a /run/aos/service-roots/demo/alpha.service/work)" = 700
        test "$(stat -c %a /run/aos/service-roots/demo/alpha.service/merged)" = 711

        printf alpha > /run/aos/service-roots/demo/alpha.service/merged/created
        test ! -e "$fixture/created"
        test ! -e /run/aos/service-roots/demo/beta.service/merged/created

        # Preparing the exact existing overlays is idempotent.
        "$helper" prepare demo "$fixture" alpha.service beta.service

        # Cleanup has the same exact identity authority as preparation.
        if "$helper" cleanup demo "$other_fixture" alpha.service beta.service; then
          echo "cleanup accepted the wrong overlay lowerdir" >&2
          exit 1
        fi
        test "$(findmnt -n -o FSTYPE /run/aos/service-roots/demo/alpha.service/merged)" = overlay
        if "$helper" cleanup demo "$fixture" alpha.service; then
          echo "cleanup accepted an incomplete unit set" >&2
          exit 1
        fi
        test "$(findmnt -n -o FSTYPE /run/aos/service-roots/demo/alpha.service/merged)" = overlay

        if "$helper" prepare '../bad' "$fixture" bad.service; then
          echo "unsafe package token accepted" >&2
          exit 1
        fi
        if "$helper" prepare bad "$fixture/share" bad.service; then
          echo "nested store payload accepted" >&2
          exit 1
        fi

        # Preparation must never tear down a pre-existing unexpected mount.
        mkdir -p \
          /run/aos/service-roots/intruder/victim.service/upper \
          /run/aos/service-roots/intruder/victim.service/work \
          /run/aos/service-roots/intruder/victim.service/merged
        mount -t tmpfs -o nodev,nosuid tmpfs \
          /run/aos/service-roots/intruder/victim.service/merged
        if "$helper" prepare intruder "$fixture" victim.service; then
          echo "unexpected pre-existing mount accepted" >&2
          exit 1
        fi
        test "$(findmnt -n -o FSTYPE /run/aos/service-roots/intruder/victim.service/merged)" = tmpfs
        umount /run/aos/service-roots/intruder/victim.service/merged
        rmdir \
          /run/aos/service-roots/intruder/victim.service/upper \
          /run/aos/service-roots/intruder/victim.service/work \
          /run/aos/service-roots/intruder/victim.service/merged
        rmdir /run/aos/service-roots/intruder/victim.service
        rmdir /run/aos/service-roots/intruder

        # A later-unit failure rolls back an earlier overlay from this invocation.
        mkdir -p /run/aos/service-roots/rollback/bad.service/upper
        ln -s /tmp /run/aos/service-roots/rollback/bad.service/upper/root
        if "$helper" prepare rollback "$fixture" good.service bad.service; then
          echo "unsafe existing component accepted" >&2
          exit 1
        fi
        test ! -e /run/aos/service-roots/rollback/good.service
        test -L /run/aos/service-roots/rollback/bad.service/upper/root

        "$helper" cleanup demo "$fixture" alpha.service beta.service
        test ! -e /run/aos/service-roots/demo
        test -r "$fixture/share/payload"
        "$helper" cleanup demo "$fixture" alpha.service beta.service

        rm /run/aos/service-roots/rollback/bad.service/upper/root
        rmdir /run/aos/service-roots/rollback/bad.service/upper
        rmdir /run/aos/service-roots/rollback/bad.service
        rmdir /run/aos/service-roots/rollback
        echo "aos-service-root overlay policy: PASS"
      '';
    };
  };

  meta = {
    description = "Prepare trusted per-unit overlay roots for package services";
    license = "MIT";
  };
}
