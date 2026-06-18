# tests/fleet/package-root-image-secureboot.nix - Secure Boot RootImage proof.
#
# RFC-0001 D21 proof harness. This runs through the real image-boot Secure
# Boot path so UEFI db enrollment feeds the kernel platform keyring before
# systemd starts dm-verity RootImage package workloads:
#
#   1. Boot the signed image in Setup Mode, enroll db/KEK/PK, and reboot into
#      enforcing Secure Boot.
#   2. Seed two baked RootImage packages whose expose artifacts carry built
#      dm-verity root hashes from their rendered manifest.json metadata.
#   3. Start the db-signed RootImage service and prove it reads a payload that
#      exists only inside the image root.
#   4. Start an otherwise identical RootImage service signed by an unrelated
#      test certificate and assert systemd/kernel reject it before ExecStart.
{
  lib,
  pkgs,
  mkSystem,
  ...
}: let
  rootSizeMiB = 6144;
  swapSizeMiB = 1024;
  diskProvision = {
    storage = {
      disks = [
        {
          device = "/dev/vda";
          wipeTable = false;
          partitions = [
            {
              number = 2;
              label = "root-a";
              sizeMiB = rootSizeMiB;
              resize = true;
              typeGuid = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
            }
            {
              number = 3;
              label = "root-b";
              sizeMiB = rootSizeMiB;
              typeGuid = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
            }
            {
              number = 4;
              label = "swap";
              sizeMiB = swapSizeMiB;
              typeGuid = "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F";
            }
            {
              number = 5;
              label = "var";
              sizeMiB = 0;
            }
          ];
        }
      ];
      filesystems = [
        {
          device = "/dev/disk/by-partlabel/root-b";
          format = "ext4";
          label = "aos-root-b";
          wipeFilesystem = false;
        }
        {
          device = "/dev/disk/by-partlabel/var";
          format = "ext4";
          label = "aos-var";
          wipeFilesystem = false;
        }
      ];
    };
  };

  storePathHash = path:
    builtins.elemAt (lib.splitString "-" (baseNameOf (builtins.toString path))) 0;
  mkPackageRootImage = import ../../lib/build/package-root-image.nix {inherit pkgs lib;};
  fakeRootHash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

  untrustedRootHashKey = pkgs.writeTextFile {
    name = "package-root-image-untrusted-key";
    destination = "/bad.key";
    text = ''
      -----BEGIN PRIVATE KEY-----
      MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC55szsukzdHbt3
      /VD4QfkLjTTUnRbCJNavkl8g3ZMtU8KKohQ4akwPA8coq7chwpveNvpWU3YgJfgj
      bAFtnveW2vTKOoet2Jb4xCPtfeILNiv+CtkkHfC9nGuJExCv0cyb55zG0XajWK5w
      QeAZhnR8L8JyY7zUr/PjkKLK6+4NSaTgnZL2iL9DeJAuaw+kuWiLNz259RLsK2j1
      XfIxfe4v3b3uP8RJ2wpE7UWWORSk+iDHlQCZnQhrJf7PWRs7CvhE5ZRXWpF2J0Da
      vd6UnSM5Uo8ci6+MoTqFuUtmYqcBaGiKg+WPDP/TVAVnbWgG8BdhtEm7LaKb4rs3
      8E7QyJ31AgMBAAECggEATn+UcbO7SDVJV4H6YlItUQDn2Y2ZshIvK0UR8UVO4/l1
      8Oc+xZGxGzf7rYNQ2asc+Sja7X/hpfKShJaTRdA1+Rfs/MXZTAHkwhfEmgCpZhWS
      XvwCs9sGsHIwAFoyFiPvk7ep/lQtlg0Y36MZd33MizH5mCbgcij4QdPtweT9CNOj
      Ch7DBtSpxx1LkCZhhfml6sLlalG+ntreUsHSyLY5BJB6hYlDQzg/7L5dNM/Z7JUI
      XI/9Mrab0e8tVW2ueAQTULoAhKmfQgxds4iD5XYNxx6793aLvTcjvbImgkSUS52X
      //e+0cM5MVb4Rf7QEqICzymENRfWo2IVQ67SOiMrswKBgQDmwQkgXxtUaivFoPB3
      nGtqrP/gHMUb7omVMFLkdS339Hnrj5oFV+JuWL+lwdKs3K66He/7xnxHV9L39hA8
      r5iv5XkJded4JqfZ54b1Mfx6j/WAidTtLjq+41E39AJ1pNtLh5Uhl3qmmHG+zHBy
      rjfS+EPrrC4CuglcGbcfBnH/EwKBgQDOPYka2PZh9NDJx92Ijqt9YYJKUdMoTjJi
      /jAtK1NdLkEBf1Y+C7TfuKFoKptlYLlKer18D2JkdiByJ/6LmKM2G+jErE2JeokY
      N9INN9pIth/w8iFiya6gCZvRaUWwW7vKmvwPjgCBsl1iKLaM65Q1W/1wBcGysjcO
      kvsLtoKn1wKBgQCVImU3msAbCpNHowBHDb0OsMiem3l41+3rkdPA+0q+Wi8B40lz
      8pzRHGKgSmhSeD4k43xaiKmBom0i/ND5p7NS20giqST0LmeFGXHLvoai36+XZ31J
      3PryrA+tzfJY/jcM1Y+4qiIG0beRzKdQNvC1VObwxdLmyD2MXMJRNuUuKQKBgQCE
      WbcHlJ4gZKQsKWfAP5ZLouyi1vnEDtKE9oxiIECiNpGe7WGh9Y9AVtK170nD+BtQ
      cY3x9El3INtXhtTyLqTmj2iD9fLYO9uIwCG7O9GIAeBjlm7YX4cBysjEzWLcdzH/
      JhCFxuIKWTVWTbxAmNmGmJ7+aaNREs8EOkyCyr/0BwKBgQCSah2AXSkO28mhVeJG
      tFZepK3ihjEOcMDUvk7/zidiZ+4u37NCXwRw80JEOQd3WphCt9QFNdIw6Va932Jg
      nVrhhHy6v1QKrbg1jGifXUXxj3WKABR4oirec0o296PMuerpwZdeRsqfkz/w1xEE
      0aUgiWsMJ84tK4V3EWAEBVP33Q==
      -----END PRIVATE KEY-----
    '';
  };

  untrustedRootHashCert = pkgs.writeTextFile {
    name = "package-root-image-untrusted-cert";
    destination = "/bad.crt";
    text = ''
      -----BEGIN CERTIFICATE-----
      MIIDHzCCAgegAwIBAgIEB1vNFTANBgkqhkiG9w0BAQsFADAnMSUwIwYDVQQDDBxB
      T1MgVGVzdCBVbnRydXN0ZWQgUm9vdEltYWdlMB4XDTI2MDYxODEzMjgyOFoXDTM2
      MDYxNTEzMjgyOFowJzElMCMGA1UEAwwcQU9TIFRlc3QgVW50cnVzdGVkIFJvb3RJ
      bWFnZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALnmzOy6TN0du3f9
      UPhB+QuNNNSdFsIk1q+SXyDdky1TwoqiFDhqTA8DxyirtyHCm942+lZTdiAl+CNs
      AW2e95ba9Mo6h63YlvjEI+194gs2K/4K2SQd8L2ca4kTEK/RzJvnnMbRdqNYrnBB
      4BmGdHwvwnJjvNSv8+OQosrr7g1JpOCdkvaIv0N4kC5rD6S5aIs3Pbn1EuwraPVd
      8jF97i/dve4/xEnbCkTtRZY5FKT6IMeVAJmdCGsl/s9ZGzsK+ETllFdakXYnQNq9
      3pSdIzlSjxyLr4yhOoW5S2ZipwFoaIqD5Y8M/9NUBWdtaAbwF2G0Sbstopviuzfw
      TtDInfUCAwEAAaNTMFEwHQYDVR0OBBYEFKbYs+MTbZpdos0cmveR4g3Iw049MB8G
      A1UdIwQYMBaAFKbYs+MTbZpdos0cmveR4g3Iw049MA8GA1UdEwEB/wQFMAMBAf8w
      DQYJKoZIhvcNAQELBQADggEBAKuo0WhnQaUUDV4pw7W8tSm4S/MMfxwf7IbhYbhN
      fB9QOHK4HrL5XuPtLviFe1m5tEaLT8UJxAf1MOZGtjbZrvMyM2erKJznpPYMzGuH
      L6OoBKpqy+jj9Tc2fWqJ++Cc3cYWYbqT3j64LxtKnXgVupPwou1vMoSbtQoL6B9X
      6NMDaKWEekkA9gN8gG0oQHoGJ9BuANq/6WQajWmHQSj35+BOuoBLREGCt3+boiXV
      VXmMO9a57Idz4SaiM7+PazqjUHY/TwzQt8wZ1XmnfF6m9DfnyJ2rHFoHPMo3siMZ
      Hm4HoUiqbsjn/ojh4G5jF7O52NmARcWLE+9eDRkSQ0BZdqI=
      -----END CERTIFICATE-----
    '';
  };

  mkVerityPackage = {
    name,
    result,
    rootHashKey,
    rootHashCert,
  }: let
    command = pkgs.writeShellScriptBin "${name}-command" ''
      state=/var/lib/aos-pkg-${name}
      test -r /share/${name}/payload.txt
      printf ${lib.escapeShellArg result} > "$state/result"
      exec ${pkgs.coreutils}/bin/sleep infinity
    '';
    root = pkgs.mkDerivation {
      pname = "${name}-root";
      version = "0";
      src = null;

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/bin" "$out/share/${name}" "$out/var/lib/aos-pkg-${name}"
            ln -s ${command}/bin/${name}-command "$out/bin/${name}-command"
            printf ${lib.escapeShellArg result} > "$out/share/${name}/payload.txt"
          '';
        }
      ];
    };
    image = mkPackageRootImage {
      pname = "${name}-image";
      inherit root rootHashKey rootHashCert;
      minSizeMiB = 16;
      headroomMiB = 2;
    };
    rendered = pkgs.mkDerivation {
      pname = name;
      version = "0";
      src = null;

      phases = [
        {
          name = "install";
          script = ''
            mkdir -p "$out/share/${name}"
            printf package > "$out/share/${name}/package.txt"
          '';
        }
      ];

      expose = {
        units."${name}.service" = {
          description = "Secure Boot dm-verity RootImage package ${name}";
          serviceConfig = {
            Type = "simple";
            ExecStart = "/bin/${name}-command";
            StateDirectory = "aos-pkg-${name}";
          };
        };
        images = [
          {
            format = "ext4-verity";
            store_path = "${image}";
            nar_hash = "sha256:test";
            nar_size = 1;
            root_image = "root.img";
            root_verity = "root.verity";
            root_hash = "sha256:${fakeRootHash}";
            root_hash_sig = "root.roothash.p7s";
          }
        ];
        permissions = {
          network = "private";
          capabilities = [];
          devices = [];
          host-paths = [];
          kernel-modules = [];
          syscalls = "restricted";
        };
        requires = [];
      };
    };
    expose =
      pkgs.runCommand "expose-${name}-root-hash" {
        buildDeps = [
          pkgs.coreutils
          pkgs.grep
          pkgs.sed
        ];
        passthru = rendered.expose.passthru;
      } ''
        set -eu
        cp -a ${rendered.expose}/. "$out/"
        chmod -R u+w "$out"

        root_hash=$(cat ${image}/root.roothash)
        for path in \
          "$out/manifest.json" \
          "$out/network-policy.json" \
          "$out/mac-profile.json" \
          "$out"/units/*.service \
          "$out"/mac/selinux/*.te; do
          [ -e "$path" ] || continue
          sed -i \
            -e "s|${rendered.expose}|$out|g" \
            -e "s|${fakeRootHash}|$root_hash|g" \
            "$path"
        done

        grep -Eq "\"root_hash\"[[:space:]]*:[[:space:]]*\"sha256:$root_hash\"" "$out/manifest.json"
        grep -q "^RootHash=$root_hash$" "$out/units/${name}.service"
      '';
  in
    rendered
    // {
      expose = expose;
      passthru = (rendered.passthru or {}) // {inherit image root;};
    };

  goodPackage = mkVerityPackage {
    name = "package-root-image-good";
    result = "good-rootimage-ok";
    rootHashKey = "${pkgs.secure-boot-test-keys}/db.key";
    rootHashCert = "${pkgs.secure-boot-test-keys}/db.crt";
  };
  badPackage = mkVerityPackage {
    name = "package-root-image-bad";
    result = "bad-rootimage-started";
    rootHashKey = "${untrustedRootHashKey}/bad.key";
    rootHashCert = "${untrustedRootHashCert}/bad.crt";
  };
  goodImage = goodPackage.passthru.image;
  badImage = badPackage.passthru.image;
  goodPackageHash = storePathHash goodPackage;
  badPackageHash = storePathHash badPackage;

  testSystem = mkSystem [
    ../../systems/server-secureboot.nix
    {
      aos.packages.package-root-image-good = {
        package = goodPackage;
        bundle = true;
        preset = false;
      };
      aos.packages.package-root-image-bad = {
        package = badPackage;
        bundle = true;
        preset = false;
      };
    }
  ];
in {
  name = "package-root-image-secureboot";
  timeout = 1800;

  machines = {
    target = {
      system = testSystem;
      bootMode = "image";
      imageDiskMiB = 16384;
      packages = [
        "aos-test-agent"
        "package-root-image-good"
        "package-root-image-bad"
      ];
      instanceMetadata = {
        format = "ignition";
        config = diskProvision;
      };
    };
  };

  testScript =
    # python
    ''
      SB_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
      DB_GUID = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
      JQ = "${pkgs.jq}/bin/jq"

      def efivar_byte(name):
          path = f"/sys/firmware/efi/efivars/{name}-{SB_GUID}"
          out = target.succeed(f"od -An -tu1 -j4 -N1 {path}").strip()
          return int(out)

      def dump_unit(unit):
          print(f"--- systemctl status {unit} ---")
          print(target.succeed(f"systemctl status --no-pager -l {unit} 2>&1 || true"))
          print(f"--- journalctl -u {unit} ---")
          print(target.succeed(f"journalctl -u {unit} -b --no-pager -n 200 2>&1 || true"))

      def assert_file_line(path, expected):
          target.succeed(
              f"needle='{expected}'; found=0; "
              f"while IFS= read -r line; do "
              f"  if [ \"$line\" = \"$needle\" ]; then found=1; break; fi; "
              f"done < {path}; "
              f"test \"$found\" = 1"
          )

      def assert_root_hash_metadata(name, package_hash, image):
          root_hash = target.succeed(f"cat {image}/root.roothash").strip()
          meta = f"/var/lib/profiles/system-packages/meta/{package_hash}.json"
          target.succeed(
              f"{JQ} -e --arg h sha256:{root_hash} "
              f"'.apm.expose.images[0].root_hash == $h' {meta}"
          )
          unit = f"/etc/systemd/system.attached/{name}.service"
          assert_file_line(unit, f"RootImage={image}/root.img")
          assert_file_line(unit, f"RootVerity={image}/root.verity")
          assert_file_line(unit, f"RootHashSignature={image}/root.roothash.p7s")
          assert_file_line(unit, f"RootHash={root_hash}")

      target.succeed("systemctl is-active multi-user.target")
      target.succeed("test -d /sys/firmware/efi/efivars")
      assert efivar_byte("SetupMode") == 1, "expected Setup Mode before enrollment"
      assert efivar_byte("SecureBoot") == 0, "Secure Boot should not enforce yet"

      eu = "PATH=${pkgs.util-linux}/bin:$PATH ${pkgs.efitools}/bin/efi-updatevar"
      keys = "${pkgs.secure-boot-test-keys}"
      for var, auth in (("db", "db.auth"), ("KEK", "KEK.auth"), ("PK", "PK.auth")):
          target.succeed(f"{eu} -f {keys}/{auth} {var} 2>&1")
      target.succeed(f"test -r /sys/firmware/efi/efivars/db-{DB_GUID}")
      assert efivar_byte("SetupMode") == 0, "PK enrollment should exit Setup Mode"

      target.reboot()
      target.wait_until_succeeds("systemctl is-active multi-user.target", timeout=120)
      assert efivar_byte("SecureBoot") == 1, "Secure Boot should enforce after reboot"
      assert efivar_byte("SetupMode") == 0, "machine should remain in User Mode"
      target.succeed(f"test -r /sys/firmware/efi/efivars/db-{DB_GUID}")

      try:
          target.wait_until_succeeds(
              "test -L /etc/systemd/system.attached/package-root-image-good.service "
              "&& test -L /etc/systemd/system.attached/package-root-image-bad.service",
              timeout=300,
          )
      except Exception:
          dump_unit("aos-seed-baked-packages.service")
          raise
      assert_root_hash_metadata(
          "package-root-image-good",
          "${goodPackageHash}",
          "${goodImage}",
      )
      assert_root_hash_metadata(
          "package-root-image-bad",
          "${badPackageHash}",
          "${badImage}",
      )

      try:
          target.succeed("systemctl start package-root-image-good.service", timeout=120)
          target.wait_until_succeeds(
              "test \"$(cat /var/lib/aos-pkg-package-root-image-good/result)\" = good-rootimage-ok",
              timeout=60,
          )
          target.succeed("systemctl is-active --quiet package-root-image-good.service")
      except Exception:
          dump_unit("package-root-image-good.service")
          raise
      finally:
          target.succeed("systemctl stop package-root-image-good.service 2>/dev/null || true")

      target.succeed("rm -rf /var/lib/aos-pkg-package-root-image-bad")
      try:
          target.fail("systemctl start package-root-image-bad.service", timeout=120)
      except Exception:
          dump_unit("package-root-image-bad.service")
          raise
      target.succeed("test ! -e /var/lib/aos-pkg-package-root-image-bad/result")
      target.succeed("systemctl is-failed --quiet package-root-image-bad.service")
      dump_unit("package-root-image-bad.service")
    '';
}
