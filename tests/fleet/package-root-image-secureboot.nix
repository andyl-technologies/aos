# tests/fleet/package-root-image-secureboot.nix - Secure Boot RootImage proof.
#
# RFC-0001 D21 proof harness. This runs through the real image-boot Secure
# Boot path so UEFI db enrollment feeds the kernel platform keyring before
# systemd starts dm-verity RootImage package workloads:
#
#   1. Boot the signed image in Setup Mode, enroll db/KEK/PK, and reboot into
#      enforcing Secure Boot.
#   2. Seed two baked per-package RootImage packages whose expose artifacts
#      carry built dm-verity root hashes from their rendered manifest.json
#      metadata.
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
  storePathHash = path:
    builtins.elemAt (lib.splitString "-" (baseNameOf (builtins.toString path))) 0;
  mkPackageRootImage = import ../../lib/build/package-root-image.nix {inherit pkgs lib;};

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
            root_hash_file = "${image}/root.roothash";
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
      };
    };
  in
    rendered
    // {
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
      # The target inspects exposed-image metadata with `${pkgs.jq}/bin/jq`, so
      # jq's closure must ride this (measured) image — image slimming dropped it
      # from the server profile. Only jq is added (not the full fleet CLI tools
      # module) to keep this Secure Boot / measured image minimal.
      environment.systemPackages = [pkgs.jq];
    }
  ];
  verifierSystem = mkSystem [
    ../../systems/server.nix
    {
      aos.services.attestationVerifier = {
        enable = true;
        catalogFiles = ["/var/lib/aos-attestation-verifier/package-attestation-catalog.json"];
        quoteIdentityFiles = ["/var/lib/aos-attestation-verifier/quote-identity.json"];
        pcr15BaselineFile = "/var/lib/aos-attestation-verifier/pcr15-baseline";
      };
    }
  ];
in {
  name = "package-root-image-secureboot";
  timeout = 1800;

  machines = {
    # systemd-repart carves swap and var on first boot.
    target = {
      system = testSystem;
      bootMode = "image";
      imageDiskMiB = 16384;
      tpm = true;
      packages = [
        "aos-test-agent"
        "package-root-image-good"
        "package-root-image-bad"
      ];
    };
    verifier = {
      system = verifierSystem;
    };
  };

  testScript =
    # python
    ''
      import hashlib
      import json
      import shlex

      SB_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
      DB_GUID = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
      APM = "${pkgs.aos}/bin/apm"
      BASE64 = "${pkgs.coreutils}/bin/base64"
      JQ = "${pkgs.jq}/bin/jq"
      TPM2_CHECKQUOTE = "${pkgs.tpm2-tools}/bin/tpm2_checkquote"
      VERIFIER_ROOT = "/var/lib/aos-attestation-verifier"
      VERIFIER_QUOTE = f"{VERIFIER_ROOT}/quote"

      def efivar_byte(name):
          path = f"/sys/firmware/efi/efivars/{name}-{SB_GUID}"
          out = target.succeed(f"od -An -tu1 -j4 -N1 {path}").strip()
          return int(out)

      def dump_unit(unit):
          print(f"--- systemctl status {unit} ---")
          print(target.succeed(f"systemctl status --no-pager -l {unit} 2>&1 || true"))
          print(f"--- journalctl -u {unit} ---")
          print(target.succeed(f"journalctl -u {unit} -b --no-pager -n 200 2>&1 || true"))

      def expect_failed_start(unit):
          target.succeed(f"systemctl reset-failed {unit} 2>/dev/null || true")
          try:
              target.succeed(f"systemctl start {unit} >/dev/null 2>&1 || true", timeout=120)
              target.wait_until_succeeds(f"systemctl is-failed --quiet {unit}", timeout=60)
          except Exception:
              dump_unit(unit)
              raise

      def assert_file_line(path, expected):
          target.succeed(
              f"needle='{expected}'; found=0; "
              f"while IFS= read -r line; do "
              f"  if [ \"$line\" = \"$needle\" ]; then found=1; break; fi; "
              f"done < {path}; "
              f"test \"$found\" = 1"
          )

      def copy_target_file_to_verifier(source, destination):
          encoded = target.succeed(f"{BASE64} -w0 {shlex.quote(source)}").strip()
          parent = destination.rsplit("/", 1)[0]
          verifier.succeed(f"mkdir -p {shlex.quote(parent)}")
          verifier.succeed(
              f"printf %s {shlex.quote(encoded)} | "
              f"{BASE64} -d > {shlex.quote(destination)}"
          )

      def write_verifier_file(destination, content):
          parent = destination.rsplit("/", 1)[0]
          verifier.succeed(f"mkdir -p {shlex.quote(parent)}")
          verifier.succeed(f"printf %s {shlex.quote(content)} > {shlex.quote(destination)}")

      def assert_standalone_verifier_accepts_quote(event_log_path, nonce, baseline_value, quote, identity_catalog):
          assert baseline_value is not None, "standalone verifier test expects PCR baseline"
          verifier.wait_until_succeeds("systemctl is-active multi-user.target", timeout=120)
          verifier.succeed("test -e /etc/systemd/system/aos-attestation-verifier.service")
          verifier.succeed(f"rm -rf {VERIFIER_ROOT}")
          verifier.succeed(f"mkdir -p {VERIFIER_QUOTE}")
          write_verifier_file(f"{VERIFIER_ROOT}/nonce", nonce)
          write_verifier_file(f"{VERIFIER_ROOT}/pcr15-baseline", baseline_value)
          write_verifier_file(
              f"{VERIFIER_ROOT}/quote-identity.json",
              json.dumps(identity_catalog),
          )
          copy_target_file_to_verifier(
              event_log_path,
              f"{VERIFIER_ROOT}/aos-packages.cel",
          )
          copy_target_file_to_verifier(
              "/etc/aos/package-attestation-catalog.json",
              f"{VERIFIER_ROOT}/package-attestation-catalog.json",
          )
          for key, filename in (
              ("ek_public", "ek.pub"),
              ("ek_name", "ek.name"),
              ("ek_qualified_name", "ek.qname"),
              ("ak_public", "ak.pub"),
              ("ak_name", "ak.name"),
              ("ak_qualified_name", "ak.qname"),
              ("quote_message", "quote.msg"),
              ("quote_signature", "quote.sig"),
              ("quote_pcrs", "quote.pcrs"),
          ):
              copy_target_file_to_verifier(quote[key], f"{VERIFIER_QUOTE}/{filename}")
          verifier.succeed(
              f"find {VERIFIER_ROOT} -type d -exec chmod 0755 {{}} + && "
              f"find {VERIFIER_ROOT} -type f -exec chmod 0644 {{}} +"
          )
          verifier.succeed("systemctl start aos-attestation-verifier.service", timeout=120)
          raw = verifier.succeed(f"cat {VERIFIER_ROOT}/result.json")
          print("=== standalone package attestation verifier result ===")
          print(raw)
          verified = json.loads(raw)
          assert verified["pcr15"] == quote["quoted_pcr15"]
          assert verified["package_count"] >= 2
          assert verified["quote_bundle_verified"] is True
          assert verified["ak_ek_trusted"] is True
          assert verified["quote_identity_pinned"] is True
          assert verified["quote_identity_label"] == "service-quote"

      def assert_root_hash_metadata(name, package_hash, image):
          root_hash = target.succeed(f"cat {image}/root.roothash").strip()
          meta = f"/var/lib/profiles/system-packages/meta/{package_hash}.json"
          target.succeed(
              f"{JQ} -e --arg h sha256:{root_hash} "
              f"'.apm.expose.images[0].root_hash == $h' {meta}"
          )
          target.succeed(
              f"{JQ} -e --arg h sha256:{root_hash} "
              f"'.apm.attestation.root_hash == $h "
              f"and .apm.attestation.root_hash_sig == \"root.roothash.p7s\" "
              f"and (.apm.attestation.measurement | test(\"^sha256:[0-9a-f]{{64}}$\"))' {meta}"
          )
          unit = f"/etc/systemd/system.attached/{name}.service"
          assert_file_line(unit, f"RootImage={image}/root.img")
          assert_file_line(unit, f"RootVerity={image}/root.verity")
          assert_file_line(unit, f"RootHashSignature={image}/root.roothash.p7s")
          assert_file_line(unit, "RootImagePolicy=root=signed")
          assert_file_line(unit, f"RootHash={root_hash}")

      def assert_per_package_root_images_are_distinct():
          good_image = "${goodImage}"
          bad_image = "${badImage}"
          assert good_image != bad_image
          good_root_hash = target.succeed(f"cat {good_image}/root.roothash").strip()
          bad_root_hash = target.succeed(f"cat {bad_image}/root.roothash").strip()
          assert good_root_hash != bad_root_hash

      def write_direct_rootimage_unit(unit, image, root_image, command, state_dir):
          root_hash = target.succeed(f"cat {image}/root.roothash").strip()
          target.succeed(
              f"cat > /run/systemd/system/{unit} <<'UNIT'\n"
              "[Unit]\n"
              f"Description=Direct no-guard RootImage proof for {unit}\n"
              "After=systemd-udevd.service\n"
              "Requires=systemd-udevd.service\n"
              "\n"
              "[Service]\n"
              "Type=simple\n"
              f"RootImage={root_image}\n"
              f"RootVerity={image}/root.verity\n"
              f"RootHash={root_hash}\n"
              f"RootHashSignature={image}/root.roothash.p7s\n"
              "RootImagePolicy=root=signed\n"
              "PrivateDevices=false\n"
              f"StateDirectory={state_dir}\n"
              f"ExecStart={command}\n"
              "UNIT\n"
              f"if grep -q '^ExecStartPre=' /run/systemd/system/{unit}; then exit 1; fi\n"
              "systemctl daemon-reload\n"
          )

      def assert_aos_attest_removes_nonce_on_failure():
          target.wait_until_succeeds("test -d /run/aos-attest", timeout=60)
          target.succeed("printf %s not-hex > /run/aos-attest/nonce")
          target.fail("systemctl start aos-attest.service", timeout=60)
          target.succeed("test -d /run/aos-attest")
          target.succeed("test ! -e /run/aos-attest/nonce")
          target.succeed("systemctl reset-failed aos-attest.service")

      def assert_aos_attest_unit_produces_quote(nonce):
          quote_dir = "/var/lib/aos-attest/quote"
          quote_json = "/var/lib/aos-attest/quote.json"
          target.wait_until_succeeds("test -d /run/aos-attest", timeout=60)
          target.succeed(f"printf %s {shlex.quote(nonce)} > /run/aos-attest/nonce")
          target.succeed("systemctl start aos-attest.service", timeout=60)
          raw = target.succeed(f"cat {quote_json}")
          print("=== aos-attest service quote ===")
          print(raw)
          quote = json.loads(raw)
          assert quote["nonce"] == nonce
          assert quote["pcr_selection"] == "sha256:7,11,12,15"
          assert len(quote["quoted_pcr15"]) == 64
          for key in (
              "ek_public",
              "ek_name",
              "ek_qualified_name",
              "ak_public",
              "ak_name",
              "ak_qualified_name",
              "quote_message",
              "quote_signature",
              "quote_pcrs",
          ):
              path = quote[key]
              assert path.startswith(f"{quote_dir}/"), path
              target.succeed(f"test -s {path}")
          target.succeed(
              f"{TPM2_CHECKQUOTE} -u {quote['ak_public']} "
              f"-m {quote['quote_message']} "
              f"-s {quote['quote_signature']} "
              f"-f {quote['quote_pcrs']} "
              f"-l sha256:7,11,12,15 "
              f"-g sha256 -q {nonce}"
          )
          target.succeed("test -d /run/aos-attest")
          target.succeed("test ! -e /run/aos-attest/nonce")
          return quote

      def assert_quote_verifies_package_event_log(prior_event_log=""):
          nonce = "00112233445566778899aabbccddeeff"
          out_dir = "/tmp/aos-package-quote"
          target.wait_until_succeeds("test -s /run/log/aos-packages.cel", timeout=60)
          target.succeed(f"test ! -e {out_dir}")
          event_log = prior_event_log + target.succeed("cat /run/log/aos-packages.cel")
          event_log_path = "/tmp/aos-packages-combined.cel"
          target.succeed(f"printf %s {shlex.quote(event_log)} > {event_log_path}")
          records = [json.loads(line) for line in event_log.splitlines() if line.strip()]
          for index, record in enumerate(records, start=1):
              assert record["sequence_number"] == index
              assert record["pcr_index"] == 15
              assert record["event_size"] == len(record["event"].encode())
              assert record["digests"] == [
                  {"algorithm": "sha256", "digest": record["digest"]}
              ]
          baseline_value = None
          baseline_arg = ""
          if records and records[0]["event_type"] == "aos-pcr-baseline":
              baseline_value = records[0]["pcr_value"]
              baseline_arg = f" --pcr15-baseline {shlex.quote(baseline_value)}"

          assert_aos_attest_removes_nonce_on_failure()
          service_quote = assert_aos_attest_unit_produces_quote(nonce)
          service_verified_raw = target.succeed(
              f"{APM} --json attest verify --system "
              f"--event-log {event_log_path} "
              f"--quote-dir /var/lib/aos-attest/quote "
              f"--nonce {nonce}{baseline_arg}"
          )
          print("=== aos-attest service package attestation verification ===")
          print(service_verified_raw)
          service_verified = json.loads(service_verified_raw)
          assert service_verified["pcr15"] == service_quote["quoted_pcr15"]
          assert service_verified["package_count"] >= 2
          assert service_verified["quote_bundle_verified"] is True
          assert service_verified["ak_ek_trusted"] is False
          service_identity_file = "/tmp/aos-service-quote-identity.json"
          service_evidence_file = "/tmp/aos-service-quote-enrollment.evidence"
          target.succeed(
              f"printf %s {shlex.quote('credential activation transcript for service-quote')} "
              f"> {service_evidence_file}"
          )
          enrolled_raw = target.succeed(
              f"{APM} --json attest enroll "
              f"--quote-dir /var/lib/aos-attest/quote "
              f"--label service-quote "
              f"--method credential-activation "
              f"--evidence-file {service_evidence_file} "
              f"--catalog-file {service_identity_file}"
          )
          print("=== aos-attest service quote enrollment ===")
          print(enrolled_raw)
          enrolled = json.loads(enrolled_raw)
          assert enrolled["label"] == "service-quote"
          assert enrolled["method"] == "credential-activation"
          assert enrolled["evidence_sha256"].startswith("sha256:")
          service_identity = json.loads(target.succeed(f"cat {service_identity_file}"))
          service_trusted_raw = target.succeed(
              f"{APM} --json attest verify --system "
              f"--event-log {event_log_path} "
              f"--quote-dir /var/lib/aos-attest/quote "
              f"--nonce {nonce} "
              f"--quote-identity-file {service_identity_file}{baseline_arg}"
          )
          print("=== aos-attest identity-pinned package attestation verification ===")
          print(service_trusted_raw)
          service_trusted = json.loads(service_trusted_raw)
          assert service_trusted["quote_bundle_verified"] is True
          assert service_trusted["ak_ek_trusted"] is True
          assert service_trusted["quote_identity_pinned"] is True
          assert service_trusted["quote_identity_label"] == "service-quote"
          assert_standalone_verifier_accepts_quote(
              event_log_path,
              nonce,
              baseline_value,
              service_quote,
              service_identity,
          )

          raw = target.succeed(
              f"{APM} --json attest quote "
              f"--nonce {nonce} --output-dir {out_dir}"
          )
          print("=== package attestation quote ===")
          print(raw)
          quote = json.loads(raw)
          assert quote["nonce"] == nonce
          assert quote["pcr_selection"] == "sha256:7,11,12,15"
          assert len(quote["quoted_pcr15"]) == 64

          target.succeed(
              f"{TPM2_CHECKQUOTE} -u {quote['ak_public']} "
              f"-m {quote['quote_message']} "
              f"-s {quote['quote_signature']} "
              f"-f {quote['quote_pcrs']} "
              f"-l sha256:7,11,12,15 "
              f"-g sha256 -q {nonce}"
          )

          verified_raw = target.succeed(
              f"{APM} --json attest verify --system "
              f"--event-log {event_log_path} "
              f"--quote-dir {out_dir} --nonce {nonce}{baseline_arg}"
          )
          print("=== package attestation verification ===")
          print(verified_raw)
          verified = json.loads(verified_raw)
          assert verified["pcr15"] == quote["quoted_pcr15"]
          assert verified["package_count"] >= 2
          assert verified["quote_bundle_verified"] is True
          assert verified["ak_ek_trusted"] is False
          identity_file = "/tmp/aos-package-quote-identity.json"
          identity = {
              "version": 1,
              "anchors": [{
                  "label": "manual-quote",
                  "identity": quote["identity"],
              }],
          }
          target.succeed(
              f"printf %s {shlex.quote(json.dumps(identity))} > {identity_file}"
          )
          trusted_raw = target.succeed(
              f"{APM} --json attest verify --system "
              f"--event-log {event_log_path} "
              f"--quote-dir {out_dir} --nonce {nonce} "
              f"--quote-identity-file {identity_file}{baseline_arg}"
          )
          print("=== identity-pinned package attestation verification ===")
          print(trusted_raw)
          trusted = json.loads(trusted_raw)
          assert trusted["pcr15"] == quote["quoted_pcr15"]
          assert trusted["quote_bundle_verified"] is True
          assert trusted["ak_ek_trusted"] is False
          assert trusted["quote_identity_pinned"] is True
          assert trusted["quote_identity_label"] == "manual-quote"
          if baseline_value is not None:
              out = target.fail(
                  f"{APM} --json attest verify --system "
                  f"--event-log {event_log_path} "
                  f"--pcr15 {quote['quoted_pcr15']} 2>&1"
              )
              assert "requires an expected baseline" in out, out
              baseline_hex = baseline_value.split(":", 1)[1]
              wrong_baseline = "sha256:" + (
                  "00" * 32 if baseline_hex != "00" * 32 else "11" * 32
              )
              out = target.fail(
                  f"{APM} --json attest verify --system "
                  f"--event-log {event_log_path} "
                  f"--pcr15 {quote['quoted_pcr15']} "
                  f"--pcr15-baseline {shlex.quote(wrong_baseline)} 2>&1"
              )
              assert "does not match the expected baseline" in out, out

          def length_prefixed_word(schema, fields):
              word = schema
              for name, value in fields:
                  word += f"|{name}={len(value)}:{value}"
              return word

          def digest_word(word):
              return hashlib.sha256(word.encode()).hexdigest()

          def refresh_pcr_event_fields(record):
              if "event_size" in record:
                  record["event_size"] = len(record["event"].encode())
              if "digests" in record:
                  record["digests"] = [
                      {"algorithm": record.get("bank", "sha256"), "digest": record["digest"]}
                  ]

          def replay_pcr15(records):
              pcr = bytes(32)
              for record in records:
                  if record["event_type"] == "aos-pcr-baseline":
                      pcr = bytes.fromhex(record["pcr_value"].split(":", 1)[1])
                      continue
                  digest = bytes.fromhex(record["digest"].split(":", 1)[1])
                  pcr = hashlib.sha256(pcr + digest).digest()
              return pcr.hex()

          def refresh_package_set_digests(records):
              index = 0
              while index < len(records):
                  record = records[index]
                  if record["event_type"] != "aos-package-set":
                      index += 1
                      continue
                  package_count = record["package_count"]
                  package_digests = []
                  for offset in range(1, package_count + 1):
                      package_record = records[index + offset]
                      assert package_record["event_type"] == "aos-package"
                      package_digests.append(package_record["digest"])
                  record["event"] = length_prefixed_word(
                      "aos-package-set-v1",
                      [
                          ("package-count", str(package_count)),
                          ("package-digests", ",".join(package_digests)),
                      ],
                  )
                  record["digest"] = f"sha256:{digest_word(record['event'])}"
                  refresh_pcr_event_fields(record)
                  index += package_count + 1

          changed = False
          for record in records:
              if (
                  record["event_type"] == "aos-package"
                  and record["package"] == "package-root-image-good"
              ):
                  record["package"] = "package-root-image-evil"
                  record["event"] = length_prefixed_word(
                      "aos-package-v1",
                      [
                          ("name", record["package"]),
                          ("version", record["version"]),
                          ("root-digest", record["root_digest"]),
                          ("manifest-digest", record["manifest_digest"]),
                      ],
                  )
                  record["digest"] = f"sha256:{digest_word(record['event'])}"
                  refresh_pcr_event_fields(record)
                  changed = True
                  break
          assert changed, "expected package-root-image-good in package event log"
          refresh_package_set_digests(records)
          tampered_log = "\n".join(
              json.dumps(record, separators=(",", ":")) for record in records
          ) + "\n"
          tampered_pcr15 = replay_pcr15(records)
          target.succeed(
              f"printf %s {shlex.quote(tampered_log)} > /tmp/aos-packages-tampered.cel"
          )
          out = target.fail(
              f"{APM} --json attest verify --system "
              f"--event-log /tmp/aos-packages-tampered.cel "
              f"--pcr15 {quote['quoted_pcr15']}{baseline_arg} 2>&1"
          )
          assert "no golden measurement" in out or "replayed PCR 15" in out, out
          out = target.fail(
              f"{APM} --json attest verify --system "
              f"--event-log /tmp/aos-packages-tampered.cel "
              f"--pcr15 {tampered_pcr15}{baseline_arg} 2>&1"
          )
          assert "no golden measurement" in out, out

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
      assert_per_package_root_images_are_distinct()
      assert_quote_verifies_package_event_log()

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

      write_direct_rootimage_unit(
          "direct-rootimage-good.service",
          "${goodImage}",
          "${goodImage}/root.img",
          "/bin/package-root-image-good-command",
          "aos-pkg-package-root-image-good",
      )
      target.succeed("rm -f /var/lib/aos-pkg-package-root-image-good/result")
      try:
          target.succeed("systemctl start direct-rootimage-good.service", timeout=120)
          target.wait_until_succeeds(
              "test \"$(cat /var/lib/aos-pkg-package-root-image-good/result)\" = good-rootimage-ok",
              timeout=60,
          )
      except Exception:
          dump_unit("direct-rootimage-good.service")
          raise
      finally:
          target.succeed("systemctl stop direct-rootimage-good.service 2>/dev/null || true")

      write_direct_rootimage_unit(
          "direct-rootimage-bad-signature.service",
          "${badImage}",
          "${badImage}/root.img",
          "/bin/package-root-image-bad-command",
          "aos-pkg-package-root-image-bad",
      )
      target.succeed("rm -rf /var/lib/aos-pkg-package-root-image-bad")
      expect_failed_start("direct-rootimage-bad-signature.service")
      target.succeed("test ! -e /var/lib/aos-pkg-package-root-image-bad/result")
      target.succeed("systemctl is-failed --quiet direct-rootimage-bad-signature.service")
      dump_unit("direct-rootimage-bad-signature.service")

      target.succeed(
          "cp ${goodImage}/root.img /run/aos-tampered-root.img && "
          "chmod u+w /run/aos-tampered-root.img && "
          "printf AOS-TAMPERED-BLOCK | dd of=/run/aos-tampered-root.img bs=1 seek=4096 conv=notrunc"
      )
      write_direct_rootimage_unit(
          "direct-rootimage-tampered.service",
          "${goodImage}",
          "/run/aos-tampered-root.img",
          "/bin/package-root-image-good-command",
          "aos-pkg-package-root-image-good",
      )
      target.succeed("rm -f /var/lib/aos-pkg-package-root-image-good/result")
      expect_failed_start("direct-rootimage-tampered.service")
      target.succeed("test ! -e /var/lib/aos-pkg-package-root-image-good/result")
      target.succeed("systemctl is-failed --quiet direct-rootimage-tampered.service")
      dump_unit("direct-rootimage-tampered.service")

      target.succeed("rm -rf /var/lib/aos-pkg-package-root-image-bad")
      expect_failed_start("package-root-image-bad.service")
      target.succeed("test ! -e /var/lib/aos-pkg-package-root-image-bad/result")
      target.succeed("systemctl is-failed --quiet package-root-image-bad.service")
      dump_unit("package-root-image-bad.service")
    '';
}
