# tests/fleet/package-attestation-quote.nix — TPM quote smoke test for RFC-0001.
{
  pkgs,
  systems,
  ...
}: {
  name = "package-attestation-quote";
  timeout = 900;
  bootTimeout = 300;

  machines = {
    target = {
      system = systems.server;
      tpm = true;
    };
  };

  testScript =
    # python
    ''
      import json

      nonce = "00112233445566778899aabbccddeeff"
      out_dir = "/tmp/aos-package-quote"
      apm = "${pkgs.aos}/bin/apm"
      checkquote = "${pkgs.tpm2-tools}/bin/tpm2_checkquote"
      openssl = "${pkgs.openssl}/bin/openssl"
      startup = "${pkgs.tpm2-tools}/bin/tpm2_startup"

      target.wait_until_succeeds("test -e /dev/tpm0", timeout=60)
      target.succeed(f"{startup} -c 2>&1 || true")
      target.succeed(f"test ! -e {out_dir}")

      credential_private = "/tmp/apm-credential-policy-private.pem"
      credential_public = "/tmp/apm-credential-policy-public.pem"
      credential_plaintext = "/tmp/apm-credential-plaintext"
      credential_ciphertext = "/tmp/apm-credential-ciphertext"
      target.succeed(
          f"{openssl} genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 "
          f"-out {credential_private}"
      )
      target.succeed(
          f"{openssl} pkey -in {credential_private} -pubout "
          f"-out {credential_public}"
      )
      target.succeed(
          f"printf '%s' production-bootstrap-secret > {credential_plaintext}"
      )
      credential_raw = target.succeed(
          f"{apm} --json credential encrypt bootstrap-token "
          f"{credential_plaintext} --pcr-public-key {credential_public} "
          f"--output {credential_ciphertext} --unit bootstrap.service --expose-nix"
      )
      credential = json.loads(credential_raw)
      assert credential["name"] == "bootstrap-token", credential
      assert len(credential["ciphertext"]) > 64, credential
      assert "bootstrap.service" in credential["expose_nix"], credential
      target.succeed(f"test -s {credential_ciphertext}")
      target.succeed(f"test $(stat -c %a {credential_ciphertext}) = 600")

      raw = target.succeed(
          f"{apm} --json attest quote "
          f"--nonce {nonce} --output-dir {out_dir}"
      )
      print("=== package attestation quote ===")
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
          target.succeed(f"test -s {path}")

      target.succeed(
          f"{checkquote} -u {quote['ak_public']} "
          f"-m {quote['quote_message']} "
          f"-s {quote['quote_signature']} "
          f"-f {quote['quote_pcrs']} "
          f"-l sha256:7,11,12,15 "
          f"-g sha256 -q {nonce}"
      )

      evidence = "/tmp/package-attestation-enrollment-proof"
      identity_catalog = "/tmp/package-attestation-identities.json"
      target.succeed(
          f"printf '%s\\n' 'fleet out-of-band enrollment approval' > {evidence}"
      )
      enrolled_raw = target.succeed(
          f"{apm} --json attest enroll "
          f"--quote-dir {out_dir} "
          f"--label fleet-target "
          f"--method out-of-band "
          f"--evidence-file {evidence} "
          f"--catalog-file {identity_catalog}"
      )
      enrolled = json.loads(enrolled_raw)
      assert enrolled["label"] == "fleet-target", enrolled
      assert enrolled["method"] == "out-of-band", enrolled
      target.succeed(f"test -s {identity_catalog}")

      catalog_raw = target.succeed(f"{apm} --json attest catalog --system")
      catalog = json.loads(catalog_raw)
      assert isinstance(catalog, (dict, list)), catalog
    '';
}
