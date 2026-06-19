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
      startup = "${pkgs.tpm2-tools}/bin/tpm2_startup"

      target.wait_until_succeeds("test -e /dev/tpm0", timeout=60)
      target.succeed(f"{startup} -c 2>&1 || true")
      target.succeed(f"test ! -e {out_dir}")

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
    '';
}
