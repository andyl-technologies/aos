##! secure-boot-keys — CI/test Secure Boot key hierarchy (RFC-0006)
##!
##! Generates a self-owned PK → KEK → db hierarchy and the signed
##! enrollment blobs, for the secure-boot CI test ONLY. These are
##! ephemeral, clearly-named TEST keys with no custody — they protect
##! nothing real. Production deployments supply their own keys held
##! offline/HSM (the signing interface takes key references, never these
##! files); see RFC-0006 key-custody.md.
##!
##! Output ($out):
##!   db.key, db.crt   — db signing key/cert; the image build signs the
##!                      UKI + sd-boot with these (db is what the
##!                      firmware checks loaded PEs against).
##!   PK.auth, KEK.auth, db.auth — signed authenticated-variable blobs
##!                      the guest writes via efivarfs to enroll, in the
##!                      order db → KEK → PK (setting PK exits Setup
##!                      Mode → User Mode → enforcing).
##!   modsign.pem      — combined key+cert PEM for the kernel's
##!                      CONFIG_MODULE_SIG_KEY (RFC-0006 phase 2 lockdown
##!                      overlay). A DISTINCT key from db — module signing
##!                      is a separate trust domain from UEFI SB.
##!   pcr.key, pcr.pem — PCR-policy signing key (private) and public key
##!                      (RFC-0006 phase 3). ukify signs the UKI's PCR
##!                      policy with pcr.key and embeds pcr.pem; /var is
##!                      sealed to "any UKI signed by this key". Again
##!                      DISTINCT from db and the module-signing key — a
##!                      release-time offline key in production.
{
  mkDerivation,
  openssl,
  efitools,
}: let
  # Fixed test owner GUID — arbitrary, identifies the siglist owner.
  guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
  # Fixed timestamp keeps the signed blobs reproducible across rebuilds;
  # initial enrollment in Setup Mode does not enforce monotonicity.
  ts = "2020-01-01 00:00:00";
  mkReq = cn: key: crt: ''
    openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
      -subj "/CN=${cn}/" -keyout ${key} -out ${crt}
  '';
in
  mkDerivation {
    pname = "secure-boot-test-keys";
    version = "1";
    src = null;

    buildDeps = [openssl efitools];
    runtimeDeps = [];

    phases = [
      {
        name = "gen";
        script = ''
          mkdir -p $out
          cd $out

          # --- key hierarchy ---
          ${mkReq "AOS Test Platform Key" "PK.key" "PK.crt"}
          ${mkReq "AOS Test KEK" "KEK.key" "KEK.crt"}
          ${mkReq "AOS Test db" "db.key" "db.crt"}

          # --- EFI signature lists (owner GUID baked in) ---
          cert-to-efi-sig-list -g ${guid} PK.crt PK.esl
          cert-to-efi-sig-list -g ${guid} KEK.crt KEK.esl
          cert-to-efi-sig-list -g ${guid} db.crt db.esl

          # --- signed authenticated-variable blobs ---
          # PK self-signed; KEK signed by PK; db signed by KEK.
          sign-efi-sig-list -t "${ts}" -k PK.key  -c PK.crt  PK  PK.esl  PK.auth
          sign-efi-sig-list -t "${ts}" -k PK.key  -c PK.crt  KEK KEK.esl KEK.auth
          sign-efi-sig-list -t "${ts}" -k KEK.key -c KEK.crt db  db.esl  db.auth

          # --- kernel module-signing key (phase 2 lockdown) ---
          # Distinct from db. CONFIG_MODULE_SIG_KEY wants ONE PEM holding
          # the private key followed by the X.509 cert.
          ${mkReq "AOS Test Module Signing" "modsign.key" "modsign.crt"}
          cat modsign.key modsign.crt > modsign.pem

          # --- PCR-policy signing key (phase 3 measured boot) ---
          # ukify signs the UKI's PCR policy with the private key and
          # embeds the public key; systemd-cryptenroll --tpm2-public-key
          # seals /var to that public key. A plain RSA keypair (no X.509).
          openssl genrsa -out pcr.key 2048
          openssl rsa -in pcr.key -pubout -out pcr.pem

          # The private keys other than db are not needed downstream, but
          # keeping them is harmless for a test fixture and aids debugging.
        '';
      }
    ];

    meta = {
      description = "secure-boot-keys — CI/test Secure Boot key hierarchy";
      license = "MIT";
    };
  }
