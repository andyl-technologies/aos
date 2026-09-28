##! Image-pinned method-46 floor mode and external per-owner NV credentials.
{lib}: {
  options = {
    required = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Pins this existing Controller-Storage client or Storage broker owner to its already provisioned TPM floor at every broker-session journal boundary. False permanently closes execution-output methods without disabling unrelated Storage methods; missing required state never falls back.";
    };

    provisionCredential = lib.mkOption {
      type = lib.types.nullOr lib.serviceTypes.credentialName;
      default = null;
      description = "External exact AOSBTD01 public provisioning credential for this owner, binding node/deployment epoch/endpoint and its separately provisioned SHA-256 salt-key Name. Normal startup never creates or adopts TPM/journal state.";
    };

    indexAuthCredential = lib.mkOption {
      type = lib.types.nullOr lib.serviceTypes.credentialName;
      default = null;
      description = "External exact 32-byte high-entropy owner-specific NV index auth. It must grant no owner/platform/lockout hierarchy authority, Clear, Define or Undefine; never put it in the Nix store. The existing daemon UID requires a separately provisioned /dev/tpmrm0 ACL.";
    };
  };

  configure = cfg: {
    modeText =
      if cfg.required
      then "required-v1\n"
      else "legacy-closed-v1\n";
    assertions = [
      {
        assertion =
          if cfg.required
          then
            cfg.provisionCredential
            != null
            && cfg.indexAuthCredential != null
            && cfg.provisionCredential != cfg.indexAuthCredential
          else cfg.provisionCredential == null && cfg.indexAuthCredential == null;
        message = "method46TpmFloor requires distinct external public/auth credentials in required mode, or neither in permanently closed legacy mode";
      }
    ];
    loadCredentials = lib.optionals cfg.required [
      "broker-method46-tpm-provision-v1:/run/credentials/@system/${cfg.provisionCredential}"
      "broker-method46-tpm-index-auth-v1:/run/credentials/@system/${cfg.indexAuthCredential}"
    ];
  };
}
