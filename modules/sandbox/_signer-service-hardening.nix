##! Shared, static systemd confinement for the separate Cache and Source signers.
{
  CapabilityBoundingSet = "";
  NoNewPrivileges = true;
  PrivateDevices = true;
  PrivateNetwork = true;
  PrivateTmp = true;
  ProtectSystem = "strict";
  ProtectHome = true;
  ProtectProc = "invisible";
  ProcSubset = "pid";
  ProtectClock = true;
  ProtectControlGroups = true;
  ProtectKernelLogs = true;
  ProtectKernelModules = true;
  ProtectKernelTunables = true;
  RestrictNamespaces = true;
  RestrictRealtime = true;
  RestrictSUIDSGID = true;
  RestrictAddressFamilies = ["AF_UNIX"];
  DevicePolicy = "closed";
  LockPersonality = true;
  MemoryDenyWriteExecute = true;
}
