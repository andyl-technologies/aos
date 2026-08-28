##! Signed expose and credential-lifetime contract for PostgreSQL.
{
  pkgs,
  self,
}: let
  signed = builtins.fromJSON self.expose.manifest;
  credentials = signed.expose.config.credentials;
  byName = name:
    builtins.head (builtins.filter (credential: credential.name == name) credentials);
  bootstrap = byName "bootstrap-superuser-password";
  replication = byName "replication-passfile";
  tlsCredentials = builtins.map byName [
    "tls-ca"
    "tls-certificate"
    "tls-private-key"
  ];
  credentialBaseValid = credential:
    credential.source
    == "/run/credstore/postgresql/${credential.name}"
    && !credential.encrypted
    && credential.optional;
in
  assert builtins.length credentials == 5;
  assert builtins.all credentialBaseValid credentials;
  assert bootstrap.units == ["postgresql-init.service"];
  assert replication.units == ["postgresql-init.service" "postgresql.service"];
  assert builtins.all (credential: credential.units == ["postgresql.service"]) tlsCredentials;
    pkgs.runCommand "storage-postgresql-expose-contract" {} ''
      ${pkgs.grep}/bin/grep -qx 'Before=postgresql.service' \
        ${self.expose}/units/postgresql-init.service
      ${pkgs.grep}/bin/grep -q '^Requires=.*postgresql-init.service' \
        ${self.expose}/units/postgresql.service
      ${pkgs.grep}/bin/grep -q '^ExecStart=.*-- /bin/postgresql-control prepare$' \
        ${self.expose}/units/postgresql-init.service
      if ${pkgs.grep}/bin/grep -Fq 'postgresql-control prepare' \
        ${self.expose}/units/postgresql.service; then
        echo "bootstrap preparation must not run inside the long-lived PostgreSQL unit" >&2
        exit 1
      fi
      if ${pkgs.grep}/bin/grep -Eq \
        'LoadCredential(Encrypted)?=.*bootstrap-superuser-password' \
        ${self.expose}/units/postgresql.service; then
        echo "bootstrap password must never be mounted into postgresql.service" >&2
        exit 1
      fi
      mkdir -p "$out"
      printf '%s\n' verified >"$out/result"
    ''
