##! Hybrid Hub transport qualification across separate Native, Worker, S3, and client VMs.
##!
##! Miniflare runs the deployable Worker under local workerd with a persistent
##! emulated R2 binding. PostgreSQL runs on Native by default or on an independent
##! VM when separateDatabase is enabled. Native has no R2 credentials.
##! The suite exercises signed routing, browser and control APIs,
##! storage-local work, concurrent uploads, failure recovery, and byte budgets.
{
  lib,
  mkSystem,
  pkgs,
  runtimeSource ? null,
  separateDatabase ? false,
  externalDirect ? false,
  readRevisionFixture ? null,
}: let
  databaseHost =
    if separateDatabase
    then "database"
    else "127.0.0.1";
  databaseListenAddress =
    if separateDatabase
    then "0.0.0.0"
    else "127.0.0.1";
  databaseUsesNetwork =
    if separateDatabase
    then "true"
    else "false";
  databaseOperatorHost =
    if separateDatabase
    then "database"
    else "native";
  fixture = import ./_native-hub-production.nix {inherit lib mkSystem pkgs;};
  garage =
    if externalDirect
    then import ./_hub-garage-refusal-drain.nix {inherit pkgs;}
    else pkgs.garage;
  workerDist =
    if externalDirect
    then pkgs.aos-hub-direct-guard-e2e.passthru.workerDist
    else pkgs.aos-hub-worker-dist;
  alternateRevision = import ./_hub-direct-read-revision-fixture.nix {
    inherit lib pkgs;
    worker = workerDist;
    selected = readRevisionFixture;
  };
  containerFixture = mkSystem {
    systemName = "server";
    modules = [
      ../../systems/server.nix
      {
        # Bind the real AOS base image to the first signed qualification release.
        aos.containers.definitions.aos.publication.releaseIdentity = lib.mkForce "1.0.0";
      }
    ];
  };
  containerPublicationInputs = containerFixture.config.system.build.containers.aos.publicationInputs;
  managedCleanupNativeHelper = import ./_hub-managed-cleanup-native-helper.nix {inherit pkgs;};
  verificationObservationHelper = import ./_hub-direct-verification-native-helper.nix {inherit pkgs;};
  verificationObservationHelperProvenance = import ./_hub-direct-verification-helper-provenance.nix {
    inherit pkgs;
    runtimeSource =
      if runtimeSource == null
      then throw "External verification fixture needs its immutable runtimeSource"
      else runtimeSource;
    helper = verificationObservationHelper;
    worker = workerDist;
  };
  leaseScaleReplyCodec = import ./_hub-lease-scale-reply-codec.nix {inherit pkgs;};
  storageBodyCodec = import ./_hub-storage-body-codec.nix {
    inherit pkgs;
    source =
      if runtimeSource == null
      then throw "External storage observation fixture needs its immutable runtimeSource"
      else runtimeSource;
  };
  # This dependent fixture measures the installed ELF after normal package fixup.
  # Its source coordinates and bytes receive independent tuple review before launch.
  managedCleanupHelperProvenance =
    pkgs.runCommand "hub-managed-cleanup-helper-provenance" {
      buildDeps = [pkgs.python3];
    } ''
      mkdir -p "$out"
      ${pkgs.python3}/bin/python3 - "$out/provenance.json" <<'CLEANUP_HELPER_PROVENANCE'
      import hashlib, json, os, stat, sys
      from pathlib import Path

      path = Path("${managedCleanupNativeHelper}/bin/aos-hub-managed-cleanup-contract")
      with path.open("rb") as executable:
          before = os.fstat(executable.fileno())
          if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 536870912:
              raise ValueError("Installed cleanup ELF exceeded the selected bound")
          if executable.read(4) != b"\x7fELF":
              raise ValueError("Cleanup artifact is not an installed ELF")
          executable.seek(0)
          digest = hashlib.file_digest(executable, "sha256").hexdigest()
          after = os.fstat(executable.fileno())
      if any(getattr(before, name) != getattr(after, name)
              for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")):
          raise ValueError("Installed cleanup ELF changed during observation")
      proof = {"version": 1,
          "commonSourceStorePath": "${
        if runtimeSource == null
        then throw "External fleet needs its immutable runtimeSource"
        else toString runtimeSource
      }",
          "workerFilteredSourceStorePath": "${workerDist.src}",
          "testExecutableSha256": digest, "testExecutableBytes": str(before.st_size)}
      with Path(sys.argv[1]).open("x") as output:
          json.dump(proof, output, sort_keys=True, separators=(",", ":"))
          output.write("\n")
      CLEANUP_HELPER_PROVENANCE
    '';

  caCertificate = builtins.readFile ../fixtures/hub-hybrid-fleet-ca.crt;
  s3CaCertificate = builtins.readFile ../fixtures/hub-hybrid-fleet-s3-ca.crt;
  writeFixture = name: text:
    pkgs.writeTextFile {
      inherit name text;
      destination = "/value";
    };

  serverCertificate = writeFixture "hub-hybrid-fleet-certificate" (
    builtins.readFile ../fixtures/hub-hybrid-fleet-server.crt
  );
  serverPrivateKey = writeFixture "hub-hybrid-fleet-private-key" (
    builtins.readFile ../fixtures/hub-hybrid-fleet-server.key
  );
  s3Certificate = writeFixture "hub-hybrid-fleet-s3-certificate" (
    builtins.readFile ../fixtures/hub-hybrid-fleet-s3.crt
  );
  s3PrivateKey = writeFixture "hub-hybrid-fleet-s3-private-key" (
    builtins.readFile ../fixtures/hub-hybrid-fleet-s3.key
  );
  s3PublicTrust = writeFixture "hub-hybrid-fleet-s3-public-trust" s3CaCertificate;
  garageConfig = writeFixture "hub-hybrid-fleet-garage.toml" ''
    metadata_dir = "/var/lib/hybrid-s3/meta"
    data_dir = "/var/lib/hybrid-s3/data"
    db_engine = "sqlite"
    replication_factor = 1
    rpc_bind_addr = "127.0.0.1:3901"
    rpc_secret_file = "/var/lib/hybrid-s3/rpc-secret"

    [s3_api]
    api_bind_addr = "127.0.0.1:3900"
    s3_region = "garage"
    ${lib.optionalString externalDirect "fixture_no_such_upload_drain = true"}
  '';
  s3ProxyConfig = writeFixture "hub-hybrid-fleet-s3-nginx.conf" ''
    # The disposable S3 VM does not provision nginx's default account or state dirs.
    user root;
    pid /var/lib/hybrid-s3/nginx.pid;
    error_log /var/lib/hybrid-s3/nginx-error.log info;
    events { worker_connections 128; }
    http {
      # Only reads use the hold chain; multipart mutations retain Garage's replies.
      map $request_method $provider_upstream {
        default http://127.0.0.1:3900;
        GET http://127.0.0.1:${if externalDirect then "3903" else "3900"};
      }
      map $request_uri $provider_upload_query {
        ~[?&]uploadId(?:=|&|$) multipart_session;
        ~[?&]uploads(?:=|&|$) multipart_begin;
        default object;
      }
      log_format provider_bytes escape=json
        '{"method":"$request_method","caller":"$remote_addr","path":"$uri",'
        '"operation":"$provider_upload_query",'
        '"status":"$status","request_http_bytes":"$request_length",'
        '"request_body_bytes":"$content_length","transfer_encoding":"$http_transfer_encoding",'
        '"response_http_bytes":"$bytes_sent","response_body_bytes":"$body_bytes_sent",'
        '"etag":"$sent_http_etag","content_md5":"$http_content_md5",'
        '"elapsed_seconds":"$request_time"}';
      ${
      if externalDirect
      then "access_log /var/lib/hybrid-s3/provider-observations.jsonl provider_bytes;"
      else "access_log off;"
    }
      client_body_temp_path /var/lib/hybrid-s3/client-body;
      proxy_temp_path /var/lib/hybrid-s3/proxy-temp;
      fastcgi_temp_path /var/lib/hybrid-s3/fastcgi-temp;
      uwsgi_temp_path /var/lib/hybrid-s3/uwsgi-temp;
      scgi_temp_path /var/lib/hybrid-s3/scgi-temp;
      server {
        listen 443 ssl;
        server_name s3.fleet.test;
        ssl_certificate ${s3Certificate}/value;
        ssl_certificate_key ${s3PrivateKey}/value;
        client_max_body_size 64m;
        location / {
          proxy_pass $provider_upstream$request_uri;
          proxy_set_header Host $http_host;
          proxy_http_version 1.1;
          proxy_request_buffering off;
        }
      }
    }
  '';
  storageObservationProxies = import ./_hub-direct-storage-proxies.nix {
    inherit serverCertificate serverPrivateKey;
    heldExecuteUpstream =
      if externalDirect
      then "https://localhost:4650"
      else null;
  };
  nativeObservationProxyConfig = writeFixture "hub-hybrid-fleet-native-observation-nginx.conf" (
    import ./_hub-direct-native-proxy.nix {
      inherit serverCertificate serverPrivateKey;
      storageHttp = storageObservationProxies.nativeHttp;
    }
  );
  workerObservationProxyConfig = writeFixture "hub-hybrid-fleet-worker-observation-nginx.conf" storageObservationProxies.workerConfiguration;
  managedObservationProxies = import ./_hub-managed-storage-proxies.nix {
    includeMirrorControls = externalDirect;
    inherit serverCertificate serverPrivateKey;
    managedCleanupLossUpstream = "http://127.0.0.1:4660";
    managedOciProfileHoldUpstream = "http://127.0.0.1:4649";
  };
  managedNativeObservationProxyTemplate = writeFixture "hub-hybrid-fleet-managed-native-observation-template.conf" managedObservationProxies.nativeConfiguration;
  managedWorkerObservationProxyTemplate = writeFixture "hub-hybrid-fleet-managed-worker-observation-template.conf" managedObservationProxies.workerConfiguration;
  externalOciObservationProxies = import ./_hub-external-oci-proxies.nix {
    inherit serverCertificate serverPrivateKey;
  };
  externalOciNativeProxyTemplate = writeFixture "hub-hybrid-fleet-external-oci-native-template.conf" externalOciObservationProxies.nativeConfiguration;
  externalOciWorkerProxyTemplate = writeFixture "hub-hybrid-fleet-external-oci-worker-template.conf" externalOciObservationProxies.workerConfiguration;
  databaseUrl =
    writeFixture
    "hub-hybrid-fleet-database-url"
    "postgresql://postgres@${databaseHost}:5432/postgres\n";
  ingressKey =
    writeFixture
    "hub-hybrid-fleet-ingress-key"
    "hybrid-fleet-ingress-key-with-at-least-thirty-two-bytes";
  storageKey =
    writeFixture
    "hub-hybrid-fleet-storage-key"
    "hybrid-fleet-storage-key-with-at-least-thirty-two-bytes";
  instanceSecretKey =
    writeFixture
    "hub-hybrid-fleet-instance-secret-key"
    "1111111111111111111111111111111111111111111111111111111111111111";
  releaseReceiptKey =
    writeFixture
    "hub-hybrid-fleet-release-receipt-key"
    "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=";
  channelReceiptKey =
    writeFixture
    "hub-hybrid-fleet-channel-receipt-key"
    "CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo=";
  releasePublicationKeys =
    writeFixture
    "hub-hybrid-fleet-release-publication-keys"
    (builtins.toJSON {
      "staging-publication-v1" = "/RckOFqgx1tk+3jNYC+h2ZH96/drE8WO1wLqyDXp9hg=";
    });
  qualificationKeys =
    writeFixture
    "hub-hybrid-fleet-qualification-keys"
    (builtins.toJSON {
      "qualification-v1" = "E5j2LG0aRXxRumpLXz29L2n8qTIWIY3ImX5Ba9F9k8o=";
    });
  secretVersionManifest =
    writeFixture
    "hub-hybrid-fleet-secret-version-manifest"
    (builtins.toJSON (
      if externalDirect
      then {}
      else {
        "native://fleet/external/storage/v1" = "/var/lib/aos-hub/fleet-s3-secret";
      }
    ));

  # Diagnostic guests retain the ordinary AOS runtime and boot identity CLI.
  # Use the established qualification closure allowance and measured initrd bound.
  # Per-role raw download limits retain the complete disk; production defaults and
  # the remaining image budgets stay intact.
  qualificationImageBudget = {
    rawDownloadMiB,
    recoveryBundleMiB,
  }: {
    aos.image.budgets = {
      maxRuntimeClosureMiB = 912;
      maxInitrdMiB = 144;
      # The complete diagnostic runtime produces a 731 MiB EROFS root.
      maxRootMiB = lib.mkForce 768;
      maxDownloadMiB = lib.mkForce rawDownloadMiB;
      # Recovery bundles retain their existing allowance independently of raw disks.
      maxRecoveryBundleMiB = lib.mkForce recoveryBundleMiB;
    };
  };

  nativeSystem = fixture.hubSystem.extendModules {
    modules = [
      (qualificationImageBudget {
        rawDownloadMiB = 896;
        recoveryBundleMiB = 816;
      })
      {
        # Native also retains the full Hub server and initializer payload.
        aos.image.budgets.maxRuntimeClosureMiB = lib.mkForce 1024;

        aos.registry-hub = {
          deploymentId = "fleet-hybrid-v1";
          externalUrl = "https://aos.andyl.org";
          listen =
            if externalDirect
            then "127.0.0.1:4443"
            else "0.0.0.0:443";
          releaseReceiptKeyId = "staging-publication-v1";
          channelReceiptKeyId = "staging-channel-v1";
          hybrid = {
            enable = true;
            workerUrl = "https://aos.andyl.org";
            originUrl = "https://aos.staging.andyl.org";
          };
          credentials = {
            databaseUrl = "hybrid-fleet-database-url";
            hybridIngressKey = "hybrid-fleet-ingress-key";
            storageWorkKey = "hybrid-fleet-storage-key";
            instanceSecretKey = "hybrid-fleet-instance-secret-key";
            releaseReceiptKey = "hybrid-fleet-release-receipt-key";
            channelReceiptKey = "hybrid-fleet-channel-receipt-key";
            releasePublicationKeys = "hybrid-fleet-release-publication-keys";
            qualificationKeys = "hybrid-fleet-qualification-keys";
            secretVersionManifest = "hybrid-fleet-secret-version-manifest";
            tlsCertificate = "hybrid-fleet-certificate";
            tlsPrivateKey = "hybrid-fleet-private-key";
          };
        };
        aos.security.pki.certificates = [caCertificate s3CaCertificate];
        aos.firewall.allowedTCP =
          [443]
          ++ lib.optionals externalDirect [8443 8453 4644 4673 4674 4677]
          ++ lib.optional (externalDirect && !separateDatabase) 5432;
        aos.kernel.modules = ["9pnet_virtio" "9p"];
        environment.systemPackages = [pkgs.util-linux];
        systemd.services.aos-hub.serviceConfig.Environment = [
          "HUB_OCI_PULL_ENABLED=true"
          "HUB_OCI_PUSH_ENABLED=true"
          "HUB_OCI_GC_ENABLED=true"
        ];
        environment.etc."tmpfiles.d/hub-hybrid-fleet-credentials.conf".text = ''
          d /run/credentials/@system 0700 root root -
          C /run/credentials/@system/hybrid-fleet-database-url 0600 root root - ${databaseUrl}/value
          C /run/credentials/@system/hybrid-fleet-ingress-key 0600 root root - ${ingressKey}/value
          C /run/credentials/@system/hybrid-fleet-storage-key 0600 root root - ${storageKey}/value
          C /run/credentials/@system/hybrid-fleet-instance-secret-key 0600 root root - ${instanceSecretKey}/value
          C /run/credentials/@system/hybrid-fleet-release-receipt-key 0600 root root - ${releaseReceiptKey}/value
          C /run/credentials/@system/hybrid-fleet-channel-receipt-key 0600 root root - ${channelReceiptKey}/value
          C /run/credentials/@system/hybrid-fleet-release-publication-keys 0600 root root - ${releasePublicationKeys}/value
          C /run/credentials/@system/hybrid-fleet-qualification-keys 0600 root root - ${qualificationKeys}/value
          C /run/credentials/@system/hybrid-fleet-secret-version-manifest 0600 root root - ${secretVersionManifest}/value
          C /run/credentials/@system/hybrid-fleet-certificate 0600 root root - ${serverCertificate}/value
          C /run/credentials/@system/hybrid-fleet-private-key 0600 root root - ${serverPrivateKey}/value
        '';
      }
    ];
  };

  edgeSystem = mkSystem [
    ../../systems/server-test.nix
    (qualificationImageBudget {
      rawDownloadMiB = 864;
      recoveryBundleMiB = 800;
    })
    {
      aos.security.pki.certificates = [caCertificate s3CaCertificate];
      aos.firewall.allowedTCP = [443] ++ lib.optionals externalDirect [8453 4643 4644 4673 4674];
      aos.kernel.modules = ["9pnet_virtio" "9p"];
      environment.systemPackages = [pkgs.util-linux];
    }
  ];
  clientSystem = mkSystem [
    ../../systems/server-test.nix
    (qualificationImageBudget {
      rawDownloadMiB = 864;
      recoveryBundleMiB = 800;
    })
    {
      aos.security.pki.certificates = [caCertificate s3CaCertificate];
      aos.kernel.modules = ["9pnet_virtio" "9p"];
      environment.systemPackages = [pkgs.util-linux];
    }
  ];

  databaseSystem = edgeSystem.extendModules {
    modules = [
      {
        aos.firewall.allowedTCP = [5432];
        aos.users.users.aos-hub = {
          uid = 802;
          group = "aos-hub";
          home = "/var/lib/hybrid-postgres";
          shell = "/sbin/nologin";
          description = "Disposable fleet PostgreSQL owner";
        };
        aos.users.groups.aos-hub.gid = 802;
      }
    ];
  };

  workerRunner = writeFixture "hub-hybrid-fleet-worker-runner" (builtins.readFile ./_hub-worker-runner.cjs);
  # Adjacent imports select the same reviewed fixture files in every guest.
  managedFixtureModules = pkgs.runCommand "hub-managed-fleet-fixture-modules" {} ''
    mkdir -p "$out"
    cp ${./_hub-direct-issuer-scale-setup.py} "$out/_hub-direct-issuer-scale-setup.py"
    cp ${./_hub-direct-issuer-scale-workload.py} "$out/_hub-direct-issuer-scale-workload.py"
    cp ${./_hub-direct-issuer-scale.py} "$out/_hub-direct-issuer-scale.py"
    cp ${./_hub-direct-issuer-scale-process.py} "$out/_hub-direct-issuer-scale-process.py"
    cp ${./_hub-direct-issuer-scale-runtime.py} "$out/_hub-direct-issuer-scale-runtime.py"
    cp ${./_hub-direct-issuer-scale-joins.py} "$out/_hub-direct-issuer-scale-joins.py"
    cp ${./_hub-oci-sdk-namespace.py} "$out/_hub-oci-sdk-namespace.py"
    cp ${./_hub-oci-sdk-anchor.py} "$out/_hub-oci-sdk-anchor.py"
    cp ${./_hub-oci-sdk-install.py} "$out/_hub-oci-sdk-install.py"
    cp ${./_hub-managed-container.py} "$out/_hub-managed-container.py"
    cp ${./_hub-external-oci-setup.py} "$out/_hub-external-oci-setup.py"
    cp ${./_hub-external-inventory-resume.py} "$out/_hub-external-inventory-resume.py"
    cp ${./_hub-external-workflow-accounting.py} "$out/_hub-external-workflow-accounting.py"
    cp ${./_hub-external-mirror-accounting.py} "$out/_hub-external-mirror-accounting.py"
    cp ${./_hub-native-sql-projection.py} "$out/_hub-native-sql-projection.py"
    cp ${./_hub-direct-boundary.py} "$out/_hub-direct-boundary.py"
    cp ${./_hub-direct-runtime-observations.py} "$out/_hub-direct-runtime-observations.py"
    cp ${./_hub-external-copy-window.py} "$out/_hub-external-copy-window.py"
    cp ${./_hub-external-copy-isolation.cjs} "$out/_hub-external-copy-isolation.cjs"
    cp ${./_hub-external-mirror-install.cjs} "$out/_hub-external-mirror-install.cjs"
    cp ${./_hub-external-copy-lifetime.py} "$out/_hub-external-copy-lifetime.py"
    cp ${./_hub-external-copy-partial-hold.mjs} "$out/_hub-external-copy-partial-hold.mjs"
    cp ${./_hub-external-copy-closed-loss.mjs} "$out/_hub-external-copy-closed-loss.mjs"
    cp ${./_hub-worker-cache-observer.cjs} "$out/_hub-worker-cache-observer.cjs"
    cp ${./_hub-direct-read-parity.py} "$out/_hub-direct-read-parity.py"
    cp ${./_hub-index-parity.py} "$out/_hub-index-parity.py"
    cp ${./_hub-direct-read-window.py} "$out/_hub-direct-read-window.py"
    cp ${./_hub-managed-gc.py} "$out/_hub-managed-gc.py"
    cp ${./_hub-managed-gc-observer.py} "$out/_hub-managed-gc-observer.py"
    cp ${./_hub-managed-gc-sql.py} "$out/_hub-managed-gc-sql.py"
    cp ${./_hub-inventory-gc.py} "$out/_hub-inventory-gc.py"
    cp ${./_hub-managed-gc-runner-observer.cjs} "$out/_hub-managed-gc-runner-observer.cjs"
    cp ${./_hub-managed-cleanup-install.cjs} "$out/_hub-managed-cleanup-install.cjs"
    cp ${./_hub-managed-cleanup-loss.py} "$out/_hub-managed-cleanup-loss.py"
    cp ${./_hub-managed-cleanup-runtime.py} "$out/_hub-managed-cleanup-runtime.py"
    cp ${./_hub-managed-cleanup-accounting.py} "$out/_hub-managed-cleanup-accounting.py"
    cp ${./_hub-managed-workflow-accounting.py} "$out/_hub-managed-workflow-accounting.py"
    cp ${./_hub-managed-cleanup-sql.py} "$out/_hub-managed-cleanup-sql.py"
    cp ${./_hub-direct-provider-response-hold.mjs} "$out/_hub-direct-provider-response-hold.mjs"
    cp ${./_hub-oci-profile-mismatch.py} "$out/_hub-oci-profile-mismatch.py"
    cp ${./_hub-oci-profile-process.py} "$out/_hub-oci-profile-process.py"
    cp ${./_hub-oci-profile-mismatch-listener.mjs} "$out/_hub-oci-profile-mismatch-listener.mjs"
    cp ${./_hub-direct-stale-index.py} "$out/_hub-direct-stale-index.py"
    cp ${./_hub-direct-stale-index-listener.mjs} "$out/_hub-direct-stale-index-listener.mjs"
    cp ${./_hub-direct-stale-index-process.py} "$out/_hub-direct-stale-index-process.py"
    cp ${./_hub-direct-stale-placement.py} "$out/_hub-direct-stale-placement.py"
    cp ${./_hub-direct-stale-placement-hold.mjs} "$out/_hub-direct-stale-placement-hold.mjs"
  '';
  processSampler = writeFixture "hub-hybrid-fleet-process-sampler" (builtins.readFile ./_hub-perf-proc.py);
  installationObserver = writeFixture "hub-hybrid-fleet-installation-observer" (builtins.readFile ./_hub-direct-installation.py);
  namespaceObserver = writeFixture "hub-hybrid-fleet-namespace-observer" (builtins.readFile ./_hub-direct-namespace.py);
  queueObserver = writeFixture "hub-hybrid-fleet-queue-observer" (builtins.readFile ./_hub-direct-queue-observer.py);
  operatorFixture = writeFixture "hub-hybrid-fleet-operator-fixture" (builtins.readFile ./_hub-direct-operator.py);
  consumerConfiguration = writeFixture "hub-hybrid-fleet-consumer-configuration" (builtins.readFile ./_hub-direct-configuration.py);
  acceptanceInstaller = writeFixture "hub-hybrid-fleet-acceptance-installer" (builtins.readFile ./_hub-direct-kv-install.py);
  bootstrapControls = writeFixture "hub-hybrid-fleet-bootstrap-controls" (builtins.readFile ./_hub-direct-controls.py);
  bootstrapFlow = writeFixture "hub-hybrid-fleet-bootstrap-flow" (builtins.readFile ./_hub-direct-bootstrap.py);
  authorityFlow = writeFixture "hub-hybrid-fleet-authority-flow" (builtins.readFile ./_hub-direct-authority.py);
  qualificationFlow = writeFixture "hub-hybrid-fleet-qualification-flow" (builtins.readFile ./_hub-direct-qualification.py);
  qualificationDriver = writeFixture "hub-hybrid-fleet-qualification-driver" (builtins.readFile ../../pkgs/tools/aos-hub-direct-qualification.mjs);
  independentReview = writeFixture "hub-hybrid-fleet-independent-review" (builtins.readFile ./_hub-direct-review.py);
  sqlObserver = writeFixture "hub-hybrid-fleet-sql-observer" (builtins.readFile ./_hub-direct-sql-proxy.py);
  workerOptions = writeFixture "hub-hybrid-fleet-worker-options" (builtins.toJSON ({
      name = "hub-hybrid-fleet";
      scriptPath = "${workerDist}/shim.mjs";
      compatibilityDate = "2024-09-23";
      host =
        if externalDirect
        then "127.0.0.1"
        else "0.0.0.0";
      port =
        if externalDirect
        then 4443
        else 443;
      certificatePath = "${serverCertificate}/value";
      privateKeyPath = "${serverPrivateKey}/value";
      r2Buckets.REGISTRY_BUCKET = "hybrid-fleet-r2";
      resourcePersistencePath = "/var/lib/hybrid-worker/state";
      durableObjects =
        {
          HYBRID_OBJECT_GUARD = {
            className = "HybridObjectGuard";
            useSQLite = true;
          };
          HYBRID_BINDING_STATE = {
            className = "HybridBindingState";
            useSQLite = true;
          };
        }
        // lib.optionalAttrs externalDirect {
          HYBRID_AUTHORITY_STATE = {
            className = "HybridAuthorityState";
            useSQLite = true;
          };
          EXTERNAL_OBJECT_GUARD = {
            className = "ExternalObjectGuard";
            useSQLite = true;
          };
          HYBRID_DIRECT_UPLOAD = {
            className = "HybridDirectUpload";
            useSQLite = true;
          };
        };
      bindings =
        {
          HUB_TOPOLOGY = "hybrid";
          HUB_DEPLOYMENT_ID = "fleet-hybrid-v1";
          HUB_HYBRID_ORIGIN_URL = "https://aos.staging.andyl.org";
          HUB_HYBRID_INGRESS_KEY = "hybrid-fleet-ingress-key-with-at-least-thirty-two-bytes";
          HUB_STORAGE_WORK_KEY = "hybrid-fleet-storage-key-with-at-least-thirty-two-bytes";
        }
        // lib.optionalAttrs externalDirect {
          HUB_DIRECT_UPLOAD_PUBLIC_ORIGIN = "https://aos.andyl.org";
          HUB_DIRECT_UPLOAD_MANAGED_R2 = "false";
          HUB_DIRECT_UPLOAD_QUALIFICATION_ENABLED = "true";
          HUB_DIRECT_UPLOAD_CLOCK_MODE = "bounded_utc";
          HUB_DIRECT_UPLOAD_CLOCK_UNCERTAINTY_SECONDS = "1";
          # The shared source-built clock-policy command serializes this fixed
          # candidate policy. Its commitment conveys no observed clock facts.
          HUB_DIRECT_UPLOAD_CLOCK_QUALIFICATION = "39b56754e1529d7090138c9798df5b4c045338cce500548f095a08220f7bfe40";
          HUB_DIRECT_VERIFY_BULK_NAME = "fleet-direct-verify-bulk";
          HUB_DIRECT_VERIFY_METADATA_NAME = "fleet-direct-verify-metadata";
          HUB_DIRECT_VERIFY_BULK_MAX_BATCH_SIZE = "2";
          HUB_DIRECT_VERIFY_METADATA_MAX_BATCH_SIZE = "3";
          # Miniflare has no global invocation cap. Participating-isolate capacity
          # and actual provider pool observations are reviewed independently.
          HUB_DIRECT_VERIFY_BULK_MAX_CONCURRENT_INVOCATIONS = "unsupported";
          HUB_DIRECT_VERIFY_METADATA_MAX_CONCURRENT_INVOCATIONS = "unsupported";
          HUB_DIRECT_VERIFY_MAX_PARALLEL_OBJECTS = "3";
          HUB_DIRECT_QUALIFY_MAX_PROVIDER_REQUESTS = "3";
          # This fixed initial policy is measured with the genuine preflight.
          HUB_PROVIDER_CAPACITY_POLICY = builtins.toJSON {
            version = 1;
            deployment_id = "fleet-hybrid-v1";
            source_digest = builtins.hashString "sha256" (toString workerDist.src);
            script_version = "emulated-${builtins.hashString "sha256" (toString workerDist.src)}";
            maximum_provider_requests = 3;
          };
          HUB_DIRECT_QUALIFY_MAX_OBJECT_BYTES = "2147483648";
        };
    }
    // lib.optionalAttrs externalDirect {
      copyIsolationSelection = {
        version = 1;
        sourceWorkerName = "hub-hybrid-fleet";
      };
      copyIsolationModulePath = "${managedFixtureModules}/_hub-external-copy-isolation.cjs";
      queueObservationPath = "/var/lib/hybrid-worker/queue-startup";
      namespaceObservationPath = "/var/lib/hybrid-worker/namespace-startup";
      acceptanceSocketPath = "/var/lib/hybrid-worker/acceptance-control.sock";
      kvNamespaces.HUB_DIRECT_UPLOAD_ACCEPTANCE = "hybrid-fleet-direct-acceptance";
      queueProducers = {
        HUB_DIRECT_VERIFY_BULK = "fleet-direct-verify-bulk";
        HUB_DIRECT_VERIFY_METADATA = "fleet-direct-verify-metadata";
      };
      queueConsumers = {
        fleet-direct-verify-bulk.maxBatchSize = 2;
        fleet-direct-verify-bulk.maxBatchTimeout = 0;
        fleet-direct-verify-metadata.maxBatchSize = 3;
        # Partial metadata batches are delivered immediately during bulk work.
        # The separate pure metadata batch still measures all three admissions.
        fleet-direct-verify-metadata.maxBatchTimeout = 0;
      };
    }));
  parityRouteKeys = writeFixture "hub-runtime-parity-route-keys" (builtins.toJSON {
    activeVersion = 1;
    keys = [
      {
        version = 1;
        keyBase64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
      }
    ];
  });
  toolClosureInfo = import ../../lib/build/closure-info.nix {inherit lib pkgs;} {
    pname = "hub-hybrid-fleet-tool-closure-info";
    rootPaths =
      [
        pkgs.aos
        pkgs.aos.apr
        pkgs.aos-hub
        workerDist
        pkgs.coreutils
        pkgs.curl
        pkgs.gawk
        pkgs.git
        pkgs.grep
        pkgs.jq
        pkgs.miniflare
        pkgs.nodejs
        pkgs.workerd-source
        pkgs.python3
        pkgs.socat
        garage
        pkgs.nginx
        pkgs.nix
        pkgs.openssh
        pkgs.postgresql
        pkgs.sed
        pkgs.sqlite
        pkgs.tar
        pkgs.util-linux
        fixture.helperV1
        fixture.helperV2
        containerPublicationInputs
        containerFixture.config.aos.config.evalAtBoot.baseLib
        pkgs.aos-hub-console-dist
        databaseUrl
        ingressKey
        storageKey
        instanceSecretKey
        releaseReceiptKey
        channelReceiptKey
        releasePublicationKeys
        qualificationKeys
        serverCertificate
        serverPrivateKey
        s3Certificate
        s3PrivateKey
        garageConfig
        s3ProxyConfig
        workerRunner
        processSampler
        workerOptions
        parityRouteKeys
      ]
      ++ lib.optionals externalDirect [
        pkgs.openssl
        pkgs.aos-hub-worker-dist
        s3PublicTrust
        workerDist.src
        alternateRevision.source
        alternateRevision.distribution
        nativeObservationProxyConfig
        workerObservationProxyConfig
        managedNativeObservationProxyTemplate
        managedWorkerObservationProxyTemplate
        externalOciNativeProxyTemplate
        externalOciWorkerProxyTemplate
        installationObserver
        namespaceObserver
        queueObserver
        operatorFixture
        consumerConfiguration
        acceptanceInstaller
        bootstrapControls
        bootstrapFlow
        authorityFlow
        qualificationFlow
        qualificationDriver
        managedFixtureModules
        managedCleanupNativeHelper
        managedCleanupHelperProvenance
        verificationObservationHelper
        verificationObservationHelperProvenance
        leaseScaleReplyCodec
        storageBodyCodec
        independentReview
        sqlObserver
      ];
  };
in {
  name =
    if separateDatabase
    then "hub-hybrid-postgres"
    else "hub-hybrid";
  # Independent review checkpoints precede two disk-backed large-object workloads.
  timeout =
    if externalDirect
    then 14400
    else 2400;
  bootTimeout = 600;

  machines =
    {
      client = {
        system = clientSystem;
        bootMode = "image";
        hostStoreMount = true;
        imageDiskMiB =
          if externalDirect
          then 32768
          else 16384;
        memoryMiB = 2048;
        varProvisioning = "repart";
      };
      native = {
        system = nativeSystem;
        bootMode = "image";
        hostStoreMount = true;
        hostAliases = ["aos.staging.andyl.org"];
        imageDiskMiB = 16384;
        memoryMiB = 4096;
        varProvisioning = "repart";
      };
      worker = {
        system = edgeSystem;
        bootMode = "image";
        hostStoreMount = true;
        hostAliases = ["aos.andyl.org"];
        imageDiskMiB =
          if externalDirect
          then 32768
          else 16384;
        memoryMiB = 8192;
        vcpuCount = 4;
        varProvisioning = "repart";
      };
      s3 = {
        system = edgeSystem;
        bootMode = "image";
        hostStoreMount = true;
        hostAliases = ["s3.fleet.test"];
        imageDiskMiB =
          if externalDirect
          then 65536
          else 16384;
        memoryMiB = 2048;
        varProvisioning = "repart";
      };
    }
    // lib.optionalAttrs separateDatabase {
      database = {
        system = databaseSystem;
        bootMode = "image";
        hostStoreMount = true;
        imageDiskMiB = 16384;
        memoryMiB = 2048;
        varProvisioning = "repart";
      };
    };

  testScript =
    builtins.readFile ./_hub-publication.py
    + builtins.readFile ./_hub-perf.py
    + builtins.readFile ./_hub-direct-transport.py
    + lib.optionalString externalDirect (
      builtins.readFile ./_hub-direct-controls.py
      + builtins.readFile ./_hub-managed-pair.py
      + builtins.readFile ./_hub-external-oci-pair.py
      + builtins.readFile ./_hub-external-mirror-admission.py
      + builtins.readFile ./_hub-external-mirror-window.py
      + builtins.readFile ./_hub-external-mirror-source.py
      + builtins.readFile ./_hub-external-mirror-observations.py
      + builtins.readFile ./_hub-external-mirror-producer.py
      + builtins.readFile ./_hub-external-mirror-functional.py
      + builtins.readFile ./_hub-external-mirror-epoch.py
      + builtins.readFile ./_hub-external-mirror-business.py
      + builtins.readFile ./_hub-external-oci-process.py
      + builtins.readFile ./_hub-external-oci-direct.py
      + builtins.readFile ./_hub-external-oci-business.py
      + builtins.readFile ./_hub-external-inventory-window.py
      + builtins.readFile ./_hub-external-oci-accounting.py
      + builtins.readFile ./_hub-external-oci-teardown.py
      + builtins.readFile ./_hub-external-copy-loss-setup.py
      + builtins.readFile ./_hub-external-copy-cold.py
      + builtins.readFile ./_hub-external-copy-cancel.py
      + builtins.readFile ./_hub-external-copy-loss.py
      + builtins.readFile ./_hub-external-oci-window.py
      + builtins.readFile ./_hub-external-copy-window.py
      + builtins.readFile ./_hub-external-copy-configuration.py
      + builtins.readFile ./_hub-direct-runtime-profile.py
      + builtins.readFile ./_hub-managed-window.py
      + builtins.readFile ./_hub-managed-profile-call.py
      + builtins.readFile ./_hub-managed-control.py
      + builtins.readFile ./_hub-managed-route.py
      + builtins.readFile ./_hub-managed-terminal-cleanup.py
      + builtins.readFile ./_hub-managed-read.py
      + builtins.readFile ./_hub-managed-gc-window.py
      + builtins.readFile ./_hub-direct-issuer-scale-main.py
      + builtins.readFile ./_hub-direct-stale-index-setup.py
      + builtins.readFile ./_hub-direct-read-fault-window.py
      + builtins.readFile ./_hub-direct-provider-hold-setup.py
      + builtins.readFile ./_hub-direct-verification-source.py
      + builtins.readFile ./_hub-direct-verification-timeout.py
      + builtins.readFile ./_hub-native-sql-projection.py
      + builtins.readFile ./_hub-direct-operator.py
      + builtins.readFile ./_hub-direct-configuration.py
      + builtins.readFile ./_hub-direct-review.py
      + builtins.readFile ./_hub-direct-bootstrap.py
      + builtins.readFile ./_hub-direct-authority.py
      + builtins.readFile ./_hub-direct-shared-controls.py
      + builtins.readFile ./_hub-direct-prebody.py
      + builtins.readFile ./_hub-direct-publisher.py
      + builtins.readFile ./_hub-direct-qualification.py
      + builtins.readFile ./_hub-direct-queue-restart.py
      + builtins.readFile ./_hub-direct-runtime-observations.py
      + builtins.readFile ./_hub-direct-observations.py
      + builtins.readFile ./_hub-direct-boundary.py
      + builtins.readFile ./_hub-native-corpus-segments.py
      + builtins.readFile ./_hub-direct-codec-assessment.py
      + builtins.readFile ./_hub-direct-worker-lifecycle.py
      + builtins.readFile ./_hub-direct-concurrent-publications.py
      + builtins.readFile ./_hub-direct-sparse-publisher.py
      + builtins.readFile ./_hub-direct-recovery-evidence.py
      + builtins.readFile ./_hub-direct-issuer-lifecycle.py
      + builtins.readFile ./_hub-direct-issuer-cutoff.py
      + builtins.readFile ./_hub-direct-failure-windows.py
      + builtins.readFile ./_hub-direct-browser.py
      + builtins.readFile ./_hub-direct-storage-boundary.py
      + builtins.readFile ./_hub-storage-capture.py
      + builtins.readFile ./_hub-storage-work-execute-observation.py
      + builtins.readFile ./_hub-storage-final-sql.py
      + builtins.readFile ./_hub-storage-workflow-assessment.py
      + builtins.readFile ./_hub-managed-storage-boundary.py
      + builtins.readFile ./_hub-managed-storage-window.py
      + builtins.readFile ./_hub-index-parity.py
      + builtins.readFile ./_hub-runtime-parity.py
      + builtins.readFile ./_hub-direct-index-parity.py
      + builtins.readFile ./_hub-direct-flow.py
    )
    # python
    + ''
      import base64
      import hashlib
      import hmac
      import json
      import re
      import shlex
      import statistics
      import textwrap
      import time
      import urllib.parse
      import zlib

      CURL = "${pkgs.curl}/bin/curl --noproxy '*' --cacert /etc/ssl/certs/ca-certificates.crt"
      GREP = "${pkgs.grep}/bin/grep"
      SED = "${pkgs.sed}/bin/sed"
      AOS = "${pkgs.aos}/bin/aos"
      APR = "${pkgs.aos.apr}/bin/apr"
      CHROOT = "${pkgs.coreutils}/bin/chroot --userspec=802:802 /"
      POSTGRES = "${pkgs.postgresql}/bin"
      DATABASE_HOST = "${databaseHost}"
      DATABASE_OPERATOR_HOST = "${databaseOperatorHost}"
      DATABASE_LISTEN_ADDRESS = "${databaseListenAddress}"
      EXTERNAL_DIRECT = ${
        if externalDirect
        then "True"
        else "False"
      }
      database_machine = ${
        if separateDatabase
        then "database"
        else "native"
      }
      GARAGE = "${garage}/bin/garage -c /var/lib/hybrid-s3/garage.toml"
      FLEET_CUTOFF_MONOTONIC = time.monotonic() + ${toString (if externalDirect then 14400 else 2400)}

      for machine in (client, native, worker, s3${lib.optionalString separateDatabase ", database"}):
          machine.wait_for_unit("multi-user.target", timeout=240)
          machine.succeed(textwrap.dedent("""
              set -eu
              mkdir -p /run/aos-host-store
              ${pkgs.util-linux}/bin/mount -t 9p -o trans=virtio,version=9p2000.L,msize=1048576,ro \\
                aos-host-store /run/aos-host-store
              while IFS= read -r store_path; do
                test -e "$store_path" && continue
                source_path="/run/aos-host-store/$(basename "$store_path")"
                if [ -d "$source_path" ]; then
                  mkdir "$store_path"
                  ${pkgs.util-linux}/bin/mount --bind "$source_path" "$store_path"
                elif [ -f "$source_path" ]; then
                  touch "$store_path"
                  ${pkgs.util-linux}/bin/mount --bind "$source_path" "$store_path"
                elif [ -L "$source_path" ]; then
                  ln -s "$(readlink "$source_path")" "$store_path"
                else
                  exit 1
                fi
              done < "/run/aos-host-store/$(basename ${toolClosureInfo})/store-paths"
              ${pkgs.nix}/bin/nix-store --load-db \\
                < "/run/aos-host-store/$(basename ${toolClosureInfo})/registration"
              ${pkgs.util-linux}/bin/findmnt -rn -t 9p -o OPTIONS \\
                /run/aos-host-store | ${pkgs.grep}/bin/grep -qw ro
          """), timeout=180)

      s3.succeed(textwrap.dedent("""
          set -eu
          install -d -m 0700 /var/lib/hybrid-s3 /var/lib/hybrid-s3/meta \
            /var/lib/hybrid-s3/data /var/lib/hybrid-s3/client-body \
            /var/lib/hybrid-s3/proxy-temp
          printf '%s\n' '1799bccfd7411eddcf9ebd316bc1f5287ad12a68094e1c6ac6abde7e6feae1ec' \
            > /var/lib/hybrid-s3/rpc-secret
          chmod 0600 /var/lib/hybrid-s3/rpc-secret
          cp ${garageConfig}/value /var/lib/hybrid-s3/garage.toml
          ${garage}/bin/garage -c /var/lib/hybrid-s3/garage.toml server \
            > /var/lib/hybrid-s3/garage.log 2>&1 < /dev/null &
          echo $! > /var/lib/hybrid-s3/garage.pid
          cp ${s3ProxyConfig}/value /var/lib/hybrid-s3/nginx.conf
          ${pkgs.nginx}/bin/nginx -t -c /var/lib/hybrid-s3/nginx.conf \
            -p /var/lib/hybrid-s3/
          ${pkgs.nginx}/bin/nginx -c /var/lib/hybrid-s3/nginx.conf \
            -p /var/lib/hybrid-s3/ -g 'daemon off;' \
            > /var/lib/hybrid-s3/nginx.log 2>&1 < /dev/null &
          echo $! > /var/lib/hybrid-s3/nginx-process.pid
      """), timeout=60)
      ${lib.optionalString externalDirect ''
        external_copy_cases = {case: secrets.token_hex(16)
            for case in ("same_worker", "source_worker")}
        retain_direct_flow("external-copy-initial-cases.json", external_copy_cases)
        provider_hold = install_direct_provider_hold(s3, {
            "python": "${pkgs.python3}/bin/python3",
            "node": "${pkgs.nodejs}/bin/node",
            "providerHoldListener": "${managedFixtureModules}/_hub-direct-provider-response-hold.mjs",
        })
        copy_partial_hold = install_direct_provider_hold(s3, {
            "python": "${pkgs.python3}/bin/python3",
            "node": "${pkgs.nodejs}/bin/node",
            "externalCopyPartialHold": "${managedFixtureModules}/_hub-external-copy-partial-hold.mjs",
        }, partial_prefixes=[external_oci_provider_prefix("fleet-s3",
            external_oci_pair_coordinates(run)["placementPrefix"].rsplit("/", 1)[0],
            external_oci_pair_coordinates(run)["placementPrefix"])
            for run in external_copy_cases.values()])
      ''}
      s3.wait_until_succeeds(f"{GARAGE} status > /dev/null", timeout=180)
      s3.succeed(textwrap.dedent(f"""
          set -eu
          node_id=$({GARAGE} node id -q | cut -d@ -f1)
          test -n "$node_id"
          {GARAGE} layout assign -z fleet -c ${
        if externalDirect
        then "48G"
        else "1G"
      } "$node_id"
          {GARAGE} layout apply --version 1
          {GARAGE} bucket create fleet-s3
          {GARAGE} key create fleet-s3-key > /dev/null
          {GARAGE} bucket allow --read --write fleet-s3 --key fleet-s3-key
      """), timeout=90)
      wait_provider_transport(
          s3, CURL + " --resolve s3.fleet.test:443:127.0.0.1",
          "${pkgs.python3}/bin/python3", "provider-local", timeout=30,
      )
      wait_provider_transport(
          client, CURL, "${pkgs.python3}/bin/python3", "provider-client",
      )

      database_listen_address = DATABASE_LISTEN_ADDRESS
      direct_operator_hba = ""
      if EXTERNAL_DIRECT:
          import ipaddress

          addresses = json.loads(native.succeed(
              "${pkgs.python3}/bin/python3 - <<'FLEET_SQL_ADDRESSES'\n"
              "import json, socket\n"
              f"names = ['native', 'worker', {DATABASE_OPERATOR_HOST!r}]\n"
              "print(json.dumps({name: socket.gethostbyname(name) for name in names}))\n"
              "FLEET_SQL_ADDRESSES\n"
          ))
          for address in addresses.values():
              assert ipaddress.IPv4Address(address).is_private, addresses
          assert addresses["native"] != addresses["worker"], addresses
          database_listen_address = "127.0.0.1," + addresses[DATABASE_OPERATOR_HOST]
          # The operator carries provider material on Worker. Its database
          # access is authenticated separately from Native's existing role.
          direct_operator_hba = (
              f"host postgres postgres {addresses['native']}/32 trust\n"
              f"host postgres fleet_direct_operator {addresses['worker']}/32 scram-sha-256\n"
          )
          print("hybrid operator SQL boundary addresses:", addresses)
      direct_operator_hba_base64 = base64.b64encode(direct_operator_hba.encode()).decode()

      database_machine.succeed(textwrap.dedent(f"""
          install -d -m 0700 -o aos-hub -g aos-hub /var/lib/hybrid-postgres
          {CHROOT} {POSTGRES}/initdb -D /var/lib/hybrid-postgres \\
            --username=postgres --auth-local=trust --auth-host=trust \\
            --encoding=UTF8 --locale=C
          cat > /var/lib/hybrid-postgres/fleet.conf <<'EOF'
          data_directory = '/var/lib/hybrid-postgres'
          listen_addresses = '{database_listen_address}'
          port = 5432
          unix_socket_directories = '/tmp'
          shared_buffers = '32MB'
          dynamic_shared_memory_type = 'mmap'
          logging_collector = off
          EOF
          chown aos-hub:aos-hub /var/lib/hybrid-postgres/fleet.conf
          if ${databaseUsesNetwork} && ! ${
        if externalDirect
        then "true"
        else "false"
      }; then
              # Trust is restricted to the isolated disposable fleet subnet.
              echo 'host all postgres samenet trust' >> /var/lib/hybrid-postgres/pg_hba.conf
          fi
          if ${
        if externalDirect
        then "true"
        else "false"
      }; then
              printf '%s' '{direct_operator_hba_base64}' | ${pkgs.coreutils}/bin/base64 -d \\
                >> /var/lib/hybrid-postgres/pg_hba.conf
          fi
          {CHROOT} {POSTGRES}/pg_ctl -D /var/lib/hybrid-postgres \\
            -l /var/lib/hybrid-postgres/server.log -w start \\
            -o '-c config_file=/var/lib/hybrid-postgres/fleet.conf'
          {POSTGRES}/psql -h 127.0.0.1 -U postgres -d postgres -Atc 'select 1'
      """), timeout=180)
      ${lib.optionalString separateDatabase ''
        database_addresses = native.succeed(
            f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
            "-c 'SELECT inet_client_addr(), inet_server_addr()'"
        ).strip().split("|")
        assert len(database_addresses) == 2, database_addresses
        assert database_addresses[0] != database_addresses[1], database_addresses
        native.succeed("test ! -d /var/lib/hybrid-postgres")
        print("hybrid separate PostgreSQL TCP addresses:", database_addresses)
      ''}
      native.succeed(textwrap.dedent("""
          install -d -m 0700 /run/hybrid-bootstrap-credentials
          install -m 0600 ${databaseUrl}/value /run/hybrid-bootstrap-credentials/database-url
          HUB_DATABASE_URL_FILE=/run/hybrid-bootstrap-credentials/database-url \\
            ${pkgs.aos-hub}/bin/aos-hub --root /var/lib/aos-hub init \\
            --root-email fleet-root@example.test \\
            --root-password fleet-root-password
      """), timeout=180)

    ''
    + (
      if externalDirect
      then
        # python
        ''
          direct_tools = {
              "fleetCutoffMonotonic": FLEET_CUTOFF_MONOTONIC,
              "nativeSourcePath": "${pkgs.aos-hub.src}",
              "python": "${pkgs.python3}/bin/python3", "node": "${pkgs.nodejs}/bin/node",
              "runner": "${workerRunner}/value", "miniflare": "${pkgs.miniflare}",
              "workerd": "${pkgs.workerd-source}/bin/workerd", "curl": CURL,
              "nginx": "${pkgs.nginx}/bin/nginx", "socat": "${pkgs.socat}/bin/socat",
              "ociNamespaceObserver": "${managedFixtureModules}/_hub-oci-sdk-namespace.py",
              "ociAnchor": "${managedFixtureModules}/_hub-oci-sdk-anchor.py",
              "ociInstaller": "${managedFixtureModules}/_hub-oci-sdk-install.py",
              "managedDnsJsonEndpoint": "https://localhost:4644/.aos/dns-json-unavailable",
              "separateDatabase": ${
            if separateDatabase
            then "True"
            else "False"
          },
              "leaseScaleSources": {
                  "setup": {"path": "${managedFixtureModules}/_hub-direct-issuer-scale-setup.py",
                      "sha256": "${builtins.hashFile "sha256" ./_hub-direct-issuer-scale-setup.py}"},
                  "workload": {"path": "${managedFixtureModules}/_hub-direct-issuer-scale-workload.py",
                      "sha256": "${builtins.hashFile "sha256" ./_hub-direct-issuer-scale-workload.py}"},
                  "collector": {"path": "${managedFixtureModules}/_hub-direct-issuer-scale.py",
                      "sha256": "${builtins.hashFile "sha256" ./_hub-direct-issuer-scale.py}"},
                  "process": {"path": "${managedFixtureModules}/_hub-direct-issuer-scale-process.py",
                      "sha256": "${builtins.hashFile "sha256" ./_hub-direct-issuer-scale-process.py}"},
                  "runtime": {"path": "${managedFixtureModules}/_hub-direct-issuer-scale-runtime.py",
                      "sha256": "${builtins.hashFile "sha256" ./_hub-direct-issuer-scale-runtime.py}"},
                  "joins": {"path": "${managedFixtureModules}/_hub-direct-issuer-scale-joins.py",
                      "sha256": "${builtins.hashFile "sha256" ./_hub-direct-issuer-scale-joins.py}"},
              },
              "leaseScaleReplyCodec": {"path": "${leaseScaleReplyCodec}/bin/lease_scale_observe",
                  "sha256": hashlib.sha256(Path("${leaseScaleReplyCodec}/bin/lease_scale_observe").read_bytes()).hexdigest(),
                  "sourceDigest": "${leaseScaleReplyCodec.passthru.nativeSourceDigest}"},
              "leaseScaleCertificateFile": "${serverCertificate}/value",
              "leaseScaleCertificateSha256": "${builtins.hashFile "sha256" ../fixtures/hub-hybrid-fleet-server.crt}",
              "commonSourceStorePath": ${
            if runtimeSource == null
            then "None"
            else builtins.toJSON (toString runtimeSource)
          },
              "externalOciSetup": "${managedFixtureModules}/_hub-external-oci-setup.py",
              "externalInventoryResume": "${managedFixtureModules}/_hub-external-inventory-resume.py",
              "externalCopyIsolation": "${managedFixtureModules}/_hub-external-copy-isolation.cjs",
              "externalMirrorInstaller": "${managedFixtureModules}/_hub-external-mirror-install.cjs",
              "externalCopyClosedLoss": "${managedFixtureModules}/_hub-external-copy-closed-loss.mjs",
              "externalCopyLifetime": "${managedFixtureModules}/_hub-external-copy-lifetime.py",
              "externalCopyCases": external_copy_cases,
              "externalCopyPartialInstallation": copy_partial_hold,
              "externalWorkflowAccounting": "${managedFixtureModules}/_hub-external-workflow-accounting.py",
              "managedContainerProducer": "${managedFixtureModules}/_hub-managed-container.py",
              "documentedPackage": {"storePath": "${pkgs.aos-hub}", "version": "${pkgs.aos-hub.version}",
                  "baseLib": "${containerFixture.config.aos.config.evalAtBoot.baseLib}"},
              "publicDocumentCacheObserver": "${managedFixtureModules}/_hub-worker-cache-observer.cjs",
              "readParityModule": "${managedFixtureModules}/_hub-direct-read-parity.py",
              "readIndexModule": "${managedFixtureModules}/_hub-index-parity.py",
              "readWindowModule": "${managedFixtureModules}/_hub-direct-read-window.py",
              "managedCleanupNativeHelper": "${managedCleanupNativeHelper}/bin/aos-hub-managed-cleanup-contract",
              "managedCleanupNativeHelperProvenance": "${managedCleanupHelperProvenance}/provenance.json",
              "verificationObservationHelper": "${verificationObservationHelper}/bin/aos-hub-worker-verification-observation",
              "verificationObservationHelperProvenance": "${verificationObservationHelperProvenance}/provenance.json",
              "consoleAssetInputs": [
                  "${pkgs.aos-hub.src}/crates/aos-hub-core/src/web/static_assets/style.css",
                  "${pkgs.aos-hub.src}/crates/aos-hub-core/src/web/static_assets/app.js",
                  "${pkgs.aos-hub.src}/crates/aos-hub-core/src/web/static_assets/theme.js",
                  "${pkgs.aos-hub-console-dist}/hub-console.js",
                  "${pkgs.aos-hub-console-dist}/hub-console_bg.wasm",
                  "${pkgs.aos-hub-console-dist}/hub-console.css"],
              "managedGcHelper": "${managedFixtureModules}/_hub-managed-gc.py",
              "managedGcCollector": "${managedFixtureModules}/_hub-managed-gc-observer.py",
              "managedGcSql": "${managedFixtureModules}/_hub-managed-gc-sql.py",
              "managedGcObserver": "${managedFixtureModules}/_hub-managed-gc-runner-observer.cjs",
              "managedCleanupInstaller": "${managedFixtureModules}/_hub-managed-cleanup-install.cjs",
              "managedCleanupLossListener": "${managedFixtureModules}/_hub-managed-cleanup-loss.py",
              "managedCleanupRuntime": "${managedFixtureModules}/_hub-managed-cleanup-runtime.py",
              "managedCleanupAccounting": "${managedFixtureModules}/_hub-managed-cleanup-accounting.py",
              "managedWorkflowAccounting": "${managedFixtureModules}/_hub-managed-workflow-accounting.py",
              "managedCleanupSql": "${managedFixtureModules}/_hub-managed-cleanup-sql.py",
              "storageCodecSourceSha256": "${builtins.hashString "sha256" (builtins.concatStringsSep "" (map (name: builtins.readFile (runtimeSource + ("/tests/fleet/storage-body-codec/src/" + name))) ["main.rs" "files.rs" "classify.rs" "storage_work.rs" "ingress.rs" "controls.rs" "copy_request.rs" "copy_closed.rs" "mirror.rs"]))}",
              "storageCodecExecutable": {"path": "${storageBodyCodec}/bin/aos-storage-body-codec",
                  "sha256": hashlib.sha256(Path("${storageBodyCodec}/bin/aos-storage-body-codec").read_bytes()).hexdigest()},
              "managedIngressObservationSources": {
                  "nativeHandlerSourceSha256": "${builtins.hashString "sha256" ((builtins.readFile (pkgs.aos-hub.src + "/crates/aos-hub/src/server.rs")) + (builtins.readFile (pkgs.aos-hub.src + "/crates/aos-hub/src/server/hybrid_observation.rs")))}",
                  "checkedContextSourceSha256": "${builtins.hashFile "sha256" (pkgs.aos-hub.src + "/crates/aos-hub-core/src/hybrid_ingress/observation.rs")}"},
              "ociProfileController": "${managedFixtureModules}/_hub-oci-profile-mismatch.py",
              "ociProfileProcess": "${managedFixtureModules}/_hub-oci-profile-process.py",
              "ociProfileListener": "${managedFixtureModules}/_hub-oci-profile-mismatch-listener.mjs",
              "curlBin": "${pkgs.curl}/bin/curl",
              "providerHoldListener": "${managedFixtureModules}/_hub-direct-provider-response-hold.mjs",
              "providerHoldInstallation": provider_hold,
              "staleIndexController": "${managedFixtureModules}/_hub-direct-stale-index.py",
              "staleIndexListener": "${managedFixtureModules}/_hub-direct-stale-index-listener.mjs",
              "staleIndexProcess": "${managedFixtureModules}/_hub-direct-stale-index-process.py",
              "staleIndexHold": "${managedFixtureModules}/_hub-direct-stale-placement-hold.mjs",
              "stalePlacementHelper": "${managedFixtureModules}/_hub-direct-stale-placement.py",
              "managedNativeObservationProxyTemplate": {"path": "${managedNativeObservationProxyTemplate}/value",
                  "sha256": hashlib.sha256(Path("${managedNativeObservationProxyTemplate}/value").read_bytes()).hexdigest()},
              "managedWorkerObservationProxyTemplate": {"path": "${managedWorkerObservationProxyTemplate}/value",
                  "sha256": hashlib.sha256(Path("${managedWorkerObservationProxyTemplate}/value").read_bytes()).hexdigest()},
              "nativeObservationProxyConfiguration": "${nativeObservationProxyConfig}/value",
              "workerObservationProxyConfiguration": "${workerObservationProxyConfig}/value",
              "externalOciNativeProxyTemplate": {"path": "${externalOciNativeProxyTemplate}/value",
                  "sha256": hashlib.sha256(Path("${externalOciNativeProxyTemplate}/value").read_bytes()).hexdigest()},
              "externalOciWorkerProxyTemplate": {"path": "${externalOciWorkerProxyTemplate}/value",
                  "sha256": hashlib.sha256(Path("${externalOciWorkerProxyTemplate}/value").read_bytes()).hexdigest()},
              "managedNativeObservationProxyTemplate": {"path": "${managedNativeObservationProxyTemplate}/value",
                  "sha256": hashlib.sha256(Path("${managedNativeObservationProxyTemplate}/value").read_bytes()).hexdigest()},
              "managedWorkerObservationProxyTemplate": {"path": "${managedWorkerObservationProxyTemplate}/value",
                  "sha256": hashlib.sha256(Path("${managedWorkerObservationProxyTemplate}/value").read_bytes()).hexdigest()},
              "nixStore": "${pkgs.nix}/bin/nix-store", "nixBin": "${pkgs.nix}/bin",
              "readRevisionFixture": ${builtins.toJSON {
                source = toString alternateRevision.source;
                distribution = toString alternateRevision.distribution;
                inherit (alternateRevision) purpose sourceDigest scriptVersion features;
              }},
              "workerSourcePath": "${workerDist.src}", "workerDistribution": "${workerDist}",
              "wasm": "${workerDist}/index.wasm", "shim": "${workerDist}/shim.mjs",
              "nativeSqlProjectionCollector": "${managedFixtureModules}/_hub-native-sql-projection.py",
              "processSampler": "${processSampler}/value", "installationObserver": "${installationObserver}/value",
              "namespaceObserver": "${namespaceObserver}/value", "queueObserver": "${queueObserver}/value",
              "acceptanceInstaller": "${acceptanceInstaller}/value", "qualificationDriver": "${qualificationDriver}/value",
              "providerConformance": "${pkgs.aos-hub}/bin/aos-hub-provider-conformance",
              "authorityBootstrap": "${pkgs.aos-hub}/bin/aos-hub-authority-bootstrap",
              "authority": "${pkgs.aos-hub}/bin/aos-hub-authority", "hub": "${pkgs.aos-hub}/bin/aos-hub",
              "reviewer": "${pkgs.aos-hub}/bin/aos-hub-direct-review", "postgres": POSTGRES,
              "chroot": "${pkgs.coreutils}/bin/chroot",
              "aos": AOS, "apr": APR, "git": "${pkgs.git}/bin/git", "opensshBin": "${pkgs.openssh}/bin",
              "aosStorePath": "${pkgs.aos}", "containerPublicationInputs": "${containerPublicationInputs}",
              "openssl": "${pkgs.openssl}/bin/openssl", "helperStorePath": "${fixture.helperV1}",
              "deploymentId": "fleet-hybrid-v1", "workerUrl": "https://aos.andyl.org",
              "nativeOriginUrl": "https://aos.staging.andyl.org", "garage": GARAGE,
              "s3Ca": "${s3PublicTrust}/value",
              "s3PublicTrust": "${s3PublicTrust}/value",
              "issuerCertificate": "${serverCertificate}/value", "issuerPrivateKey": "${serverPrivateKey}/value",
              "issuerAuthorityPrivateKey": "/run/credentials/@system/hybrid-fleet-private-key",
              "issuerCertificateHost": "localhost", "fleetCaPem": ${builtins.toJSON caCertificate},
              "nativeDatabaseUrlFile": "/run/hybrid-bootstrap-credentials/database-url",
              "nativeDatabaseHost": DATABASE_HOST,
              "nativeStorageWorkKeyFile": "/run/credentials/@system/hybrid-fleet-storage-key",
              "nativeIngressKeyFile": "/run/credentials/@system/hybrid-fleet-ingress-key",
              "sharedControlInterpreter": "${pkgs.glibc}/lib/ld-linux-x86-64.so.2",
              "sharedControlRuntimeRoots": ["${pkgs.glibc}", "${pkgs.openssl}", "${pkgs.sqlite}"],
              "parityTools": {
                  "coreutils": "${pkgs.coreutils}/bin", "jq": "${pkgs.jq}/bin/jq",
                  "sqlite": "${pkgs.sqlite}/bin/sqlite3", "tar": "${pkgs.tar}/bin/tar",
                  "postgres_host": DATABASE_HOST,
                  "worker_runner": "${workerRunner}/value",
                  "worker_main": "${pkgs.aos-hub-worker-dist}/shim.mjs",
              },
              "parityFixture": {
                  "certificate": "${serverCertificate}/value", "private_key": "${serverPrivateKey}/value",
                  "release_seed": "${releaseReceiptKey}/value", "channel_seed": "${channelReceiptKey}/value",
                  "publication_keys": "${releasePublicationKeys}/value", "qualification_keys": "${qualificationKeys}/value",
                  "route_keys": "${parityRouteKeys}/value",
              },
          }
          direct_tools["staleIndexInstallation"] = install_direct_stale_index_path(native, direct_tools)
          direct_tools["storageBoundaryInstallation"] = install_direct_storage_boundaries(native, worker, direct_tools)
          direct_producer_error = None
          try:
              run_external_direct_fleet(client, native, worker, s3, database_machine,
                  direct_tools, DATABASE_OPERATOR_HOST, "${workerOptions}/value")
          except Exception as error:
              direct_producer_error = error
              raise
          finally:
              stop_direct_provider_listeners(s3, direct_tools,
                  {"verification": provider_hold, "copy-partial": copy_partial_hold}, direct_producer_error)
        ''
      else
        import ./_hub-hybrid-legacy.nix {
          inherit channelReceiptKey containerPublicationInputs databaseUrl fixture parityRouteKeys pkgs processSampler qualificationKeys releasePublicationKeys releaseReceiptKey secretVersionManifest serverCertificate serverPrivateKey storageKey workerOptions workerRunner;
        }
    );
}
