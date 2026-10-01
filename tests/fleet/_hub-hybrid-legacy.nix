# Preserve the historical same-machine and separate-PostgreSQL qualification.
# The External direct fixture has a separate genuine operator/API entry point.
{
  channelReceiptKey,
  containerPublicationInputs,
  databaseUrl,
  fixture,
  parityRouteKeys,
  pkgs,
  processSampler,
  qualificationKeys,
  releasePublicationKeys,
  releaseReceiptKey,
  secretVersionManifest,
  serverCertificate,
  serverPrivateKey,
  storageKey,
  workerOptions,
  workerRunner,
}:
# python
''
  worker.succeed(textwrap.dedent("""
      umask 077
      install -d -m 0700 /var/lib/hybrid-worker
      cd /var/lib/hybrid-worker
      # The pinned Miniflare copies NODE_EXTRA_CA_CERTS into workerd's
      # outbound TLS policy; SSL_CERT_FILE alone does not install that root.
      NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt \\
      SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \\
        MINIFLARE_WORKERD_PATH=${pkgs.workerd-source}/bin/workerd \\
        ${pkgs.nodejs}/bin/node ${workerRunner}/value \\
        ${pkgs.miniflare} ${workerOptions}/value \\
        > /var/lib/hybrid-worker/worker.log 2>&1 < /dev/null &
      echo $! > /var/lib/hybrid-worker/worker.pid
  """), timeout=30)
  wait_worker_transport(
      worker, CURL, "${pkgs.python3}/bin/python3", EXTERNAL_DIRECT,
  )

  def worker_runtime_status():
      return worker.succeed(textwrap.dedent("""
          pid=$(cat /var/lib/hybrid-worker/worker.pid)
          if kill -0 "$pid" 2>/dev/null; then
            cat "/proc/$pid/status" | head -n 12
          else
            echo "Worker runner process $pid exited"
          fi
      """))

  def sign_storage_plan(plan):
      body = json.dumps(plan, separators=(",", ":")).encode()
      signature = hmac.new(
          b"hybrid-fleet-storage-key-with-at-least-thirty-two-bytes",
          b"aos-storage-work-v1\0" + body,
          hashlib.sha256,
      ).hexdigest()
      return body, signature

  challenge = b"aos-storage-capabilities-v1"
  challenge_signature = hmac.new(
      b"hybrid-fleet-storage-key-with-at-least-thirty-two-bytes",
      b"aos-storage-work-v1\0" + challenge,
      hashlib.sha256,
  ).hexdigest()
  capabilities = json.loads(client.succeed(
      f"{CURL} -fsS -X POST "
      f"-H 'x-aos-storage-work-signature: {challenge_signature}' "
      f"--data-binary {shlex.quote(challenge.decode())} "
      "https://aos.andyl.org/_internal/storage/v1/capabilities",
      timeout=60,
  ))
  assert capabilities["deployment_id"] == "fleet-hybrid-v1", capabilities
  duplicate_signature_status = client.succeed(
      f"{CURL} -sS -o /dev/null -w '%{{http_code}}' -X POST "
      f"-H 'x-aos-storage-work-signature: {challenge_signature}' "
      f"-H 'x-aos-storage-work-signature: {challenge_signature}' "
      f"--data-binary {shlex.quote(challenge.decode())} "
      "https://aos.andyl.org/_internal/storage/v1/capabilities",
      timeout=60,
  ).strip()
  assert duplicate_signature_status == "401", duplicate_signature_status

  def post_binding_control(control):
      control_body, control_signature = sign_storage_plan(control)
      status = client.succeed(
          f"{CURL} -sS -o /tmp/hybrid-binding-control.response -w '%{{http_code}}' "
          "-X POST -H 'content-type: application/json' "
          f"-H 'x-aos-storage-work-signature: {control_signature}' "
          f"--data-binary {shlex.quote(control_body.decode())} "
          "https://aos.andyl.org/_internal/storage/v1/bindings",
          timeout=60,
      ).strip()
      return status, client.succeed("cat /tmp/hybrid-binding-control.response")

  unsigned_binding_status = client.succeed(
      f"{CURL} -sS -o /dev/null -w '%{{http_code}}' -X POST "
      "-H 'content-type: application/json' --data '{}' "
      "https://aos.andyl.org/_internal/storage/v1/bindings",
      timeout=60,
  ).strip()
  assert unsigned_binding_status == "401", unsigned_binding_status

  key_info = s3.succeed(f"{GARAGE} key info --show-secret fleet-s3-key")
  access_key = re.search(r"Key ID:\s*(\S+)", key_info)
  secret_key = re.search(r"Secret key:\s*(\S+)", key_info)
  assert access_key and secret_key, "Garage did not return test key material"
  binding_secret = f"{access_key.group(1)}:{secret_key.group(1)}:garage".encode()
  native.succeed(
      "umask 077; "
      f"printf '%s' {shlex.quote(binding_secret.decode())} "
      "> /var/lib/aos-hub/fleet-s3-secret; "
      "chown aos-hub:aos-hub /var/lib/aos-hub/fleet-s3-secret"
  )
  s3_object = b"fleet external S3 object inspected beside storage"
  client.succeed(
      f"{CURL} -fsS --aws-sigv4 'aws:amz:garage:s3' "
      f"-u {shlex.quote(access_key.group(1) + ':' + secret_key.group(1))} "
      "-X PUT -H 'content-type: application/octet-stream' "
      f"--data-binary {shlex.quote(s3_object.decode())} "
      "https://s3.fleet.test/fleet-s3/tenant/registry/exists",
      timeout=60,
  )
  metadata_path = "releases/fleet-metadata"
  client.succeed(
      f"{CURL} -fsS --aws-sigv4 'aws:amz:garage:s3' "
      f"-u {shlex.quote(access_key.group(1) + ':' + secret_key.group(1))} "
      "-X PUT -H 'content-type: application/octet-stream' "
      f"--data-binary {shlex.quote(s3_object.decode())} "
      f"https://s3.fleet.test/fleet-s3/tenant/registry/{metadata_path}",
      timeout=60,
  )
  git_content = b"fleet S3 Git projection"
  git_plain = b"blob " + str(len(git_content)).encode() + b"\0" + git_content
  git_oid = hashlib.sha256(git_plain).hexdigest()
  git_loose = zlib.compress(git_plain)
  client.succeed(
      f"printf '%s' {shlex.quote(base64.b64encode(git_loose).decode())} | "
      "${pkgs.coreutils}/bin/base64 -d > /tmp/hybrid-git-loose"
  )
  client.succeed(
      f"{CURL} -fsS --aws-sigv4 'aws:amz:garage:s3' "
      f"-u {shlex.quote(access_key.group(1) + ':' + secret_key.group(1))} "
      "-X PUT -H 'content-type: application/octet-stream' "
      "--data-binary @/tmp/hybrid-git-loose "
      f"https://s3.fleet.test/fleet-s3/tenant/registry/objects/{git_oid[:2]}/{git_oid[2:]}",
      timeout=60,
  )
  binding_issued_at = int(time.time())
  binding_snapshot = {
      "version": 1,
      "deployment_id": "fleet-hybrid-v1",
      "binding_id": 98765,
      "binding_resource_version": 1,
      "binding_stable_id": "fleet-external-binding-1",
      "binding_kind": "s3",
      "object_bucket": "fleet-s3",
      "object_prefix": "tenant",
      "endpoint_scheme": "https",
      "endpoint_host_kind": "dns",
      "endpoint_host_bytes": list(b"s3.fleet.test"),
      "endpoint_port": 443,
      "signing_region": "garage",
      "access_mode": "private",
      "credentials": [
          {
              "purpose": "delete",
              "generation": 1,
              "secret_version_ref": "secret://fleet/external/delete/v1",
              "fingerprint": hashlib.sha256(binding_secret).hexdigest(),
          },
          {
              "purpose": "list",
              "generation": 1,
              "secret_version_ref": "secret://fleet/external/list/v1",
              "fingerprint": hashlib.sha256(binding_secret).hexdigest(),
          },
          {
              "purpose": "read",
              "generation": 1,
              "secret_version_ref": "secret://fleet/external/read/v1",
              "fingerprint": hashlib.sha256(binding_secret).hexdigest(),
          },
          {
              "purpose": "write",
              "generation": 1,
              "secret_version_ref": "secret://fleet/external/write/v1",
              "fingerprint": hashlib.sha256(binding_secret).hexdigest(),
          },
      ],
      "issued_at": binding_issued_at,
      "expires_at": binding_issued_at + 300,
  }
  publish_binding = {
      "kind": "publish",
      "publication": {
          "snapshot": binding_snapshot,
          "materials": [
              {
                  "selector": {"purpose": "delete", "generation": 1},
                  "value_base64": base64.b64encode(binding_secret).decode(),
              },
              {
                  "selector": {"purpose": "list", "generation": 1},
                  "value_base64": base64.b64encode(binding_secret).decode(),
              },
              {
                  "selector": {"purpose": "read", "generation": 1},
                  "value_base64": base64.b64encode(binding_secret).decode(),
              },
              {
                  "selector": {"purpose": "write", "generation": 1},
                  "value_base64": base64.b64encode(binding_secret).decode(),
              },
          ],
      },
  }
  publish_status, publish_response = post_binding_control(publish_binding)
  assert publish_status == "200", (publish_status, publish_response)
  published_revision = json.loads(publish_response)["revision"]
  assert len(published_revision) == 64, published_revision

  def external_binding_plan(revision, operation, plan_id):
      issued_at = int(time.time())
      credential_purposes = {
          "list_page": ("list",),
          "put_metadata": ("write",),
          "put_probe": ("write",),
          "delete_probe": ("delete",),
          "create_multipart": ("write",),
          "complete_multipart": ("read", "write"),
          "abort_multipart": ("write",),
      }.get(operation["kind"], ("read",))
      external_plan = {
          "version": 1,
          "plan_id": plan_id,
          "deployment_id": "fleet-hybrid-v1",
          "issued_at": issued_at,
          "expires_at": issued_at + 30,
          "placement_id": 1,
          "placement_resource_version": 1,
          "binding_id": 98765,
          "binding_resource_version": 1,
          "binding_kind": "s3",
          "binding_snapshot_revision": revision,
          "credential_references": [
              {"purpose": purpose, "generation": 1}
              for purpose in credential_purposes
          ],
          "placement_prefix": "registry",
          "operation": operation,
      }
      plan_body, plan_signature = sign_storage_plan(external_plan)
      status = client.succeed(
          f"{CURL} -sS -o /tmp/hybrid-external-plan.response -w '%{{http_code}}' -X POST "
          "-H 'content-type: application/json' "
          f"-H 'x-aos-storage-work-signature: {plan_signature}' "
          f"--data-binary {shlex.quote(plan_body.decode())} "
          "https://aos.andyl.org/_internal/storage/v1/execute",
          timeout=60,
      ).strip()
      return status, client.succeed("cat /tmp/hybrid-external-plan.response")

  head_operation = {"kind": "head", "path": "exists"}
  head_status, head_response = external_binding_plan(
      published_revision, head_operation, "f" * 32
  )
  if head_status != "200":
      print("external S3 HEAD Worker diagnostics:", worker.succeed(
          "${pkgs.coreutils}/bin/tail -n 80 /var/lib/hybrid-worker/worker.log"
      ))
  assert head_status == "200", (head_status, head_response)
  head_result = json.loads(head_response)
  assert head_result["outcome"]["kind"] == "head", head_result
  assert head_result["outcome"]["object"]["key"] == "registry/exists", head_result
  assert head_result["outcome"]["object"]["size"] == len(s3_object), head_result
  assert head_result["source_bytes"] == 0, head_result
  absent_status, absent_response = external_binding_plan(
      published_revision, {"kind": "head", "path": "absent"}, "e" * 32
  )
  assert absent_status == "200", (absent_status, absent_response)
  assert json.loads(absent_response)["outcome"]["kind"] == "not_found"
  hash_status, hash_response = external_binding_plan(
      published_revision,
      {
          "kind": "inspect_sha256",
          "path": "exists",
          "expected_sha256": hashlib.sha256(s3_object).hexdigest(),
          "max_source_bytes": 1024,
      },
      "d" * 32,
  )
  assert hash_status == "200", (hash_status, hash_response)
  hash_result = json.loads(hash_response)
  assert hash_result["outcome"]["kind"] == "sha256_evidence", hash_result
  assert hash_result["outcome"]["sha256"] == hashlib.sha256(s3_object).hexdigest()
  assert hash_result["source_bytes"] == len(s3_object), hash_result
  metadata_status, metadata_response = external_binding_plan(
      published_revision,
      {"kind": "inspect_metadata", "path": metadata_path},
      "b" * 32,
  )
  assert metadata_status == "200", (metadata_status, metadata_response)
  metadata_result = json.loads(metadata_response)
  assert metadata_result["outcome"]["kind"] == "metadata", metadata_result
  assert base64.b64decode(metadata_result["outcome"]["content_base64"]) == s3_object
  assert metadata_result["source_bytes"] == len(s3_object), metadata_result
  list_status, list_response = external_binding_plan(
      published_revision,
      {"kind": "list_page", "prefix": "releases/", "cursor": None, "limit": 10},
      "6" * 32,
  )
  assert list_status == "200", (list_status, list_response)
  list_result = json.loads(list_response)
  assert list_result["outcome"]["kind"] == "list_page", list_result
  assert list_result["outcome"]["cursor"] is None, list_result
  assert list_result["outcome"]["objects"] == [{
      "key": "registry/" + metadata_path,
      "size": len(s3_object),
      "etag": metadata_result["outcome"]["source"]["etag"],
  }], list_result

  large_metadata_size = 128 * 1024
  client.succeed(
      f"${pkgs.coreutils}/bin/head -c {large_metadata_size} /dev/zero "
      "> /tmp/hybrid-large-metadata"
  )
  large_metadata_paths = ["releases/fleet-large-a", "releases/fleet-large-b"]
  for path in large_metadata_paths:
      client.succeed(
          f"{CURL} -fsS --aws-sigv4 'aws:amz:garage:s3' "
          f"-u {shlex.quote(access_key.group(1) + ':' + secret_key.group(1))} "
          "-X PUT -H 'content-type: application/octet-stream' "
          "--data-binary @/tmp/hybrid-large-metadata "
          f"https://s3.fleet.test/fleet-s3/tenant/registry/{path}",
          timeout=60,
      )
  metadata_batch_paths = [
      "releases/aaa-absent", *large_metadata_paths, metadata_path,
      "releases/zzz-absent",
  ]
  assert metadata_batch_paths == sorted(metadata_batch_paths)
  metadata_cursor = 0
  metadata_observations = []
  metadata_pages = 0
  while True:
      metadata_pages += 1
      batch_status, batch_response = external_binding_plan(
          published_revision,
          {"kind": "inspect_metadata_objects", "paths": metadata_batch_paths, "cursor": metadata_cursor},
          f"{9000 + metadata_pages:032x}",
      )
      assert batch_status == "200", (batch_status, batch_response)
      assert len(batch_response.encode()) <= 256 * 1024, len(batch_response)
      batch_result = json.loads(batch_response)
      assert batch_result["outcome"]["kind"] == "metadata_objects", batch_result
      page = batch_result["outcome"]["page"]
      assert page["objects"], page
      next_position = metadata_cursor + len(page["objects"])
      assert [obj["path"] for obj in page["objects"]] == metadata_batch_paths[metadata_cursor:next_position]
      metadata_observations.extend(page["objects"])
      if page["next_cursor"] is None:
          assert next_position == len(metadata_batch_paths), page
          break
      assert page["next_cursor"] == next_position > metadata_cursor, page
      metadata_cursor = next_position
  assert metadata_pages > 1, metadata_pages
  assert len(metadata_observations) == len(metadata_batch_paths), metadata_observations
  for obj in metadata_observations:
      if obj["path"].endswith("-absent"):
          assert obj["document"] is None, obj
          continue
      document = obj["document"]
      expected = bytes(large_metadata_size) if obj["path"] in large_metadata_paths else s3_object
      assert base64.b64decode(document["content_base64"]) == expected, obj["path"]
      assert document["source"]["key"] == "registry/" + obj["path"], obj["path"]
  print("hybrid external S3 metadata batches preserve maximum documents and absence:", metadata_pages, "pages")

  narinfo_path = "0" * 32 + ".narinfo"
  narinfo_bytes = b"fleet narinfo written beside external S3"
  narinfo_status, narinfo_response = external_binding_plan(
      published_revision,
      {
          "kind": "put_metadata",
          "path": narinfo_path,
          "content_base64": base64.b64encode(narinfo_bytes).decode(),
          "sha256": hashlib.sha256(narinfo_bytes).hexdigest(),
      },
      "51" * 16,
  )
  assert narinfo_status == "200", (narinfo_status, narinfo_response)
  assert json.loads(narinfo_response)["outcome"]["kind"] == "metadata_written"
  narinfo_read_status, narinfo_read_response = external_binding_plan(
      published_revision,
      {"kind": "inspect_metadata", "path": narinfo_path},
      "52" * 16,
  )
  assert narinfo_read_status == "200", (narinfo_read_status, narinfo_read_response)
  assert base64.b64decode(
      json.loads(narinfo_read_response)["outcome"]["content_base64"]
  ) == narinfo_bytes
  probe_path = ".aos-internal/conditional-delete-probes/12345-67890"
  put_probe_status, put_probe_response = external_binding_plan(
      published_revision,
      {
          "kind": "put_probe",
          "path": probe_path,
          "content_base64": base64.b64encode(b"probe").decode(),
      },
      "53" * 16,
  )
  assert put_probe_status == "200", (put_probe_status, put_probe_response)
  assert json.loads(put_probe_response)["outcome"]["kind"] == "probe_acknowledged"
  probe_head_status, probe_head_response = external_binding_plan(
      published_revision,
      {"kind": "head", "path": probe_path},
      "54" * 16,
  )
  assert probe_head_status == "200", (probe_head_status, probe_head_response)
  assert json.loads(probe_head_response)["outcome"]["object"]["size"] == 5
  delete_probe_status, delete_probe_response = external_binding_plan(
      published_revision,
      {"kind": "delete_probe", "path": probe_path},
      "55" * 16,
  )
  assert delete_probe_status == "200", (delete_probe_status, delete_probe_response)
  assert json.loads(delete_probe_response)["outcome"]["kind"] == "probe_acknowledged"
  absent_probe_status, absent_probe_response = external_binding_plan(
      published_revision,
      {"kind": "head", "path": probe_path},
      "56" * 16,
  )
  assert absent_probe_status == "200", (absent_probe_status, absent_probe_response)
  assert json.loads(absent_probe_response)["outcome"]["kind"] == "not_found"
  multipart_path = "multipart/fleet-recovery-probe.bin"
  create_status, create_response = external_binding_plan(
      published_revision,
      {"kind": "create_multipart", "path": multipart_path},
      "57" * 16,
  )
  assert create_status == "200", (create_status, create_response)
  upload_id = json.loads(create_response)["outcome"]["upload_id"]
  abort_status, abort_response = external_binding_plan(
      published_revision,
      {"kind": "abort_multipart", "path": multipart_path, "upload_id": upload_id},
      "58" * 16,
  )
  assert abort_status == "200", (abort_status, abort_response)
  assert json.loads(abort_response)["outcome"] == {
      "kind": "multipart_aborted", "outcome": "aborted",
  }, abort_response

  complete_path = "multipart/fleet-complete-probe.bin"
  complete_size = 8 * 1024 * 1024
  complete_create_status, complete_create_response = external_binding_plan(
      published_revision,
      {"kind": "create_multipart", "path": complete_path},
      "59" * 16,
  )
  assert complete_create_status == "200", (complete_create_status, complete_create_response)
  complete_upload_id = json.loads(complete_create_response)["outcome"]["upload_id"]
  encoded_upload_id = urllib.parse.quote(complete_upload_id, safe="")
  client.succeed(
      f"${pkgs.coreutils}/bin/head -c {complete_size} /dev/zero "
      "> /tmp/hybrid-external-multipart-part"
  )
  part_url = (
      f"https://s3.fleet.test/fleet-s3/tenant/registry/{complete_path}"
      f"?partNumber=1&uploadId={encoded_upload_id}"
  )
  part_headers = client.succeed(
      f"{CURL} -fsS --aws-sigv4 'aws:amz:garage:s3' "
      f"-u {shlex.quote(access_key.group(1) + ':' + secret_key.group(1))} "
      "-X PUT -D - -o /dev/null "
      f"--data-binary @/tmp/hybrid-external-multipart-part {shlex.quote(part_url)}",
      timeout=60,
  )
  part_etag = re.search(r"(?im)^etag:\s*(\S+)", part_headers)
  assert part_etag is not None, part_headers
  complete_status, complete_response = external_binding_plan(
      published_revision,
      {
          "kind": "complete_multipart", "path": complete_path,
          "upload_id": complete_upload_id,
          "parts": [{"part_number": 1, "etag": part_etag.group(1)}],
      },
      "5a" * 16,
  )
  assert complete_status == "200", (complete_status, complete_response)
  completed_object = json.loads(complete_response)["outcome"]["object"]
  assert completed_object["key"] == f"registry/{complete_path}", completed_object
  assert completed_object["size"] == complete_size, completed_object
  print("hybrid external S3 large multipart create, abort, and complete: passed")

  # A provider outage must fail the signed work request, then allow a new
  # plan to recover once the same binding becomes reachable again.
  s3.succeed(
      "${pkgs.nginx}/bin/nginx -s stop -c /var/lib/hybrid-s3/nginx.conf "
      "-p /var/lib/hybrid-s3/"
  )
  s3.wait_until_succeeds(
      "test ! -e /var/lib/hybrid-s3/nginx.pid", timeout=30
  )
  unavailable_status, _ = external_binding_plan(
      published_revision, head_operation, "5b" * 16
  )
  assert int(unavailable_status) >= 500, unavailable_status
  s3.succeed(
      "${pkgs.nginx}/bin/nginx -c /var/lib/hybrid-s3/nginx.conf "
      "-p /var/lib/hybrid-s3/ -g 'daemon off;' "
      "> /var/lib/hybrid-s3/nginx.log 2>&1 < /dev/null & "
      "echo $! > /var/lib/hybrid-s3/nginx-process.pid"
  )
  client.wait_until_succeeds(
      f"{CURL} -sS -o /dev/null -w '%{{http_code}}' "
      "https://s3.fleet.test/fleet-s3/absent | "
      f"{GREP} -Eq '^(403|404)$'",
      timeout=60,
  )
  recovered_status, recovered_response = external_binding_plan(
      published_revision, head_operation, "5c" * 16
  )
  assert recovered_status == "200", (recovered_status, recovered_response)
  assert json.loads(recovered_response)["outcome"]["kind"] == "head"
  print("hybrid external S3 outage and signed-work recovery: passed")
  git_status, git_response = external_binding_plan(
      published_revision,
      {"kind": "inspect_git_object", "oid": git_oid},
      "a" * 32,
  )
  assert git_status == "200", (git_status, git_response)
  git_result = json.loads(git_response)
  assert git_result["outcome"]["kind"] == "git_object", git_result
  assert git_result["outcome"]["oid"] == git_oid, git_result
  assert git_result["outcome"]["object_kind"] == "blob", git_result
  assert base64.b64decode(git_result["outcome"]["content_base64"]) == git_content
  assert git_result["source_bytes"] == len(git_loose), git_result
  batch_status, batch_response = external_binding_plan(
      published_revision,
      {"kind": "inspect_git_objects", "oids": [git_oid]},
      "9" * 32,
  )
  assert batch_status == "200", (batch_status, batch_response)
  batch_result = json.loads(batch_response)
  assert batch_result["outcome"]["kind"] == "git_objects", batch_result
  assert len(batch_result["outcome"]["objects"]) == 1, batch_result
  assert batch_result["outcome"]["objects"][0]["oid"] == git_oid
  oci_bytes = b"fleet S3 OCI range inspected and hashed beside storage"
  oci_path = "oci/blobs/sha256/" + hashlib.sha256(oci_bytes).hexdigest()
  client.succeed(
      f"{CURL} -fsS --aws-sigv4 'aws:amz:garage:s3' "
      f"-u {shlex.quote(access_key.group(1) + ':' + secret_key.group(1))} "
      "-X PUT -H 'content-type: application/octet-stream' "
      f"--data-binary {shlex.quote(oci_bytes.decode())} "
      f"https://s3.fleet.test/fleet-s3/tenant/registry/{oci_path}",
      timeout=60,
  )
  range_status, range_response = external_binding_plan(
      published_revision,
      {
          "kind": "inspect_oci_range",
          "path": oci_path,
          "start": 6,
          "end": 11,
      },
      "8" * 32,
  )
  assert range_status == "200", (range_status, range_response)
  range_result = json.loads(range_response)
  assert range_result["outcome"]["kind"] == "oci_range", range_result
  assert base64.b64decode(range_result["outcome"]["content_base64"]) == oci_bytes[6:12]
  assert range_result["source_bytes"] == 6, range_result
  initial_sha256_state = {
      "version": 1,
      "words": [
          0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
      ],
      "total_bytes": 0,
      "tail_hex": "",
  }
  hash_range_status, hash_range_response = external_binding_plan(
      published_revision,
      {
          "kind": "hash_oci_range",
          "path": oci_path,
          "start": 0,
          "end": len(oci_bytes) - 1,
          "total": len(oci_bytes),
          "strong_etag": range_result["outcome"]["source"]["etag"],
          "sha256_state": initial_sha256_state,
      },
      "7" * 32,
  )
  assert hash_range_status == "200", (hash_range_status, hash_range_response)
  hash_range_result = json.loads(hash_range_response)
  assert hash_range_result["outcome"]["kind"] == "oci_range_hashed", hash_range_result
  assert hash_range_result["outcome"]["sha256_state"]["total_bytes"] == len(oci_bytes)
  assert hash_range_result["source_bytes"] == len(oci_bytes), hash_range_result
  revoke_issued_at = max(binding_issued_at + 1, int(time.time()))
  revoke_binding = {
      "kind": "revoke",
      "deployment_id": "fleet-hybrid-v1",
      "binding_id": 98765,
      "revision": published_revision,
      "issued_at": revoke_issued_at,
      "expires_at": revoke_issued_at + 30,
  }
  revoke_status, revoke_response = post_binding_control(revoke_binding)
  assert revoke_status == "200", (revoke_status, revoke_response)
  revoked_status, _ = external_binding_plan(
      published_revision, head_operation, "c" * 32
  )
  assert revoked_status == "409", revoked_status
  replay_status, _ = post_binding_control(publish_binding)
  assert replay_status == "503", replay_status
  print("hybrid S3 reads, bounded writes, OCI ranges, binding revocation, and replay fence: passed")

  now = int(time.time())
  plan = {
      "version": 1,
      "plan_id": "0" * 32,
      "deployment_id": "fleet-hybrid-v1",
      "issued_at": now,
      "expires_at": now + 30,
      "placement_id": 1,
      "placement_resource_version": 1,
      "binding_id": 1,
      "binding_resource_version": 1,
      "binding_kind": "deployment_r2",
      "placement_prefix": "fleet-probe",
      "operation": {"kind": "head", "path": "absent-object"},
  }
  body, signature = sign_storage_plan(plan)
  command = (
      f"{CURL} -fsS -X POST "
      f"-H 'content-type: application/json' "
      f"-H 'x-aos-storage-work-signature: {signature}' "
      f"--data-binary {shlex.quote(body.decode())} "
      "https://aos.andyl.org/_internal/storage/v1/execute"
  )
  result = json.loads(client.succeed(command, timeout=60))
  assert result["outcome"]["kind"] == "not_found", result
  assert result["source_bytes"] == 0, result

  expired_plan = {
      **plan,
      "plan_id": "e" * 32,
      "issued_at": now - 61,
      "expires_at": now - 31,
  }
  expired_body, expired_signature = sign_storage_plan(expired_plan)
  expired_status = client.succeed(
      f"{CURL} -sS -o /dev/null -w '%{{http_code}}' -X POST "
      f"-H 'content-type: application/json' "
      f"-H 'x-aos-storage-work-signature: {expired_signature}' "
      f"--data-binary {shlex.quote(expired_body.decode())} "
      "https://aos.andyl.org/_internal/storage/v1/execute",
      timeout=60,
  ).strip()
  assert expired_status == "401", expired_status

  worker.wait_until_succeeds(
      f"{CURL} -sS -o /dev/null -w '%{{http_code}}' "
      "https://aos.staging.andyl.org/healthz | "
      f"{GREP} -qx 401",
      timeout=180,
  )
  client.wait_until_succeeds(
      f"{CURL} -fsS -H 'cf-connecting-ip: 192.0.2.10' https://aos.andyl.org/healthz",
      timeout=180,
  )
  client.succeed(
      f"test \"$({CURL} -fsS -H 'cf-connecting-ip: 192.0.2.10' https://aos.andyl.org/.well-known/aos-deployment)\" = fleet-hybrid-v1"
  )
  client.succeed(
      f"{CURL} -fsS -H 'cf-connecting-ip: 192.0.2.10' https://aos.andyl.org/login | {GREP} -q '<html'"
  )
  oci_creation_body_status = client.succeed(
      f"{CURL} -sS -o /dev/null -w '%{{http_code}}' -X POST "
      "--data-binary 'unexpected-oci-upload-body' "
      "https://aos.andyl.org/team/containers/v2/aos/blobs/uploads/",
      timeout=60,
  ).strip()
  assert oci_creation_body_status == "400", oci_creation_body_status
  client.succeed(textwrap.dedent(f"""
      set -eu
      {CURL} -sS -D /tmp/hybrid-login.headers -o /dev/null -X POST \\
        -H 'cf-connecting-ip: 192.0.2.10' \\
        --data-urlencode 'email=fleet-root@example.test' \\
        --data-urlencode 'password=fleet-root-password' \\
        https://aos.andyl.org/login/password
      cookie=$({SED} -n 's/^set-cookie: \\([^;]*\\).*/\\1/ip' /tmp/hybrid-login.headers | head -n1)
      test -n "$cookie"
      printf '%s' "$cookie" > /tmp/hybrid-cookie
      {CURL} -fsS -D /tmp/hybrid-instance.headers -H 'cf-connecting-ip: 192.0.2.10' \\
        -H "Cookie: $cookie" \\
        https://aos.andyl.org/-/instance | {GREP} -q '<html'
      ! {GREP} -qi '^x-aos-hybrid-native-ms:' /tmp/hybrid-instance.headers
  """), timeout=120)
  client.succeed(
      f"test \"$({CURL} -s -o /dev/null -w '%{{http_code}}' https://aos.staging.andyl.org/-/instance)\" = 401"
  )

  def worker_process_counters():
      return json.loads(worker.succeed(
          "${pkgs.python3}/bin/python3 ${processSampler}/value "
          "--pid-file /var/lib/hybrid-worker/worker.pid "
          "--node-exe ${pkgs.nodejs}/bin/node "
          "--workerd-exe ${pkgs.workerd-source}/bin/workerd"
      ))

  baseline_process_before = worker_process_counters()
  samples = client.succeed(textwrap.dedent(f"""
      set -eu
      cookie=$(cat /tmp/hybrid-cookie)
      attempt=0
      while test "$attempt" -lt 100; do
        {CURL} -sS -o /dev/null -w {shlex.quote(PAGE_PERF_WRITEOUT)} \\
          -H 'cf-connecting-ip: 192.0.2.10' -H "Cookie: $cookie" \\
          https://aos.andyl.org/-/instance
        attempt=$((attempt + 1))
      done
  """), timeout=180).splitlines()
  baseline_process_after = worker_process_counters()
  baseline_observations = parse_page_observations("\n".join(samples), 100)
  report_page_observations("baseline", baseline_observations)
  report_process_window("baseline", baseline_process_before, baseline_process_after)
  first_bytes = page_cumulative_values(baseline_observations, "time_starttransfer")
  baseline_tls = page_cumulative_values(baseline_observations, "time_appconnect")
  print("hybrid authenticated page TTFB seconds:", {
      "p50": statistics.median(first_bytes),
      "p95": first_bytes[94],
      "p99": first_bytes[98],
      "max": first_bytes[99],
      "tls_p95": baseline_tls[94],
  })
  assert first_bytes[94] < 0.5, first_bytes

  # Client TTFB includes time queued before the Worker handler runs.
  def page_worker_timings():
      log = worker.succeed(
          f"{GREP} 'route_class=instance_page' /var/lib/hybrid-worker/worker.log"
      )
      return [
          (int(origin), int(total), int(native))
          for origin, total, native in re.findall(
              r"elapsed_ms=(\d+) worker_elapsed_ms=(\d+) native_elapsed_ms=(\d+)", log
          )
      ]

  baseline_worker_timings = page_worker_timings()
  assert len(baseline_worker_timings) >= 100, len(baseline_worker_timings)
  baseline_origin_ms = sorted(origin for origin, _, _ in baseline_worker_timings[-100:])
  baseline_worker_ms = sorted(total for _, total, _ in baseline_worker_timings[-100:])
  baseline_native_ms = sorted(native for _, _, native in baseline_worker_timings[-100:])
  baseline_origin_transit_ms = sorted(
      max(0, origin - native)
      for origin, _, native in baseline_worker_timings[-100:]
  )
  print("hybrid baseline instance page Worker stage milliseconds:", {
      "origin_p50": statistics.median(baseline_origin_ms),
      "origin_p95": baseline_origin_ms[94],
      "origin_p99": baseline_origin_ms[98],
      "worker_p50": statistics.median(baseline_worker_ms),
      "worker_p95": baseline_worker_ms[94],
      "worker_p99": baseline_worker_ms[98],
      "native_p95": baseline_native_ms[94],
      "origin_transit_p95": baseline_origin_transit_ms[94],
  })

  def refresh_session_token():
      return json.loads(client.succeed(textwrap.dedent(f"""
          set -eu
          cookie=$(cat /tmp/hybrid-cookie)
          {CURL} -fsS -H 'cf-connecting-ip: 192.0.2.10' \\
            -H "Cookie: $cookie" https://aos.andyl.org/-/instance \\
            > /tmp/hybrid-instance.html
          csrf=$({SED} -n 's/.*name="aos-session-csrf" content="\\([^"]*\\)".*/\\1/p' \\
            /tmp/hybrid-instance.html | head -n1)
          test -n "$csrf"
          {CURL} -fsS -X POST -H 'cf-connecting-ip: 192.0.2.10' \\
            -H "Cookie: $cookie" -H 'Origin: https://aos.andyl.org' \\
            -H "x-aos-csrf: $csrf" -H 'x-aos-console-route: /-/instance' \\
            https://aos.andyl.org/-/auth/session-token
      """), timeout=120))["accessToken"]

  session_token = refresh_session_token()
  whoami = json.loads(client.succeed(
      f"{CURL} -fsS -X POST -H 'cf-connecting-ip: 192.0.2.10' "
      f"-H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' "
      f"-H 'Authorization: Bearer {session_token}' --data '{{}}' "
      "https://aos.andyl.org/aos.hub.v1.IdentityService/WhoAmI",
      timeout=60,
  ))
  assert whoami["principalRef"] == "fleet-root@example.test", whoami

  def hub_command(subcommand, mutation=""):
      return (
          f"{AOS} --json hub {subcommand} --hub https://aos.andyl.org "
          f"--token {shlex.quote(session_token)} {mutation}"
      )

  def reviewed(label, subcommand, timeout=120):
      planned = json.loads(client.succeed(hub_command(
          subcommand,
          f"--plan --idempotency-key {shlex.quote(label + '-plan')}",
      ), timeout=timeout))
      plan = planned["data"]["plan"]
      assert plan["effects"], plan
      return json.loads(client.succeed(hub_command(
          subcommand,
          " ".join([
              "--plan-id", shlex.quote(plan["plan_id"]),
              "--confirm-hash", shlex.quote(plan["confirmation_hash"]),
              "--yes --idempotency-key", shlex.quote(label + "-apply"),
          ]),
      ), timeout=timeout))

  def reviewed_control(label, plan_command, apply_command, timeout=120):
      planned = json.loads(client.succeed(hub_command(
          plan_command,
          f"--idempotency-key {shlex.quote(label + '-plan')}",
      ), timeout=timeout))
      plan = planned["data"]["plan"]
      assert plan["effects"], plan
      return json.loads(client.succeed(hub_command(
          apply_command,
          " ".join([
              "--plan-id", shlex.quote(plan["plan_id"]),
              "--confirm-hash", shlex.quote(plan["confirmation_hash"]),
              "--yes --idempotency-key", shlex.quote(label + "-apply"),
          ]),
      ), timeout=timeout))

  reviewed("hybrid-org", "org create --slug fleet --display-name 'Hybrid fleet'")
  org = json.loads(client.succeed(hub_command("org show fleet")))["data"]["organization"]
  reviewed(
      "hybrid-binding-grant",
      f"binding grant instance:default --consumer-scope {shlex.quote(org['stable_id'])}",
  )
  reviewed(
      "hybrid-public-network-grant",
      f"network-policy grant instance:public --consumer-scope {shlex.quote(org['stable_id'])}",
  )
  reviewed(
      "hybrid-cache",
      "cache create fleet/objects --name 'Hybrid objects' --visibility private",
  )
  reviewed(
      "hybrid-cache-placement",
      "placement add cache:fleet/objects primary --binding instance-default "
      "--prefix caches/fleet-objects --kind complete --desired-state active --read enabled",
  )
  placement = json.loads(client.succeed(hub_command(
      "placement show cache:fleet/objects primary"
  )))["data"]["placement"]
  reviewed(
      "hybrid-cache-scan",
      "placement scan cache:fleet/objects primary --wait --timeout 2m "
      f"--if-version {shlex.quote(placement['resource_version'])}",
      timeout=180,
  )
  placement = json.loads(client.succeed(hub_command(
      "placement show cache:fleet/objects primary"
  )))["data"]["placement"]
  reviewed(
      "hybrid-cache-promote",
      "placement promote cache:fleet/objects primary "
      f"--if-version {shlex.quote(placement['resource_version'])}",
  )

  trust_key = client.succeed(textwrap.dedent(f"""
      set -eu
      export HOME=/tmp/hybrid-apr-home
      mkdir -p "$HOME"
      {APR} keys generate initial --registry containers 2>&1 | \\
        ${pkgs.gawk}/bin/awk '/Public key:/ {{print $NF; exit}}'
  """), timeout=120).strip()
  assert trust_key.startswith("containers:Ed25519:"), trust_key
  reviewed(
      "hybrid-oci-registry",
      f"registry create --org fleet --name containers --visibility public "
      f"--trust-key {shlex.quote(trust_key)}",
  )
  reviewed(
      "hybrid-oci-placement",
      "placement add registry:fleet/containers primary --binding instance-default "
      "--prefix registries/fleet-containers --kind complete "
      "--desired-state active --read enabled",
  )
  oci_placement = json.loads(client.succeed(hub_command(
      "placement show registry:fleet/containers primary"
  )))["data"]["placement"]
  reviewed(
      "hybrid-oci-placement-scan",
      "placement scan registry:fleet/containers primary --wait --timeout 2m "
      f"--if-version {shlex.quote(oci_placement['resource_version'])}",
      timeout=180,
  )
  oci_placement = json.loads(client.succeed(hub_command(
      "placement show registry:fleet/containers primary"
  )))["data"]["placement"]
  reviewed(
      "hybrid-oci-placement-promote",
      "placement promote registry:fleet/containers primary "
      f"--if-version {shlex.quote(oci_placement['resource_version'])}",
  )
  reviewed(
      "hybrid-oci-domain",
      "domain add aos.andyl.org --org fleet",
  )
  reviewed_control(
      "hybrid-oci-controller-account",
      "org service-account create plan fleet hybrid-controller",
      "org service-account create apply",
  )
  reviewed_control(
      "hybrid-oci-controller-membership",
      "org member set-role plan --principal-kind service_account "
      "--principal fleet/hybrid-controller "
      f"--scope {shlex.quote(org['stable_id'])} "
      "--role owner --if-version absent",
      "org member set-role apply",
  )
  controller_token_response = reviewed_control(
      "hybrid-oci-controller-token",
      f"access-token issue plan {shlex.quote(org['stable_id'])} "
      "--owner service_account:fleet/hybrid-controller "
      "--permission endpoint.read --permission endpoint.manage "
      "--ttl-secs 3600 --comment 'Hybrid fleet endpoint controller'",
      "access-token issue apply",
  )
  controller_secret = controller_token_response["data"]["result"]["secret"]
  controller_token = json.loads(client.succeed(
      f"{CURL} -fsS -X POST "
      "-H 'Content-Type: application/x-www-form-urlencoded' "
      f"-H 'Authorization: Bearer {controller_secret}' "
      "--data-urlencode "
      "'grant_type=urn:aos:params:oauth:grant-type:provisioning-token' "
      "https://aos.andyl.org/oauth2/token",
      timeout=60,
  ))["access_token"]
  reviewed(
      "hybrid-oci-endpoint",
      "endpoint add https://aos.andyl.org --stable-id hybrid-oci --org fleet "
      "--network-policy instance:public@1 --ingress layer7 "
      "--listener-provider layer7 --listener-resource-id hybrid-worker "
      "--tls-provider external --certificate-ref hybrid-fleet "
      "--probe-provider native-file --probe-signer-secret-ref fleet-probe-v1 "
      "--probe-public-key ${fixture.probePublicKey}",
  )
  oci_endpoint = json.loads(client.succeed(hub_command(
      "endpoint show hybrid-oci"
  )))["data"]["endpoint"]
  oci_generation = int(oci_endpoint["desired_generation"])
  observation = {
      "stableId": "hybrid-oci",
      "expectedObservationVersion": oci_endpoint["resource_version"],
      "controllerLeaseId": "hybrid-fleet-controller",
      "controllerGeneration": 1,
      "observation": {
          "observedGeneration": oci_generation,
          "boundaryRevision": oci_endpoint["desired"]["boundary_revision"],
          "state": "healthy",
          "listenerObserved": True,
          "tlsObserved": True,
      },
  }
  client.succeed(
      f"{CURL} -fsS -X POST -H 'Content-Type: application/json' "
      "-H 'Connect-Protocol-Version: 1' "
      f"-H 'Authorization: Bearer {controller_token}' "
      f"--data {shlex.quote(json.dumps(observation))} "
      "https://aos.andyl.org/aos.hub.v1.DeliveryControllerService/ReportEndpoint",
      timeout=60,
  )
  reviewed(
      "hybrid-oci-route",
      "route add registry:fleet/containers --stable-id hybrid-oci-route "
      f"--endpoint hybrid-oci@{oci_generation} --base-path / "
      "--mode hub-proxy --placement primary --serves oci --access public",
  )
  oci_routes = json.loads(client.succeed(hub_command(
      "route list registry:fleet/containers"
  )))["data"]["routes"]
  oci_route = next(route for route in oci_routes if route["stable_id"] == "hybrid-oci-route")
  reviewed(
      "hybrid-oci-route-enable",
      "route enable hybrid-oci-route "
      f"--if-version {shlex.quote(oci_route['resource_version'])}",
  )
  client.wait_until_succeeds(
      f"{CURL} -fsS https://aos.andyl.org/v2/",
      timeout=180,
  )
  print("hybrid OCI route ready through public Worker")

  external_cache_bytes = b"fleet external S3 delivery through Worker\n"
  external_cache_path = "nar/fleet-external-probe.nar.zst"
  external_store_hash = "a" * 32
  external_narinfo_path = f"{external_store_hash}.narinfo"
  external_cache_digest = hashlib.sha256(external_cache_bytes).hexdigest()
  external_narinfo = (
      f"StorePath: /nix/store/{external_store_hash}-fleet-external-probe\n"
      f"URL: {external_cache_path}\n"
      "Compression: none\n"
      f"FileHash: sha256:{external_cache_digest}\n"
      f"FileSize: {len(external_cache_bytes)}\n"
      f"NarHash: sha256:{external_cache_digest}\n"
      f"NarSize: {len(external_cache_bytes)}\n"
  )
  client.succeed(
      f"printf '%s' {shlex.quote(base64.b64encode(external_cache_bytes).decode())} | "
      "${pkgs.coreutils}/bin/base64 -d > /tmp/hybrid-external-cache-object"
  )
  client.succeed(
      f"{CURL} -fsS --aws-sigv4 'aws:amz:garage:s3' "
      f"-u {shlex.quote(access_key.group(1) + ':' + secret_key.group(1))} "
      "-X PUT -H 'content-type: application/octet-stream' "
      "--data-binary @/tmp/hybrid-external-cache-object "
      f"https://s3.fleet.test/fleet-s3/tenant/caches/fleet-external/{external_cache_path}",
      timeout=60,
  )
  client.succeed(
      f"{CURL} -fsS --aws-sigv4 'aws:amz:garage:s3' "
      f"-u {shlex.quote(access_key.group(1) + ':' + secret_key.group(1))} "
      "-X PUT -H 'content-type: text/x-nix-narinfo' "
      f"--data-binary {shlex.quote(external_narinfo)} "
      f"https://s3.fleet.test/fleet-s3/tenant/caches/fleet-external/{external_narinfo_path}",
      timeout=60,
  )
  reviewed(
      "hybrid-external-binding",
      "binding create --org fleet --name external-s3 "
      "--stable-id fleet-external-s3 --kind s3 --bucket fleet-s3 "
      "--prefix tenant --endpoint https://s3.fleet.test "
      "--region garage --access private",
  )
  external_binding = json.loads(client.succeed(hub_command(
      "binding show fleet:external-s3"
  )))["data"]["binding"]
  external_binding_id = external_binding["stable_id"]
  for purpose in ("delete", "list", "read", "write"):
      reviewed(
          f"hybrid-external-{purpose}-credential",
          f"binding credential set {shlex.quote(external_binding_id)} "
          f"--purpose {purpose} "
          "--secret-version-ref native://fleet/external/storage/v1 "
          f"--credential-fingerprint {hashlib.sha256(binding_secret).hexdigest()}",
      )
  external_binding = json.loads(client.succeed(hub_command(
      "binding show fleet:external-s3"
  )))["data"]["binding"]
  for purpose in ("delete", "list", "read", "write"):
      validated = reviewed(
          f"hybrid-external-{purpose}-credential-validate",
          f"binding credential validate {shlex.quote(external_binding_id)} "
          f"--purpose {purpose} "
          f"--if-version {shlex.quote(external_binding['resource_version'])}",
      )
      validation_operation_id = validated["data"]["operation"]["operation_id"]
      client.succeed(hub_command(
          f"operation watch {shlex.quote(validation_operation_id)} --timeout 2m"
      ), timeout=180)

  reviewed(
      "hybrid-external-cache",
      "cache create fleet/external --name 'Hybrid external objects' --visibility public",
  )
  reviewed(
      "hybrid-external-cache-placement",
      "placement add cache:fleet/external primary "
      f"--binding {shlex.quote(external_binding_id)} "
      "--prefix caches/fleet-external --kind complete "
      "--desired-state active --read enabled",
  )
  external_placement = json.loads(client.succeed(hub_command(
      "placement show cache:fleet/external primary"
  )))["data"]["placement"]
  reviewed(
      "hybrid-external-cache-scan",
      "placement scan cache:fleet/external primary --wait --timeout 2m "
      f"--if-version {shlex.quote(external_placement['resource_version'])}",
      timeout=180,
  )
  external_placement = json.loads(client.succeed(hub_command(
      "placement show cache:fleet/external primary"
  )))["data"]["placement"]
  reviewed(
      "hybrid-external-cache-promote",
      "placement promote cache:fleet/external primary "
      f"--if-version {shlex.quote(external_placement['resource_version'])}",
  )
  reviewed(
      "hybrid-external-cache-route",
      "route add cache:fleet/external --stable-id hybrid-external-cache-route "
      f"--endpoint hybrid-oci@{oci_generation} --base-path /external-cache "
      "--mode hub-proxy --placement primary --serves cache --access public",
  )
  external_routes = json.loads(client.succeed(hub_command(
      "route list cache:fleet/external"
  )))["data"]["routes"]
  external_route = next(
      route for route in external_routes
      if route["stable_id"] == "hybrid-external-cache-route"
  )
  reviewed(
      "hybrid-external-cache-route-enable",
      "route enable hybrid-external-cache-route "
      f"--if-version {shlex.quote(external_route['resource_version'])}",
  )
  external_url = f"https://aos.andyl.org/external-cache/{external_cache_path}"
  delivered = client.wait_until_succeeds(
      f"{CURL} -fsS {external_url}", timeout=180,
  )
  assert delivered.encode() == external_cache_bytes, delivered
  ranged = client.succeed(
      f"{CURL} -fsS -H 'Range: bytes=6-13' {external_url}"
  )
  assert ranged.encode() == external_cache_bytes[6:14], ranged
  head = client.succeed(f"{CURL} -fsSI {external_url}")
  assert f"content-length: {len(external_cache_bytes)}" in head.lower(), head
  print("hybrid external S3 delivery through Native authorization and Worker streaming: passed")

  cache_size = 1024 * 1024
  cache_path = "web/fleet-probe.bin"
  cache_digest = hashlib.sha256(bytes(cache_size)).hexdigest()
  client.succeed(
      f"${pkgs.coreutils}/bin/head -c {cache_size} /dev/zero > /tmp/hybrid-cache-object"
  )
  cache_upload = json.loads(client.succeed(
      f"{CURL} -fsS -X POST -H 'cf-connecting-ip: 192.0.2.10' "
      f"-H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' "
      f"-H 'Authorization: Bearer {session_token}' "
      f"--data {shlex.quote(json.dumps({'cacheId': 'fleet/objects', 'path': cache_path, 'size': cache_size}))} "
      "https://aos.andyl.org/aos.hub.v1.BinaryCacheService/CreateCacheObjectUploads",
      timeout=60,
  ))
  assert cache_upload["uploadUrl"].startswith(
      "https://aos.andyl.org/aos.hub.v1.BinaryCacheService/UploadObject/"
  ), cache_upload
  assert cache_upload["uploadTicketId"], cache_upload
  client.succeed(
      f"{CURL} -fsS -X PUT -H 'cf-connecting-ip: 192.0.2.10' "
      f"-H 'Authorization: Bearer {session_token}' "
      f"--data-binary @/tmp/hybrid-cache-object {shlex.quote(cache_upload['uploadUrl'])}",
      timeout=120,
  )
  ticket_id = cache_upload["uploadTicketId"]
  assert ticket_id.isascii() and all(character.isalnum() or character == "-" for character in ticket_id)
  ticket_query = f"SELECT state FROM cache_write_tickets WHERE ticket_id = '{ticket_id}'"
  ticket_state = native.succeed(
      f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
      f"-c {shlex.quote(ticket_query)}"
  ).strip()
  assert ticket_state == "completed", ticket_state
  replay_status = client.succeed(
      f"{CURL} -sS -o /dev/null -w '%{{http_code}}' -X PUT "
      f"-H 'cf-connecting-ip: 192.0.2.10' "
      f"-H 'Authorization: Bearer {session_token}' "
      f"--data-binary @/tmp/hybrid-cache-object {shlex.quote(cache_upload['uploadUrl'])}",
      timeout=120,
  ).strip()
  assert replay_status == "201", replay_status
  client.succeed(
      "${pkgs.coreutils}/bin/cp /tmp/hybrid-cache-object /tmp/hybrid-cache-conflict && "
      "printf x | ${pkgs.coreutils}/bin/dd of=/tmp/hybrid-cache-conflict "
      "bs=1 count=1 conv=notrunc status=none"
  )
  conflict_status = client.succeed(
      f"{CURL} -sS -o /dev/null -w '%{{http_code}}' -X PUT "
      f"-H 'cf-connecting-ip: 192.0.2.10' "
      f"-H 'Authorization: Bearer {session_token}' "
      f"--data-binary @/tmp/hybrid-cache-conflict {shlex.quote(cache_upload['uploadUrl'])}",
      timeout=120,
  ).strip()
  assert conflict_status == "400", conflict_status

  multipart_part_size = 8 * 1024 * 1024
  multipart_final_size = 13
  multipart_size = multipart_part_size + multipart_final_size
  multipart_digest = hashlib.sha256(bytes(multipart_size)).hexdigest()
  client.succeed(
      f"${pkgs.coreutils}/bin/head -c {multipart_part_size} /dev/zero "
      "> /tmp/hybrid-cache-multipart-part-1"
  )
  client.succeed(
      f"${pkgs.coreutils}/bin/head -c {multipart_final_size} /dev/zero "
      "> /tmp/hybrid-cache-multipart-part-2"
  )
  multipart_upload = json.loads(client.succeed(
      f"{CURL} -fsS -X POST -H 'cf-connecting-ip: 192.0.2.10' "
      f"-H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' "
      f"-H 'Authorization: Bearer {session_token}' "
      f"--data {shlex.quote(json.dumps({'cacheId': 'fleet/objects', 'path': 'web/multipart.bin', 'byteSize': multipart_size, 'sha256': multipart_digest}))} "
      "https://aos.andyl.org/aos.hub.v1.BinaryCacheService/BeginCacheMultipartUpload",
      timeout=60,
  ))
  assert int(multipart_upload["partSize"]) == multipart_part_size, multipart_upload
  assert multipart_upload["partUploadUrl"].startswith(
      "https://aos.andyl.org/aos.hub.v1.BinaryCacheService/UploadPart/"
  ), multipart_upload
  multipart_parts = []
  for part_number in (1, 2):
      multipart_parts.append(json.loads(client.succeed(
          f"{CURL} -fsS -X PUT -H 'Expect: 100-continue' "
          "-H 'cf-connecting-ip: 192.0.2.10' "
          f"-H 'Authorization: Bearer {session_token}' "
          f"--data-binary @/tmp/hybrid-cache-multipart-part-{part_number} "
          f"{shlex.quote(multipart_upload['partUploadUrl'] + '/' + str(part_number))}",
          timeout=180,
      )))
  assert [part["partNumber"] for part in multipart_parts] == [1, 2], multipart_parts
  multipart_retry = json.loads(client.succeed(
      f"{CURL} -fsS -X PUT -H 'cf-connecting-ip: 192.0.2.10' "
      f"-H 'Authorization: Bearer {session_token}' "
      "--data-binary @/tmp/hybrid-cache-multipart-part-1 "
      f"{shlex.quote(multipart_upload['partUploadUrl'] + '/1')}",
      timeout=180,
  ))
  assert multipart_retry == multipart_parts[0], multipart_retry
  multipart_completion = json.loads(client.succeed(
      f"{CURL} -fsS -X POST -H 'cf-connecting-ip: 192.0.2.10' "
      f"-H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' "
      f"-H 'Authorization: Bearer {session_token}' "
      f"--data {shlex.quote(json.dumps({'uploadId': multipart_upload['uploadId'], 'parts': multipart_parts}))} "
      "https://aos.andyl.org/aos.hub.v1.BinaryCacheService/CompleteCacheMultipartUpload",
      timeout=180,
  ))
  assert multipart_completion["state"] == "completed", multipart_completion
  multipart_ticket_id = multipart_upload["uploadId"]
  assert re.fullmatch(r"[0-9a-f-]{32,36}", multipart_ticket_id), multipart_ticket_id
  multipart_state = native.succeed(
      f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
      f"-c \"SELECT state FROM cache_write_tickets "
      f"WHERE ticket_id = '{multipart_ticket_id}'\""
  ).strip()
  assert multipart_state == "completed", multipart_state

  publication_size = multipart_part_size + 13
  publication_path = "web/fleet-large.bin"
  publication_digest = hashlib.sha256(bytes(publication_size)).hexdigest()
  # Complete source evidence exceeds /tmp's memory-backed capacity.
  finalized_container = json.loads(client.succeed(textwrap.dedent(f"""
      set -euo pipefail
      export HOME=/tmp/hybrid-apr-home USER=fleet-publisher
      export PATH=${pkgs.git}/bin:${pkgs.openssh}/bin:$PATH
      key="$HOME/.config/apm/keys/containers-initial.key"
      {AOS} --json --progress off --color never container prepare-signature \\
        ${containerPublicationInputs} --output /tmp/hybrid-container-signature.pae
      ${pkgs.openssh}/bin/ssh-keygen -Y sign -f "$key" \\
        -n aos-container-signature-dsse-v1 /tmp/hybrid-container-signature.pae
      {AOS} --json --progress off --color never container finalize-signature \\
        ${containerPublicationInputs} --signer {shlex.quote(trust_key)} \\
        --signature /tmp/hybrid-container-signature.pae.sig \\
        --output /var/lib/hybrid-container-final
  """), timeout=900).splitlines()[-1])
  assert finalized_container["verification"] == "verified-external-sshsig", finalized_container
  assert finalized_container["release_identity"] == "1.0.0", finalized_container
  session_token = refresh_session_token()
  client.succeed("install -d -m 0700 /var/lib/hybrid-container-upload-state")
  container_stage = json.loads(client.succeed(
      "XDG_CACHE_HOME=/var/lib/hybrid-container-upload-state "
      f"{AOS} --json --progress off --color never container publish aos "
      "aos.andyl.org/aos:parity "
      f"--release {shlex.quote(finalized_container['release'])} "
      f"--release-layout {shlex.quote(finalized_container['layout'])} "
      f"--signature-input {shlex.quote(finalized_container['signature_input'])} "
      "--registry fleet/containers --registry-origin https://aos.andyl.org "
      f"--registry-token {shlex.quote(session_token)} "
      "--idempotency-key hybrid-container-parity-stage --stage-only",
      timeout=900,
  ))
  assert container_stage["state"] == "staged" and not container_stage["tag_updated"], container_stage
  assert container_stage["index_digest"] == finalized_container["index_digest"], container_stage
  client.succeed(textwrap.dedent(f"""
      set -eu
      export HOME=/tmp/hybrid-apr-home USER=fleet-publisher
      export PATH=${pkgs.git}/bin:${pkgs.nix}/bin:$PATH
      export NIX_REMOTE=""
      export NIX_CONF_DIR="$HOME/.config/nix"
      mkdir -p "$NIX_CONF_DIR"
      printf 'experimental-features = nix-command\\nsandbox = false\\nbuild-users-group =\\n' \\
        > "$NIX_CONF_DIR/nix.conf"
      git config --global user.name 'Hybrid Fleet Publisher'
      git config --global user.email 'fleet-publisher@example.test'
      key="$HOME/.config/apm/keys/containers-initial.key"
      {APR} create containers --trust-key {shlex.quote(trust_key)} \\
        --trust-key-id initial --key "$key"
      registry="$HOME/.local/share/apm/registries/containers"
      mkdir -p "$HOME/.config/apm/registries.d"
      printf '[registry]\\nname = "containers"\\nurl = "file://%s"\\n\\n[registry.signing_keys]\\ninitial = "%s"\\n' \\
        "$registry" "$key" > "$HOME/.config/apm/registries.d/containers.toml"
      # The signed image identity requires its exact package/version in
      # the signed release tree, alongside the changing helper package.
      {APR} publish ${pkgs.aos} --registry containers --name aos --version 0.1.0 \\
        --description 'AOS command-line package for the base-image release' \\
        --license Apache-2.0 --maintainer fleet-publisher@example.test --key-id initial
      {APR} release 1.0.0 --registry containers \\
        --container-release /var/lib/hybrid-container-final/container-release.json \\
        --container-signature-input /var/lib/hybrid-container-final/signature-input.json \\
        --store-path ${fixture.helperV1} --name hub-helper \\
        --description 'Hybrid release indexing fixture' --license MIT \\
        --maintainer fleet-publisher@example.test --key-id initial \\
        --cache-url https://aos.andyl.org/fleet/containers \\
        --upload-url file:///tmp/hybrid-publication-surface
      # The next release has no container; remove its predecessor's sidecar
      # through a real commit rather than carrying a mismatched identity.
      git -C "$registry" rm containers/v1/index.json
      git -C "$registry" commit -m 'Remove the previous release container sidecar'
      {APR} release 2.0.0 --registry containers \\
        --store-path ${fixture.helperV2} --name hub-helper --previous 1.0.0 \\
        --description 'Hybrid release indexing fixture' --license MIT \\
        --maintainer fleet-publisher@example.test --key-id initial \\
        --channel stable --init-channel \\
        --cache-url https://aos.andyl.org/fleet/containers \\
        --upload-url file:///tmp/hybrid-publication-surface
      {APR} verify --registry containers
      mkdir -p /tmp/hybrid-publication-surface/web
      ${pkgs.coreutils}/bin/head -c {publication_size} /dev/zero \\
        > /tmp/hybrid-publication-surface/{publication_path}
  """), timeout=600)
  # Authoring and uploading the signed channel can each exceed a browser
  # token lifetime. Resume only the exact publication after JWT expiry.
  session_token = refresh_session_token()
  print("hybrid signed two-release and stable-channel publication starting")
  try:
      publication, session_token = publish_signed_surface(
          client,
          lambda token: (
              f"{AOS} --json hub registry publish upload fleet/containers "
              "--root /tmp/hybrid-publication-surface --hub https://aos.andyl.org "
              f"--token {shlex.quote(token)}"
          ),
          session_token,
          refresh_session_token,
      )
  except Exception:
      print("hybrid Worker runtime log after publication upload failure:", worker.succeed(
          "tail -n 100 /var/lib/hybrid-worker/worker.log"
      ))
      print("Native errors after publication upload failure:", native.succeed(
          "journalctl -u aos-hub.service -p warning --no-pager -n 60"
      ))
      raise
  assert publication["state"] == "ready", publication
  large_object = next(
      obj for obj in publication["objects"] if obj["path"] == publication_path
  )
  assert large_object["verified"], large_object
  assert int(large_object["byte_size"]) == publication_size, large_object
  assert large_object["sha256"] == publication_digest, large_object
  publication_multipart = native.succeed(
      f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
      f"-c \"SELECT state FROM registry_publication_multipart_uploads "
      f"WHERE publication_id = '{publication['publication_id']}' "
      f"AND surface_object_id = {large_object['object_id']}\""
  ).strip()
  assert publication_multipart == "completed", publication_multipart
  session_token = refresh_session_token()
  try:
      client.wait_until_succeeds(
          hub_command("registry show fleet/containers")
          + " | ${pkgs.jq}/bin/jq -e '.data.registry.index_state == \"fresh\"' "
          "> /dev/null",
          timeout=180,
      )
  except Exception:
      print("Worker runner status after index freshness failure:", worker_runtime_status())
      print("Worker runtime log after index freshness failure:", worker.succeed(
          "tail -n 100 /var/lib/hybrid-worker/worker.log"
      ))
      print("Native index errors after freshness failure:", native.succeed(
          "journalctl -u aos-hub.service -p warning --no-pager -n 60"
      ))
      print("Authoritative registry index status:", native.succeed(
          f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
          "-c \"SELECT state, error FROM registry_index index "
          "JOIN registries registry ON registry.id = index.registry_id "
          "WHERE registry.slug = 'fleet/containers'\""
      ))
      raise

  # The operator command must use the same Worker storage adapter as the
  # service. Copy fixtures into private files owned by the workload user,
  # matching the secure credential loader rather than bypassing it.
  native.succeed(textwrap.dedent(f"""
      set -eu
      ${pkgs.coreutils}/bin/install -d -m 0700 -o 802 -g 802 /var/lib/aos-hub/fleet-index
      ${pkgs.coreutils}/bin/install -m 0600 -o 802 -g 802 \\
        ${databaseUrl}/value /var/lib/aos-hub/fleet-index/database-url
      ${pkgs.coreutils}/bin/install -m 0600 -o 802 -g 802 \\
        ${storageKey}/value /var/lib/aos-hub/fleet-index/storage-key
      ${pkgs.coreutils}/bin/install -m 0600 -o 802 -g 802 \\
        ${secretVersionManifest}/value /var/lib/aos-hub/fleet-index/secret-version-manifest
  """))
  operator_index_logs = []

  def run_hybrid_operator_index(slug):
      output = native.succeed(
          "HUB_DATABASE_URL_FILE=/var/lib/aos-hub/fleet-index/database-url "
          "HUB_TOPOLOGY=hybrid HUB_DEPLOYMENT_ID=fleet-hybrid-v1 "
          "HUB_HYBRID_WORKER_URL=https://aos.andyl.org "
          "HUB_STORAGE_WORK_KEY_FILE=/var/lib/aos-hub/fleet-index/storage-key "
          "HUB_SECRET_VERSION_MANIFEST_FILE=/var/lib/aos-hub/fleet-index/secret-version-manifest "
          f"{CHROOT} ${pkgs.aos-hub}/bin/aos-hub index {shlex.quote(slug)} 2>&1",
          timeout=180,
      )
      operator_index_logs.append("\n".join(
          line for line in output.splitlines()
          if any(marker in line for marker in (
              "hybrid storage boundary", "registry release index phase completed",
              "registry index run completed",
          ))
      ))
      return output

  operator_index = run_hybrid_operator_index("fleet/containers")
  operator_index_summary = re.search(
      r"fleet/containers: \d+ packages, 2 releases, \d+ channels @ [0-9a-f]+",
      operator_index,
  )
  assert operator_index_summary, operator_index
  print("standalone hybrid operator indexing:", operator_index_summary.group(0))

  # The same signed tags produced by APR must reach the authoritative DB.
  # Comparing exact object identities catches successful but partial walks.
  release_query = (
      "SELECT release.semver, release.tag_oid, release.signer "
      "FROM releases release JOIN registries registry "
      "ON registry.id = release.registry_id "
      "WHERE registry.slug = 'fleet/containers' ORDER BY release.semver"
  )
  indexed_releases = native.succeed(
      f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At -F '|' "
      f"-c {shlex.quote(release_query)}"
  ).strip().splitlines()
  assert len(indexed_releases) == 2, indexed_releases
  for version, row in zip(("1.0.0", "2.0.0"), indexed_releases):
      expected_tag = client.succeed(
          f"${pkgs.git}/bin/git -C /tmp/hybrid-apr-home/.local/share/apm/registries/containers "
          f"rev-parse refs/tags/{version}"
      ).strip()
      semver, tag_oid, signer = row.split("|")
      assert (semver, tag_oid) == (version, expected_tag), row
      assert signer, row
  indexed_package = json.loads(client.succeed(hub_command(
      "registry package show fleet/containers hub-helper"
  )))["data"]
  assert all(version in json.dumps(indexed_package) for version in ("1.0.0", "2.0.0")), indexed_package
  channel_query = (
      "SELECT floor.floor FROM channel_floors floor "
      "JOIN registries registry ON registry.id = floor.registry_id "
      "WHERE registry.slug = 'fleet/containers' AND floor.channel = 'stable'"
  )
  channel_floor = native.succeed(
      f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
      f"-c {shlex.quote(channel_query)}"
  ).strip()
  assert channel_floor == "2.0.0", channel_floor

  # Container indexes must revalidate exact placement evidence on refresh.
  # Exercise the channel-only optimization with a separately signed graph
  # whose immutable releases contain package metadata and no image roots.
  metadata_trust_key = client.succeed(textwrap.dedent(f"""
      set -eu
      export HOME=/tmp/hybrid-apr-home
      {APR} keys generate initial --registry metadata 2>&1 | \\
        ${pkgs.gawk}/bin/awk '/Public key:/ {{print $NF; exit}}'
  """), timeout=120).strip()
  assert metadata_trust_key.startswith("metadata:Ed25519:"), metadata_trust_key
  session_token = refresh_session_token()
  reviewed(
      "hybrid-metadata-registry",
      "registry create --org fleet --name metadata --visibility public "
      f"--trust-key {shlex.quote(metadata_trust_key)}",
  )
  reviewed(
      "hybrid-metadata-placement",
      "placement add registry:fleet/metadata primary --binding instance-default "
      "--prefix registries/fleet-metadata --kind complete "
      "--desired-state active --read enabled",
  )
  metadata_placement = json.loads(client.succeed(hub_command(
      "placement show registry:fleet/metadata primary"
  )))["data"]["placement"]
  reviewed(
      "hybrid-metadata-placement-scan",
      "placement scan registry:fleet/metadata primary --wait --timeout 2m "
      f"--if-version {shlex.quote(metadata_placement['resource_version'])}",
      timeout=180,
  )
  metadata_placement = json.loads(client.succeed(hub_command(
      "placement show registry:fleet/metadata primary"
  )))["data"]["placement"]
  reviewed(
      "hybrid-metadata-placement-promote",
      "placement promote registry:fleet/metadata primary "
      f"--if-version {shlex.quote(metadata_placement['resource_version'])}",
  )
  client.succeed(textwrap.dedent(f"""
      set -eu
      export HOME=/tmp/hybrid-apr-home
      export PATH=${pkgs.git}/bin:${pkgs.openssh}/bin:$PATH
      key="$HOME/.config/apm/keys/metadata-initial.key"
      {APR} create metadata --trust-key {shlex.quote(metadata_trust_key)} \\
        --trust-key-id initial --key "$key"
      registry="$HOME/.local/share/apm/registries/metadata"
      printf '[registry]\\nname = "metadata"\\nurl = "file://%s"\\n\\n[registry.signing_keys]\\ninitial = "%s"\\n' \\
        "$registry" "$key" > "$HOME/.config/apm/registries.d/metadata.toml"
      {APR} release 1.0.0 --registry metadata \\
        --store-path ${fixture.helperV1} --name hub-helper \\
        --description 'Hybrid metadata-only indexing fixture' --license MIT \\
        --maintainer fleet-publisher@example.test --key-id initial \\
        --channel stable --init-channel \\
        --cache-url https://aos.andyl.org/fleet/objects \\
        --upload-url file:///tmp/hybrid-metadata-surface
      {APR} verify --registry metadata
  """), timeout=180)
  session_token = refresh_session_token()
  metadata_publication, session_token = publish_signed_surface(
      client,
      lambda token: (
          f"{AOS} --json hub registry publish upload fleet/metadata "
          "--root /tmp/hybrid-metadata-surface --hub https://aos.andyl.org "
          f"--token {shlex.quote(token)}"
      ),
      session_token,
      refresh_session_token,
  )
  assert metadata_publication["state"] == "ready", metadata_publication
  # Publication explicitly schedules the cold walk. Wait for its commit
  # before invoking an unchanged refresh rather than depending on a timer.
  client.wait_until_succeeds(
      hub_command("registry show fleet/metadata")
      + " | ${pkgs.jq}/bin/jq -e '.data.registry.index_state == \"fresh\"' > /dev/null",
      timeout=180,
  )
  metadata_registry_id = int(native.succeed(
      f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
      "-c \"SELECT id FROM registries WHERE slug = 'fleet/metadata'\""
  ).strip())
  container_registry_id = int(native.succeed(
      f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
      "-c \"SELECT id FROM registries WHERE slug = 'fleet/containers'\""
  ).strip())
  metadata_image_count = int(native.succeed(
      f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
      "-c \"SELECT (SELECT COUNT(*) FROM registry_system_images "
      f"WHERE registry_id = {metadata_registry_id}) + "
      "(SELECT COUNT(*) FROM oci_release_roots "
      f"WHERE registry_id = {metadata_registry_id})\""
  ).strip())
  assert metadata_image_count == 0, metadata_image_count
  metadata_identity_query = (
      f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
      "-c \"SELECT last_indexed_commit, refs_digest FROM registry_index "
      f"WHERE registry_id = {metadata_registry_id}\""
  )
  metadata_identity = native.succeed(metadata_identity_query).strip()
  assert re.fullmatch(r"[0-9a-f]{64}\|[0-9a-f]{64}", metadata_identity), metadata_identity
  metadata_index = run_hybrid_operator_index("fleet/metadata")
  assert re.search(r"fleet/metadata: 1 packages, 1 releases, 1 channels @ ", metadata_index), metadata_index
  assert native.succeed(metadata_identity_query).strip() == metadata_identity
  print("hybrid metadata-only unchanged operator indexing: passed")

  parallel_size = 4 * 1024 * 1024
  client.succeed(
      f"${pkgs.coreutils}/bin/head -c {parallel_size} "
      "/tmp/hybrid-cache-multipart-part-1 > /tmp/hybrid-parallel-object"
  )
  parallel_paths = [f"web/parallel-{index}.bin" for index in range(8)]
  parallel_admission_status = client.succeed(
      f"{CURL} -sS -o /tmp/hybrid-parallel-admission.response "
      "-w '%{http_code}' -X POST -H 'cf-connecting-ip: 192.0.2.10' "
      f"-H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' "
      f"-H 'Authorization: Bearer {session_token}' "
      f"--data {shlex.quote(json.dumps({'cacheId': 'fleet/objects', 'paths': parallel_paths, 'sizes': [parallel_size] * len(parallel_paths)}))} "
      "https://aos.andyl.org/aos.hub.v1.BinaryCacheService/CreateCacheObjectUploads",
      timeout=60,
  ).strip()
  if parallel_admission_status != "200":
      print("hybrid parallel cache admission status:", parallel_admission_status)
      print("hybrid parallel cache admission response:", client.succeed(
          "cat /tmp/hybrid-parallel-admission.response"
      ))
      print("Native errors during parallel cache admission:", native.succeed(
          "journalctl -u aos-hub.service -p warning --no-pager -n 60"
      ))
      print("Building cache inventories during admission:", native.succeed(
          f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
          "-c \"SELECT COUNT(*) FROM cache_inventory_generations inventory "
          "JOIN binary_caches cache ON cache.id = inventory.cache_id "
          "WHERE cache.slug = 'fleet/objects' AND inventory.state = 'building'\""
      ).strip())
  assert parallel_admission_status == "200", parallel_admission_status
  parallel_uploads = json.loads(client.succeed(
      "cat /tmp/hybrid-parallel-admission.response"
  ))["uploads"]
  assert [upload["path"] for upload in parallel_uploads] == parallel_paths, parallel_uploads
  assert all(upload["uploadUrl"] and upload["uploadTicketId"] for upload in parallel_uploads), parallel_uploads

  loaded_process_before = worker_process_counters()
  parallel_commands = ["set -eu", 'pids=""']
  for index, upload in enumerate(parallel_uploads):
      parallel_commands.append(
          f"{CURL} -fsS -X PUT -H 'cf-connecting-ip: 192.0.2.10' "
          f"-H 'Authorization: Bearer {session_token}' "
          f"-o /tmp/hybrid-parallel-{index}.response "
          f"-w '%{{time_total}}\\n' "
          f"--data-binary @/tmp/hybrid-parallel-object "
          f"{shlex.quote(upload['uploadUrl'])} "
          f"> /tmp/hybrid-parallel-{index}.time &"
      )
      parallel_commands.append('pids="$pids $!"')
  native_page_commands = []
  for index in range(25):
      issued_at = int(time.time())
      assertion = {
          "version": 1,
          "deployment_id": "fleet-hybrid-v1",
          "issued_at": issued_at,
          "expires_at": issued_at + 30,
          "request_id": f"fleet-native-load-{issued_at}-{index}",
          "scheme": "https",
          "authority": "aos.andyl.org",
          "method": "GET",
          "path_and_query": "/-/instance",
          "body_sha256": hashlib.sha256(b"").hexdigest(),
          "client_ip": "192.0.2.10",
      }
      payload = base64.urlsafe_b64encode(
          json.dumps(assertion, separators=(",", ":")).encode()
      ).rstrip(b"=").decode()
      signature = base64.urlsafe_b64encode(hmac.new(
          b"hybrid-fleet-ingress-key-with-at-least-thirty-two-bytes",
          payload.encode(), hashlib.sha256,
      ).digest()).rstrip(b"=").decode()
      compact = payload + "." + signature
      native_page_commands.append(
          f"{CURL} -sS -o /dev/null -w {shlex.quote(PAGE_PERF_WRITEOUT)} "
          f"-H 'x-aos-hybrid-ingress: {compact}' -H \"Cookie: $cookie\" "
          "https://aos.staging.andyl.org/-/instance"
      )

  parallel_commands.extend([
      'cookie=$(cat /tmp/hybrid-cookie)',
      "(\n" + "\n".join(native_page_commands) + "\n) > /tmp/hybrid-native-pages &",
      'native_pid=$!',
      'attempt=0',
      'while test "$attempt" -lt 25; do',
      f"{CURL} -sS -o /dev/null -w {shlex.quote(PAGE_PERF_WRITEOUT)} "
      "-H 'cf-connecting-ip: 192.0.2.10' -H \"Cookie: $cookie\" "
      "https://aos.andyl.org/-/instance >> /tmp/hybrid-parallel-pages",
      'attempt=$((attempt + 1))',
      'done',
  ])
  parallel_commands.append('wait "$native_pid"')
  parallel_commands.append('for pid in $pids; do wait "$pid"; done')
  try:
      client.succeed("\n".join(parallel_commands), timeout=180)
  except Exception:
      upload_errors = {}
      for index in range(len(parallel_uploads)):
          response = client.succeed(
              f"cat /tmp/hybrid-parallel-{index}.response 2>/dev/null || true"
          ).strip()
          if not response:
              continue
          try:
              error = json.loads(response).get("error")
          except (ValueError, AttributeError):
              error = response[:160]
          if error:
              detail = str(error)[:300]
              if any(secret in detail.lower() for secret in (
                  "bearer", "token", "secret", "signature", "cookie", "password"
              )):
                  detail = "[sensitive error redacted]"
              upload_errors[index] = detail
      print("hybrid parallel upload errors:", upload_errors)
      print("hybrid Native warnings after parallel upload failure:", native.succeed(
          "journalctl -u aos-hub.service -p warning --no-pager -n 80"
      ))
      print("hybrid Worker memory after parallel upload failure:", worker.succeed(
          "cat /proc/meminfo | head -n 8"
      ))
      print("hybrid Worker process after parallel upload failure:",
            worker_runtime_status())
      print("hybrid Worker logs after parallel upload failure:", worker.succeed(
          "tail -n 120 /var/lib/hybrid-worker/worker.log"
      ))
      print("hybrid Worker kernel logs after parallel upload failure:", worker.succeed(
          "journalctl -k --no-pager -n 60"
      ))
      raise

  loaded_samples = client.succeed("cat /tmp/hybrid-parallel-pages").splitlines()
  loaded_process_after = worker_process_counters()
  loaded_observations = parse_page_observations("\n".join(loaded_samples), 25)
  report_page_observations("loaded", loaded_observations)
  report_process_window(
      "loaded including all eight uploads", loaded_process_before, loaded_process_after
  )
  loaded_first_bytes = page_cumulative_values(loaded_observations, "time_starttransfer")
  loaded_tls = page_cumulative_values(loaded_observations, "time_appconnect")
  print("hybrid authenticated page TTFB during parallel uploads:", {
      "p50": statistics.median(loaded_first_bytes),
      "p95": loaded_first_bytes[23],
      "max": loaded_first_bytes[24],
      "p95_ratio": loaded_first_bytes[23] / first_bytes[94],
      "tls_p95": loaded_tls[23],
  })
  native_samples = client.succeed("cat /tmp/hybrid-native-pages").splitlines()
  native_observations = parse_page_observations("\n".join(native_samples), 25)
  report_page_observations("direct Native loaded", native_observations)
  native_first_bytes = page_cumulative_values(native_observations, "time_starttransfer")
  print("hybrid direct Native page TTFB during parallel uploads:", {
      "p50": statistics.median(native_first_bytes),
      "p95": native_first_bytes[23],
      "max": native_first_bytes[24],
  })

  # Local Wrangler serializes R2 emulation and Worker execution in one VM.
  # The signed direct probe isolates Native and PostgreSQL responsiveness.
  assert native_first_bytes[23] < 0.5, native_first_bytes
  loaded_page_gate = (
      loaded_first_bytes[23] < 0.5
      and loaded_first_bytes[23] <= first_bytes[94] * 1.25
  )
  loaded_worker_timings = page_worker_timings()
  assert len(loaded_worker_timings) >= len(baseline_worker_timings) + 25
  loaded_origin_ms = sorted(origin for origin, _, _ in loaded_worker_timings[-25:])
  loaded_worker_ms = sorted(total for _, total, _ in loaded_worker_timings[-25:])
  loaded_native_ms = sorted(native for _, _, native in loaded_worker_timings[-25:])
  loaded_origin_transit_ms = sorted(
      max(0, origin - native)
      for origin, _, native in loaded_worker_timings[-25:]
  )
  print("hybrid loaded instance page Worker stage milliseconds:", {
      "origin_p50": statistics.median(loaded_origin_ms),
      "origin_p95": loaded_origin_ms[23],
      "origin_max": loaded_origin_ms[24],
      "worker_p50": statistics.median(loaded_worker_ms),
      "worker_p95": loaded_worker_ms[23],
      "worker_max": loaded_worker_ms[24],
      "native_p95": loaded_native_ms[23],
      "origin_transit_p95": loaded_origin_transit_ms[23],
  })

  parallel_ticket_ids = [upload["uploadTicketId"] for upload in parallel_uploads]
  assert all(
      ticket_id.isascii()
      and all(character.isalnum() or character == "-" for character in ticket_id)
      for ticket_id in parallel_ticket_ids
  )
  ticket_list = ", ".join(f"'{ticket_id}'" for ticket_id in parallel_ticket_ids)
  parallel_query = f"SELECT COUNT(*) FROM cache_write_tickets WHERE state = 'completed' AND ticket_id IN ({ticket_list})"
  completed = int(native.succeed(
      f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
      f"-c {shlex.quote(parallel_query)}"
  ).strip())
  assert completed == len(parallel_paths), completed

  # Parallel uploads can outlast the console token used by reviewed CLI calls.
  session_token = refresh_session_token()

  reviewed(
      "hybrid-cache-replica-placement",
      "placement add cache:fleet/objects replica --binding instance-default "
      "--prefix caches/fleet-objects-replica --kind complete "
      "--desired-state active --read enabled",
  )
  replica = json.loads(client.succeed(hub_command(
      "placement show cache:fleet/objects replica"
  )))["data"]["placement"]
  reviewed(
      "hybrid-cache-replicate",
      "placement replicate cache:fleet/objects --from primary --to replica "
      "--wait --timeout 5m "
      f"--if-version {shlex.quote(replica['resource_version'])}",
      timeout=360,
  )
  replica = json.loads(client.succeed(hub_command(
      "placement show cache:fleet/objects replica"
  )))["data"]["placement"]
  assert replica["observation"]["state"] == "ready", replica
  assert replica["observation"]["completeness"] == "complete", replica

  oci_token = json.loads(client.succeed(
      f"{CURL} -fsS -H 'Authorization: Bearer {session_token}' "
      "'https://aos.andyl.org/v2/token?"
      "service=aos.andyl.org&scope=repository:aos:pull,push'",
      timeout=60,
  ))["token"]
  client.succeed(
      f"{CURL} -fsS -X POST -D /tmp/hybrid-oci-start.headers "
      f"-H 'Authorization: Bearer {oci_token}' -H 'Content-Length: 0' "
      "https://aos.andyl.org/v2/aos/blobs/uploads/ "
      "-o /dev/null",
      timeout=60,
  )
  location = client.succeed(
      f"{SED} -n 's/^location: *//ip' /tmp/hybrid-oci-start.headers | tr -d '\\r' | tail -n1"
  ).strip()
  assert "/blobs/uploads/" in location, location
  upload_id = location.rsplit("/", 1)[-1]
  assert re.fullmatch(r"[0-9a-f-]{32,36}", upload_id), upload_id
  upload_url = f"https://aos.andyl.org/v2/aos/blobs/uploads/{upload_id}"
  invalid_range_status = client.succeed(
      f"{CURL} -sS -o /dev/null -w '%{{http_code}}' -X PATCH "
      f"-H 'Authorization: Bearer {oci_token}' "
      "-H 'Content-Range: bytes 2-5' --data-binary 'abcd' "
      f"{shlex.quote(upload_url)}",
      timeout=60,
  ).strip()
  assert invalid_range_status == "416", invalid_range_status
  client.succeed(
      f"{CURL} -fsS -X PATCH -H 'Authorization: Bearer {oci_token}' "
      f"--data-binary @/tmp/hybrid-cache-object {shlex.quote(upload_url)} "
      "-o /dev/null",
      timeout=180,
  )
  client.succeed(
      f"{CURL} -fsS -X PUT -H 'Authorization: Bearer {oci_token}' "
      f"-H 'Content-Length: 0' "
      f"{shlex.quote(upload_url + '?digest=sha256:' + cache_digest)} -o /dev/null",
      timeout=180,
  )
  client.succeed(
      f"{CURL} -fsS -H 'Authorization: Bearer {oci_token}' "
      f"'https://aos.andyl.org/v2/aos/blobs/sha256:{cache_digest}' "
      "-o /tmp/hybrid-oci-downloaded",
      timeout=180,
  )
  downloaded_digest = client.succeed(
      "${pkgs.coreutils}/bin/sha256sum /tmp/hybrid-oci-downloaded | cut -d' ' -f1"
  ).strip()
  assert downloaded_digest == cache_digest, downloaded_digest
  upload_state = native.succeed(
      f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
      f"-c \"SELECT state || ':' || cleanup_state FROM oci_upload_sessions "
      f"WHERE id = '{upload_id}'\""
  ).strip()
  assert upload_state == "complete:complete", upload_state

  final_bytes = b"hybrid-final-oci-chunk"
  final_digest = hashlib.sha256(bytes(cache_size) + final_bytes).hexdigest()
  client.succeed(
      f"printf %s {shlex.quote(final_bytes.decode())} > /tmp/hybrid-oci-final-chunk"
  )
  client.succeed(
      f"{CURL} -fsS -X POST -D /tmp/hybrid-oci-final-start.headers "
      f"-H 'Authorization: Bearer {oci_token}' -H 'Content-Length: 0' "
      "https://aos.andyl.org/v2/aos/blobs/uploads/ "
      "-o /dev/null",
      timeout=60,
  )
  final_location = client.succeed(
      f"{SED} -n 's/^location: *//ip' /tmp/hybrid-oci-final-start.headers | tr -d '\\r' | tail -n1"
  ).strip()
  final_upload_id = final_location.rsplit("/", 1)[-1]
  assert re.fullmatch(r"[0-9a-f-]{32,36}", final_upload_id), final_upload_id
  final_upload_url = (
      f"https://aos.andyl.org/v2/aos/blobs/uploads/{final_upload_id}"
  )
  client.succeed(
      f"{CURL} -fsS -X PATCH -H 'Authorization: Bearer {oci_token}' "
      f"--data-binary @/tmp/hybrid-cache-object {shlex.quote(final_upload_url)} "
      "-o /dev/null",
      timeout=180,
  )
  client.succeed(
      f"{CURL} -fsS -X PUT -H 'Authorization: Bearer {oci_token}' "
      f"--data-binary @/tmp/hybrid-oci-final-chunk "
      f"{shlex.quote(final_upload_url + '?digest=sha256:' + final_digest)} "
      "-o /dev/null",
      timeout=180,
  )
  client.succeed(
      f"{CURL} -fsS -H 'Authorization: Bearer {oci_token}' "
      f"{shlex.quote('https://aos.andyl.org/v2/aos/blobs/sha256:' + final_digest)} "
      "-o /tmp/hybrid-oci-final-downloaded",
      timeout=180,
  )
  final_downloaded_digest = client.succeed(
      "${pkgs.coreutils}/bin/sha256sum /tmp/hybrid-oci-final-downloaded | cut -d' ' -f1"
  ).strip()
  assert final_downloaded_digest == final_digest, final_downloaded_digest
  final_upload_state = native.succeed(
      f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
      f"-c \"SELECT state || ':' || cleanup_state FROM oci_upload_sessions "
      f"WHERE id = '{final_upload_id}'\""
  ).strip()
  assert final_upload_state == "complete:complete", final_upload_state

  client.succeed(
      f"{CURL} -fsS -X POST -D /tmp/hybrid-oci-large-start.headers "
      f"-H 'Authorization: Bearer {oci_token}' -H 'Content-Length: 0' "
      "https://aos.andyl.org/v2/aos/blobs/uploads/ -o /dev/null",
      timeout=60,
  )
  large_location = client.succeed(
      f"{SED} -n 's/^location: *//ip' /tmp/hybrid-oci-large-start.headers "
      "| tr -d '\\r' | tail -n1"
  ).strip()
  large_upload_id = large_location.rsplit("/", 1)[-1]
  assert re.fullmatch(r"[0-9a-f-]{32,36}", large_upload_id), large_upload_id
  large_upload_url = f"https://aos.andyl.org/v2/aos/blobs/uploads/{large_upload_id}"
  try:
      client.succeed(
          f"{CURL} -fsS -X PATCH -H 'Authorization: Bearer {oci_token}' "
          f"--data-binary @/tmp/hybrid-publication-surface/{publication_path} "
          f"{shlex.quote(large_upload_url)} -o /dev/null",
          timeout=180,
      )
  except Exception:
      print("hybrid Worker process after large OCI part failure:",
            worker_runtime_status())
      print("hybrid Worker logs after large OCI part failure:", worker.succeed(
          "tail -n 120 /var/lib/hybrid-worker/worker.log"
      ))
      print("hybrid Native logs after large OCI part failure:", native.succeed(
          "journalctl -u aos-hub --no-pager -n 100"
      ))
      print("hybrid Worker memory after large OCI part failure:", worker.succeed(
          "cat /proc/meminfo | head -n 8"
      ))
      raise
  client.succeed(
      f"{CURL} -fsS -X PUT -H 'Authorization: Bearer {oci_token}' "
      f"-H 'Content-Length: 0' "
      f"{shlex.quote(large_upload_url + '?digest=sha256:' + publication_digest)} "
      "-o /dev/null",
      timeout=180,
  )
  client.succeed(
      f"{CURL} -fsS -H 'Authorization: Bearer {oci_token}' "
      f"{shlex.quote('https://aos.andyl.org/v2/aos/blobs/sha256:' + publication_digest)} "
      "-o /tmp/hybrid-oci-large-downloaded",
      timeout=180,
  )
  large_downloaded_digest = client.succeed(
      "${pkgs.coreutils}/bin/sha256sum /tmp/hybrid-oci-large-downloaded | cut -d' ' -f1"
  ).strip()
  assert large_downloaded_digest == publication_digest, large_downloaded_digest
  large_downloaded_size = int(client.succeed(
      "${pkgs.coreutils}/bin/stat -c %s /tmp/hybrid-oci-large-downloaded"
  ).strip())
  assert large_downloaded_size == publication_size, large_downloaded_size
  inventory_query = (
      "SELECT COUNT(*) FROM oci_provider_inventory_entries entry "
      "JOIN oci_provider_inventory_heads head "
      "ON head.generation_id = entry.generation_id "
      f"WHERE entry.object_key = 'oci/blobs/sha256/{publication_digest}' "
      f"AND entry.observed_hash = 'sha256:{publication_digest}' "
      f"AND entry.byte_size = {publication_size}"
  )
  native.wait_until_succeeds(
      f"test \"$({POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
      f"-c {shlex.quote(inventory_query)})\" = 1",
      timeout=240,
  )
  inventory_progress = json.loads(native.succeed(
      f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
      "-c \"SELECT json_build_object("
      "'pages', generation.checkpoint_ordinal, "
      "'objects', COUNT(entry.object_key), "
      "'distinctObjects', COUNT(DISTINCT entry.object_key), "
      "'observedHashes', COUNT(entry.observed_hash), "
      "'hashMismatches', SUM(CASE WHEN entry.observed_hash <> "
      "'sha256:' || SUBSTRING(entry.object_key FROM 18) THEN 1 ELSE 0 END)) "
      "FROM oci_provider_inventory_generations generation "
      "JOIN oci_provider_inventory_heads head "
      "ON head.generation_id = generation.id "
      "JOIN oci_provider_inventory_entries target "
      "ON target.generation_id = generation.id "
      "JOIN oci_provider_inventory_entries entry "
      "ON entry.generation_id = generation.id "
      f"WHERE target.object_key = 'oci/blobs/sha256/{publication_digest}' "
      "GROUP BY generation.id\""
  ).strip())
  # The collector checkpoints one canonical object per page. Sixteen is
  # its per-dispatch budget; this real image spans several dispatches.
  assert inventory_progress["objects"] > 16, inventory_progress
  assert inventory_progress["pages"] == inventory_progress["objects"], inventory_progress
  assert inventory_progress["distinctObjects"] == inventory_progress["objects"], inventory_progress
  assert inventory_progress["observedHashes"] == inventory_progress["objects"], inventory_progress
  assert inventory_progress["hashMismatches"] == 0, inventory_progress
  print("hybrid sealed OCI inventory:", inventory_progress)

  durations = [
      float(client.succeed(f"cat /tmp/hybrid-parallel-{index}.time").strip())
      for index in range(len(parallel_paths))
  ]
  print("hybrid parallel cache upload seconds:", {
      "count": len(durations),
      "p50": statistics.median(durations),
      "max": max(durations),
  })

  pool_log = native.succeed(
      f"journalctl -u aos-hub.service -o cat --no-pager | "
      f"{GREP} 'hybrid SQL pool'"
  )
  pool_samples = []
  for line in pool_log.splitlines():
      fields = {
          name: int(value)
          for name, value in re.findall(r"\b(open|idle|maximum)=(\d+)", line)
      }
      if {"open", "idle", "maximum"} <= fields.keys():
          pool_samples.append((fields["open"], fields["idle"], fields["maximum"]))
  assert pool_samples, pool_log
  assert all(0 <= idle <= opened <= maximum for opened, idle, maximum in pool_samples), pool_samples
  print("hybrid SQL pool:", {
      "maximum": max(maximum for _, _, maximum in pool_samples),
      "max_open": max(opened for opened, _, _ in pool_samples),
      "max_busy": max(opened - idle for opened, idle, _ in pool_samples),
  })

  boundary_log = native.succeed(
      f"journalctl -u aos-hub.service -o cat --no-pager | "
      f"{GREP} -E 'hybrid storage boundary|registry release index phase completed|registry index run completed'"
  )
  boundary_log += "\n" + "\n".join(operator_index_logs)
  assert "inspect_git_object" in boundary_log, boundary_log
  assert "hash_oci_range" in boundary_log, boundary_log
  assert "copy_object" in boundary_log, boundary_log
  transferred = [
      (int(response), int(source))
      for response, source in re.findall(
          r"response_bytes=(\d+) source_bytes=(\d+)", boundary_log
      )
  ]
  boundary_events = [
      dict(token.split("=", 1) for token in shlex.split(line) if "=" in token)
      for line in boundary_log.splitlines()
  ]
  outbound_plan_bytes = [
      int(event["request_bytes"]) * int(event["attempts"])
      for event in boundary_events if "request_bytes" in event
  ]
  assert len(outbound_plan_bytes) >= len(transferred), boundary_log
  print("hybrid Native-to-Worker storage boundary:", {
      "completed_calls": len(transferred),
      "offered_plan_bytes_including_retries": sum(outbound_plan_bytes),
      "inbound_result_bytes": sum(response for response, _ in transferred),
      "object_bytes_processed_at_worker": sum(source for _, source in transferred),
  })

  # Task-scoped spans prevent concurrent releases and retries from mixing
  # their counters. Registry preload/channel work remains a shared bucket.
  def empty_work_totals():
      return {
          "terminal_calls": 0,
          "attempts": 0,
          "completed_calls": 0,
          "offered_plan_bytes_including_retries": 0,
          "inbound_result_bytes": 0,
          "object_bytes_processed_at_worker": 0,
      }

  index_runs = {}
  for event in boundary_events:
      if "index_run" not in event:
          continue
      run_id = event["index_run"]
      assert re.fullmatch(r"[0-9a-f]{32}", run_id), event
      run = index_runs.setdefault(run_id, {
          "index_run": run_id,
          "registry_id": int(event["registry_id"]),
          "completed": False,
          "shared": empty_work_totals(),
          "releases": {},
      })
      assert run["registry_id"] == int(event["registry_id"]), event
      if "success" in event:
          run["completed"] = True
          run["success"] = event["success"] == "true"
      release = event.get("release")
      if release is None:
          totals = run["shared"]
      else:
          totals = run["releases"].setdefault(release, empty_work_totals())
          if "reused" in event:
              totals["phase_completed"] = True
              totals["reused"] = event["reused"] == "true"
      if "request_bytes" in event:
          attempts = int(event["attempts"])
          totals["terminal_calls"] += 1
          totals["attempts"] += attempts
          totals["offered_plan_bytes_including_retries"] += int(event["request_bytes"]) * attempts
      if "response_bytes" in event:
          totals["completed_calls"] += 1
          totals["inbound_result_bytes"] += int(event["response_bytes"])
          totals["object_bytes_processed_at_worker"] += int(event["source_bytes"])
  assert index_runs, boundary_log
  for release in ("1.0.0", "2.0.0"):
      cold_release_walks = [
          run["releases"][release]
          for run in index_runs.values()
          if run["registry_id"] == container_registry_id
          and release in run["releases"]
          and run.get("success", False)
          and run["releases"][release]["completed_calls"] > 0
      ]
      assert cold_release_walks, (release, index_runs)
  container_refreshes = [
      run for run in index_runs.values()
      if run["registry_id"] == container_registry_id
      and run.get("success", False)
      and set(run["releases"]) == {"1.0.0", "2.0.0"}
  ]
  assert len(container_refreshes) >= 2, index_runs
  assert all(
      release.get("phase_completed", False)
      and release.get("reused") is False
      and release["completed_calls"] > 0
      for run in container_refreshes for release in run["releases"].values()
  ), container_refreshes
  metadata_cold_walks = [
      run for run in index_runs.values()
      if run["registry_id"] == metadata_registry_id
      and run.get("success", False)
      and "1.0.0" in run["releases"]
      and run["releases"]["1.0.0"]["completed_calls"] > 0
      and run["releases"]["1.0.0"].get("reused") is False
  ]
  assert metadata_cold_walks, index_runs
  print("hybrid indexing work by run and release:", json.dumps(
      list(index_runs.values()), sort_keys=True
  ))
  warm_refreshes = [
      run["shared"] for run in index_runs.values()
      if run["registry_id"] == metadata_registry_id
      and run.get("success", False) and not run["releases"]
      and run["shared"]["object_bytes_processed_at_worker"] > 0
  ]
  assert warm_refreshes, index_runs
  # Two branches require eight batches each, plus HEAD and info/refs.
  assert all(refresh["completed_calls"] <= 18 for refresh in warm_refreshes), warm_refreshes
  assert all(
      refresh["offered_plan_bytes_including_retries"] < 32 * 1024
      for refresh in warm_refreshes
  ), warm_refreshes
  compact_verifications = [
      response for response, source in transferred
      if source == cache_size and response < 2048
  ]
  assert compact_verifications, transferred
  parallel_verifications = [
      response for response, source in transferred
      if source == parallel_size and response < 2048
  ]
  assert len(parallel_verifications) >= len(parallel_paths), transferred
  large_verifications = [
      response for response, source in transferred
      if source == publication_size and response < 2048
  ]
  assert large_verifications, transferred
  inventory_hashes = [
      (int(response), int(source))
      for line in boundary_log.splitlines()
      if 'operation="hash_oci_range"' in line
      for response, source in re.findall(
          r"response_bytes=(\d+) source_bytes=(\d+)", line
      )
  ]
  assert sum(source for _, source in inventory_hashes) >= publication_size, inventory_hashes
  assert all(response < 2048 for response, _ in inventory_hashes), inventory_hashes
  placement_copies = [
      (int(response), int(source))
      for line in boundary_log.splitlines()
      if 'operation="copy_object"' in line
      for response, source in re.findall(
          r"response_bytes=(\d+) source_bytes=(\d+)", line
      )
  ]
  assert sum(source for _, source in placement_copies) >= multipart_size, placement_copies
  assert all(response < 2048 for response, _ in placement_copies), placement_copies
  origin_log = worker.succeed(
      f"{GREP} 'hybrid_origin_request' /var/lib/hybrid-worker/worker.log"
  )
  origin_request_bytes = [
      int(size) for size in re.findall(r"request_bytes=(\d+)", origin_log)
  ]
  assert origin_request_bytes and max(origin_request_bytes) < 64 * 1024, origin_request_bytes

  selector = native.succeed(
      f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At -F ' ' "
      "-c \"SELECT p.id, p.resource_version, b.id, b.resource_version, p.prefix "
      "FROM surface_placements p JOIN bindings b ON b.id = p.binding_id "
      "JOIN binary_caches cache ON cache.id = p.cache_id "
      "WHERE p.name = 'primary' AND cache.slug = 'fleet/objects'\""
  ).strip().split()
  assert len(selector) == 5, selector
  now = int(time.time())
  cache_verification_plan = {
      "version": 1,
      "plan_id": "1" * 32,
      "deployment_id": "fleet-hybrid-v1",
      "issued_at": now,
      "expires_at": now + 30,
      "placement_id": int(selector[0]),
      "placement_resource_version": int(selector[1]),
      "binding_id": int(selector[2]),
      "binding_resource_version": int(selector[3]),
      "binding_kind": "deployment_r2",
      "placement_prefix": selector[4],
      "operation": {
          "kind": "inspect_sha256",
          "path": cache_path,
          "expected_sha256": cache_digest,
          "max_source_bytes": cache_size,
      },
  }
  body, signature = sign_storage_plan(cache_verification_plan)
  cache_verification_bytes = client.succeed(
      f"{CURL} -fsS -X POST -H 'content-type: application/json' "
      f"-H 'x-aos-storage-work-signature: {signature}' "
      f"--data-binary {shlex.quote(body.decode())} "
      "https://aos.andyl.org/_internal/storage/v1/execute",
      timeout=60,
  )
  assert len(cache_verification_bytes) < 2048, len(cache_verification_bytes)
  cache_verification = json.loads(cache_verification_bytes)
  assert cache_verification["outcome"]["kind"] == "sha256_evidence", cache_verification
  assert cache_verification["outcome"]["object"]["size"] == cache_size, cache_verification
  assert cache_verification["outcome"]["object"]["key"] == f"{selector[4]}/{cache_path}", cache_verification
  assert cache_verification["outcome"]["sha256"] == cache_digest, cache_verification
  assert cache_verification["source_bytes"] == cache_size, cache_verification

  probe_path = ".aos-internal/conditional-delete-probes/900-1"
  probe_sequence = 0
  def probe_work(operation):
      global probe_sequence
      probe_sequence += 1
      issued = int(time.time())
      plan = {
          **cache_verification_plan,
          "plan_id": f"{probe_sequence:032x}",
          "issued_at": issued,
          "expires_at": issued + 30,
          "operation": operation,
      }
      request_body, request_signature = sign_storage_plan(plan)
      return json.loads(client.succeed(
          f"{CURL} -fsS -X POST -H 'content-type: application/json' "
          f"-H 'x-aos-storage-work-signature: {request_signature}' "
          f"--data-binary {shlex.quote(request_body.decode())} "
          "https://aos.andyl.org/_internal/storage/v1/execute",
          timeout=60,
      ))["outcome"]

  def write_probe(contents):
      outcome = probe_work({
          "kind": "put_probe",
          "path": probe_path,
          "content_base64": base64.b64encode(contents).decode(),
      })
      assert outcome["kind"] == "probe_acknowledged", outcome
      observed = probe_work({"kind": "head", "path": probe_path})
      assert observed["kind"] == "head", observed
      return observed["object"]

  first_probe = write_probe(b"reviewed identity")
  second_probe = write_probe(b"replacement identity")
  assert first_probe["etag"] != second_probe["etag"]
  for probe in (first_probe, second_probe):
      version = probe["provider_version"]
      assert isinstance(version, str) and 0 < len(version.encode()) <= 512, probe
      assert not any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in version), probe
  assert first_probe["provider_version"] != second_probe["provider_version"]

  rejected_delete = probe_work({
      "kind": "delete_if_matches",
      "path": probe_path,
      "claim_id": "fleet-mismatched-claim",
      "expected_etag": first_probe["etag"],
      "expected_size": first_probe["size"],
      "expected_provider_version": first_probe["provider_version"],
      "expected_hash": None,
  })
  assert rejected_delete["kind"] == "delete_precondition_failed", rejected_delete
  assert probe_work({"kind": "head", "path": probe_path})["object"] == second_probe
  reviewed_delete = {
      "kind": "delete_if_matches",
      "path": probe_path,
      "claim_id": "fleet-reviewed-claim",
      "expected_etag": second_probe["etag"],
      "expected_size": second_probe["size"],
      "expected_provider_version": second_probe["provider_version"],
      "expected_hash": None,
  }
  removed = probe_work(reviewed_delete)
  assert removed == {"kind": "object_deleted", "etag": second_probe["etag"]}, removed
  later_probe = write_probe(b"later physical object")
  assert probe_work(reviewed_delete) == removed
  assert probe_work({"kind": "head", "path": probe_path})["object"] == later_probe
  cleanup = probe_work({"kind": "delete_probe", "path": probe_path})
  assert cleanup["kind"] == "probe_acknowledged", cleanup
  assert probe_work({"kind": "head", "path": probe_path})["kind"] == "not_found"

  for _ in range(90):
      capability_state = native.succeed(
          f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
          "-c \"SELECT state FROM oci_conditional_delete_capabilities "
          "WHERE binding_id = (SELECT id FROM bindings "
          "WHERE kind = 'deployment_r2')\""
      ).strip()
      if capability_state == "valid":
          break
      time.sleep(2)
  assert capability_state == "valid", capability_state

  session_token = refresh_session_token()

  reviewed(
      "hybrid-oci-retention",
      "registry container retention set fleet/containers --untagged-grace 0s "
      "--deleted-tag-history 0s --recent-manual-tag-revisions 0 "
      "--retain-referrers disabled",
  )
  retention = json.loads(client.succeed(hub_command(
      "registry container retention show fleet/containers"
  )))["data"]["policy"]
  # A retention update advances the OCI mutation epoch. GC must review a
  # provider enumeration sealed against that new epoch.
  current_inventory_query = (
      "SELECT COUNT(*) FROM oci_provider_inventory_heads head "
      "JOIN oci_provider_inventory_generations generation "
      "ON generation.id = head.generation_id "
      "JOIN surface_placements placement ON placement.id = head.placement_id "
      "JOIN surface_placement_observations observation "
      "ON observation.placement_id = placement.id "
      "JOIN bindings binding ON binding.id = placement.binding_id "
      "JOIN binding_write_state write_state ON write_state.binding_id = binding.id "
      "JOIN oci_registry_state state ON state.registry_id = head.registry_id "
      "WHERE placement.prefix = 'registries/fleet-containers' "
      "AND generation.state = 'complete' "
      "AND generation.captured_mutation_epoch = state.mutation_epoch "
      "AND generation.placement_resource_version = placement.resource_version "
      "AND generation.placement_write_spec_version = placement.write_spec_version "
      "AND generation.placement_observation_version = observation.observation_version "
      "AND generation.binding_resource_version = binding.resource_version "
      "AND generation.binding_write_revision = write_state.current_write_revision"
  )
  native.wait_until_succeeds(
      f"test \"$({POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
      f"-c {shlex.quote(current_inventory_query)})\" = 1",
      timeout=180,
  )
  gc_result = json.loads(client.succeed(hub_command(
      "registry container gc plan fleet/containers "
      f"--if-version {shlex.quote(retention['resource_version'])} "
      "--idempotency-key hybrid-oci-gc-plan"
  ), timeout=180))["data"]
  gc_plan = gc_result["plan"]
  gc_run = gc_result["run"]
  assert not gc_result.get("blockers", []), gc_result
  candidate_count = int(gc_run["candidate_object_count"])
  assert candidate_count >= 1, gc_run
  assert int(gc_run["placement_action_count"]) >= 1, gc_run
  client.succeed(hub_command(
      "registry container gc apply",
      " ".join([
          "--plan-id", shlex.quote(gc_plan["plan_id"]),
          "--confirm-hash", shlex.quote(gc_plan["confirmation_hash"]),
          "--idempotency-key hybrid-oci-gc-apply --yes",
      ]),
  ), timeout=120)
  gc_run_id = gc_run["run_id"]
  gc_status_query = (
      "SELECT state || ':' || deleted_object_count FROM oci_gc_runs "
      f"WHERE id = '{gc_run_id}'"
  )
  try:
      native.wait_until_succeeds(
          f"test \"$({POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
          f"-c {shlex.quote(gc_status_query)})\" = "
          f"'complete:{candidate_count}'",
          timeout=240,
      )
  except Exception:
      run_status_sql = (
          "SELECT state, last_error FROM oci_gc_runs "
          f"WHERE id = {repr(gc_run_id)}"
      )
      action_status_sql = (
          "SELECT state, last_error FROM oci_gc_placement_actions "
          f"WHERE run_id = {repr(gc_run_id)}"
      )
      print("hybrid OCI GC run after timeout:", native.succeed(
          f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -c "
          f"{shlex.quote(run_status_sql)}"
      ))
      print("hybrid OCI GC actions after timeout:", native.succeed(
          f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -c "
          f"{shlex.quote(action_status_sql)}"
      ))
      raise

  registry_selector = native.succeed(
      f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At -F ' ' "
      "-c \"SELECT p.id, p.resource_version, b.id, b.resource_version, p.prefix "
      "FROM surface_placements p JOIN bindings b ON b.id = p.binding_id "
      "WHERE p.name = 'primary' AND p.prefix = 'registries/fleet-containers'\""
  ).strip().split()
  assert len(registry_selector) == 5, registry_selector
  head_time = int(time.time())
  deleted_head_plan = {
      **cache_verification_plan,
      "plan_id": "7" * 32,
      "issued_at": head_time,
      "expires_at": head_time + 30,
      "placement_id": int(registry_selector[0]),
      "placement_resource_version": int(registry_selector[1]),
      "binding_id": int(registry_selector[2]),
      "binding_resource_version": int(registry_selector[3]),
      "placement_prefix": registry_selector[4],
      "operation": {
          "kind": "head",
          "path": f"oci/blobs/sha256/{publication_digest}",
      },
  }
  for attempt in range(3):
      head_time = int(time.time())
      deleted_head_plan["issued_at"] = head_time
      deleted_head_plan["expires_at"] = head_time + 30
      head_body, head_signature = sign_storage_plan(deleted_head_plan)
      try:
          deleted_head = json.loads(client.succeed(
              f"{CURL} -fsS -X POST -H 'content-type: application/json' "
              f"-H 'x-aos-storage-work-signature: {head_signature}' "
              f"--data-binary {shlex.quote(head_body.decode())} "
              "https://aos.andyl.org/_internal/storage/v1/execute",
              timeout=60,
          ))
          break
      except Exception:
          if attempt < 2:
              time.sleep(2)
              continue
          print("hybrid Worker log after OCI GC:", worker.succeed(
              "tail -n 120 /var/lib/hybrid-worker/worker.log"
          ))
          print("hybrid Worker kernel log after OCI GC:", worker.succeed(
              "journalctl -k --no-pager -n 60"
          ))
          raise
  assert deleted_head["outcome"]["kind"] == "not_found", deleted_head

  # The console token is deliberately short lived. Refresh it after the
  # long OCI phase before starting a new reviewed cache-GC workflow.
  session_token = refresh_session_token()

  # Publish a real NAR/narinfo pair so cache GC has a logical object and
  # placement evidence to delete, rather than only an orphan surface file.
  gc_store_hash = "f1gc0000000000000000000000000000"
  gc_nar_path = f"nar/{gc_store_hash}-payload.nar"
  gc_nar_bytes = b"hybrid-cache-gc-nar"
  gc_nar_digest = hashlib.sha256(gc_nar_bytes).hexdigest()
  client.succeed(
      f"printf %s {shlex.quote(gc_nar_bytes.decode())} > /tmp/hybrid-gc-nar"
  )
  gc_upload_status = client.succeed(
      f"{CURL} -sS -o /tmp/hybrid-gc-upload.response -w '%{{http_code}}' "
      "-X POST -H 'cf-connecting-ip: 192.0.2.10' "
      "-H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' "
      f"-H 'Authorization: Bearer {session_token}' "
      f"--data {shlex.quote(json.dumps({'cacheId': 'fleet/objects', 'path': gc_nar_path, 'size': len(gc_nar_bytes)}))} "
      "https://aos.andyl.org/aos.hub.v1.BinaryCacheService/CreateCacheObjectUploads",
      timeout=60,
  ).strip()
  if gc_upload_status != "200":
      print("cache GC NAR admission response:", client.succeed(
          "cat /tmp/hybrid-gc-upload.response"
      ))
      print("Native journal at cache GC admission:", native.succeed(
          "journalctl -u aos-hub.service -p err --no-pager -n 40"
      ))
      print("Worker log at cache GC admission:", worker.succeed(
          "tail -n 100 /var/lib/hybrid-worker/worker.log"
      ))
  assert gc_upload_status == "200", gc_upload_status
  gc_upload = json.loads(client.succeed("cat /tmp/hybrid-gc-upload.response"))
  client.succeed(
      f"{CURL} -fsS -X PUT -H 'cf-connecting-ip: 192.0.2.10' "
      f"-H 'Authorization: Bearer {session_token}' "
      f"--data-binary @/tmp/hybrid-gc-nar {shlex.quote(gc_upload['uploadUrl'])}",
      timeout=60,
  )
  gc_narinfo = (
      f"StorePath: /nix/store/{gc_store_hash}-hybrid-gc\n"
      f"URL: {gc_nar_path}\n"
      "Compression: none\n"
      f"FileHash: sha256:{gc_nar_digest}\n"
      f"FileSize: {len(gc_nar_bytes)}\n"
      f"NarHash: sha256:{gc_nar_digest}\n"
      f"NarSize: {len(gc_nar_bytes)}\n"
  )
  gc_registration = json.loads(client.succeed(
      f"{CURL} -fsS -X POST -H 'cf-connecting-ip: 192.0.2.10' "
      "-H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' "
      f"-H 'Authorization: Bearer {session_token}' "
      f"--data {shlex.quote(json.dumps({'cacheId': 'fleet/objects', 'narinfos': [{'storeHash': gc_store_hash, 'narinfo': gc_narinfo}]}))} "
      "https://aos.andyl.org/aos.hub.v1.BinaryCacheService/RegisterCacheNarinfos",
      timeout=60,
  ))
  assert int(gc_registration["registered"]) == 1, gc_registration

  gc_replica = json.loads(client.succeed(hub_command(
      "placement show cache:fleet/objects replica"
  )))["data"]["placement"]
  reviewed(
      "hybrid-cache-gc-replicate",
      "placement replicate cache:fleet/objects --from primary --to replica "
      "--wait --timeout 5m "
      f"--if-version {shlex.quote(gc_replica['resource_version'])}",
      timeout=360,
  )

  gc_policy = json.loads(client.succeed(hub_command(
      "cache gc policy show fleet/objects"
  )))["data"]["policy"]
  reviewed(
      "hybrid-cache-gc-policy",
      "cache gc policy set fleet/objects --unreferenced-grace 0s "
      "--schedule 3600 --deletion-concurrency 2 "
      "--retry-initial 2s --retry-max 30s --retry-max-attempts 5 "
      "--tombstone-retention 24h "
      f"--if-version {shlex.quote(gc_policy['resource_version'])}",
  )
  gc_inventory_query = (
      "SELECT COUNT(*) FROM cache_objects object "
      "JOIN binary_caches cache ON cache.id = object.cache_id "
      f"WHERE cache.slug = 'fleet/objects' AND object.store_hash = '{gc_store_hash}' "
      "AND object.lifecycle_state = 'active'"
  )
  native.wait_until_succeeds(
      f"test \"$({POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
      f"-c {shlex.quote(gc_inventory_query)})\" = 1",
      timeout=180,
  )
  gc_placement_query = (
      "SELECT COUNT(*) FROM object_placements presence "
      "JOIN surface_objects object ON object.id = presence.surface_object_id "
      "JOIN cache_gc_state state ON state.cache_id = presence.cache_id "
      "JOIN binary_caches cache ON cache.id = presence.cache_id "
      "WHERE cache.slug = 'fleet/objects' "
      f"AND object.object_key IN ('{gc_store_hash}.narinfo', '{gc_nar_path}') "
      "AND presence.state = 'present' "
      "AND presence.observed_inventory_generation = state.inventory_generation"
  )
  native.wait_until_succeeds(
      f"test \"$({POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
      f"-c {shlex.quote(gc_placement_query)})\" = 4",
      timeout=180,
  )

  bootstrap_gc = json.loads(client.succeed(hub_command(
      "cache gc plan create fleet/objects"
  ), timeout=180))["data"]["plan"]
  marker_query = (
      "SELECT COUNT(*) FROM binding_credential_revisions marker "
      "JOIN bindings binding ON binding.id = marker.binding_id "
      "WHERE binding.kind = 'deployment_r2' "
      "AND marker.purpose = 'delete' AND marker.generation = 1 "
      "AND marker.validation_state = 'invalid' "
      "AND NOT EXISTS (SELECT 1 FROM binding_credential_heads head "
      "WHERE head.binding_id = marker.binding_id "
      "AND head.purpose = marker.purpose)"
  )
  marker_count = int(native.succeed(
      f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At "
      f"-c {shlex.quote(marker_query)}"
  ).strip())
  assert marker_count == 1, marker_count
  ack_plan = json.loads(client.succeed(hub_command(
      "cache gc first-sweep plan-acknowledgement fleet/objects "
      f"--gc-plan-id {shlex.quote(bootstrap_gc['plan_id'])} "
      "--idempotency-key hybrid-cache-gc-ack-plan"
  )))["data"]["plan"]
  client.succeed(hub_command(
      "cache gc first-sweep acknowledge fleet/objects",
      " ".join([
          "--ack-plan-id", shlex.quote(ack_plan["plan_id"]),
          "--confirm-hash", shlex.quote(ack_plan["confirmation_hash"]),
          "--idempotency-key hybrid-cache-gc-ack-apply --yes",
      ]),
  ))
  gc_delete_plan = json.loads(client.succeed(hub_command(
      "cache gc plan create fleet/objects"
  ), timeout=180))["data"]["plan"]
  gc_detail = json.loads(client.succeed(hub_command(
      f"cache gc plan show fleet/objects {shlex.quote(gc_delete_plan['plan_id'])}"
  )))["data"]["plan"]
  assert any(candidate["store_hash"] == gc_store_hash for candidate in gc_detail["candidates"]), gc_detail
  assert len(gc_detail["placement_actions"]) >= 2, gc_detail

  reviewed(
      "hybrid-cache-gc-new-root",
      f"cache root create fleet/objects {gc_store_hash} "
      "--reason 'rooted after GC plan review'",
  )
  stale_gc_result = json.loads(client.succeed(
      hub_command(
          "cache gc run fleet/objects",
          " ".join([
              "--plan-id", shlex.quote(gc_delete_plan["plan_id"]),
              "--confirm-hash", shlex.quote(gc_delete_plan["confirmation_hash"]),
              "--idempotency-key hybrid-cache-gc-stale-root --yes",
          ]),
      ) + " || true"
  ))
  assert "failed_precondition" in stale_gc_result.get("error", ""), stale_gc_result
  for path in (f"{gc_store_hash}.narinfo", gc_nar_path):
      assert probe_work({"kind": "head", "path": path})["kind"] == "head"

  root_record = native.succeed(
      f"{POSTGRES}/psql -h {DATABASE_HOST} -U postgres -d postgres -At -F '|' "
      "-c \"SELECT root.id, root.resource_version FROM manual_retention_roots root "
      "JOIN binary_caches cache ON cache.id = root.cache_id "
      f"WHERE cache.slug = 'fleet/objects' AND root.store_hash = '{gc_store_hash}' "
      "AND root.deleted_at IS NULL\""
  ).strip()
  root_id, root_version = root_record.split("|", 1)
  assert re.fullmatch(r"[0-9a-f-]{32,64}", root_id), root_id
  assert root_version.isdecimal(), root_version
  reviewed(
      "hybrid-cache-gc-new-root-delete",
      f"cache root delete fleet/objects {shlex.quote(root_id)} "
      f"--if-version {root_version}",
  )
  session_token = refresh_session_token()
  gc_delete_plan = json.loads(client.succeed(hub_command(
      "cache gc plan create fleet/objects"
  ), timeout=180))["data"]["plan"]

  gc_operation = json.loads(client.succeed(hub_command(
      "cache gc run fleet/objects",
      " ".join([
          "--plan-id", shlex.quote(gc_delete_plan["plan_id"]),
          "--confirm-hash", shlex.quote(gc_delete_plan["confirmation_hash"]),
          "--idempotency-key hybrid-cache-gc-run --yes",
      ]),
  )))["data"]["operation"]
  gc_operation_id = gc_operation["operation_id"]
  gc_run = json.loads(client.succeed(hub_command(
      f"cache gc runs watch fleet/objects {shlex.quote(gc_operation_id)} --timeout 3m"
  ), timeout=240))["data"]
  assert gc_run["terminal"], gc_run
  replayed_gc_operation = json.loads(client.succeed(hub_command(
      "cache gc run fleet/objects",
      " ".join([
          "--plan-id", shlex.quote(gc_delete_plan["plan_id"]),
          "--confirm-hash", shlex.quote(gc_delete_plan["confirmation_hash"]),
          "--idempotency-key hybrid-cache-gc-run --yes",
      ]),
  )))["data"]["operation"]
  assert replayed_gc_operation["operation_id"] == gc_operation_id
  gc_jobs = json.loads(client.succeed(hub_command(
      f"cache gc jobs list fleet/objects {shlex.quote(gc_operation_id)}"
  )))["data"]["jobs"]
  assert len(gc_jobs) >= 2, gc_jobs
  assert all(job["state"] == "succeeded" for job in gc_jobs), gc_jobs
  for path in (f"{gc_store_hash}.narinfo", gc_nar_path):
      head = probe_work({"kind": "head", "path": path})
      assert head["kind"] == "not_found", (path, head)
  print("hybrid cache GC plan, jobs, and physical deletion: passed")

  invalid_plan_time = int(time.time())
  rejected_plans = [
      {
          **cache_verification_plan,
          "plan_id": "3" * 32,
          "issued_at": invalid_plan_time - 60,
          "expires_at": invalid_plan_time - 30,
      },
      {
          **cache_verification_plan,
          "plan_id": "4" * 32,
          "deployment_id": "other-hybrid-fleet",
          "issued_at": invalid_plan_time,
          "expires_at": invalid_plan_time + 30,
      },
  ]
  for rejected_plan in rejected_plans:
      rejected_body, rejected_signature = sign_storage_plan(rejected_plan)
      rejected_status = client.succeed(
          f"{CURL} -sS -o /dev/null -w '%{{http_code}}' -X POST "
          "-H 'content-type: application/json' "
          f"-H 'x-aos-storage-work-signature: {rejected_signature}' "
          f"--data-binary {shlex.quote(rejected_body.decode())} "
          "https://aos.andyl.org/_internal/storage/v1/execute",
          timeout=60,
      ).strip()
      assert rejected_status == "401", (rejected_plan, rejected_status)

  native.succeed("systemctl stop aos-hub.service")
  outage_now = int(time.time())
  outage_plan = {
      **cache_verification_plan,
      "plan_id": "2" * 32,
      "issued_at": outage_now,
      "expires_at": outage_now + 30,
  }
  outage_body, outage_signature = sign_storage_plan(outage_plan)
  outage_result = json.loads(client.succeed(
      f"{CURL} -fsS -X POST -H 'content-type: application/json' "
      f"-H 'x-aos-storage-work-signature: {outage_signature}' "
      f"--data-binary {shlex.quote(outage_body.decode())} "
      "https://aos.andyl.org/_internal/storage/v1/execute",
      timeout=60,
  ))
  assert outage_result["outcome"]["kind"] == "sha256_evidence", outage_result
  assert outage_result["outcome"]["sha256"] == cache_digest, outage_result

  client.succeed(textwrap.dedent(f"""
      set -eu
      {CURL} -fsS https://aos.andyl.org/_assets/style.css \
        > /tmp/hybrid-origin-outage.css
      {GREP} -q 'Geist Sans' /tmp/hybrid-origin-outage.css
      asset_code=$({CURL} -sS -I -o /tmp/hybrid-origin-outage-font.headers \
        -w '%{{http_code}}' \
        https://aos.andyl.org/_assets/geist-sans-variable.woff2)
      test "$asset_code" = 200
      {GREP} -qi '^content-type: font/woff2' \
        /tmp/hybrid-origin-outage-font.headers
      cookie=$(cat /tmp/hybrid-cookie)
      code=$({CURL} -sS -o /tmp/hybrid-origin-outage.html -w '%{{http_code}}' \\
        -H 'cf-connecting-ip: 192.0.2.10' -H "Cookie: $cookie" \\
        https://aos.andyl.org/-/instance)
      test "$code" -ge 500
      code=$({CURL} -sS -o /dev/null -w '%{{http_code}}' -X PUT \\
        --data-binary 'storage-body-must-stay-at-worker' \\
        https://aos.andyl.org/aos.hub.v1.PublishService/UploadPart/missing/1)
      test "$code" = 503
      code=$({CURL} -sS -o /dev/null -w '%{{http_code}}' -X PATCH \\
        --data-binary 'oci-chunk-must-stay-at-worker' \\
        https://aos.andyl.org/v2/aos/blobs/uploads/missing)
      test "$code" = 503
      code=$({CURL} -sS -o /dev/null -w '%{{http_code}}' -X DELETE \\
        --data-binary 'delete-body-must-stay-at-worker' \\
        https://aos.andyl.org/v2/aos/blobs/uploads/missing)
      test "$code" = 400
  """), timeout=60)
  native.succeed("systemctl start aos-hub.service")
  client.wait_until_succeeds(
      f"{CURL} -fsS -H 'cf-connecting-ip: 192.0.2.10' https://aos.andyl.org/healthz",
      timeout=180,
  )

  database_machine.succeed(
      f"{CHROOT} {POSTGRES}/pg_ctl -D /var/lib/hybrid-postgres "
      "-m immediate -w stop",
      timeout=60,
  )
  database_outage_status = client.succeed(textwrap.dedent(f"""
      cookie=$(cat /tmp/hybrid-cookie)
      {CURL} -sS -o /dev/null -w '%{{http_code}}' \\
        -H 'cf-connecting-ip: 192.0.2.10' -H "Cookie: $cookie" \\
        https://aos.andyl.org/-/instance
  """), timeout=60).strip()
  assert int(database_outage_status) >= 500, database_outage_status
  client.succeed(
      f"{CURL} -fsS https://aos.andyl.org/_assets/style.css > /dev/null",
      timeout=60,
  )
  database_machine.succeed(
      f"{CHROOT} {POSTGRES}/pg_ctl -D /var/lib/hybrid-postgres "
      "-l /var/lib/hybrid-postgres/server.log -w start "
      "-o '-c config_file=/var/lib/hybrid-postgres/fleet.conf'",
      timeout=120,
  )
  client.wait_until_succeeds(
      f"{CURL} -fsS -H 'cf-connecting-ip: 192.0.2.10' "
      "-H \"Cookie: $(cat /tmp/hybrid-cookie)\" "
      "https://aos.andyl.org/-/instance | "
      f"{GREP} -q '<html'",
      timeout=180,
  )
  # Local Miniflare co-hosts R2 emulation and Worker execution on one VM.
  # The hosted staging gate applies the 25% target to real Worker and R2.
  print("hybrid local-emulator upload latency target:", {
      "met": loaded_page_gate,
      "baseline_p95": first_bytes[94],
      "loaded_p95": loaded_first_bytes[23],
      "native_p95": native_first_bytes[23],
  })
''
+ builtins.readFile ./_hub-index-parity.py
+ builtins.readFile ./_hub-runtime-parity.py
+ ''
  qualify_registry_runtime_parity(
      client, native, worker,
      tools={
          "aos": AOS,
          "hub": "${pkgs.aos-hub}/bin/aos-hub",
          "coreutils": "${pkgs.coreutils}/bin",
          "curl": CURL,
          "jq": "${pkgs.jq}/bin/jq",
          "postgres": POSTGRES,
          "postgres_host": DATABASE_HOST,
          "sqlite": "${pkgs.sqlite}/bin/sqlite3",
          "tar": "${pkgs.tar}/bin/tar",
          "node": "${pkgs.nodejs}/bin/node",
          "miniflare": "${pkgs.miniflare}",
          "worker_runner": "${workerRunner}/value",
          "worker_main": "${pkgs.aos-hub-worker-dist}/shim.mjs",
      },
      fixture={
          "certificate": "${serverCertificate}/value",
          "private_key": "${serverPrivateKey}/value",
          "release_seed": "${releaseReceiptKey}/value",
          "channel_seed": "${channelReceiptKey}/value",
          "publication_keys": "${releasePublicationKeys}/value",
          "qualification_keys": "${qualificationKeys}/value",
          "route_keys": "${parityRouteKeys}/value",
          "trust_key": trust_key,
          "probe_public_key": "${fixture.probePublicKey}",
          "container_root": "/var/lib/hybrid-container-final",
          "container_inputs": "${containerPublicationInputs}",
          "container_signature": client.succeed("cat /tmp/hybrid-container-signature.pae.sig"),
          "container_index_digest": finalized_container["index_digest"],
      },
      snapshot_assert=assert_registry_index_parity,
  )
''
