"""Capture actual pending SQL originals and exercise the public token lifecycle.

Raw admissions, Complete requests, access tokens and API replies stay in private
guest files. Public projections contain bounded digests, sizes and actual status.
The selected fleet supplies its existing private guest command and file-copy
functions; none of these functions returns a caller-provided qualification flag.
"""

import hashlib
import json
import re
import shlex
import time


DIGEST = re.compile(r"[0-9a-f]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
MAX_BODY = 256 * 1024


def admission_only_query(deployment, session):
    """Read the original admission before any completion intent exists."""
    # Reuse the existing closed SQL-identity checks, never a caller SQL fragment.
    pending_original_query(deployment, session, "0" * 64)
    return (
        "BEGIN TRANSACTION READ ONLY; SET LOCAL statement_timeout = '30s'; "
        "SELECT json_build_object('sessionId',s.session_id,'deploymentId',s.deployment_id,"
        "'principalId',s.principal_id,'state',s.state,'admission',s.admission_json::json,"
        "'intent',s.intent_json::json,'logicalFingerprint',s.logical_fingerprint,"
        "'sourceSha256',s.source_sha256,'declaredSize',s.declared_size::text,"
        "'publicationId',s.publication_id,'publicationState',p.state,"
        "'completionIntents',(SELECT count(*) FROM direct_upload_completion_intents c "
        "WHERE c.deployment_id=s.deployment_id AND c.session_id=s.session_id),"
        "'completionReceipts',(SELECT count(*) FROM direct_upload_completion_receipts r "
        "WHERE r.deployment_id=s.deployment_id AND r.session_id=s.session_id))::text "
        "FROM direct_upload_sessions s JOIN registry_publications p "
        "ON p.publication_id=s.publication_id "
        f"WHERE s.deployment_id='{deployment}' AND s.session_id='{session}'; COMMIT;"
    )


def _sql_row(body):
    if not isinstance(body, bytes) or not 0 < len(body) <= MAX_BODY:
        raise ValueError("SQL original exceeds its private bound")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("SQL original contains duplicate fields")
            result[key] = value
        return result

    lines = body.splitlines()
    if len(lines) != 1:
        raise ValueError("SQL did not select exactly one original")
    return json.loads(lines[0], object_pairs_hook=pairs)


def admission_snapshot(body, session, intent, whoami, placement_id):
    """Join actual SQL admission to prepared production Begin and current actor.

    The returned full admission stays private. It is not a completion intent,
    queue acceptance, provider permission or caller-supplied accepted flag.
    """
    row = _sql_row(body)
    fields = {"sessionId", "deploymentId", "principalId", "state", "admission",
              "intent", "logicalFingerprint", "sourceSha256", "declaredSize",
              "publicationId", "publicationState", "completionIntents", "completionReceipts"}
    if set(row) != fields or not isinstance(row["admission"], dict):
        raise ValueError("admission SQL schema differs")
    admission = row["admission"]
    if (session != {"sessionId": row["sessionId"], "logicalFingerprint": row["logicalFingerprint"]}
            or admission["sessionId"] != row["sessionId"]
            or admission["logicalFingerprint"] != row["logicalFingerprint"]
            or row["intent"] != intent or admission["intent"] != intent
            or row["sourceSha256"] != intent["expectedSha256"]
            or row["declaredSize"] != intent["byteSize"]
            or row["principalId"] != admission["principalId"]
            or intent["target"]["kind"] != "publication_object"
            or row["publicationId"] != intent["target"]["publicationId"]
            or row["state"] != "admitted" or row["publicationState"] != "preparing"
            or type(row["completionIntents"]) is not int or row["completionIntents"] != 0
            or type(row["completionReceipts"]) is not int or row["completionReceipts"] != 0
            or len([item for item in admission["placements"]
                    if item["placementId"] == placement_id]) != 1):
        raise ValueError("prepared source, owner or pre-Complete SQL original differs")
    assert_original_actor(whoami, admission, row["deploymentId"])
    # Copy the parsed document so later callback mutations cannot alter this join.
    retained = json.loads(json.dumps(admission))
    encoded = json.dumps(retained, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    projection = {"sessionDigest": hashlib.sha256(row["sessionId"].encode()).hexdigest(),
                  "admissionDigest": hashlib.sha256(encoded).hexdigest(),
                  "state": row["state"], "publicationState": row["publicationState"],
                  "completionReceipts": 0}
    return retained, projection


def capture_admission_sql(native, tools, guest_python, session, sequence):
    """Capture actual admission-only SQL through the same source-built reader."""
    return _capture_sql(native, tools, guest_python,
                        admission_only_query(tools["deploymentId"], session), sequence, "admission")


def admission_codec_manifest(capture, public_begin, sql_admissions, codec_revision, source_digest):
    """Select the existing Core-backed logical-admission projection.

    All references name independently retained bytes. The SQL image comes from
    the existing measured SQL reader, not a synthesized logical reply. Runtime,
    reader and authenticated control custody remain the caller's obligations.
    """
    if (not re.fullmatch(r"[0-9a-f]{40}", codec_revision)
            or not DIGEST.fullmatch(source_digest)
            or capture.get("phase") != "admission" or capture.get("method") != "POST"
            or capture.get("procedure") != "/aos.hub.v1.DirectUploadService/BeginBatch"
            or type(capture.get("status")) is not int or capture["status"] != 200
            or capture.get("responseContentType") != "application/json"
            or capture.get("responseContentEncoding") not in {None, "", "identity"}
            or set(capture.get("bodies", {})) != {"request", "response"}):
        raise ValueError("selected actual logical Admission capture differs")
    references = [*capture["bodies"].values(), public_begin, sql_admissions]
    for reference in references:
        if (not isinstance(reference, dict) or set(reference) != {"file", "sha256", "byteSize"}
                or not isinstance(reference["file"], str) or not reference["file"].startswith("/")
                or not isinstance(reference["sha256"], str) or not DIGEST.fullmatch(reference["sha256"])
                or not isinstance(reference["byteSize"], str)
                or not re.fullmatch(r"[1-9][0-9]{0,6}", reference["byteSize"])
                or int(reference["byteSize"]) > MAX_BODY):
            raise ValueError("actual Admission image reference differs")
    selected = json.loads(json.dumps(capture))
    selected["immutableProjection"] = {
        "kind": "direct_admission", "originalRequest": selected["bodies"]["request"],
        "originalPublicRequest": dict(public_begin), "sqlAdmissions": dict(sql_admissions)}
    return {"version": 1, "codecRevision": codec_revision, "sourceDigest": source_digest,
            "issuerVerifier": None, "captures": [selected]}


def admission_codec_result(body, manifest, manifest_sha256):
    """Require the actual codec result for every selected immutable byte image.

    This comparison grants neither SQL-reader authority nor authentication. The
    existing codec explicitly retains those missing joins in its own output.
    """
    result = _sql_row(body)
    if (result.get("version") != 1 or type(result.get("version")) is not int
            or result.get("codecRevision") != manifest["codecRevision"]
            or result.get("selectedSourceDigest") != manifest["sourceDigest"]
            or result.get("manifestSha256") != manifest_sha256
            or not isinstance(result.get("captures"), list) or len(result["captures"]) != 1):
        raise ValueError("actual admission codec runtime or input differs")
    original = manifest["captures"][0]
    capture = result["captures"][0]
    projection = capture.get("immutableProjection")
    selected = original["immutableProjection"]
    if (capture.get("requestIdSha256") != hashlib.sha256(original["requestId"].encode()).hexdigest()
            or capture.get("procedure") != original["procedure"] or capture.get("method") != "POST"
            or capture.get("phase") != "admission"
            or capture.get("originalPublicRequestSha256") != selected["originalPublicRequest"]["sha256"]
            or not isinstance(projection, dict)
            or projection.get("version") != 1 or type(projection.get("version")) is not int
            or projection.get("kind") != "direct_logical_admission"
            or projection.get("matchedOriginalCount") != "1"
            or projection.get("originalRequestSha256") != original["bodies"]["request"]["sha256"]
            or projection.get("sqlEvidenceSha256") != selected["sqlAdmissions"]["sha256"]
            or projection.get("objectPayloadBytes") is not None
            or projection.get("sqlReaderAuthority") != "not_checked_join_measured_read_only_source_process_and_window"
            or projection.get("missing") != ["independent_sql_reader_custody_and_temporal_current_fences"]):
        raise ValueError("Core admission projection does not match the actual original")
    for direction in ("request", "response"):
        reference = original["bodies"][direction]
        observed = capture.get(direction, {})
        if (observed.get("sha256") != reference["sha256"]
                or observed.get("byteSize") != reference["byteSize"]):
            raise ValueError("Core admission capture bytes changed")
    if (projection.get("requestControlBytes") != original["bodies"]["request"]["byteSize"]
            or projection.get("replyControlBytes") != original["bodies"]["response"]["byteSize"]):
        raise ValueError("Core admission control lengths changed")
    return json.loads(json.dumps(projection))


def pending_original_query(deployment, session, operation):
    """Construct a bounded read-only query for the retained Complete original."""
    if (not isinstance(deployment, str) or not re.fullmatch(r"[a-z0-9-]{1,128}", deployment)
            or not isinstance(session, str) or not IDENTIFIER.fullmatch(session)
            or not isinstance(operation, str) or not IDENTIFIER.fullmatch(operation)):
        raise ValueError("pending SQL identity is not a bounded original")
    return (
        "BEGIN TRANSACTION READ ONLY; SET LOCAL statement_timeout = '30s'; "
        "SELECT json_build_object('sessionId',s.session_id,'state',s.state,"
        "'admission',s.admission_json::json,'complete',c.intent_json::json,"
        "'completeOperationId',c.operation_id,'publicationId',s.publication_id,"
        "'publicationState',p.state,'completionReceipts',"
        "(SELECT count(*) FROM direct_upload_completion_receipts r "
        "WHERE r.deployment_id=s.deployment_id AND r.session_id=s.session_id))::text "
        "FROM direct_upload_sessions s JOIN direct_upload_completion_intents c "
        "ON c.deployment_id=s.deployment_id AND c.session_id=s.session_id "
        "JOIN registry_publications p ON p.publication_id=s.publication_id "
        f"WHERE s.deployment_id='{deployment}' AND s.session_id='{session}' "
        f"AND c.operation_id='{operation}'; COMMIT;"
    )


def capture_pending_sql(native, tools, guest_python, session, operation, sequence):
    """Run actual source-built psql without modifying target schema or rows."""
    query = pending_original_query(tools["deploymentId"], session, operation)
    return _capture_sql(native, tools, guest_python, query, sequence, "snapshot")


def _capture_sql(native, tools, guest_python, query, sequence, kind):
    if type(sequence) is not int or not 0 <= sequence < 4096:
        raise ValueError("pending SQL observation sequence differs")
    if not tools["postgres"].startswith("/nix/store/") or not tools["python"].startswith("/nix/store/"):
        raise ValueError("pending SQL observation requires declared source-built tools")
    selected = {"query": query, "databaseUrlFile": tools["nativeDatabaseUrlFile"],
                "psql": tools["postgres"] + "/psql", "sequence": sequence, "kind": kind}
    # This code runs on the selected Native machine through the existing private
    # transport. The URL is loaded there; it never enters the returned receipt.
    body = """
        import hashlib, json, os, subprocess
        from pathlib import Path

        root = Path('/var/lib/hybrid-native-observations/queue-faults')
        root.mkdir(mode=0o700, exist_ok=True)
        os.umask(0o077)
        path = root / ('%s-%04d.jsonl' % (selected['kind'], selected['sequence']))
        environment = dict(os.environ)
        environment['PGDATABASE'] = Path(selected['databaseUrlFile']).read_text().strip()
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as output:
            result = subprocess.run([selected['psql'], '-X', '-qAt', '-v', 'ON_ERROR_STOP=1',
                '-c', selected['query']], stdout=output, stderr=subprocess.PIPE,
                env=environment, timeout=40, check=False)
            output.flush()
            os.fsync(output.fileno())
        with path.open('rb') as source:
            sha = hashlib.file_digest(source, 'sha256').hexdigest()
        print(json.dumps({'version':1, 'path':str(path), 'sha256':sha,
            'bytes':path.stat().st_size, 'exitCode':result.returncode,
            'stderrSha256':hashlib.sha256(result.stderr).hexdigest(),
            'querySha256':hashlib.sha256(selected['query'].encode()).hexdigest()}))
    """
    receipt = json.loads(guest_python(native, tools["python"], body, selected, timeout=50))
    if receipt["exitCode"] != 0 or not 0 < receipt["bytes"] <= MAX_BODY:
        raise RuntimeError("actual pending SQL snapshot failed or exceeded its bound")
    return receipt


def pending_snapshot(body, admission, complete):
    """Validate a privately copied SQL row against the actual retained originals."""
    if not isinstance(body, bytes) or not 0 < len(body) <= MAX_BODY:
        raise ValueError("pending SQL row exceeds its bound")
    def closed_pairs(pairs):
        row = {}
        for key, value in pairs:
            if key in row:
                raise ValueError("pending SQL row has duplicate JSON fields")
            row[key] = value
        return row
    rows = body.splitlines()
    if len(rows) != 1:
        raise ValueError("pending SQL query did not select exactly one original")
    row = json.loads(rows[0], object_pairs_hook=closed_pairs)
    fields = {"sessionId", "state", "admission", "complete", "completeOperationId",
              "publicationId", "publicationState", "completionReceipts"}
    if (set(row) != fields or row["admission"] != admission or row["complete"] != complete
            or row["sessionId"] != admission["sessionId"]
            or row["completeOperationId"] != complete["operationId"]
            or admission["intent"]["target"]["kind"] != "publication_object"
            or row["publicationId"] != admission["intent"]["target"]["publicationId"]
            or type(row["completionReceipts"]) is not int or row["completionReceipts"] < 0):
        raise ValueError("actual SQL original or owner differs")
    encoded = json.dumps(admission, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return {"sessionDigest": hashlib.sha256(row["sessionId"].encode()).hexdigest(),
            "admissionDigest": hashlib.sha256(encoded).hexdigest(), "state": row["state"],
            "completionReceipts": row["completionReceipts"], "publicationState": row["publicationState"]}


class QueueFaultNativeTransport:
    """Send closed publication setup, actual WhoAmI and exact Complete.

    This metadata transport never refreshes an original bearer or uploads bytes.
    The separately selected staged driver owns ordinary Direct admission/parts.
    """

    ROUTES = {"IdentityService/WhoAmI", "DirectUploadService/CompleteBatch",
              "DirectUploadService/GetCapabilities",
              "PublishService/BeginRegistryPublicationManifest",
              "PublishService/AppendRegistryPublicationManifest",
              "PublishService/SealRegistryPublicationManifest"}

    def __init__(self, client, tools, token_file, guest_python, copy_private_body):
        self.client = client
        self.tools = tools
        self.token_file = token_file
        self.provisioned = False
        self.jwt_sha256 = None
        self.guest_python = guest_python
        self.copy_private_body = copy_private_body
        self.observations = []
        self.saved_complete_dispatched = False
        if not isinstance(token_file, str) or not re.fullmatch(
                r"/var/lib/hybrid-client/queue-faults/[A-Za-z0-9_-]+\.token", token_file):
            raise ValueError("queue fault token must be one owner-private fixture file")
        self.jwt_file = token_file.removesuffix(".token") + ".jwt"

    def provision(self):
        """Exchange the persisted secret for a real JWT before any RPC call.

        The actual OAuth response and JWT stay in private guest files. Its
        lifetime is separate from the underlying persisted token lifecycle.
        """
        if self.provisioned or self.observations:
            raise ValueError("fault provisioning exchange is a one-time original")
        curl = shlex.split(self.tools["curl"])
        if (not curl or not curl[0].startswith("/nix/store/") or not curl[0].endswith("/bin/curl")
                or not self.tools["python"].startswith("/nix/store/")):
            raise ValueError("fault provisioning requires source-built transport")
        selected = {"curl": curl, "tokenFile": self.token_file, "jwtFile": self.jwt_file}
        observation = {"sequence": 0, "route": "/oauth2/token", "outcome": "pending"}
        self.observations.append(observation)
        body = """
            import hashlib, json, os, re, subprocess
            from pathlib import Path

            os.umask(0o077)
            secret = Path(selected['tokenFile']).read_text().strip()
            if not re.fullmatch(r'[A-Za-z0-9._-]{1,8192}',secret):
                raise ValueError('provisioning secret encoding differs')
            response = selected['jwtFile'] + '.oauth-response.json'
            headers = selected['jwtFile'] + '.oauth-headers'
            if any(Path(name).exists() for name in (response,headers,selected['jwtFile'])):
                raise ValueError('fault provisioning output already exists')
            configuration = 'header = "Authorization: Bearer ' + secret + '"\\n'
            result = subprocess.run(selected['curl'] + ['-sS','--max-time','30',
                '--max-filesize','262144','--config','-','-X','POST',
                '-H','Content-Type: application/x-www-form-urlencoded',
                '-H','cf-connecting-ip: 192.0.2.10','--data',
                'grant_type=urn%3Aaos%3Aparams%3Aoauth%3Agrant-type%3Aprovisioning-token',
                '--dump-header',headers,'--output',response,'--write-out','%{http_code}',
                'https://aos.fleet.test/oauth2/token'],
                input=configuration.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                timeout=35,check=False)
            raw = Path(response).read_bytes() if Path(response).is_file() else b''
            receipt = {'path':response,'sha256':hashlib.sha256(raw).hexdigest(),
                'bytes':len(raw),'exitCode':result.returncode,
                'status':result.stdout.decode() if re.fullmatch(rb'[0-9]{3}',result.stdout) else None,
                'stderrSha256':hashlib.sha256(result.stderr).hexdigest(),
                'jwtFile':None,'jwtSha256':None,'jwtBytes':None,'oauthExpiresInSeconds':None}
            if result.returncode == 0 and result.stdout == b'200' and 0 < len(raw) <= 262144:
                reply = json.loads(raw)
                jwt = reply.get('access_token')
                lifetime = reply.get('expires_in')
                if (reply.get('token_type') != 'Bearer' or type(lifetime) is not int
                        or not 0 < lifetime <= 3600 or not isinstance(jwt,str)
                        or len(jwt) > 8192 or not re.fullmatch(r'[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+',jwt)):
                    raise ValueError('actual provisioning response differs')
                descriptor = os.open(selected['jwtFile'],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(descriptor,'wb') as output:
                    output.write(jwt.encode()); output.flush(); os.fsync(output.fileno())
                receipt.update(jwtFile=selected['jwtFile'],jwtSha256=hashlib.sha256(jwt.encode()).hexdigest(),
                    jwtBytes=len(jwt),oauthExpiresInSeconds=lifetime)
            print(json.dumps(receipt))
        """
        try:
            receipt = json.loads(self.guest_python(self.client, self.tools["python"], body, selected, timeout=45))
            observation.update(receipt, outcome="received" if receipt["exitCode"] == 0 else "unknown")
            if (receipt["exitCode"] != 0 or receipt["status"] != "200"
                    or receipt["jwtFile"] != self.jwt_file or not DIGEST.fullmatch(receipt["jwtSha256"] or "")
                    or type(receipt["jwtBytes"]) is not int or not 0 < receipt["jwtBytes"] <= 8192
                    or type(receipt["oauthExpiresInSeconds"]) is not int
                    or not 0 < receipt["oauthExpiresInSeconds"] <= 3600):
                raise RuntimeError("actual provisioning exchange has no retained JWT")
            self.provisioned = True
            self.jwt_sha256 = receipt["jwtSha256"]
            return receipt
        except Exception:
            if observation["outcome"] == "pending":
                observation["outcome"] = "unknown"
            raise

    def call(self, route, request):
        """Retain the actual request/reply prefix and return independently copied JSON."""
        return self._call_encoded(route, json.dumps(request, separators=(",", ":")))

    def select_browser_bearer(self, token, install_private):
        """Retain the actual existing caller bearer without issuing or refreshing it.

        This chooses transport bytes only; the following actual WhoAmI and SQL
        actor join establish the observed caller, not this local state change.
        """
        if (self.provisioned or self.observations or not isinstance(token, str)
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,8192}", token)):
            raise ValueError("browser bearer selection is substituted or repeated")
        install_private(self.jwt_file, token.encode())
        self.jwt_sha256 = hashlib.sha256(token.encode()).hexdigest()
        self.provisioned = True

    def _call_encoded(self, route, encoded):
        if route not in self.ROUTES:
            raise ValueError("queue fault route is outside the selected identity/retry contract")
        if not self.provisioned:
            raise ValueError("actual provisioning exchange must precede RPC")
        if len(encoded.encode()) >= 64 * 1024 or len(self.observations) >= 4096:
            raise ValueError("queue fault metadata transport bound differs")
        index = len(self.observations)
        observation = {"sequence": index, "route": route, "outcome": "pending",
                       "requestSha256": hashlib.sha256(encoded.encode()).hexdigest()}
        self.observations.append(observation)
        curl = shlex.split(self.tools["curl"])
        if (not curl or not curl[0].startswith("/nix/store/") or not curl[0].endswith("/bin/curl")
                or not self.tools["python"].startswith("/nix/store/")):
            raise ValueError("queue fault exchange requires declared source-built transport tools")
        selected = {"curl": curl, "request": encoded, "route": route,
                    "tokenFile": self.jwt_file, "jwtSha256": self.jwt_sha256, "index": index}
        body = """
            import hashlib, json, os, re, subprocess, time
            from pathlib import Path

            os.umask(0o077)
            token = Path(selected['tokenFile']).read_text().strip()
            if hashlib.sha256(token.encode()).hexdigest() != selected['jwtSha256']:
                raise ValueError('fault original JWT changed')
            if not re.fullmatch(r'[A-Za-z0-9._-]{1,8192}',token):
                raise ValueError('queue fault token encoding differs')
            root = Path('/var/lib/hybrid-client/queue-faults')
            token_digest = hashlib.sha256(selected['tokenFile'].encode()).hexdigest()[:16]
            path = root / ('exchange-' + token_digest + '-%04d' % selected['index'])
            request = str(path) + '.request.json'
            response = str(path) + '.response.json'
            headers = str(path) + '.headers'
            if any(Path(name).exists() for name in (request,response,headers)):
                raise ValueError('queue fault exchange files already exist')
            with open(request,'x') as output:
                output.write(selected['request'])
            # Secret header material is passed via stdin, not process arguments.
            configuration = 'header = "Authorization: Bearer ' + token + '"\\n'
            result = subprocess.run(selected['curl'] + ['-sS','--max-time','60',
                '--max-filesize','262144','--config','-','-X','POST',
                '-H','Content-Type: application/json','-H','Connect-Protocol-Version: 1',
                '-H','cf-connecting-ip: 192.0.2.10','--data-binary','@'+request,
                '--dump-header',headers,'--output',response,'--write-out','%{http_code}',
                'https://aos.fleet.test/aos.hub.v1.'+selected['route']],
                input=configuration.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=65,check=False)
            raw = Path(response).read_bytes() if Path(response).is_file() else b''
            print(json.dumps({'path':response,'sha256':hashlib.sha256(raw).hexdigest(),
                'bytes':len(raw),'exitCode':result.returncode,
                'status':result.stdout.decode() if re.fullmatch(rb'[0-9]{3}',result.stdout) else None,
                'stderrSha256':hashlib.sha256(result.stderr).hexdigest(),
                'observedAtUnixSeconds':int(time.time())}))
        """
        try:
            receipt = json.loads(self.guest_python(
                self.client, self.tools["python"], body, selected, timeout=75))
            observation.update(receipt, outcome="received" if receipt["exitCode"] == 0 else "unknown")
            if receipt["exitCode"] != 0 or not 0 < receipt["bytes"] <= MAX_BODY:
                raise RuntimeError("queue fault exchange has no complete bounded reply")
            raw = self.copy_private_body(self.client, receipt)
            if len(raw) != receipt["bytes"] or hashlib.sha256(raw).hexdigest() != receipt["sha256"]:
                raise ValueError("queue fault reply changed during private retrieval")
            return receipt, json.loads(raw)
        except Exception:
            if observation["outcome"] == "pending":
                observation["outcome"] = "unknown"
            raise

    def whoami(self):
        """Observe the current actor, scope and separate JWT expiry through Native."""
        return self.call("IdentityService/WhoAmI", {})

    def complete(self, original, batch_operation_id):
        """Retry the exact retained item under one explicitly selected batch identity."""
        if not isinstance(batch_operation_id, str) or not DIGEST.fullmatch(batch_operation_id):
            raise ValueError("queue fault Complete batch identity differs")
        return self.call("DirectUploadService/CompleteBatch", {
            "operationId": batch_operation_id, "items": [original],
        })

    def complete_saved(self, body, reference, original, batch_operation_id):
        """Dispatch the prepared original byte image once, retaining unknown effects.

        This is for the prepared production handoff, not a retry authority. Even
        a local transport error consumes this object's dispatch opportunity.
        """
        if (self.saved_complete_dispatched or not isinstance(body, bytes)
                or not 0 < len(body) < 64 * 1024
                or set(reference) != {"sha256", "byteSize"}
                or reference["byteSize"] != str(len(body))
                or reference["sha256"] != hashlib.sha256(body).hexdigest()):
            raise ValueError("saved Complete is changed or already dispatched")
        parsed = _sql_row(body)
        if parsed != {"operationId": batch_operation_id, "items": [original]}:
            raise ValueError("saved Complete batch identity or composition differs")
        encoded = body.decode("utf-8")
        self.saved_complete_dispatched = True
        return self._call_encoded("DirectUploadService/CompleteBatch", encoded)


def retire_actual_token(controls, token_id, scope, label):
    """Use the current list revision and persisted retirement Plan/Apply pair."""
    reply = controls.call("IdentityService", "ListAccessTokens", {"scope": scope, "pageSize": 128})
    if reply.get("nextPageToken"):
        raise ValueError("token retirement selection needs a complete bounded token list")
    rows = [row for row in reply.get("tokens", []) if row["tokenId"] == token_id]
    if len(rows) != 1 or rows[0]["scope"] != scope or rows[0]["resourceVersion"] != "active":
        raise ValueError("token retirement does not select one current active generation")
    result = controls.reviewed("IdentityService", "PlanRetireAccessToken", "RetireAccessToken", {
        "tokenId": token_id, "expectedResourceVersion": rows[0]["resourceVersion"],
    }, label)
    return {"tokenDigest": hashlib.sha256(token_id.encode()).hexdigest(),
            "retirementReplyDigest": hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()}


def issue_fault_token(controls, owner, scope, permissions, ttl_seconds, label):
    """Issue a real bounded delegation through the existing reviewed public API.

    The one-time secret belongs in an exclusive owner-private token file. The
    caller exchanges it through actual provisioning, authenticates WhoAmI before
    Begin, and retains JWT and persisted token expiries separately. No fixture
    JWT is minted.
    """
    if (type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 60
            or not isinstance(owner, str) or not owner.startswith(("user:", "service_account:"))
            or not isinstance(scope, str) or not scope
            or not isinstance(permissions, list) or not permissions
            or len(permissions) > 32 or not all(isinstance(value, str) and value for value in permissions)):
        raise ValueError("fault delegation must be an actual short-lived selected owner token")
    return controls.reviewed("IdentityService", "PlanIssueAccessToken", "IssueAccessToken", {
        "owner": owner, "scope": scope, "permissions": permissions,
        "ttlSecs": str(ttl_seconds), "expectedResourceVersion": "",
        "comment": "Controlled queued verification fault",
    }, label)


def assert_complete_denied(receipt, reply, original, batch_operation_id):
    """Require a real authentication/authorization denial for the exact retry."""
    if type(receipt.get("exitCode")) is not int or receipt["exitCode"] != 0:
        raise ValueError("Complete denial has no successful actual reply transport")
    if (receipt["status"] in {"401", "403"}
            and reply.get("code") in {"unauthenticated", "permission_denied"}):
        return
    if (receipt["status"] != "200" or reply.get("operationId") != batch_operation_id
            or reply.get("sessions") or reply.get("grants")
            or reply.get("errors") != [{"itemId": original["session"]["sessionId"], "code": "denied"}]):
        raise AssertionError("exact Complete retry did not receive an authorization denial")


def assert_original_actor(whoami, admission, deployment_id=None):
    """Join the actual pre-fault token identity to its admitted session actor."""
    # DirectUploadAdmission deliberately has no deploymentId. Production joins
    # use its independently read SQL namespace rather than extending the wire.
    namespace = deployment_id if deployment_id is not None else admission.get("deploymentId")
    if (not namespace or whoami.get("deploymentId") != namespace
            or whoami.get("principalId") != admission.get("principalId")
            or not whoami.get("principalId")
            or whoami.get("principalKind") != admission["actorSlot"]["kind"]):
        raise ValueError("fault token is not the original admitted actor")


def retain_actual_token(controls, token_id, scope):
    """Retain real active token metadata after provisioning and before admission."""
    listed = controls.call("IdentityService", "ListAccessTokens", {"scope": scope, "pageSize": 128})
    tokens = [row for row in listed.get("tokens", []) if row["tokenId"] == token_id]
    if (listed.get("nextPageToken") or len(tokens) != 1 or tokens[0]["scope"] != scope
            or tokens[0]["resourceVersion"] != "active"
            or int(tokens[0].get("retiredAt", "0")) != 0
            or int(tokens[0].get("rotatedAt", "0")) != 0):
        raise ValueError("selected token is not a retained active unretired original")
    return json.loads(json.dumps(tokens[0]))


def wait_actual_token_expiry(transport, retained_whoami, retained_token, controls, scope, maximum_seconds=65):
    """Require actual persisted-token expiry refusal with a separately live JWT."""
    expiry = int(retained_token["expiresAt"])
    jwt_expiry = int(retained_whoami["accessExpiresAt"])
    created = int(retained_token["createdAt"])
    if (not 0 < maximum_seconds <= 65 or not 1 <= expiry - created <= 60
            or jwt_expiry <= expiry or retained_token["scope"] != scope
            or retained_token["resourceVersion"] != "active"
            or int(retained_token.get("retiredAt", "0")) != 0
            or int(retained_token.get("rotatedAt", "0")) != 0):
        raise ValueError("expiry case requires one actual short-lived access token")
    deadline = time.monotonic() + maximum_seconds
    while True:
        receipt, reply = transport.whoami()
        if receipt["status"] == "403" and reply.get("code") == "permission_denied":
            observed = receipt.get("observedAtUnixSeconds")
            if type(observed) is not int or not expiry <= observed < jwt_expiry:
                raise ValueError("lifecycle refusal is outside the retained token/JWT expiry window")
            token = retain_actual_token(controls, retained_token["tokenId"], scope)
            if token != retained_token:
                raise ValueError("expiry refusal also changed the selected token lifecycle")
            return {"tokenExpiryUnixSeconds": expiry, "jwtExpiryUnixSeconds": jwt_expiry,
                    "exchange": receipt,
                    "scope": "actual persisted lifecycle refusal; independent actor/Complete/provider joins still required"}
        if receipt["status"] != "200" or reply != retained_whoami:
            raise ValueError("token expiry wait changed actor or returned an unrelated refusal")
        if time.monotonic() >= deadline:
            raise TimeoutError("actual token did not expire within the bounded wait")
        time.sleep(0.25)
