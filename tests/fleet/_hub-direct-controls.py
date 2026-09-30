"""Issue real reviewed bootstrap decisions through the public Native API.

Requests carry metadata and immutable secret references. Material installation
belongs to the separate Worker operator. Raw requests/replies stay in the private
client fixture directory; the driver retains numeric sizes and commitments.
"""

import hashlib
import json
import re
import shlex
import time


def direct_root_browser_token(client, curl, python, private_command, reuse_session=False):
    """Obtain the genuine root browser bearer without retaining its material in logs."""
    arguments = shlex.split(curl)
    command = (
        "# Private root browser fixture authentication.\n"
        f"{shlex.quote(python)} - <<'DIRECT_BROWSER_LOGIN'\n"
        "import json,os,re,subprocess\nfrom pathlib import Path\n"
        "root=Path('/var/lib/hybrid-client/browser-session')\n"
        f"reuse_session={reuse_session!r}\n"
        "if reuse_session:\n"
        "    if not root.is_dir() or not (root/'cookies').is_file():raise RuntimeError('root browser session absent')\n"
        "else:root.mkdir(mode=0o700,parents=True,exist_ok=False)\n"
        "os.umask(0o077)\n"
        f"curl={arguments!r}\n"
        "origin='https://aos.andyl.org'\n"
        "cookie=str(root/'cookies')\n"
        "def request(arguments):\n"
        "    result=subprocess.run(curl+['-sS','--max-time','60','--max-filesize','262144']+arguments,capture_output=True,timeout=65)\n"
        "    if result.returncode!=0:raise RuntimeError('root browser transport failed')\n"
        "    return result.stdout\n"
        "if not reuse_session:\n"
        "    status=request(['-c',cookie,'-o',str(root/'login-body'),'-w','%{http_code}',\n"
        "    '-X','POST','-H','cf-connecting-ip: 192.0.2.10',\n"
        "    '--data-urlencode','email=fleet-root@example.test',\n"
        "    '--data-urlencode','password=fleet-root-password',origin+'/login/password'])\n"
        "    if status not in {b'302',b'303'}:raise RuntimeError('root browser login refused')\n"
        "status=request(['-b',cookie,'-o',str(root/'instance.html'),'-w','%{http_code}',\n"
        "    '-H','cf-connecting-ip: 192.0.2.10',origin+'/-/instance'])\n"
        "if status!=b'200':raise RuntimeError('root browser instance refused')\n"
        "html=(root/'instance.html').read_bytes()\n"
        "if len(html)>262144:raise RuntimeError('root browser instance exceeds bound')\n"
        "csrf=re.findall(rb'name=\"aos-session-csrf\" content=\"([^\"]+)\"',html)\n"
        "if len(csrf)!=1:raise RuntimeError('root browser CSRF capture invalid')\n"
        "session_reply=request(['-b',cookie,'-w','\\n%{http_code}',\n"
        "    '-X','POST','-H','cf-connecting-ip: 192.0.2.10','-H','Origin: '+origin,\n"
        "    '-H','x-aos-csrf: '+csrf[0].decode(),'-H','x-aos-console-route: /-/instance',\n"
        "    origin+'/-/auth/session-token'])\n"
        "body,separator,status=session_reply.rpartition(b'\\n')\n"
        "if not separator or status!=b'200':raise RuntimeError('root browser bearer refused')\n"
        "token=json.loads(body)['accessToken']\n"
        "if not isinstance(token,str) or not token:raise RuntimeError('root browser bearer missing')\n"
        "print(json.dumps({'accessToken':token}))\n"
        "DIRECT_BROWSER_LOGIN\n"
    )
    return json.loads(private_command(client, command, timeout=210))["accessToken"]


class DirectBootstrapControls:
    """Retain actual metadata controls and apply the server's persisted plans."""

    def __init__(self, client, curl, python, token, private_command, refresh_token=None):
        self.client = client
        self.curl = curl
        self.python = python
        self.token = token
        self.private_command = private_command
        self.refresh_token = refresh_token
        self.token_refreshed_at = time.monotonic()
        self.observations = []
        client.succeed("install -d -m 0700 /var/lib/hybrid-client/bootstrap-controls")

    def call(self, service, method, request):
        """Send one actual bounded metadata request without logging its bearer."""
        # Console bearers expire after 300 seconds. Refresh before a new control
        # after a review wait; never replay a mutation on an ambiguous exchange.
        if self.refresh_token is not None and time.monotonic() - self.token_refreshed_at >= 120:
            self.token = self.refresh_token()
            self.token_refreshed_at = time.monotonic()
        if service not in {
            "BindingService", "StorageAuthorityService", "IdentityService",
            "OrganizationService", "OperationService", "RegistryService",
            "TopologyService",
        }:
            raise ValueError("bootstrap control service is not allowed")
        if not re.fullmatch(r"[A-Z][A-Za-z]{0,63}", method):
            raise ValueError("bootstrap control method is invalid")
        body = json.dumps(request, separators=(",", ":"))
        body_bytes = body.encode()
        if len(body_bytes) >= 64 * 1024:
            raise ValueError("bootstrap metadata request exceeds the legacy request gate")
        sequence = len(self.observations)
        root = f"/var/lib/hybrid-client/bootstrap-controls/{sequence:04d}"
        route = f"/aos.hub.v1.{service}/{method}"
        observation = {
            "sequence": sequence, "route": route, "outcome": "pending",
            "request_body_bytes": len(body_bytes),
            "request_body_sha256": hashlib.sha256(body_bytes).hexdigest(),
            "traffic_class": "bootstrap_metadata_control",
        }
        self.observations.append(observation)
        command = (
            "set -eu\numask 077\n"
            f"test ! -e {root}.request.json\ntest ! -e {root}.response.json\n"
            f"printf '%s' {shlex.quote(body)} > {root}.request.json\n"
            f"{self.curl} -sS --max-filesize 262144 "
            f"-o {root}.response.json -w '%{{http_code}}' -X POST "
            "-H 'Content-Type: application/json' -H 'Connect-Protocol-Version: 1' "
            "-H 'cf-connecting-ip: 192.0.2.10' "
            f"-H {shlex.quote('Authorization: Bearer ' + self.token)} "
            f"--data-binary @{root}.request.json https://aos.andyl.org{route}\n"
        )
        try:
            status_text = self.private_command(self.client, command, timeout=120).strip()
        except RuntimeError:
            observation["outcome"] = "unknown"
            raise
        if not re.fullmatch(r"[0-9]{3}", status_text):
            raise RuntimeError("bootstrap control returned no HTTP status")
        response = self.private_command(
            self.client,
            f"{shlex.quote(self.python)} - <<'BOOTSTRAP_RESPONSE'\n"
            "from pathlib import Path\nimport sys\n"
            f"body = Path({root + '.response.json'!r}).read_bytes()\n"
            "if len(body) > 262144: raise ValueError('bootstrap response exceeds bound')\n"
            "sys.stdout.buffer.write(body)\nBOOTSTRAP_RESPONSE\n",
        )
        response_bytes = response.encode()
        observation.update({
            "http_status": int(status_text),
            "response_body_bytes": len(response_bytes),
            "response_body_sha256": hashlib.sha256(response_bytes).hexdigest(),
            "outcome": "received",
        })
        if observation["http_status"] != 200:
            raise RuntimeError(f"actual bootstrap control refused with HTTP {status_text}")
        return json.loads(response)

    def reviewed(self, service, plan_method, apply_method, request, label):
        """Apply only the exact plan ID and confirmation returned by Native."""
        planned = self.call(service, plan_method, {
            **request, "idempotencyKey": label + "-plan",
        })
        plan = planned["plan"]
        if not plan["effects"] or not plan["planId"] or not plan["confirmationHash"]:
            raise ValueError("Native returned an incomplete reviewed bootstrap plan")
        return self.call(service, apply_method, {
            "planId": plan["planId"], "confirmationHash": plan["confirmationHash"],
            "idempotencyKey": label + "-apply",
        })

    def authority_decision(self, decision, expected_resource_version, label):
        """Apply one genuine root authority decision with its current version pin."""
        return self.reviewed(
            "StorageAuthorityService", "PlanStorageAuthorityDecision",
            "StorageAuthorityDecision", {
                "decision": decision,
                "expectedResourceVersion": str(expected_resource_version),
            }, label,
        )

    def create_external_binding(self, org_slug, display_name, binding_stable_id,
                                binding_name, provider_coordinates):
        """Create an organization-owned private binding through persisted plans."""
        required = {"bucket", "prefix", "endpoint", "signingRegion", "accessMode"}
        if set(provider_coordinates) != required or provider_coordinates["accessMode"] != "private":
            raise ValueError("External fixture requires explicit private S3 coordinates")
        organization = self.reviewed(
            "OrganizationService", "PlanCreateOrganization", "CreateOrganization", {
                "slug": org_slug, "displayName": display_name,
                "expectedResourceVersion": "",
            }, "fleet-direct-organization",
        )["organization"]
        owner = organization["ownerScopeKey"]
        if not owner or organization["slug"] != org_slug:
            raise ValueError("Native returned another organization owner")
        binding = self.reviewed(
            "BindingService", "PlanCreateBinding", "CreateBinding", {
                "stableId": binding_stable_id, "ownerScopeKey": owner,
                "expectedResourceVersion": "",
                "spec": {"name": binding_name, "s3": provider_coordinates},
            }, "fleet-direct-binding",
        )["binding"]
        if binding["stableId"] != binding_stable_id or binding["ownerScopeKey"] != owner:
            raise ValueError("Native returned another private binding")
        return organization, binding

    def get_external_binding(self, org_slug, binding_name):
        """Read current public binding identity and its resource version."""
        return self.call("BindingService", "GetBinding", {
            "binding": {"organization": {"orgSlug": org_slug, "name": binding_name}},
        })["binding"]

    def create_external_registry(self, organization, binding, registry_name,
                                 trust_keys, placement_name, placement_prefix,
                                 current_write_revision, requires_conditional_writes):
        """Select External storage through a genuine scan and writer promotion."""
        if binding["ownerScopeKey"] != organization["ownerScopeKey"]:
            raise ValueError("registry and External binding require the same actual owner")
        if not trust_keys or any(not isinstance(key, str) or not key for key in trust_keys):
            raise ValueError("registry requires the actual signed publisher trust anchors")
        binding_prefix = binding["spec"]["s3"]["prefix"].rstrip("/")
        if (
            not binding_prefix or not placement_prefix.startswith(binding_prefix + "/")
            or any(part in {"", ".", ".."} for part in placement_prefix.split("/"))
            or type(requires_conditional_writes) is not bool
            or not re.fullmatch(r"[1-9][0-9]*", str(current_write_revision))
        ):
            raise ValueError("registry placement does not pin the admitted physical scope and writer")

        registry = self.reviewed(
            "RegistryService", "PlanCreateRegistry", "CreateRegistry", {
                "orgSlug": organization["slug"], "projectPath": "",
                "name": registry_name, "visibility": "private", "trustKeys": trust_keys,
                "expectedResourceVersion": "",
            }, "fleet-direct-registry",
        )["registry"]
        surface = {"registrySlug": registry["slug"]}
        self.reviewed(
            "TopologyService", "PlanCreatePlacement", "CreatePlacement", {
                "surface": surface, "name": placement_name, "bindingId": binding["stableId"],
                "prefix": placement_prefix, "kind": "complete", "desiredState": "active",
                "desiredReadEnabled": True, "readOrder": "0",
                "requiresConditionalWrites": requires_conditional_writes,
                "expectedResourceVersion": "",
            }, "fleet-direct-placement",
        )
        placement = self.call("TopologyService", "GetPlacement", {
            "surface": surface, "name": placement_name,
        })["placement"]
        scan = self.reviewed(
            "TopologyService", "PlanScanPlacement", "ScanPlacement", {
                "surface": surface, "placementName": placement_name,
                "expectedResourceVersion": placement["resourceVersion"],
            }, "fleet-direct-placement-scan",
        )["operation"]
        completed_scan = self.wait_operation(scan["operationId"], {"succeeded"})
        placement = self.call("TopologyService", "GetPlacement", {
            "surface": surface, "name": placement_name,
        })["placement"]
        if (
            placement["prefix"] != placement_prefix
            or placement["spec"]["kind"] != "complete"
            or placement["spec"]["desiredState"] != "active"
            or placement["observation"]["state"] != "ready"
            or placement["observation"]["completeness"] != "complete"
        ):
            raise RuntimeError("actual placement scan did not establish the selected complete namespace")
        self.reviewed(
            "TopologyService", "PlanPromotePlacement", "PromotePlacement", {
                "surface": surface, "placementName": placement_name,
                "expectedResourceVersion": placement["resourceVersion"],
            }, "fleet-direct-placement-promote",
        )

        deadline = time.monotonic() + 120
        while True:
            authority = self.call("TopologyService", "GetWriteAuthority", {
                "surface": surface,
            })["authority"]
            state = authority["reconciliationState"]
            if state == "ready":
                break
            if state == "failed" or time.monotonic() >= deadline:
                raise RuntimeError("actual registry writer did not reconcile within the bound")
            time.sleep(0.5)
        if (
            authority["desiredPlacementName"] != placement_name
            or authority["observedPlacementName"] != placement_name
            or str(authority["desiredBindingWriteRevision"]) != str(current_write_revision)
            or str(authority["observedBindingWriteRevision"]) != str(current_write_revision)
            or authority["observedGeneration"] != authority["desiredGeneration"]
        ):
            raise RuntimeError("actual registry authority selected another placement or writer")
        placement = self.call("TopologyService", "GetPlacement", {
            "surface": surface, "name": placement_name,
        })["placement"]
        if (
            placement["status"]["observedWriter"] is not True
            or placement["status"]["effectiveWriteEnabled"] is not True
        ):
            raise RuntimeError("promoted registry placement has no actual effective writer")
        return {"registry": registry, "placement": placement,
                "completedScan": completed_scan, "authority": authority}

    def validate_external_credentials(self, org_slug, binding_name, versions,
                                      fingerprint, stage_original):
        """Exercise actual unstaged refusal, Worker staging and controller validation."""
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
            raise ValueError("provider material fingerprint is invalid")
        purposes = [purpose for purpose in ("presign", "read", "list", "delete", "write")
                    if purpose in versions]
        if set(purposes) != set(versions) or not {"presign", "read", "write"}.issubset(versions):
            raise ValueError("External credential selection is incomplete")

        validated = {}
        for purpose in purposes:
            # Write validation selects the current writer and changes write-state
            # pins. Completing every other original first avoids stale claims.
            binding = self.get_external_binding(org_slug, binding_name)
            credential = self.reviewed(
                "BindingService", "PlanSetBindingCredential", "SetBindingCredential", {
                    "bindingId": binding["stableId"], "purpose": purpose,
                    "secretVersionRef": versions[purpose],
                    "credentialFingerprint": fingerprint,
                    "expectedResourceVersion": binding["resourceVersion"],
                    "expectedCurrentGeneration": "0",
                }, "fleet-direct-credential-" + purpose,
            )["credential"]
            if (
                credential["bindingId"] != binding["stableId"]
                or credential["purpose"] != purpose
                or credential["secretVersionRef"] != versions[purpose]
                or credential["credentialFingerprint"] != fingerprint
                or credential["validationState"] == "valid"
            ):
                raise ValueError("Native returned another or prematurely validated credential")

            queued = self.reviewed(
                "BindingService", "PlanValidateBindingCredential", "ValidateBindingCredential", {
                    "bindingId": binding["stableId"], "purpose": purpose,
                    "generation": str(credential["generation"]),
                    "expectedResourceVersion": credential["resourceVersion"],
                }, "fleet-direct-validate-" + purpose,
            )["operation"]
            operation_id = queued["operationId"]
            initial_failure = self.wait_operation(operation_id, {"failed"})
            # This original has never been staged. Retain its real refusal before
            # installing material and explicitly retrying that same persisted task.
            stage_receipt = stage_original(operation_id, purpose)
            current_failure = self.operation(operation_id)
            if current_failure["resourceVersion"] != initial_failure["resourceVersion"]:
                raise ValueError("unstaged original changed before its explicit retry")
            self.retry_failed_operation(current_failure, "fleet-direct-retry-" + purpose)
            completed = self.wait_operation(operation_id, {"succeeded"})
            validated[purpose] = {
                "credential": credential, "operationId": operation_id,
                "initialUnstagedFailure": initial_failure,
                "stageReceipt": stage_receipt, "completedOperation": completed,
            }
        return validated

    def operation(self, operation_id):
        """Read the persisted operation and require its exact original identity."""
        detail = self.call("OperationService", "GetOperation", {
            "operationId": operation_id,
        })["operation"]
        if detail["operation"]["operationId"] != operation_id:
            raise ValueError("Native returned another queued operation")
        return detail

    def wait_operation(self, operation_id, terminal_states, timeout=120):
        """Observe a bounded controller outcome without replaying its task."""
        expected = set(terminal_states)
        if not expected or not expected.issubset({"succeeded", "failed", "cancelled"}):
            raise ValueError("invalid expected controller terminal states")
        deadline = time.monotonic() + timeout
        while True:
            detail = self.operation(operation_id)
            state = detail["operation"]["state"]
            if state in {"succeeded", "failed", "cancelled"}:
                if state not in expected:
                    raise RuntimeError(f"actual topology controller ended in {state}")
                return detail
            if time.monotonic() >= deadline:
                raise RuntimeError("actual topology controller did not finish within the bound")
            time.sleep(0.5)

    def retry_failed_operation(self, detail, label):
        """Request an explicit retry using the observed failed original's CAS."""
        operation = detail["operation"]
        if operation["state"] != "failed":
            raise ValueError("only an observed failed operation may be explicitly retried")
        return self.call("OperationService", "RetryOperation", {
            "operationId": operation["operationId"],
            "expectedResourceVersion": detail["resourceVersion"],
            "idempotencyKey": label,
        })


def admit_external_fixture_authority(controls, org_slug, binding, sql_pins, reviewed,
                                     observed_native_time):
    """Apply only independently selected authority inputs with actual SQL/API pins."""
    fields = {
        "authorityId", "aliasId", "associationId", "attestationId", "guardNamespaceId",
        "physicalResourceEvidenceDigest", "qualificationDigest", "qualifiedManagedPrefix",
        "equivalenceEvidenceDigest", "providerPolicyEvidenceDigest", "executorIdentity",
        "attestationLifetimeSeconds",
    }
    if set(reviewed) != fields:
        raise ValueError("independent authority selection differs from the closed fixture schema")
    lifetime = reviewed["attestationLifetimeSeconds"]
    if type(lifetime) is not int or not 1 <= lifetime <= 3600:
        raise ValueError("independently selected attestation exceeds the fixture run bound")
    if type(observed_native_time) is not int or observed_native_time <= 0:
        raise ValueError("actual Native clock observation is unavailable")
    if (
        sql_pins["bindingStableId"] != binding["stableId"]
        or sql_pins["bindingResourceVersion"] != binding["resourceVersion"]
    ):
        raise ValueError("selected binding differs between SQL and the actual public API")

    writer = controls.call("BindingService", "GetBindingWriteRevision", {
        "binding": {"organization": {
            "orgSlug": org_slug, "name": binding["spec"]["name"],
        }}, "revision": sql_pins["currentWriteRevision"],
    })["revision"]
    write_credential = next(item for item in sql_pins["credentials"] if item["purpose"] == "write")
    if (
        writer["bindingId"] != binding["stableId"]
        or str(writer["revision"]) != sql_pins["currentWriteRevision"]
        or str(writer["writeCredentialGeneration"]) != write_credential["generation"]
        or writer["writeCredentialVersionRef"] != write_credential["secretVersionRef"]
        or writer["validationState"] != "valid" or writer["writesSupported"] is not True
    ):
        raise ValueError("current public writer has no matching positive controller evidence")

    creation = {key: reviewed[key] for key in (
        "authorityId", "guardNamespaceId", "physicalResourceEvidenceDigest",
        "qualificationDigest", "qualifiedManagedPrefix",
    )}
    controls.authority_decision({"create": creation}, "", "fleet-direct-authority")
    authority = controls.call("StorageAuthorityService", "GetAuthority", {
        "authorityId": reviewed["authorityId"],
    })
    provider = binding["spec"]["s3"]
    controls.authority_decision({"approveAlias": {
        "aliasId": reviewed["aliasId"], "authorityId": reviewed["authorityId"],
        "address": {"dnsName": provider["endpoint"]["dnsName"],
                    "port": provider["endpoint"]["port"], "bucket": provider["bucket"]},
        "equivalenceEvidenceDigest": reviewed["equivalenceEvidenceDigest"],
    }}, authority["resourceVersion"], "fleet-direct-alias")
    controls.authority_decision({"associateBinding": {
        "associationId": reviewed["associationId"], "authorityId": reviewed["authorityId"],
        "aliasId": reviewed["aliasId"], "bindingId": sql_pins["bindingId"],
        "bindingStableId": binding["stableId"],
        "bindingResourceVersion": binding["resourceVersion"],
        "bindingWriteRevision": sql_pins["currentWriteRevision"],
        "bindingPrefix": sql_pins["bindingPrefix"],
    }}, binding["resourceVersion"], "fleet-direct-association")
    members = [{"associationId": reviewed["associationId"], **{
        key: credential[key] for key in
        ("purpose", "generation", "secretVersionRef", "credentialFingerprint")
    }} for credential in sql_pins["credentials"]]
    controls.authority_decision({"attest": {
        "attestationId": reviewed["attestationId"], "authorityId": reviewed["authorityId"],
        "managedPrefix": reviewed["qualifiedManagedPrefix"],
        "qualificationDigest": reviewed["qualificationDigest"],
        "providerPolicyEvidenceDigest": reviewed["providerPolicyEvidenceDigest"],
        "executorIdentity": reviewed["executorIdentity"], "credentials": members,
        "validUntil": str(observed_native_time + lifetime),
    }}, authority["resourceVersion"], "fleet-direct-attestation")
    controls.authority_decision({"setAdmission": {
        "authorityId": reviewed["authorityId"], "expectedGeneration": "0",
        "guardNamespaceId": reviewed["guardNamespaceId"],
        "state": "STORAGE_AUTHORITY_DESIRED_STATE_ADMITTED",
        "attestationId": reviewed["attestationId"],
        "associationIds": [reviewed["associationId"]],
    }}, "0", "fleet-direct-admission")
    return controls.call("StorageAuthorityService", "GetAuthority", {
        "authorityId": reviewed["authorityId"],
    })
