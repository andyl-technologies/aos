"""Install an ordinary layer7 OCI route for the actual fresh Managed pair.

Domain identity creation does not claim DNS verification. The current internal
Hub route controller requires the selected healthy endpoint and verified network
policy, rather than a verified domain. Endpoint evidence comes from the pinned
listener configuration and an actual verified TLS exchange. Normal service-account
grants, ReportEndpoint and CompleteRouteProbe preserve current generation fences.
"""

import base64
import hashlib
import json
import shlex
import time
import urllib.parse


def observe_managed_route_listener(worker, tools, prepared, processes):
    """Recheck the actual Worker and TLS proxy around one verified TLS request."""
    return json.loads(direct_guest_python(worker, tools["python"], """
        import hashlib, os, subprocess
        from pathlib import Path

        def pin(selected_process):
            directory = Path('/proc')/str(selected_process['pid'])
            fields = (directory/'stat').read_text().rpartition(') ')[2].split()
            if (fields[0]=='Z' or fields[19]!=selected_process['startTicks']
                    or directory.stat().st_uid!=selected_process['ownerUid']):
                raise ValueError('Managed route listener lifetime changed')
            argv=(directory/'cmdline').read_bytes()
            if (len(argv)>65536 or hashlib.sha256(argv).hexdigest()!=selected_process['commandLineSha256']
                    or str(len(argv))!=selected_process['commandLineBytes']):
                raise ValueError('Managed route listener invocation changed')
            with (directory/'exe').open('rb') as source:
                sha=hashlib.file_digest(source,'sha256').hexdigest()
            if sha!=selected_process['executableSha256']:
                raise ValueError('Managed route listener executable changed')
            return {'pid':selected_process['pid'],'startTicks':fields[19],'executableSha256':sha,
                'commandLineSha256':hashlib.sha256(argv).hexdigest()}
        before=[pin(item) for item in selected['processes']]
        result=subprocess.run(selected['curl']+['--silent','--show-error','--max-time','5',
            '--max-filesize','262144','--request','POST','--output',selected['bodyFile'],
            '--dump-header',selected['headerFile'],'--write-out','%{http_code}',
            selected['origin']+'/_internal/storage/v1/capabilities'],
            stdin=subprocess.DEVNULL,capture_output=True,check=False,timeout=8)
        if result.returncode or result.stdout!=b'401':
            raise ValueError('Managed verified TLS endpoint did not return its protected refusal')
        if hashlib.sha256(Path(selected['configuration']).read_bytes()).hexdigest()!=selected['configurationSha256']:
            raise ValueError('Managed selected listener configuration changed')
        after=[pin(item) for item in selected['processes']]
        if after!=before:
            raise ValueError('Managed listener changed during verified TLS exchange')
        files={}
        for name in ('bodyFile','headerFile'):
            body=Path(selected[name]).read_bytes()
            if len(body)>262144:
                raise ValueError('Managed endpoint evidence exceeds bound')
            os.chmod(selected[name],0o600)
            files[name]={'path':selected[name],'sha256':hashlib.sha256(body).hexdigest(),'byteSize':len(body)}
        print(json.dumps({'version':1,'origin':selected['origin'],'status':401,
            'before':before,'after':after,'files':files,'configurationSha256':selected['configurationSha256'],
            'scope':'actual listener/verified TLS refusal only; no domain verification or provider authority'}))
    """, {"processes": [processes["worker"], processes["workerProxy"]],
        "configuration": prepared["configurationFile"], "configurationSha256": prepared["configurationSha256"],
        "curl": shlex.split(tools["curl"]), "origin": prepared["coordinates"]["workerOrigin"],
        "bodyFile": prepared["coordinates"]["workerRoot"] + "/endpoint-tls.body",
        "headerFile": prepared["coordinates"]["workerRoot"] + "/endpoint-tls.headers"}, timeout=20))


def managed_controller_token(client, tools, coordinates, secret):
    """Exchange the actual issued provisioning secret without logging material."""
    return json.loads(direct_guest_python(client, tools["python"], """
        import os, subprocess
        from pathlib import Path

        root=Path(selected['root'])
        root.mkdir(mode=0o700,parents=True,exist_ok=False)
        result=subprocess.run(selected['curl']+['--silent','--show-error','--max-time','20',
            '--max-filesize','262144','--request','POST','--header','Content-Type: application/x-www-form-urlencoded',
            '--header','Authorization: Bearer '+selected['secret'],
            '--data-urlencode','grant_type=urn:aos:params:oauth:grant-type:provisioning-token',
            '--output',str(root/'response.json'),'--write-out','%{http_code}',selected['origin']+'/oauth2/token'],
            stdin=subprocess.DEVNULL,capture_output=True,check=False,timeout=25)
        os.chmod(root/'response.json',0o600)
        body=(root/'response.json').read_bytes()
        if result.returncode or result.stdout!=b'200' or len(body)>262144:
            raise ValueError('Actual Managed controller provisioning exchange refused')
        value=json.loads(body)
        if value.get('token_type','').lower()!='bearer' or not value.get('access_token'):
            raise ValueError('Actual Managed controller bearer is absent')
        print(json.dumps({'token':value['access_token']}))
    """, {"root": coordinates["clientRoot"] + "/controller-token",
        "origin": coordinates["workerOrigin"], "secret": secret,
        "curl": shlex.split(tools["curl"])}, timeout=35))["token"]


def configure_managed_distribution(client, worker, tools, prepared, processes, controls, setup,
                                   *, endpoint_origin=None, ingress_kind="ENDPOINT_INGRESS_KIND_LAYER7",
                                   listener_observer=None, organization_slug=None):
    """Use current normal plans and actual endpoint evidence for the root route."""
    coordinates = prepared["coordinates"]
    run = coordinates["runId"]
    organization_slug = organization_slug or "managed-" + run
    require_managed_pair(organization_slug in {"managed-" + run, "external-" + run},
        "Selected ordinary route organization differs")
    origin = endpoint_origin or coordinates["workerOrigin"]
    parsed = urllib.parse.urlsplit(origin)
    require_managed_pair(parsed.scheme == "https" and parsed.hostname and parsed.port
        and not parsed.path and not parsed.query and not parsed.fragment
        and not parsed.username and not parsed.password
        and ingress_kind in {"ENDPOINT_INGRESS_KIND_LAYER7", "ENDPOINT_INGRESS_KIND_HUB"},
        "Selected ordinary endpoint origin or ingress differs")
    organization = controls.call("OrganizationService", "GetOrganization", {
        "slug": organization_slug,
    })["organization"]
    owner = organization["ownerScopeKey"]
    domain = controls.reviewed("DomainService", "PlanCreateDomain", "CreateDomain", {
        "ownerScopeKey": owner, "hostname": parsed.hostname, "expectedResourceVersion": "",
    }, "managed-domain-" + run)["domain"]
    controls.reviewed("NetworkPolicyService", "PlanGrantNetworkPolicyScope", "GrantNetworkPolicyScope", {
        "resourceKind": "network_policy", "resourceStableId": "instance:public", "resourceGeneration": "0",
        "consumerScopeKey": owner, "expectedResourceVersion": "",
    }, "managed-network-grant-" + run)
    probe = json.dumps({"provider": "native_file", "signerSecretRef": coordinates["probeSecretRef"],
        "publicKey": prepared["probePublicKey"]}, separators=(",", ":"))
    endpoint = controls.reviewed("DeliveryService", "PlanCreateEndpoint", "CreateEndpoint", {
        "stableId": coordinates["endpointId"], "ownerScopeKey": owner, "scheme": "https",
        "host": {"domainId": domain["stableId"]}, "effectivePort": parsed.port,
        "networkPolicyId": "instance:public", "expectedResourceVersion": "",
        "revision": {"boundaryRevision": "1", "ingressKind": ingress_kind,
            "listenerConfigurationRef": prepared.get("listenerConfigurationRef", "hub-worker:" + coordinates["workerName"]),
            "tls": {"provider": "external", "certificateRef": tools["issuerCertificate"]},
            "probeConfigurationRef": probe},
    }, "managed-endpoint-" + run)["endpoint"]
    require_managed_pair(endpoint["desiredGeneration"] == "1"
            and endpoint["stableId"] == coordinates["endpointId"],
            "Managed endpoint differs from the independently installed probe generation")
    principal = organization_slug + "/endpoint-controller"
    controls.reviewed("IdentityService", "PlanCreateServiceAccount", "CreateServiceAccount", {
        "orgSlug": organization["slug"], "name": "endpoint-controller", "expectedResourceVersion": "",
    }, "managed-controller-" + run)
    controls.reviewed("IdentityService", "PlanSetMembership", "SetMembership", {
        "principalKind": "service_account", "principalRef": principal, "scope": owner,
        "role": "owner", "expectedResourceVersion": "",
    }, "managed-controller-role-" + run)
    issued = controls.reviewed("IdentityService", "PlanIssueAccessToken", "IssueAccessToken", {
        "owner": "service_account:" + principal, "scope": owner,
        "permissions": ["endpoint.read", "endpoint.manage", "route.manage"],
        "ttlSecs": "3600", "expectedResourceVersion": "", "comment": "Local Managed endpoint controller",
    }, "managed-controller-token-" + run)
    token = managed_controller_token(client, tools, coordinates, issued["secret"])
    controller = DirectBootstrapControls(client, tools["curl"], tools["python"], token,
        private_guest_command, origin=coordinates["workerOrigin"],
        evidence_root=coordinates["clientRoot"] + "/endpoint-controls")
    actual_tls = (observe_managed_route_listener(worker, tools, prepared, processes)
        if listener_observer is None else listener_observer())
    require_managed_pair(actual_tls["origin"] == origin if "origin" in actual_tls else listener_observer is None,
        "Actual endpoint TLS observation differs from its configured origin")
    reported = controller.call("DeliveryControllerService", "ReportEndpoint", {
        "stableId": endpoint["stableId"], "expectedObservationVersion": endpoint["resourceVersion"],
        "controllerLeaseId": "managed-" + run, "controllerGeneration": "1",
        "observation": {"observedGeneration": endpoint["desiredGeneration"],
            "boundaryRevision": endpoint["desired"]["boundaryRevision"], "state": "healthy",
            "listenerObserved": actual_tls["status"] in {200, 401}, "tlsObserved": actual_tls["status"] in {200, 401}},
    })["endpoint"]
    route_id = "managed-oci-" + run
    route = controls.reviewed("RouteService", "PlanCreateRoute", "CreateRoute", {
        "stableId": route_id, "expectedResourceVersion": "",
        "spec": {"surface": {"registrySlug": setup["registry"]["slug"]},
            "endpointId": endpoint["stableId"], "endpointGeneration": endpoint["desiredGeneration"], "basePath": "/",
            "target": {"hubPlacement": {"placementName": setup["placement"]["name"],
                "deliveryKind": "HUB_DELIVERY_KIND_PROXY"}}, "accessPolicy": {"public": True},
            "capabilities": {"servesOci": True}, "enabled": False},
    }, "managed-route-" + run)["route"]
    enabled = controls.reviewed("RouteService", "PlanEnableRoute", "EnableRoute", {
        "stableId": route_id, "expectedResourceVersion": route["resourceVersion"],
    }, "managed-route-enable-" + run)["route"]
    operation = controller.call("RouteControllerService", "CompleteRouteProbe", {
        "stableId": route_id, "expectedObservationVersion": enabled["resourceVersion"],
        "controllerLeaseId": "managed-" + run, "controllerGeneration": "1",
    })["operation"]
    completed = controls.wait_operation(operation["operationId"], {"succeeded"})
    current = controls.call("RouteService", "GetRoute", {"stableId": route_id})["route"]
    require_managed_pair(current["observation"]["state"] == "healthy"
            and current["canonicalRenderedUrl"].rstrip("/") == origin,
            "Actual Managed route controller did not establish the selected root origin")
    return {"domain": domain, "endpoint": reported, "route": current, "operation": completed,
        "listenerEvidence": actual_tls, "controllerObservations": controller.observations,
        "controllerTokenSha256": hashlib.sha256(token.encode()).hexdigest(),
        "domainVerification": None,
        "scope": "normal current layer7 route and actual TLS observation; DNS verification remains absent"}
