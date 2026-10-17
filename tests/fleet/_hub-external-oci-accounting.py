"""Capture the dedicated External lane across distinct stock and helper epochs.

Proxy files belong to the configured pair and survive its owned transitions.
Native and Worker logs belong to each actual executable lifetime. The collector
never concatenates different process logs or treats a candidate as Managed
permission. Missing decoded, current SQL or provider joins remain unresolved.
"""

import copy
import hashlib
import json
from pathlib import Path


EXTERNAL_CAPTURE_ROLES = ('native', 'worker', 'nativeProxy', 'workerProxy')
EXTERNAL_PROXY_FILES = ('nativeOutbound', 'workerReceived', 'nativeHeaders', 'workerHeaders',
    'workerOriginal', 'workerOriginalHeaders', 'nativeReceived', 'nativeReceivedHeaders')
EXTERNAL_BODY_ROLES = ('nativeOutbound', 'workerReceived', 'workerOriginal', 'nativeReceived')


def external_capture_processes(processes):
    """Select all four real service/proxy pins; forwarding processes stay separate."""
    if not set(EXTERNAL_CAPTURE_ROLES) <= set(processes):
        raise ValueError("External capture is missing a selected process")
    return {role: copy.deepcopy(processes[role]) for role in EXTERNAL_CAPTURE_ROLES}


def join_external_epoch_partition(root, intervals):
    """Require exact contiguous prefixes and exclusive original/received rows."""
    starts = {role: root['rawWindowReceipts'][role]['before']['byteSize'] for role in EXTERNAL_PROXY_FILES}
    assigned = {role: {} for role in EXTERNAL_BODY_ROLES}
    for interval in intervals:
        for role in EXTERNAL_PROXY_FILES:
            receipt = interval['rawWindowReceipts'][role]
            parent = root['rawWindowReceipts'][role]
            if (any(receipt[side][field] != parent[side][field] for side in ('before', 'after')
                    for field in ('path', 'device', 'inode'))
                    or receipt['before']['byteSize'] != starts[role]
                    or receipt['after']['byteSize'] < starts[role]
                    or receipt['capturedBytes'] != receipt['after']['byteSize'] - starts[role]):
                raise ValueError("External process transition omitted or overlapped a proxy prefix")
            starts[role] = receipt['after']['byteSize']
            if role not in assigned:
                continue
            for identity, row in interval['rows'][role].items():
                if identity in assigned[role]:
                    raise ValueError("External original or received row has multiple epoch owners")
                assigned[role][identity] = {**row, 'interval': interval['sequence'], 'scope': interval['scope']}
    if any(starts[role] != root['rawWindowReceipts'][role]['after']['byteSize'] for role in EXTERNAL_PROXY_FILES):
        raise ValueError("External complete proxy corpus has an unassigned suffix")
    for role in EXTERNAL_BODY_ROLES:
        actual = {identity: {key: value for key, value in row.items() if key not in {'interval', 'scope'}}
            for identity, row in assigned[role].items()}
        if actual != root['rows'][role]:
            raise ValueError("External full original/received membership differs from its epochs")
    return {'version': 1, 'complete': True, 'assigned': assigned,
        'inventorySha256': hashlib.sha256(native_corpus_json(root['rows'])).hexdigest(),
        'scope': 'exact captured membership; authentication, purpose and provider evidence remain separate'}


class ExternalOciWorkflowCapture:
    """Retain actual log windows before any normal setup/publication business."""

    def __init__(self, native, worker, s3, tools, prepared, processes, boundaries):
        self.native, self.worker, self.s3, self.tools = native, worker, s3, tools
        self.prepared, self.boundaries = prepared, boundaries
        self.accounting = managed_fixture_module(tools['managedWorkflowAccounting'],
            'external_workflow_accounting_' + prepared['coordinates']['runId'])
        self.run = prepared['coordinates']['runId']
        self.epochs, self.startup = [], []
        self.active, self.root_before, self.last_end = None, None, None
        self.failure, self.sequence = None, 0
        self.provider_before = direct_log_position(s3, tools['python'],
            '/var/lib/hybrid-s3/provider-observations.jsonl')
        self.callers = observe_direct_provider_callers(s3, tools)
        self.resume(prepared, processes, 'ordinary_native')

    def selected(self, prepared, native_role):
        return {**prepared, 'captureSelection': {'run': self.run,
            'sourceDigest': hashlib.sha256(self.tools['workerSourcePath'].encode()).hexdigest(),
            'nativeAddress': self.boundaries['nativeAddress'], 'kind': 'external_oci',
            'nativeRole': native_role}}

    def rows(self, receipts, label):
        rows = {}
        for role in EXTERNAL_BODY_ROLES:
            rows[role] = self.accounting.managed_workflow_rows(receipts[role]['file'],
                lambda text, role=role: (managed_ingress_completion_receipts(text,
                    role == 'nativeReceived')[:2] if role in {'workerOriginal', 'nativeReceived'}
                    else direct_storage_completion_receipts(text, role == 'workerReceived')), receipts[role])
            header_role, header_name = self.accounting.MANAGED_WORKFLOW_HEADER_ROLES[role]
            headers = capture_protected_headers(Path(receipts[header_role]['file']), header_name,
                'external-oci-' + self.run + '-' + label)
            if set(headers) != set(rows[role]):
                raise ValueError("External complete protected headers differ from the proxy corpus")
            for identity, row in rows[role].items():
                header = headers[identity]
                if row['originalRequestId'] != header['originalRequestId']:
                    raise ValueError("External original/received header correlation differs")
                row['transportCallId'] = header['transportCallId']
                compact = {field: {'sha256': value['sha256'], 'byteSize': value['byteSize']}
                    if value else None for field, value in header['files'].items()}
                row['compactSha256'] = hashlib.sha256(native_corpus_json(compact)).hexdigest()
        return rows

    def retain_prefixes(self, before, label, after=None):
        receipts = {}
        for role, position in before.items():
            machine = self.native if role.startswith('native') else self.worker
            path, receipt = retain_direct_log_window(machine, self.tools['python'], position,
                'external-oci-' + self.run + '-' + label + '-' + role + '.jsonl',
                after=None if after is None else after[role])
            receipts[role] = {'file': str(path), **receipt}
        return receipts

    def resume(self, prepared, processes, native_role):
        if self.active is not None or len(self.epochs) >= 16:
            raise ValueError("External process epoch is already live or exceeds its bound")
        self.prepared = self.selected(prepared, native_role)
        label = 'external-whole-' + str(len(self.epochs))
        self.active = copy.deepcopy(begin_managed_storage_window(self.native, self.worker, self.tools,
            self.prepared, external_capture_processes(processes), self.boundaries, label))
        positions = {role: self.active['positions'][role] for role in EXTERNAL_PROXY_FILES}
        if self.root_before is None:
            self.root_before = copy.deepcopy(positions)
        else:
            receipts = self.retain_prefixes(self.last_end, 'startup-' + str(self.sequence), positions)
            self.startup.append({'sequence': self.sequence, 'scope': 'startup',
                'rawWindowReceipts': receipts, 'rows': self.rows(receipts, 'startup-' + str(self.sequence))})
            self.sequence += 1

    def close(self, processes):
        if self.active is None:
            raise ValueError("External process epoch has no actual original")
        token = self.active
        try:
            window = finish_managed_storage_window(self.native, self.worker, self.tools,
                self.prepared, external_capture_processes(processes), self.boundaries, token, token['label'])
        except Exception as error:
            self.failure = type(error).__name__
            receipts = self.retain_prefixes(token['positions'], 'incomplete-' + str(self.sequence))
            window = {'rawWindowReceipts': receipts, 'beforeProcesses': token['beforeProcesses'],
                'failureClass': self.failure, 'nativeBulkBytes': None}
        receipts = window['rawWindowReceipts']
        epoch = {'sequence': self.sequence, 'scope': 'business', 'window': {**window, 'workerLogText': None},
            'processRole': self.prepared['captureSelection']['nativeRole'],
            'rawWindowReceipts': receipts, 'rows': self.rows(receipts, 'epoch-' + str(self.sequence))}
        self.epochs.append(epoch)
        self.sequence += 1
        self.last_end = {role: copy.deepcopy(receipts[role]['after']) for role in EXTERNAL_PROXY_FILES}
        self.active = None
        retain_direct_flow('external-oci-' + self.run + '-epoch-' + str(epoch['sequence']) + '.json', epoch)
        return epoch

    def complete(self, processes):
        if self.active is not None:
            self.close(processes)
        if self.root_before is None or not self.epochs:
            raise ValueError("External complete capture has no actual original epoch")
        receipts = self.retain_prefixes(self.root_before, 'complete')
        root = {'rawWindowReceipts': receipts, 'rows': self.rows(receipts, 'complete')}
        intervals = sorted(self.epochs + self.startup, key=lambda item: item['sequence'])
        try:
            coverage = join_external_epoch_partition(root, intervals)
        except Exception as error:
            self.failure = type(error).__name__
            coverage = {'version': 1, 'complete': False, 'failureClass': self.failure}
        provider_path, provider_receipt = retain_direct_log_window(self.s3, self.tools['python'],
            self.provider_before, 'external-oci-' + self.run + '-provider-private.jsonl')
        provider = provider_boundary_observations(provider_path.read_text(), self.callers)
        result = {'version': 1, 'root': root, 'epochs': self.epochs, 'startup': self.startup,
            'coverage': coverage, 'failureClass': self.failure, 'nativeBulkBytes': None,
            'provider': {'rawWindowReceipt': {'file': str(provider_path), **provider_receipt},
                'observations': provider, 'callers': self.callers}}
        assessment = self.accounting.assess_managed_workflow(result, {},
            source_digest=self.prepared['captureSelection']['sourceDigest'])
        result['bodyAssessment'] = assessment
        retain_direct_flow('external-oci-' + self.run + '-complete-workflow.json',
            self.accounting.managed_workflow_bounded_encoded(result))
        return result


def select_external_storage_codec(tools, artifacts, process, run, role, epoch=None):
    """Select a current decoder against this actual stock or helper executable."""
    import re

    if role not in {'ordinary_native', 'controlled_external_oci_native'}:
        raise ValueError("External codec process role differs")
    label = 'external-oci-' + run + ('-stock-codec' if role == 'ordinary_native' else '-helper-codec')
    if epoch not in {None, 'inventory-restart', 'mirror-functional'}:
        raise ValueError("External codec epoch differs")
    if epoch == 'inventory-restart':
        label = 'external-oci-' + run + '-inventory-codec'
    elif epoch == 'mirror-functional':
        label = 'external-oci-' + run + '-mirror-codec'
    reviewed = await_direct_review(label, {
        'installedArtifacts': retain_direct_flow(label + '-installed-inputs.json', artifacts),
        'actualNativeProcess': retain_direct_flow(label + '-native-process.json', process),
        'commonSource': retain_direct_flow(label + '-sources.json', {
            'commonSourceStorePath': tools['commonSourceStorePath'],
            'workerSourcePath': tools['workerSourcePath'], 'processRole': role}),
    }, {'observerExecutable', 'runtimeCodecRevision', 'runtimeProvenance'})
    selected = reviewed['selection']
    if selected['observerExecutable'] != tools['storageCodecExecutable']:
        raise ValueError("External decoder differs from the actual final installed auxiliary executable")
    provenance = _closed_review_json(direct_selected_bytes(selected['runtimeProvenance'], 65536))
    if (not isinstance(provenance, dict) or set(provenance) != {'version', 'runtimeCodecRevision',
            'nativeExecutableSha256', 'workerSourceDigest', 'sourceArchiveSha256', 'codecSourceSha256'}
            or type(provenance['version']) is not int or provenance['version'] != 1
            or provenance['runtimeCodecRevision'] != selected['runtimeCodecRevision']
            or re.fullmatch(r'[0-9a-f]{40}', provenance['runtimeCodecRevision']) is None
            or provenance['nativeExecutableSha256'] != process['executableSha256']
            or provenance['workerSourceDigest'] != hashlib.sha256(tools['workerSourcePath'].encode()).hexdigest()
            or provenance['codecSourceSha256'] != tools['storageCodecSourceSha256']
            or any(re.fullmatch(r'[0-9a-f]{64}', provenance[field]) is None
                for field in ('sourceArchiveSha256', 'codecSourceSha256'))):
        raise ValueError("External decoder provenance substitutes another executable or source")
    return {'codecSelection': selected, 'codecProvenance': provenance,
        'ingressObservationSources': tools['managedIngressObservationSources']}
