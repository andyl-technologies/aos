"""Measure available application producer code without asserting runtime opt-in.

The containing package separately binds the selected archive and actual Worker
artifact. Client availability also needs an explicitly selected same-source CLI
executable. These commitments identify code, not observations or installation.
"""

import hashlib
from pathlib import Path


PAIRS = {
    'sdk': ('crates/aos-hub-worker/src/direct_upload/managed.rs',
            'crates/aos-hub-worker/src/direct_upload/sdk_observation.rs'),
    'client': ('crates/aos-net/src/direct_upload/provider.rs',
               'crates/aos-net/src/direct_upload/provider_observation.rs'),
}
MAX_SOURCE = 1024 * 1024


def commitments(source, client_executable, read_source=None):
    """Recompute the exact concatenated sources used by the compiled producers."""
    source = Path(source)
    if read_source is None:
        def read_source(path, maximum):
            with path.open('rb') as stream:
                raw = stream.read(maximum + 1)
            if len(raw) > maximum:
                raise ValueError('Producer source exceeds bound')
            return raw
    result = {'sdk': None, 'client': None}
    for role, (adapter, observer) in PAIRS.items():
        if not (source / observer).exists():
            continue
        if role == 'client' and client_executable is None:
            continue
        adapter_raw = read_source(source / adapter, MAX_SOURCE)
        observer_raw = read_source(source / observer, MAX_SOURCE)
        # Unsupported producer formulas refuse rather than guessing a log hash.
        expected = [f'include_bytes!("{Path(path).name}")'.encode()
                    for path in (adapter, observer)]
        if any(observer_raw.count(value) != 1 for value in expected):
            raise ValueError('Producer source formula differs')
        result[role] = hashlib.sha256(adapter_raw + observer_raw).hexdigest()
    return result
