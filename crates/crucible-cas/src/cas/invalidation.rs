/// A named set of content-addressed inputs recorded for an invalidation query.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DependencySnapshot {
    inputs: BTreeMap<String, ContentHash>,
}

impl DependencySnapshot {
    /// Builds an empty dependency snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `hash` for dependency `name`.
    pub fn insert(&mut self, name: impl Into<String>, hash: ContentHash) {
        self.inputs.insert(name.into(), hash);
    }

    /// Returns the recorded hash for `name`, if present.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<ContentHash> {
        self.inputs.get(name).copied()
    }

    /// Returns an iterator over dependency names and content hashes.
    pub fn iter(&self) -> impl Iterator<Item = (&str, ContentHash)> {
        self.inputs
            .iter()
            .map(|(name, hash)| (name.as_str(), *hash))
    }

    /// Returns the number of dependencies in the snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inputs.len()
    }

    /// Returns whether the snapshot contains no dependencies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty()
    }
}

/// A dependency-gated invalidation query for a previously computed node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidationQuery {
    baseline: DependencySnapshot,
}

impl InvalidationQuery {
    /// Builds a query from the dependency snapshot recorded with a node.
    #[must_use]
    pub fn new(baseline: DependencySnapshot) -> Self {
        Self { baseline }
    }

    /// Returns the baseline dependency snapshot.
    #[must_use]
    pub fn baseline(&self) -> &DependencySnapshot {
        &self.baseline
    }

    /// Evaluates the query against `current` dependency hashes.
    #[must_use]
    pub fn evaluate(&self, current: &DependencySnapshot) -> InvalidationDecision {
        let mut names = BTreeSet::new();
        for (name, _) in self.baseline.iter() {
            names.insert(name.to_owned());
        }
        for (name, _) in current.iter() {
            names.insert(name.to_owned());
        }

        let mut changed = BTreeMap::new();
        for name in names {
            let before = self.baseline.get(&name);
            let after = current.get(&name);
            if before != after {
                changed.insert(name, DependencyChange { before, after });
            }
        }

        InvalidationDecision { changed }
    }

    /// Returns whether `current` invalidates the node.
    #[must_use]
    pub fn is_invalid(&self, current: &DependencySnapshot) -> bool {
        self.evaluate(current).is_invalid()
    }
}

/// The result of a dependency-gated invalidation query.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InvalidationDecision {
    changed: BTreeMap<String, DependencyChange>,
}

impl InvalidationDecision {
    /// Returns whether any dependency hash changed, appeared, or disappeared.
    #[must_use]
    pub fn is_invalid(&self) -> bool {
        !self.changed.is_empty()
    }

    /// Returns the inputs whose hashes changed.
    #[must_use]
    pub fn changed_inputs(&self) -> &BTreeMap<String, DependencyChange> {
        &self.changed
    }
}

/// A before/after dependency hash pair for one changed input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DependencyChange {
    /// The hash recorded with the node, if the dependency existed then.
    pub before: Option<ContentHash>,
    /// The hash observed for the dependency now, if the dependency exists now.
    pub after: Option<ContentHash>,
}

fn local_store_temp_path(path: &Path, key: &ContentHash) -> PathBuf {
    let mut temp_path = path.to_path_buf();
    temp_path.set_file_name(format!(".{}.tmp", key.to_hex()));
    temp_path
}

static SHARED_STORE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
const SHARED_STORE_TEMP_CREATE_ATTEMPTS: usize = 4096;

fn shared_store_temp_path(path: &Path, key: &ContentHash, sequence: u64) -> PathBuf {
    let mut temp_path = path.to_path_buf();
    temp_path.set_file_name(format!(
        ".{}.{}.{}.tmp",
        key.to_hex(),
        std::process::id(),
        sequence
    ));
    temp_path
}

fn create_shared_store_temp_file(
    path: &Path,
    key: &ContentHash,
    bytes: &[u8],
) -> Result<PathBuf, CasError> {
    create_shared_store_temp_file_with(path, key, bytes, || {
        SHARED_STORE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    })
}

fn create_shared_store_temp_file_with(
    path: &Path,
    key: &ContentHash,
    bytes: &[u8],
    mut next_sequence: impl FnMut() -> u64,
) -> Result<PathBuf, CasError> {
    for _ in 0..SHARED_STORE_TEMP_CREATE_ATTEMPTS {
        let temp_path = shared_store_temp_path(path, key, next_sequence());
        let mut temp_file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(temp_file) => temp_file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(CasError::Io {
                    operation: "create-temp",
                    path: temp_path,
                    source,
                });
            }
        };
        if let Err(source) = temp_file.write_all(bytes) {
            let _ = fs::remove_file(&temp_path);
            return Err(CasError::Io {
                operation: "write",
                path: temp_path,
                source,
            });
        }
        return Ok(temp_path);
    }

    Err(CasError::Io {
        operation: "create-temp",
        path: path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "exhausted shared store temporary path attempts",
        ),
    })
}
