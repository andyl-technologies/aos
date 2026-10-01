//! Exercises dependency decisions without substituting publication authority.

use super::*;

fn envelope(name: &str, version: &str, hash: char) -> Envelope {
    let path = format!(
        "/nix/store/{}-{name}-{version}",
        hash.to_string().repeat(32)
    );
    Envelope {
        schema: "aos.package.deployment".into(),
        system: "x86_64-linux".into(),
        package: Artifact {
            name: name.into(),
            version: version.into(),
            path: path.clone(),
            outputs: BTreeMap::from([("out".into(), path)]),
            main_program: None,
        },
        module: Some(ModuleSource {
            name: name.into(),
            version: version.into(),
            source: format!("/nix/store/{}-{name}-module", hash.to_string().repeat(32)),
            entrypoint: "module.nix".into(),
        }),
        version_requirement: None,
        os_version: None,
        module_dependencies: Vec::new(),
        runtime_dependencies: BTreeMap::new(),
    }
}

fn ranged(seed: &Envelope, range: &str) -> ModuleDependency {
    ModuleDependency::Ranged {
        package: seed.module.clone().unwrap(),
        package_version: range.into(),
    }
}

fn bind_requesters(solution: &mut Solution) {
    if let Some(lock) = &mut solution.lock {
        for edge in &lock.edges {
            lock.requesters.insert(
                edge.requester.path.clone(),
                PathBuf::from(format!(
                    "/nix/store/{}-{}-envelope",
                    "f".repeat(32),
                    edge.requester.name
                )),
            );
        }
    }
}

#[test]
fn compatible_package_versions_are_selected() {
    let provider = envelope("provider", "19.4.0", 'b');
    let incompatible = envelope("provider", "1.3.0", 'c');
    let mut consumer = envelope("consumer", "1.0.0", 'a');
    consumer
        .module_dependencies
        .push(ranged(&provider, "^19.4"));

    let mut solved = solve(&[consumer], &[incompatible, provider.clone()], None, false).unwrap();
    bind_requesters(&mut solved);

    assert_eq!(
        solved
            .envelopes
            .iter()
            .find(|package| package.package.name == "provider")
            .unwrap()
            .package
            .version,
        "19.4.0"
    );
    solved.lock.unwrap().validate(&solved.envelopes).unwrap();
}

#[test]
fn transitive_conflict_backtracks_to_an_older_compatible_release() {
    let schema = envelope("schema", "2.0.0", 'b');
    let incompatible_schema = envelope("schema", "3.0.0", 'c');
    let mut older = envelope("engine", "8.0.0", 'd');
    older
        .module_dependencies
        .push(ModuleDependency::Exact(schema.module.clone().unwrap()));
    let mut newer = envelope("engine", "9.0.0", 'f');
    newer.module_dependencies.push(ModuleDependency::Exact(
        incompatible_schema.module.clone().unwrap(),
    ));
    let mut consumer = envelope("consumer", "1.0.0", 'a');
    consumer
        .module_dependencies
        .push(ranged(&older, ">=1, <20"));

    let solved = solve(
        &[consumer, schema.clone()],
        &[newer, older, incompatible_schema, schema],
        None,
        false,
    )
    .unwrap();

    assert_eq!(
        solved
            .envelopes
            .iter()
            .find(|package| package.package.name == "engine")
            .unwrap()
            .package
            .version,
        "8.0.0"
    );
}

#[test]
fn valid_lock_is_preferred_until_explicit_upgrade() {
    let older = envelope("engine", "8.0.0", 'b');
    let newer = envelope("engine", "9.0.0", 'c');
    let mut consumer = envelope("consumer", "1.0.0", 'a');
    consumer
        .module_dependencies
        .push(ranged(&older, ">=1, <20"));
    let previous = solve(&[consumer.clone()], &[older.clone()], None, false)
        .unwrap()
        .lock
        .unwrap();

    let preserved = solve(
        &[consumer.clone()],
        &[newer.clone(), older.clone()],
        Some(&previous),
        false,
    )
    .unwrap();
    let upgraded = solve(&[consumer], &[newer.clone(), older], Some(&previous), true).unwrap();

    assert_eq!(
        preserved
            .envelopes
            .iter()
            .find(|package| package.package.name == "engine")
            .unwrap()
            .package
            .version,
        "8.0.0"
    );
    assert_eq!(
        upgraded
            .envelopes
            .iter()
            .find(|package| package.package.name == "engine")
            .unwrap(),
        &newer
    );
}

#[test]
fn exact_edges_do_not_become_semver_ranges_or_other_providers() {
    let provider = envelope("engine", "calver-p7", 'b');
    let mut rebuild = provider.clone();
    rebuild.module.as_mut().unwrap().source = format!("/nix/store/{}-other-source", "c".repeat(32));
    let mut consumer = envelope("consumer", "1.0.0", 'a');
    consumer
        .module_dependencies
        .push(ModuleDependency::Exact(provider.module.clone().unwrap()));

    assert!(solve(&[consumer.clone()], &[rebuild], None, false).is_err());
    assert!(
        solve(&[consumer], &[provider], None, false)
            .unwrap()
            .lock
            .is_none()
    );
}

#[test]
fn unrelated_packages_cannot_satisfy_a_requirement() {
    let provider = envelope("engine", "8.0.0", 'b');
    let unrelated = envelope("other-engine", "8.0.0", 'c');
    let mut consumer = envelope("consumer", "1.0.0", 'a');
    consumer
        .module_dependencies
        .push(ranged(&provider, ">=1, <20"));

    assert!(solve(&[consumer], &[unrelated.clone()], None, false).is_err());
}

#[test]
fn locked_replay_rejects_changed_requirements_and_source_choices() {
    let provider = envelope("engine", "8.0.0", 'b');
    let mut consumer = envelope("consumer", "1.0.0", 'a');
    consumer
        .module_dependencies
        .push(ranged(&provider, ">=1, <20"));
    let mut solved = solve(&[consumer], &[provider], None, false).unwrap();
    bind_requesters(&mut solved);
    let lock = solved.lock.unwrap();
    lock.validate(&solved.envelopes).unwrap();

    let mut altered = solved.envelopes.clone();
    if let ModuleDependency::Ranged {
        package_version, ..
    } = &mut altered
        .iter_mut()
        .find(|package| package.package.name == "consumer")
        .unwrap()
        .module_dependencies[0]
    {
        *package_version = "^2".into();
    }
    assert!(lock.validate(&altered).is_err());
    let mut forged = lock;
    forged.edges[0].selected.source = format!("/nix/store/{}-replacement", "c".repeat(32));
    assert!(forged.validate(&solved.envelopes).is_err());
}

#[test]
fn moduleless_requesters_have_authenticatable_companion_bindings() {
    let provider = envelope("engine", "8.0.0", 'b');
    let mut aggregate = envelope("aggregate", "1.0.0", 'a');
    aggregate.module = None;
    aggregate
        .module_dependencies
        .push(ranged(&provider, ">=1, <20"));
    let mut solved = solve(&[aggregate.clone()], &[provider], None, false).unwrap();
    bind_requesters(&mut solved);
    let lock = solved.lock.unwrap();

    assert!(lock.requesters.contains_key(&aggregate.package.path));
    lock.validate(&solved.envelopes).unwrap();
}

fn solve(
    roots: &[Envelope],
    candidates: &[Envelope],
    preferred: Option<&ResolutionLock>,
    upgrade: bool,
) -> Result<Solution> {
    super::solve(
        roots,
        candidates,
        preferred,
        &[],
        upgrade
            .then(|| {
                roots
                    .iter()
                    .map(|root| root.package.name.clone())
                    .collect::<BTreeSet<_>>()
            })
            .as_ref(),
        &CancellationToken::default(),
        None,
    )
}

#[test]
fn cancellation_is_not_reported_as_dependency_conflict() {
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let error = super::solve(&[], &[], None, &[], None, &cancellation, None).unwrap_err();
    assert!(error.to_string().contains("module solver cancelled"));
}

#[test]
fn elapsed_search_budget_is_terminal() {
    let cancellation = CancellationToken::default();
    let mut budget = SearchBudget {
        steps: 0,
        deadline: Instant::now(),
        cancellation: &cancellation,
    };
    let error = search(
        BTreeMap::new(),
        &[],
        &SelectionPolicy::new(&[], None, &[], None).unwrap(),
        &mut budget,
        0,
    )
    .unwrap_err();
    assert!(error.downcast_ref::<SearchStopped>().is_some());
}

#[test]
fn retained_exact_only_source_is_preferred_when_a_range_is_introduced() {
    let older = envelope("engine", "8.0.0", 'b');
    let newer = envelope("engine", "9.0.0", 'c');
    let mut consumer = envelope("consumer", "1.0.0", 'a');
    consumer
        .module_dependencies
        .push(ranged(&older, ">=1, <20"));

    let solved = super::solve(
        &[consumer],
        &[newer, older.clone()],
        None,
        &[older.module.clone().unwrap()],
        None,
        &CancellationToken::default(),
        None,
    )
    .unwrap();

    assert!(solved.envelopes.contains(&older));
}

#[test]
fn scoped_upgrade_protects_shared_dependencies_and_their_transitive_choices() {
    let older_driver = envelope("driver", "1.0.0", 'b');
    let newer_driver = envelope("driver", "2.0.0", 'c');
    let mut older_engine = envelope("engine", "8.0.0", 'd');
    older_engine
        .module_dependencies
        .push(ranged(&older_driver, ">=1, <20"));
    let mut newer_engine = envelope("engine", "9.0.0", 'f');
    newer_engine
        .module_dependencies
        .push(ranged(&older_driver, ">=1, <20"));
    let mut consumer = envelope("consumer", "1.0.0", 'a');
    consumer
        .module_dependencies
        .push(ranged(&older_engine, ">=1, <20"));
    let mut protected = envelope("protected", "1.0.0", 'g');
    protected
        .module_dependencies
        .push(ranged(&older_engine, ">=1, <20"));
    let roots = [consumer, protected];
    let previous = solve(
        &roots,
        &[older_engine.clone(), older_driver.clone()],
        None,
        false,
    )
    .unwrap()
    .lock
    .unwrap();
    let candidates = [
        newer_engine.clone(),
        newer_driver.clone(),
        older_engine.clone(),
        older_driver.clone(),
    ];

    let scoped = super::solve(
        &roots,
        &candidates,
        Some(&previous),
        &[],
        Some(&BTreeSet::from(["consumer".into()])),
        &CancellationToken::default(),
        None,
    )
    .unwrap();
    let all = super::solve(
        &roots,
        &candidates,
        Some(&previous),
        &[],
        Some(&BTreeSet::from(["consumer".into(), "protected".into()])),
        &CancellationToken::default(),
        None,
    )
    .unwrap();

    assert!(scoped.envelopes.contains(&older_engine));
    assert!(scoped.envelopes.contains(&older_driver));
    assert!(all.envelopes.contains(&newer_engine));
    assert!(all.envelopes.contains(&newer_driver));
}

#[test]
fn upgrade_refreshes_dependencies_added_by_a_new_candidate_release() {
    let older_driver = envelope("driver", "1.0.0", 'b');
    let newer_driver = envelope("driver", "2.0.0", 'c');
    let older_engine = envelope("engine", "8.0.0", 'd');
    let mut newer_engine = envelope("engine", "9.0.0", 'f');
    newer_engine
        .module_dependencies
        .push(ranged(&older_driver, ">=1, <20"));
    let mut consumer = envelope("consumer", "1.0.0", 'a');
    consumer
        .module_dependencies
        .push(ranged(&older_engine, ">=1, <20"));
    let previous = solve(&[consumer.clone()], &[older_engine.clone()], None, false)
        .unwrap()
        .lock
        .unwrap();

    let solved = super::solve(
        &[consumer],
        &[
            newer_engine.clone(),
            newer_driver.clone(),
            older_engine,
            older_driver.clone(),
        ],
        Some(&previous),
        &[older_driver.module.unwrap()],
        Some(&BTreeSet::from(["consumer".into()])),
        &CancellationToken::default(),
        None,
    )
    .unwrap();

    assert!(solved.envelopes.contains(&newer_engine));
    assert!(solved.envelopes.contains(&newer_driver));
}

#[test]
fn depth_exhaustion_remains_a_terminal_error() {
    let cancellation = CancellationToken::default();
    let mut budget = SearchBudget {
        steps: 0,
        deadline: Instant::now() + Duration::from_secs(30),
        cancellation: &cancellation,
    };
    let policy = SelectionPolicy::new(&[], None, &[], None).unwrap();

    let error = search(
        BTreeMap::new(),
        &[],
        &policy,
        &mut budget,
        MAX_SEARCH_DEPTH + 1,
    )
    .unwrap_err();

    assert!(error.downcast_ref::<SearchStopped>().is_some());
}

#[test]
fn os_compatibility_filters_candidates_without_changing_the_host_release() {
    let release = aos_doc_model::runtime::OsRelease {
        name: "aos".into(),
        version: "1.4.0".into(),
    };
    let mut older = envelope("engine", "8.0.0", 'b');
    older.os_version = Some("^1.0".into());
    let mut newer = envelope("engine", "9.0.0", 'c');
    newer.os_version = Some("^2.0".into());
    let mut consumer = envelope("consumer", "1.0.0", 'a');
    consumer
        .module_dependencies
        .push(ranged(&older, ">=8, <10"));

    let solution = super::solve(
        &[consumer],
        &[older.clone(), newer],
        None,
        &[],
        None,
        &CancellationToken::default(),
        Some(&release),
    )
    .unwrap();

    assert!(solution.envelopes.contains(&older));
    assert_eq!(release.version, "1.4.0");
}

#[test]
fn os_constraints_on_moduleless_roots_require_a_compatible_host_release() {
    let mut aggregate = envelope("aggregate", "1.0.0", 'a');
    aggregate.module = None;
    aggregate.os_version = Some("^1.0".into());
    let release = aos_doc_model::runtime::OsRelease {
        name: "aos".into(),
        version: "2.0.0".into(),
    };

    for host in [None, Some(&release)] {
        assert!(
            super::solve(
                &[aggregate.clone()],
                &[],
                None,
                &[],
                None,
                &CancellationToken::default(),
                host,
            )
            .is_err()
        );
    }
}
