//! Force-cache tests for synthetic builtin attribute thunks.

use super::*;
mod part_1;
mod part_2;

fn synthetic_current_system_identity_for_attr_a(
    ir: &Ir,
    source: &str,
) -> (CacheExprIdentity, IrId) {
    let a = symbol_for(ir, b"a");
    let current_system = symbol_for(ir, b"currentSystem");
    let builtin = lookup_builtin(b"currentSystem").expect("currentSystem builtin is registered");
    let options = TreeWalkOptions::with_current_system(b"x86_64-linux".to_vec())
        .expect("currentSystem is valid");
    let mut evaluator = TreeWalk::with_options_and_source_and_eval_cache(
        ir,
        options,
        "synthetic-builtins.nix",
        source,
        Arc::new(Mutex::new(EvalCacheRuntime::enabled())),
    );
    let root = evaluator.eval_root().expect("attrset evaluates");
    let thunk_value = {
        let attrs = evaluator
            .heap()
            .get_attrs(root)
            .expect("attrset is heap-owned");
        attrs.get(a).expect("a exists")
    };
    let site = evaluator
        .heap()
        .get_thunk(thunk_value)
        .expect("a remains a suspended select thunk")
        .body()
        .expect("a thunk has a lowered select body");
    let identity = evaluator
        .cache_synthetic_builtin_attr_identity(
            EvalNodeRef::new(EvalModuleId::ROOT, site),
            current_system,
            builtin,
        )
        .expect("synthetic currentSystem identity builds");
    (identity, site)
}

fn assert_single_nix_path_entry(evaluator: &TreeWalk, value: Value, prefix: &[u8], path: &[u8]) {
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("nixPath result is a list");
    assert_eq!(list.len(), 1);
    let entry = list.get(0).expect("nixPath has one entry");
    let attrs = evaluator
        .heap()
        .get_attrs(entry)
        .expect("nixPath entry is an attrset");
    assert_eq!(
        attrs.len(),
        2,
        "nixPath entry should contain exactly prefix and path"
    );
    let mut actual_prefix = None;
    let mut actual_path = None;
    for entry in attrs.iter_source_order() {
        let name = evaluator
            .symbols
            .resolve(entry.key)
            .expect("nixPath entry key resolves");
        let value = evaluator
            .heap()
            .get_string(entry.value)
            .expect("nixPath entry value is a string")
            .bytes()
            .to_vec();
        match name {
            b"prefix" => assert!(
                actual_prefix.replace(value).is_none(),
                "nixPath entry contains duplicate prefix"
            ),
            b"path" => assert!(
                actual_path.replace(value).is_none(),
                "nixPath entry contains duplicate path"
            ),
            other => panic!(
                "nixPath entry contains unexpected key {}",
                String::from_utf8_lossy(other)
            ),
        }
    }
    assert_eq!(actual_prefix.as_deref(), Some(prefix));
    assert_eq!(actual_path.as_deref(), Some(path));
}

fn assert_empty_nix_path(evaluator: &TreeWalk, value: Value) {
    let list = evaluator
        .heap()
        .get_list(value)
        .expect("nixPath result is a list");
    assert_eq!(list.len(), 0);
}
