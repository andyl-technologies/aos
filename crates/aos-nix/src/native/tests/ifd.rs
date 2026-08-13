//! Tests for import-from-derivation realization during native instantiation.

use super::*;

#[test]
fn native_instantiation_uses_configured_ifd_realizer() -> Result<()> {
    let root = unique_temp_dir("native-ifd");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    fs::create_dir(&store)?;
    let drv_path = store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ifd.drv");
    let output_path = store.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-ifd");
    let import_path = output_path.join("imported.nix");
    let builder = store.join("cccccccccccccccccccccccccccccccc-builder");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_realizer = Arc::clone(&requests);
    let drv_path_for_realizer = drv_path.as_os_str().as_bytes().to_vec();
    let import_path_for_realizer = import_path.clone();
    let output_path_for_realizer = output_path.clone();
    let realizer = IfdRealizer::new(move |request| {
        requests_for_realizer
            .lock()
            .expect("request log lock")
            .push((
                request.path().to_vec(),
                request.drv_path().to_vec(),
                request.output_name().map(<[u8]>::to_vec),
                request.context_kind(),
                request.op(),
            ));
        if request.drv_path() != drv_path_for_realizer.as_slice() {
            return Err(IfdRealizationError::new("unexpected derivation path"));
        }
        fs::create_dir_all(&output_path_for_realizer)
            .map_err(|source| IfdRealizationError::new(source.to_string()))?;
        fs::write(&import_path_for_realizer, br#""from-ifd""#)
            .map_err(|source| IfdRealizationError::new(source.to_string()))?;
        Ok(())
    });
    let options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    let native = NixNative::with_options(0, options)?.with_ifd_realizer(realizer);
    let source = format!(
        r#"let
             imported = builtins.appendContext {imported} {{
               {drv} = {{ outputs = [ "out" ]; }};
             }};
             d = builtins.derivationStrict {{
               name = "native-ifd";
               system = "x86_64-linux";
               builder = {builder};
               args = [ (import imported) ];
             }};
           in d.drvPath"#,
        imported = nix_string_literal(&path_bytes(&import_path)?)?,
        drv = nix_string_literal(&path_bytes(&drv_path)?)?,
        builder = nix_string_literal(&path_bytes(&builder)?)?,
    );

    let path = native.eval_derivation_path_source(&source, None)?;
    assert!(path.to_string_lossy().ends_with("-native-ifd.drv"));
    let requests = requests.lock().expect("request log lock");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, import_path.as_os_str().as_bytes());
    assert_eq!(requests[0].1, drv_path.as_os_str().as_bytes());
    assert_eq!(requests[0].2.as_deref(), Some(b"out".as_slice()));
    assert_eq!(requests[0].3, crate::string::ContextKind::SingleOutput);
    assert_eq!(requests[0].4, "import");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_ifd_materializes_known_drv_before_realizer() -> Result<()> {
    use std::ffi::OsStr;

    let root = unique_temp_dir("native-ifd-known-drv");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    fs::create_dir(&store)?;
    let builder = store.join("cccccccccccccccccccccccccccccccc-builder");
    let store_for_realizer = store.clone();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let requests_for_realizer = Arc::clone(&requests);
    let realizer = IfdRealizer::new(move |request| {
        let drv_path = PathBuf::from(OsStr::from_bytes(request.drv_path()));
        let drv_bytes =
            fs::read(&drv_path).map_err(|source| IfdRealizationError::new(source.to_string()))?;
        if !drv_bytes.starts_with(b"Derive(") {
            return Err(IfdRealizationError::new(
                "materialized IFD derivation is not an ATerm derivation",
            ));
        }
        let materialized_drvs = fs::read_dir(&store_for_realizer)
            .map_err(|source| IfdRealizationError::new(source.to_string()))?
            .map(|entry| {
                entry
                    .map_err(|source| IfdRealizationError::new(source.to_string()))
                    .map(|entry| entry.path())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let materialized_drv_count = materialized_drvs
            .iter()
            .filter(|path| path.extension() == Some(OsStr::new("drv")))
            .count();
        if materialized_drv_count < 2 {
            return Err(IfdRealizationError::new(
                "native IFD did not materialize the input derivation closure",
            ));
        }
        requests_for_realizer
            .lock()
            .expect("request log lock")
            .push((
                request.path().to_vec(),
                request.drv_path().to_vec(),
                request.output_name().map(<[u8]>::to_vec),
                request.context_kind(),
                request.op(),
            ));
        let import_path = PathBuf::from(OsStr::from_bytes(request.path()));
        let Some(output_dir) = import_path.parent() else {
            return Err(IfdRealizationError::new("IFD import path has no parent"));
        };
        fs::create_dir_all(output_dir)
            .map_err(|source| IfdRealizationError::new(source.to_string()))?;
        fs::write(&import_path, br#""from-native-ifd""#)
            .map_err(|source| IfdRealizationError::new(source.to_string()))?;
        Ok(())
    });
    let options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    let native = NixNative::with_options(0, options)?.with_ifd_realizer(realizer);
    let source = format!(
        r#"let
             base = builtins.derivationStrict {{
               name = "base";
               system = "x86_64-linux";
               builder = {builder};
             }};
             producer = builtins.derivationStrict {{
               name = "producer";
               system = "x86_64-linux";
               builder = {builder};
               input = base.out;
             }};
             consumer = builtins.derivationStrict {{
               name = "consumer";
               system = "x86_64-linux";
               builder = {builder};
               args = [ (import "${{producer.out}}/imported.nix") ];
             }};
           in consumer.drvPath"#,
        builder = nix_string_literal(&path_bytes(&builder)?)?,
    );

    let path = native.eval_derivation_path_source(&source, None)?;

    assert!(path.to_string_lossy().ends_with("-consumer.drv"));
    let requests = requests.lock().expect("request log lock");
    assert_eq!(requests.len(), 1);
    assert!(requests[0].0.ends_with(b"/imported.nix"));
    assert!(requests[0].1.starts_with(store.as_os_str().as_bytes()));
    assert_eq!(requests[0].2.as_deref(), Some(b"out".as_slice()));
    assert_eq!(requests[0].3, crate::string::ContextKind::SingleOutput);
    assert_eq!(requests[0].4, "import");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn native_ifd_realizer_failures_remain_fallback_eligible() -> Result<()> {
    let root = unique_temp_dir("native-ifd-failure");
    fs::create_dir_all(&root)?;
    let root = fs::canonicalize(root)?;
    let store = root.join("store");
    fs::create_dir(&store)?;
    let drv_path = store.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-ifd.drv");
    let output_path = store.join("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-ifd");
    let import_path = output_path.join("imported.nix");
    let builder = store.join("cccccccccccccccccccccccccccccccc-builder");
    let realizer = IfdRealizer::new(|_| Err(IfdRealizationError::new("missing native drv")));
    let options = TreeWalkOptions::with_store_dir(store.as_os_str().as_bytes().to_vec())?;
    let native = NixNative::with_options(0, options)?.with_ifd_realizer(realizer);
    let source = format!(
        r#"let
             imported = builtins.appendContext {imported} {{
               {drv} = {{ outputs = [ "out" ]; }};
             }};
             d = builtins.derivationStrict {{
               name = "native-ifd";
               system = "x86_64-linux";
               builder = {builder};
               args = [ (import imported) ];
             }};
           in d.drvPath"#,
        imported = nix_string_literal(&path_bytes(&import_path)?)?,
        drv = nix_string_literal(&path_bytes(&drv_path)?)?,
        builder = nix_string_literal(&path_bytes(&builder)?)?,
    );

    let error = native
        .eval_derivation_path_source(&source, None)
        .expect_err("realizer failure remains fallback eligible");
    assert!(
        matches!(
            error.downcast_ref::<NativeEvalError>(),
            Some(NativeEvalError::Unsupported { feature, .. })
                if feature.contains("IFD realization failed")
                    && feature.contains("missing native drv")
        ),
        "{error:?}"
    );

    fs::remove_dir_all(root)?;
    Ok(())
}
