use std::path::PathBuf;

fn project_root() -> PathBuf {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    PathBuf::from(manifest).parent().unwrap().to_path_buf()
}

#[test]
fn all_example_configs_load() {
    let dir = project_root().join("examples");
    let mut count = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let cfg = vm_bandwidth_core::config::parse(&text)
            .unwrap_or_else(|e| panic!("{} failed to load: {e}", path.display()));
        assert!(!cfg.ranges.is_empty(), "{}: no ranges", path.display());
        count += 1;
    }
    assert_eq!(count, 6, "expected six algorithm example configs");
}
