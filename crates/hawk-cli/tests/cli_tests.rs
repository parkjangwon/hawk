//! End-to-end CLI integration tests.
//!
//! These tests run the compiled `hawk` binary against temporary projects so the
//! workflows the audit flagged (configuration application, baseline behavior,
//! custom pack loading, Git-aware deletion handling) are covered at the same
//! level as unit tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("hawk-cli-test-{tag}-{}-{seq}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn hawk() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hawk"))
}

fn run_in(dir: &Path, args: &[&str]) -> std::process::Output {
    hawk()
        .args(args)
        .current_dir(dir)
        .output()
        .expect("hawk binary should run")
}

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

const VULN_JAVA: &str = "class A { void m(){ Runtime.getRuntime().exec(cmd); } }\n";
const CLEAN_JAVA: &str = "class A { void m(){ System.out.println(\"hi\"); } }\n";

#[test]
fn config_controls_scope_packs_report_and_policy() {
    let dir = temp_dir("config");
    write(&dir.join("src/A.java"), VULN_JAVA);
    write(&dir.join("ignored/B.java"), VULN_JAVA);
    write(
        &dir.join("hawk.toml"),
        r#"include = ["src"]
exclude = ["ignored"]
packs = ["java"]
[report]
format = "json"
output = "report.json"
[policy]
exit-on-severity = "critical"
"#,
    );

    let output = run_in(&dir, &[]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report = dir.join("report.json");
    assert!(report.is_file(), "config report.output must be written");
    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report).unwrap()).unwrap();
    let findings = parsed["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1, "excluded file must not be analyzed");
    assert!(findings[0]["file"].as_str().unwrap().contains("A.java"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cli_overrides_config_pack_selection() {
    let dir = temp_dir("override");
    write(&dir.join("src/A.java"), VULN_JAVA);
    write(
        &dir.join("hawk.toml"),
        "include = [\"src\"]\npacks = [\"korea-secure-coding\"]\n",
    );

    // Config selects korea pack only; runtime-exec lives in java pack, so no
    // finding with default packs. CLI --pack java overrides the config pack set.
    let default = run_in(&dir, &[]);
    let default_stdout = String::from_utf8_lossy(&default.stdout);
    assert!(
        !default_stdout.contains("java.security.runtime-exec"),
        "config pack selection should exclude java pack rules: {default_stdout}"
    );

    let cli = run_in(&dir, &["--pack", "java"]);
    let cli_stdout = String::from_utf8_lossy(&cli.stdout);
    assert!(
        cli_stdout.contains("java.security.runtime-exec"),
        "CLI pack override must win over config: {cli_stdout}"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn custom_pack_dir_rules_execute_in_scans() {
    let dir = temp_dir("custompack");
    write(&dir.join("src/A.java"), VULN_JAVA);
    write(
        &dir.join("vendor/my-rules/pack.toml"),
        "name = \"my-rules\"\nversion = \"1.0.0\"\n",
    );
    write(
        &dir.join("vendor/my-rules/rules/custom.rule.toml"),
        "id = \"my-rules.java.exec\"\nname = \"Exec call\"\ndescription = \"exec\"\nseverity = \"medium\"\nlanguages = [\"java\"]\n[pattern]\nregex = \"exec\\\\(\"\n",
    );

    let output = run_in(
        &dir,
        &["--pack-dir", "vendor/my-rules", "--pack", "my-rules", "src"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(2),
        "custom pack finding expected: {stdout} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("my-rules.java.exec"));

    // Global duplicate detection: same id as a built-in rule must fail loudly.
    write(
        &dir.join("vendor/dup-rules/pack.toml"),
        "name = \"dup-rules\"\nversion = \"1.0.0\"\n",
    );
    write(
        &dir.join("vendor/dup-rules/rules/dup.rule.toml"),
        "id = \"java.security.runtime-exec\"\nname = \"Dup\"\ndescription = \"d\"\nseverity = \"low\"\nlanguages = [\"java\"]\n[pattern]\nregex = \"exec\\\\(\"\n",
    );
    let dup = run_in(&dir, &["--pack-dir", "vendor/dup-rules", "src"]);
    assert_eq!(
        dup.status.code(),
        Some(1),
        "duplicate id with built-in pack must be fatal"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn baseline_suppresses_existing_and_detects_new_findings() {
    let dir = temp_dir("baseline");
    write(&dir.join("A.java"), VULN_JAVA);

    let create = run_in(&dir, &["baseline", "create"]);
    assert_eq!(create.status.code(), Some(0));
    assert!(dir.join(".hawk/baseline.json").is_file());

    // Same code → only existing findings → exit 0 and empty terminal output.
    let same = run_in(&dir, &["--baseline", "."]);
    assert_eq!(
        same.status.code(),
        Some(0),
        "existing findings must be suppressed: {}",
        String::from_utf8_lossy(&same.stdout)
    );
    assert!(String::from_utf8_lossy(&same.stdout).contains("0 findings"));

    // New vulnerable code → new finding → exit 2.
    write(&dir.join("B.java"), VULN_JAVA);
    let new_output = run_in(&dir, &["--baseline", "."]);
    assert_eq!(new_output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&new_output.stdout).contains("1 finding"));

    // baseline status reports classification and fails when something changed.
    let status = run_in(&dir, &["baseline", "status"]);
    assert_eq!(status.status.code(), Some(2));
    let status_out = String::from_utf8_lossy(&status.stdout);
    assert!(status_out.contains("existing: 1") || status_out.contains("1 existing"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn git_changed_ignores_deleted_files() {
    let dir = temp_dir("git");
    let init = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&dir)
        .status()
        .expect("git init");
    assert!(init.success());
    for (key, value) in [("user.email", "t@t"), ("user.name", "t")] {
        Command::new("git")
            .args(["config", key, value])
            .current_dir(&dir)
            .status()
            .unwrap();
    }
    write(&dir.join("A.java"), VULN_JAVA);
    write(&dir.join("B.java"), CLEAN_JAVA);
    Command::new("git")
        .arg("add")
        .arg(".")
        .current_dir(&dir)
        .status()
        .unwrap();
    Command::new("git")
        .args(["commit", "-q", "-m", "init"])
        .current_dir(&dir)
        .status()
        .unwrap();

    // Delete one tracked file; --changed must not fail fatally.
    fs::remove_file(dir.join("B.java")).unwrap();
    let output = run_in(&dir, &["--changed"]);
    assert!(
        output.status.code() != Some(1),
        "deleted file must not abort the scan: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn oversized_files_are_skipped_explicitly_not_silently() {
    let dir = temp_dir("oversize");
    let mut content = String::from("class Big { void m(){\n");
    content.push_str(&"x = 1;\n".repeat(2_000_000)); // > 8 MiB
    content.push_str("} }\n");
    write(&dir.join("Big.java"), &content);

    let output = run_in(&dir, &["."]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "degraded scan expected for oversized file"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("exceeds"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rule_test_rejects_language_mismatched_fixtures() {
    let dir = temp_dir("rulelang");
    write(&dir.join("f.js"), "eval(x);\n");
    let rule_file = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../hawk-core/rules/java/java.security.runtime-exec.rule.toml"
    ));
    let output = run_in(&dir, &["rule", "test", rule_file.to_str().unwrap(), "f.js"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "language mismatch must be fatal"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rule_test_rejects_unknown_rule_annotations() {
    let dir = temp_dir("ruletest");
    write(&dir.join("f.java"), "// ruleid: no.such.rule\nx();\n");
    let rule_file = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../hawk-core/rules/java/java.security.runtime-exec.rule.toml"
    ));
    let output = run_in(
        &dir,
        &["rule", "test", rule_file.to_str().unwrap(), "f.java"],
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "unknown rule annotation must fail"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown rule"));
    let _ = fs::remove_dir_all(&dir);
}
