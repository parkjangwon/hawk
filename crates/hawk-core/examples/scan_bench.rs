//! Benchmark: scan a synthetic tree of Java files and print wall-clock stats.
//! Run with: cargo run --release -p hawk --example scan_bench 2000
//!
//! This is a lightweight, dependency-free stand-in for a full criterion suite:
//! it reports ms/file and total ms so regressions are visible on a dev machine.
//! Treat measurements as directional, not absolute.

use std::time::Instant;

use hawk_core::language::Language;
use hawk_core::pack::PackRegistry;
use hawk_core::parser::ParserRegistry;

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(1000);
    let registry = PackRegistry::with_built_in().expect("built-in packs load");
    let parser = ParserRegistry::default();

    let start = Instant::now();
    let mut total_findings = 0usize;
    for i in 0..n {
        let path = std::path::Path::new("Gen.java");
        let src = format!("class Gen{i} {{ void m(String x, java.sql.Statement st) {{ String id = x; st.executeQuery(id); }} }}");
        let Some(p) = parser.parser_for(Language::Java) else {
            continue;
        };
        let tree = p.parse(&src).expect("java should parse");
        for rule in registry.iter() {
            if rule.languages().contains(&Language::Java) {
                total_findings += rule.check_parsed(&tree, &src, path).len();
            }
        }
    }
    let elapsed = start.elapsed();
    println!(
        "scanned {n} files in {:.3}s ({:.2} ms/file) · cumulative findings {total_findings}",
        elapsed.as_secs_f64(),
        elapsed.as_millis() as f64 / n as f64,
    );
}
