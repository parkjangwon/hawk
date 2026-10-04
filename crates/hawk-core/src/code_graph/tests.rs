use super::*;
use crate::parser::{Parser, TreeSitterParser};

fn indexed(path: &str, language: Language, source: &str) -> IndexedFile {
    let parser = TreeSitterParser { language };
    let tree = parser.parse(source).expect("source should parse");
    IndexedFile {
        path: PathBuf::from(path),
        language,
        tree,
        source: source.to_string(),
    }
}

#[test]
fn indexes_symbols_and_resolves_cross_file_calls() {
    let graph = CodeGraph::build(vec![
        indexed(
            "Controller.java",
            Language::Java,
            r#"
class Controller {
    void handle(Service service) {
        service.deleteUser("x");
        st.executeQuery("SELECT 1");
    }
}
"#,
        ),
        indexed(
            "Service.java",
            Language::Java,
            r#"
class Service {
    void deleteUser(String id) {}
    String build() { return "x"; }
}
"#,
        ),
    ]);

    assert_eq!(graph.symbols.len(), 3);
    let controller = graph
        .symbols
        .iter()
        .find(|symbol| symbol.qualified_name == "Controller.handle")
        .expect("controller symbol");
    assert_eq!(controller.line, 3);
    let service = graph
        .symbols
        .iter()
        .find(|symbol| symbol.qualified_name == "Service.deleteUser")
        .expect("service symbol");

    let delete_edge = graph
        .edges
        .iter()
        .find(|edge| edge.callee_text == "service.deleteUser")
        .expect("delete edge");
    assert_eq!(
        graph.symbols[delete_edge.callee.unwrap()].qualified_name,
        "Service.deleteUser"
    );
    let external = graph
        .edges
        .iter()
        .find(|edge| edge.callee_text == "st.executeQuery")
        .expect("external edge");
    assert!(external.callee.is_none(), "library calls stay unresolved");
    let _ = service;
}

#[test]
fn same_file_calls_prefer_local_definitions() {
    let graph = CodeGraph::build(vec![indexed(
        "App.java",
        Language::Java,
        r#"
class A {
    void run() { helper(); }
    void helper() {}
}
class B {
    void helper() {}
}
"#,
    )]);
    let edge = graph
        .edges
        .iter()
        .find(|e| e.callee_text == "helper")
        .unwrap();
    let callee = &graph.symbols[edge.callee.unwrap()];
    assert_eq!(callee.qualified_name, "A.helper");
}

#[test]
fn type_guided_resolution_distinguishes_same_named_methods() {
    let graph = CodeGraph::build(vec![indexed(
        "App.java",
        Language::Java,
        r#"
class A {
    void handle(B b, C c) {
        b.run();
        c.run();
    }
}
class B { void run() {} }
class C { void run() {} }
"#,
    )]);
    let b_edge = graph
        .edges
        .iter()
        .find(|edge| edge.callee_text == "b.run")
        .expect("b.run edge");
    assert_eq!(
        graph.symbols[b_edge.callee.unwrap()].qualified_name,
        "B.run",
        "parameter type B must guide resolution"
    );
    let c_edge = graph
        .edges
        .iter()
        .find(|edge| edge.callee_text == "c.run")
        .expect("c.run edge");
    assert_eq!(
        graph.symbols[c_edge.callee.unwrap()].qualified_name,
        "C.run",
        "parameter type C must guide resolution"
    );
}

#[test]
fn hierarchy_resolution_finds_inherited_and_implemented_methods() {
    let graph = CodeGraph::build(vec![indexed(
        "App.java",
        Language::Java,
        r#"
class Base {
    void inherited() {}
}
class Impl extends Base implements Service {
    void own() {}
}
interface Service {
    void contract();
}
class ServiceImpl implements Service {
    void contract() {}
}
class User {
    void handle(Impl impl, Service svc) {
        impl.inherited();
        impl.own();
        svc.contract();
    }
}
"#,
    )]);
    let edge = |text: &str| {
        graph
            .edges
            .iter()
            .find(|edge| edge.callee_text == text)
            .expect(text)
    };
    // inherited via extends chain
    assert_eq!(
        graph.symbols[edge("impl.inherited").callee.unwrap()].qualified_name,
        "Base.inherited"
    );
    // own method stays direct
    assert_eq!(
        graph.symbols[edge("impl.own").callee.unwrap()].qualified_name,
        "Impl.own"
    );
    // interface-typed variable resolves to an implementing class
    assert_eq!(
        graph.symbols[edge("svc.contract").callee.unwrap()].qualified_name,
        "ServiceImpl.contract"
    );
}

#[test]
fn import_resolution_binds_calls_to_imported_files() {
    let graph = CodeGraph::build(vec![
        indexed(
            "handler.ts",
            Language::TypeScript,
            r#"
import { deleteUser, helper as h } from "./UserService";
import * as api from "./Api";
export function handle(id: string) {
    deleteUser(id);
    h(id);
    api.lookup(id);
}
"#,
        ),
        indexed(
            "UserService.ts",
            Language::TypeScript,
            "export function deleteUser(id: string) {}
export function helper(id: string) {}
",
        ),
        indexed(
            "Api.ts",
            Language::TypeScript,
            "export function lookup(id: string) {}
",
        ),
    ]);
    let edge = |text: &str| {
        graph
            .edges
            .iter()
            .find(|edge| edge.callee_text == text)
            .expect(text)
    };
    assert_eq!(
        graph.symbols[edge("deleteUser").callee.unwrap()].qualified_name,
        "deleteUser"
    );
    assert_eq!(
        graph.symbols[edge("deleteUser").callee.unwrap()].file,
        PathBuf::from("UserService.ts")
    );
    // aliased import binds to the original name
    assert_eq!(
        graph.symbols[edge("h").callee.unwrap()].file,
        PathBuf::from("UserService.ts")
    );
    // namespace call resolves into the imported file
    assert_eq!(
        graph.symbols[edge("api.lookup").callee.unwrap()].file,
        PathBuf::from("Api.ts")
    );
}

#[test]
fn python_from_import_resolves_cross_file_calls() {
    let graph = CodeGraph::build(vec![
        indexed(
            "views.py",
            Language::Python,
            "from user_service import delete_user

def view():
    delete_user(user_id)
",
        ),
        indexed(
            "user_service.py",
            Language::Python,
            "def delete_user(user_id):
    pass
",
        ),
    ]);
    let edge = graph
        .edges
        .iter()
        .find(|edge| edge.callee_text == "delete_user")
        .expect("delete_user edge");
    assert_eq!(
        graph.symbols[edge.callee.unwrap()].file,
        PathBuf::from("user_service.py")
    );
}

#[test]
fn snapshot_round_trip_preserves_symbols_edges_and_resolution() {
    let files = vec![
        indexed(
            "Controller.java",
            Language::Java,
            r#"
class Controller {
    void handle(UserService service) {
        service.deleteUser("x");
    }
}
"#,
        ),
        indexed(
            "UserService.java",
            Language::Java,
            r#"
class UserService {
    void deleteUser(String id) {}
}
"#,
        ),
    ];
    let graph = CodeGraph::build(files);
    let snapshot = GraphSnapshot {
        schema: "test".into(),
        files: vec![
            GraphFileMeta {
                path: PathBuf::from("Controller.java"),
                hash: "h1".into(),
            },
            GraphFileMeta {
                path: PathBuf::from("UserService.java"),
                hash: "h2".into(),
            },
        ],
        symbols: graph.symbols.clone(),
        edges: graph.edges.clone(),
        var_types: graph.var_types.clone(),
        hierarchy: graph.hierarchy.clone(),
        imports: graph.imports.clone(),
        namespaces: graph.namespaces.clone(),
    };

    assert!(snapshot.matches(&[
        (Path::new("Controller.java"), Some("h1")),
        (Path::new("UserService.java"), Some("h2")),
    ]));
    assert!(!snapshot.matches(&[
        (Path::new("Controller.java"), Some("h1")),
        (Path::new("UserService.java"), Some("h2-changed")),
    ]));
    assert!(!snapshot.matches(&[(Path::new("Controller.java"), Some("h1"))]));

    let restored = CodeGraph::from_snapshot(&snapshot);
    assert_eq!(restored.symbols.len(), graph.symbols.len());
    assert_eq!(restored.edges.len(), graph.edges.len());
    assert_eq!(
        restored.resolved_callees_for_file(Path::new("Controller.java"), "deleteUser"),
        graph.resolved_callees_for_file(Path::new("Controller.java"), "deleteUser"),
    );
    // Placeholder files exist for display, but carry no tree.
    assert_eq!(restored.files.len(), 2);
}

#[test]
fn snapshot_restore_reparses_callees_on_demand() {
    // Lazy parse: the restored graph has no trees; requesting a callee
    // body reads the file from disk and parses it on first use.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "hawk-graph-lazy-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let controller = dir.join("Controller.java");
    let service = dir.join("UserService.java");
    std::fs::write(
        &controller,
        "class Controller { void handle(UserService s) { s.deleteUser(); } }",
    )
    .unwrap();
    std::fs::write(&service, "class UserService { void deleteUser() {} }").unwrap();

    let graph = CodeGraph::build(vec![
        indexed(
            controller.to_str().unwrap(),
            Language::Java,
            "class Controller { void handle(UserService s) { s.deleteUser(); } }",
        ),
        indexed(
            service.to_str().unwrap(),
            Language::Java,
            "class UserService { void deleteUser() {} }",
        ),
    ]);
    let snapshot = GraphSnapshot {
        schema: "test".into(),
        files: vec![
            GraphFileMeta {
                path: controller.clone(),
                hash: "h1".into(),
            },
            GraphFileMeta {
                path: service.clone(),
                hash: "h2".into(),
            },
        ],
        symbols: graph.symbols.clone(),
        edges: graph.edges.clone(),
        var_types: graph.var_types.clone(),
        hierarchy: graph.hierarchy.clone(),
        imports: graph.imports.clone(),
        namespaces: graph.namespaces.clone(),
    };
    let restored = CodeGraph::from_snapshot(&snapshot);

    let delete_user = restored
        .symbols
        .iter()
        .find(|symbol| symbol.name == "deleteUser")
        .expect("deleteUser symbol");
    let file = restored
        .indexed_file(delete_user.file_index)
        .expect("lazy parse must load the file");
    assert_eq!(file.path, service);
    assert!(
        file.method_node_at_byte(delete_user.start_byte).is_some(),
        "callee must be re-located from the lazily parsed tree"
    );
    assert!(restored.indexed_file(99).is_none(), "out-of-range index");
    let _ = std::fs::remove_dir_all(&dir);
}
