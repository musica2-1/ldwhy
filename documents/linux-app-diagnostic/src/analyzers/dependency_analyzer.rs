use crate::core::types::{BinaryInfo, DependencyNode};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::process::Command;

/// Lê o cache do dynamic linker via `ldconfig -p`. Isso é seguro: ldconfig
/// não executa o binário que estamos diagnosticando, apenas lista o cache
/// do sistema já construído. Retorna mapa nome_da_lib -> caminho absoluto.
fn read_ldconfig_cache() -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(output) = Command::new("ldconfig").arg("-p").output() {
        let text = String::from_utf8_lossy(&output.stdout);
        // formato: "\tlibfoo.so.1 (libc6,x86-64) => /usr/lib64/libfoo.so.1"
        for line in text.lines() {
            if let Some((name_part, path_part)) = line.split_once("=>") {
                let name = name_part.trim().split_whitespace().next().unwrap_or("").to_string();
                let path = path_part.trim().to_string();
                if !name.is_empty() && !path.is_empty() {
                    map.entry(name).or_insert(path);
                }
            }
        }
    }
    map
}

fn standard_lib_dirs() -> Vec<String> {
    vec![
        "/lib".into(),
        "/lib64".into(),
        "/usr/lib".into(),
        "/usr/lib64".into(),
        "/usr/lib/x86_64-linux-gnu".into(),
        "/usr/local/lib".into(),
    ]
}

fn try_find_in_dirs(lib: &str, dirs: &[String]) -> Option<String> {
    for dir in dirs {
        let candidate = Path::new(dir).join(lib);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().to_string());
        }
    }
    None
}

/// Resolve uma lib seguindo a ordem real do dynamic linker:
/// RPATH (legado) > LD_LIBRARY_PATH > RUNPATH > cache ldconfig > dirs padrão.
fn resolve_lib(
    lib: &str,
    rpath: &[String],
    runpath: &[String],
    ld_library_path: &[String],
    ldconfig_cache: &HashMap<String, String>,
) -> Option<String> {
    if let Some(p) = try_find_in_dirs(lib, rpath) {
        return Some(p);
    }
    if let Some(p) = try_find_in_dirs(lib, ld_library_path) {
        return Some(p);
    }
    if let Some(p) = try_find_in_dirs(lib, runpath) {
        return Some(p);
    }
    if let Some(p) = ldconfig_cache.get(lib) {
        return Some(p.clone());
    }
    try_find_in_dirs(lib, &standard_lib_dirs())
}

/// Constrói o grafo de dependências fazendo BFS a partir do NEEDED do
/// binário raiz, resolvendo transitivamente. Para bibliotecas dependentes
/// (não o binário principal), fazemos uma leitura ELF simplificada apenas
/// da seção .dynamic para extrair o NEEDED delas também.
pub fn build_dependency_graph(binary: &BinaryInfo) -> HashMap<String, DependencyNode> {
    let ldconfig_cache = read_ldconfig_cache();
    let ld_library_path: Vec<String> = std::env::var("LD_LIBRARY_PATH")
        .unwrap_or_default()
        .split(':')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    let mut graph: HashMap<String, DependencyNode> = HashMap::new();
    let mut queue: VecDeque<(String, String)> = VecDeque::new(); // (lib, needed_by)

    for lib in &binary.needed {
        queue.push_back((lib.clone(), "<root>".to_string()));
    }

    while let Some((lib, needed_by)) = queue.pop_front() {
        if let Some(node) = graph.get_mut(&lib) {
            if !node.needed_by.contains(&needed_by) {
                node.needed_by.push(needed_by);
            }
            continue;
        }

        let resolved = resolve_lib(
            &lib,
            &binary.rpath,
            &binary.runpath,
            &ld_library_path,
            &ldconfig_cache,
        );

        let found = resolved.is_some();
        graph.insert(
            lib.clone(),
            DependencyNode {
                name: lib.clone(),
                found,
                resolved_path: resolved.clone(),
                needed_by: vec![needed_by],
            },
        );

        // Transitivo: se resolvemos o caminho, lemos o NEEDED dessa lib também.
        if let Some(path) = resolved {
            if let Ok(bytes) = std::fs::read(&path) {
                if let Ok(elf) = goblin::elf::Elf::parse(&bytes) {
                    for sub in elf.libraries {
                        queue.push_back((sub.to_string(), lib.clone()));
                    }
                }
            }
        }
    }

    graph
}
