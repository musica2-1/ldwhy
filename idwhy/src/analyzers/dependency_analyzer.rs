use crate::core::types::{BinaryInfo, DependencyNode};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
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
                let name = name_part.split_whitespace().next().unwrap_or("").to_string();
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

/// Contexto de busca de UM objeto carregado (binário raiz ou biblioteca).
/// Cada objeto usa seus próprios caminhos para resolver os NEEDED dele —
/// é assim que o ld.so real funciona; usar só o RPATH do binário raiz
/// para todas as libs transitivas produzia falsos "NOT FOUND".
#[derive(Clone)]
struct SearchContext {
    /// Entradas DT_RPATH cruas (podem conter $ORIGIN).
    rpath_raw: Vec<String>,
    /// Entradas DT_RUNPATH cruas (podem conter $ORIGIN).
    runpath_raw: Vec<String>,
    /// Diretório do objeto donho destes caminhos (base para $ORIGIN).
    origin: PathBuf,
}

impl SearchContext {
    fn from_binary(binary: &BinaryInfo, binary_path: &Path) -> Self {
        Self {
            rpath_raw: binary.rpath.clone(),
            runpath_raw: binary.runpath.clone(),
            origin: binary_path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("/")),
        }
    }

    /// Expande $ORIGIN/${ORIGIN} em cada entrada para o diretório do objeto.
    fn rpath_expanded(&self) -> Vec<String> {
        self.rpath_raw.iter().map(|e| expand_origin(e, &self.origin)).collect()
    }

    fn runpath_expanded(&self) -> Vec<String> {
        self.runpath_raw.iter().map(|e| expand_origin(e, &self.origin)).collect()
    }
}

/// Substitui $ORIGIN e ${ORIGIN} pelo diretório do objeto donho do RUNPATH/RPATH.
fn expand_origin(entry: &str, origin: &Path) -> String {
    let origin_str = origin.to_string_lossy();
    entry
        .replace("${ORIGIN}", &origin_str)
        .replace("$ORIGIN", &origin_str)
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

/// Resolve uma lib seguindo a ordem do dynamic linker (ld.so(8)), relativa
/// ao objeto que declara a dependência:
///
/// 1. RPATH do objeto, somente se ele NÃO tiver RUNPATH (semântica legada);
/// 2. LD_LIBRARY_PATH;
/// 3. RUNPATH do objeto;
/// 4. cache do ldconfig;
/// 5. diretórios padrão.
///
/// Simplificação documentada: o comportamento legado encadeia também os
/// RPATHs dos objetos carregadores (ancestrais); aqui usamos apenas o do
/// próprio objeto — caso raro na prática com binutils modernos, que geram
/// RUNPATH.
fn resolve_lib(
    lib: &str,
    ctx: &SearchContext,
    ld_library_path: &[String],
    ldconfig_cache: &HashMap<String, String>,
) -> Option<String> {
    if ctx.runpath_raw.is_empty() {
        let rpath = ctx.rpath_expanded();
        if let Some(p) = try_find_in_dirs(lib, &rpath) {
            return Some(p);
        }
    }
    if let Some(p) = try_find_in_dirs(lib, ld_library_path) {
        return Some(p);
    }
    if !ctx.runpath_raw.is_empty() {
        let runpath = ctx.runpath_expanded();
        if let Some(p) = try_find_in_dirs(lib, &runpath) {
            return Some(p);
        }
    }
    if let Some(p) = ldconfig_cache.get(lib) {
        return Some(p.clone());
    }
    try_find_in_dirs(lib, &standard_lib_dirs())
}

/// Extrai (NEEDED, RPATH cru, RUNPATH cru) de um arquivo ELF já resolvido,
/// sem executá-lo. Retorna None se não for um ELF válido.
fn extract_object_info(bytes: &[u8]) -> Option<(Vec<String>, Vec<String>, Vec<String>)> {
    let elf = goblin::elf::Elf::parse(bytes).ok()?;
    let split_entries = |entries: &[&str]| -> Vec<String> {
        entries.iter().flat_map(|p| p.split(':').map(|s| s.to_string())).filter(|s| !s.is_empty()).collect()
    };
    Some((
        elf.libraries.iter().map(|s| s.to_string()).collect(),
        split_entries(&elf.rpaths),
        split_entries(&elf.runpaths),
    ))
}

/// Constrói o grafo de dependências fazendo BFS a partir do NEEDED do
/// binário raiz, resolvendo transitivamente. Para cada lib resolvida,
/// extrai o NEEDED dela e cria um NOVO contexto de busca com os
/// RPATH/RUNPATH DA PRÓPRIA LIB (com $ORIGIN apontando para o diretório dela).
pub fn build_dependency_graph(
    binary: &BinaryInfo,
    binary_path: &Path,
) -> HashMap<String, DependencyNode> {
    let ldconfig_cache = read_ldconfig_cache();
    let ld_library_path: Vec<String> = std::env::var("LD_LIBRARY_PATH")
        .unwrap_or_default()
        .split(':')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    let root_ctx = SearchContext::from_binary(binary, binary_path);

    let mut graph: HashMap<String, DependencyNode> = HashMap::new();
    // (nome da lib, quem requer, contexto do objeto requerente)
    let mut queue: VecDeque<(String, String, SearchContext)> = VecDeque::new();

    for lib in &binary.needed {
        queue.push_back((lib.clone(), "<root>".to_string(), root_ctx.clone()));
    }

    while let Some((lib, needed_by, ctx)) = queue.pop_front() {
        if let Some(node) = graph.get_mut(&lib) {
            if !node.needed_by.contains(&needed_by) {
                node.needed_by.push(needed_by);
            }
            continue;
        }

        let resolved = resolve_lib(&lib, &ctx, &ld_library_path, &ldconfig_cache);
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

        // Transitivo: lê o NEEDED da lib resolvida e enfileira com o
        // contexto de busca DELA (RPATH/RUNPATH próprios + $ORIGIN local).
        if let Some(path) = resolved {
            if let Ok(bytes) = std::fs::read(&path) {
                if let Some((sub_needed, sub_rpath, sub_runpath)) = extract_object_info(&bytes) {
                    let sub_ctx = SearchContext {
                        rpath_raw: sub_rpath,
                        runpath_raw: sub_runpath,
                        origin: Path::new(&path)
                            .parent()
                            .map(Path::to_path_buf)
                            .unwrap_or_else(|| PathBuf::from("/")),
                    };
                    for sub in sub_needed {
                        queue.push_back((sub, lib.clone(), sub_ctx.clone()));
                    }
                }
            }
        }
    }

    graph
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("diag_dep_test_{}_{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn touch(dir: &Path, name: &str) -> String {
        let file = dir.join(name);
        fs::write(&file, b"placeholder").unwrap();
        file.to_string_lossy().to_string()
    }

    fn ctx_with(rpath: &[&str], runpath: &[&str], origin: &Path) -> SearchContext {
        SearchContext {
            rpath_raw: rpath.iter().map(|s| s.to_string()).collect(),
            runpath_raw: runpath.iter().map(|s| s.to_string()).collect(),
            origin: origin.to_path_buf(),
        }
    }

    #[test]
    fn expand_origin_substitui_as_duas_formas() {
        let origin = Path::new("/opt/myapp/bin");
        assert_eq!(expand_origin("$ORIGIN/../libs", origin), "/opt/myapp/bin/../libs");
        assert_eq!(expand_origin("${ORIGIN}:$ORIGIN/lib", origin), "/opt/myapp/bin:/opt/myapp/bin/lib");
        assert_eq!(expand_origin("/usr/lib", origin), "/usr/lib");
    }

    #[test]
    fn ld_library_path_tem_prioridade_sobre_runpath() {
        // Ordem real do ld.so(8): RPATH legado > LD_LIBRARY_PATH > RUNPATH.
        let dir_run = tempdir("run");
        let dir_ld = tempdir("ld");
        touch(&dir_run, "libx.so.1");
        let esperado = touch(&dir_ld, "libx.so.1");

        let ctx = ctx_with(&[], &[&dir_run.to_string_lossy()], Path::new("/tmp"));
        let res = resolve_lib("libx.so.1", &ctx, &[dir_ld.to_string_lossy().to_string()], &HashMap::new());
        assert_eq!(res.as_deref(), Some(esperado.as_str()));

        let res2 = resolve_lib("libx.so.1", &ctx, &[dir_ld.join("vazio").to_string_lossy().to_string()], &HashMap::new());
        assert_eq!(
            res2.as_deref(),
            Some(dir_run.join("libx.so.1").to_string_lossy().as_ref() as &str)
        );
    }

    #[test]
    fn rpath_usado_apenas_quando_sem_runpath() {
        let dir_rp = tempdir("rponly");
        let esperado = touch(&dir_rp, "liby.so.2");

        let ctx = ctx_with(&[&dir_rp.to_string_lossy()], &[], Path::new("/tmp"));
        let res = resolve_lib("liby.so.2", &ctx, &[], &HashMap::new());
        assert_eq!(res.as_deref(), Some(esperado.as_str()));

        // Com RUNPATH presente (mesmo vazio de resultados válidos), RPATH legado é ignorado.
        let ctx2 = ctx_with(&["/caminho/inexistente"], &["/caminho/tambem/inexistente"], Path::new("/tmp"));
        let res2 = resolve_lib("liby.so.2", &ctx2, &[], &HashMap::new());
        assert_ne!(res2.as_deref(), Some(esperado.as_str()));
    }

    #[test]
    fn origem_do_contexto_resolve_origin_nas_entradas() {
        let base = tempdir("origin");
        // O kernel resolve ".." literalmente: bin/ precisa existir para
        // "bin/../libs" ser aberto — igual ao comportamento do ld.so.
        fs::create_dir_all(base.join("bin")).unwrap();
        fs::create_dir_all(base.join("libs")).unwrap();
        let esperado = touch(&base.join("libs"), "libz.so.0");

        let ctx = ctx_with(&["$ORIGIN/../libs"], &[], &base.join("bin"));
        let res = resolve_lib("libz.so.0", &ctx, &[], &HashMap::new());
        let res_canon = res.map(|p| fs::canonicalize(p).unwrap());
        assert_eq!(res_canon, Some(fs::canonicalize(esperado).unwrap()));
    }

    #[test]
    fn cache_ldconfig_vem_depois_dos_caminhos_do_objeto() {
        let dir_ctx = tempdir("ctxcache");
        let local = touch(&dir_ctx, "libw.so.9");

        let mut cache = HashMap::new();
        cache.insert("libw.so.9".to_string(), "/do/cache/libw.so.9".to_string());

        // Sem RPATH/RUNPATH -> vai ao cache.
        let ctx_vazio = ctx_with(&[], &[], Path::new("/tmp"));
        assert_eq!(
            resolve_lib("libw.so.9", &ctx_vazio, &[], &cache).as_deref(),
            Some("/do/cache/libw.so.9")
        );

        // Com RUNPATH local válido -> prefere o local antes do cache.
        let ctx_local = ctx_with(&[], &[&dir_ctx.to_string_lossy()], Path::new("/tmp"));
        assert_eq!(
            resolve_lib("libw.so.9", &ctx_local, &[], &cache).as_deref(),
            Some(local.as_str())
        );
    }

    #[test]
    fn extract_object_info_le_elf_do_sistema() {
        let bytes = std::fs::read("/bin/true").expect("/bin/true deve existir");
        let (needed, _rpath, _runpath) =
            extract_object_info(&bytes).expect("/bin/true é ELF válido");
        assert!(!needed.is_empty(), "ELF dinâmico precisa ter ao menos libc no NEEDED");
    }

    #[test]
    fn extract_object_info_rejeita_nao_elf() {
        assert!(extract_object_info(b"isto nao e um elf").is_none());
    }
}
