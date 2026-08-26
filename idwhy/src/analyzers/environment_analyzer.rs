use serde::Serialize;

use crate::core::types::ApplicationProfile;

/// Prefixos de bibliotecas que indicam que a aplicação precisa de
/// servidor gráfico. Casamento por prefixo do nome da lib no NEEDED
/// (ex: "libX11.so.6", "libwayland-client.so.0").
const GUI_LIBRARY_PREFIXES: &[&str] = &[
    "libX11", "libxcb", "libXext", "libXi",
    "libwayland", "libgtk", "libgdk", "libgdk_pixbuf",
    "libQt5", "libQt6", "libSDL2", "libEGL", "libGL",
];

#[derive(Debug, Serialize, Clone)]
pub struct EnvironmentAnalysis {
    /// Libs gráficas encontradas no NEEDED/grafo (vazio = app não-gráfico).
    pub gui_libraries: Vec<String>,
    pub display_set: bool,
    pub wayland_set: bool,
    pub ld_preload: Option<String>,
    pub ld_library_path: Vec<String>,
}

impl EnvironmentAnalysis {
    pub fn is_graphical(&self) -> bool {
        !self.gui_libraries.is_empty()
    }

    pub fn has_display_server(&self) -> bool {
        self.display_set || self.wayland_set
    }
}

/// Lê o ambiente DO PRÓPRIO PROCESSO (herdado do shell do usuário).
/// Limitação MVP documentada: serviços iniciados pelo systemd têm um
/// ambiente diferente do ambiente interativo.
pub fn scan(profile: &ApplicationProfile) -> EnvironmentAnalysis {
    let mut gui_libraries: Vec<String> = profile.binary.iter().flat_map(|b| b.needed.iter()).filter(|lib| is_gui_library(lib)).cloned().collect();

    for node in profile.dependency_graph.values() {
        if is_gui_library(&node.name) && !gui_libraries.contains(&node.name) {
            gui_libraries.push(node.name.clone());
        }
    }
    gui_libraries.sort();

    let ld_library_path = std::env::var("LD_LIBRARY_PATH")
        .unwrap_or_default()
        .split(':')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    EnvironmentAnalysis {
        gui_libraries,
        display_set: env_nonempty("DISPLAY"),
        wayland_set: env_nonempty("WAYLAND_DISPLAY"),
        ld_preload: std::env::var("LD_PRELOAD").ok().filter(|v| !v.is_empty()),
        ld_library_path,
    }
}

fn env_nonempty(key: &str) -> bool {
    std::env::var(key).map(|v| !v.trim().is_empty()).unwrap_or(false)
}

fn is_gui_library(name: &str) -> bool {
    GUI_LIBRARY_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// Lista curta para descrições: primeiras libs + contagem das restantes.
pub fn summarize_libraries(libs: &[String], max: usize) -> String {
    match libs.len() {
        0 => String::new(),
        n if n <= max => libs.join(", "),
        _ => format!(
            "{} e {} outras",
            libs[..max].join(", "),
            libs.len() - max
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{ApplicationProfile, BinaryInfo, DependencyNode};

    fn node(name: &str) -> DependencyNode {
        DependencyNode { name: name.into(), found: true, resolved_path: None, needed_by: vec![] }
    }

    fn profile_with(needed: &[&str], graph_libs: &[&str]) -> ApplicationProfile {
        ApplicationProfile {
            input_path: "/tmp/app".into(),
            resolved_executable: "/tmp/app".into(),
            binary: Some(BinaryInfo {
                elf_valid: true,
                arch: "x86_64".into(),
                is_pie: false,
                interpreter: None,
                needed: needed.iter().map(|s| s.to_string()).collect(),
                rpath: vec![],
                runpath: vec![],
                sha256: "0".repeat(64),
            }),
            dependency_graph: graph_libs.iter().map(|n| (n.to_string(), node(n))).collect(),
            permissions: None,
            environment: None,
            package_owner: None,
            integrity: None,
            runtime: None,
            wrapper_chain: Vec::new(),
        }
    }

    #[test]
    fn detecta_libs_graficas_por_prefixo() {
        assert!(is_gui_library("libX11.so.6"));
        assert!(is_gui_library("libwayland-client.so.0"));
        assert!(is_gui_library("libQt6Core.so.6"));
        assert!(is_gui_library("libSDL2-2.0.so.0"));
        assert!(!is_gui_library("libc.so.6"));
        assert!(!is_gui_library("libpthread.so.0"));
        assert!(!is_gui_library("libssl.so.3"));
    }

    #[test]
    fn app_de_terminal_nao_e_classificado_como_grafico() {
        let analysis = scan(&profile_with(
            &["libc.so.6", "libm.so.6"],
            &["libc.so.6", "libtinfo.so.6"],
        ));
        assert!(!analysis.is_graphical());
        assert!(analysis.gui_libraries.is_empty());
    }

    #[test]
    fn lib_grafica_transitiva_tambem_conta() {
        let analysis = scan(&profile_with(&["libc.so.6"], &["libX11.so.6"]));
        assert!(analysis.is_graphical());
        assert_eq!(analysis.gui_libraries, vec!["libX11.so.6"]);
    }

    #[test]
    fn sem_duplicacao_quando_lib_aparece_em_dois_lugares() {
        let analysis = scan(&profile_with(&["libX11.so.6"], &["libX11.so.6"]));
        assert_eq!(analysis.gui_libraries.len(), 1);
    }

    #[test]
    fn summarize_comprime_listas_longas() {
        let libs: Vec<String> = ["libA", "libB", "libC"].iter().map(|s| s.to_string()).collect();
        assert_eq!(summarize_libraries(&libs, 3), "libA, libB, libC");
        assert_eq!(summarize_libraries(&[], 3), "");

        let long: Vec<String> = ["libX11.so.6", "libxcb.so.1", "libwayland-client.so.0", "libGL.so.1"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            summarize_libraries(&long, 3),
            "libX11.so.6, libxcb.so.1, libwayland-client.so.0 e 1 outras"
        );
    }

    #[test]
    fn variaveis_ld_sao_capturadas() {
        let analysis = scan(&profile_with(&["libc.so.6"], &[]));
        let ld_path = std::env::var("LD_LIBRARY_PATH").unwrap_or_default();
        let expected: Vec<&str> = ld_path.split(':').filter(|s| !s.is_empty()).collect();
        assert_eq!(analysis.ld_library_path, expected);
    }
}
