use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct RunningApp {
    pub pid: u32,
    pub comm: String,
    pub exe_path: PathBuf,
}

/// Varre /proc e lista os executáveis atualmente em execução, deduplicado
/// por caminho real (mantém o menor PID de cada binário). Nunca executa
/// nada — apenas lê links simbólicos e arquivos de metadados do kernel.
pub fn list_running_apps(exclude_exe: Option<&Path>) -> Vec<RunningApp> {
    let mut by_path: HashMap<PathBuf, RunningApp> = HashMap::new();

    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    for entry in entries.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(raw_link) = fs::read_link(entry.path().join("exe")) else {
            continue;
        };
        let exe_path = normalize_proc_link(&raw_link);
        if exe_path.as_os_str().is_empty() {
            continue;
        }
        if let Some(excluded) = exclude_exe {
            if exe_path.as_path() == excluded {
                continue;
            }
        }

        let comm = fs::read_to_string(entry.path().join("comm"))
            .map(|c| c.trim().to_string())
            .ok()
            .filter(|c| !c.is_empty())
            .unwrap_or_else(|| exe_name_fallback(&exe_path));

        match by_path.get_mut(&exe_path) {
            Some(existing) => {
                if pid < existing.pid {
                    existing.pid = pid;
                    if comm.len() > existing.comm.len() || existing.comm.starts_with('.') {
                        existing.comm = comm;
                    }
                }
            }
            None => {
                by_path.insert(exe_path.clone(), RunningApp { pid, comm, exe_path });
            }
        }
    }

    let mut apps: Vec<RunningApp> = by_path.into_values().collect();
    apps.sort_by(|a, b| a.comm.to_lowercase().cmp(&b.comm.to_lowercase()).then(a.pid.cmp(&b.pid)));
    apps
}

/// O kernel sufixa "(deleted)" em links de binários removidos do disco.
fn normalize_proc_link(link: &Path) -> PathBuf {
    let text = link.to_string_lossy();
    match text.strip_suffix(" (deleted)") {
        Some(stripped) => PathBuf::from(stripped),
        None => link.to_path_buf(),
    }
}

fn exe_name_fallback(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

const SYSTEM_PATH_PREFIXES: &[&str] = &[
    "/usr/libexec/", "/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/",
    "/usr/sbin/", "/sbin/", "/usr/lib/x86_64-linux-gnu/",
];

/// Palavras que identificam daemons/serviços mesmo quando o binário mora
/// em /usr/bin (ex: akonadiserver, baloo_file). Lista curada, não exaustiva:
/// falso negativo só custa uma linha a mais no menu; falso positivo esconde
/// um app real — por isso o toggle 't' existe.
const SYSTEM_NAME_HINTS: &[&str] = &[
    "systemd", "dbus", "gvfs", "xdg-", "at-spi", "pipewire", "wireplumber",
    "pulseaudio", "polkit", "rtkit", "colord", "upower", "udisks", "accounts-daemon",
    "packagekit", "switcheroo", "-portal", "portal-", "gnome-shell", "gsd-",
    "ibus", "kded", "klauncher", "akonadi", "baloo", "kactivitymanagerd",
    "kglobalaccel", "kscreen", "kwalletd", "kwin", "plasma", "drkonqi",
    "xorg", "xsettingsd", "xembedsniproxy", "sshd", "cupsd", "snapd",
    "systemsettings", "kio", "dconf-service", "gnome-keyring", "gcr-",
    "seahorse", "tracker", "goa-daemon", "gvfsd", "at-spi2",
];

/// Heurística: provável serviço de sistema/plano de fundo, não um app
/// que o usuário tentaria diagnosticar. Nunca bloqueia — só filtra a
/// visão padrão do modo interativo.
pub fn is_likely_system_service(app: &RunningApp) -> bool {
    let path = app.exe_path.to_string_lossy();
    if SYSTEM_PATH_PREFIXES.iter().any(|p| path.starts_with(p)) {
        return true;
    }
    let comm = app.comm.to_lowercase();
    SYSTEM_NAME_HINTS.iter().any(|hint| comm.contains(hint))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lista_nao_vazia_e_sem_o_proprio_binario() {
        let self_exe = std::env::current_exe().unwrap();
        let apps = list_running_apps(Some(&self_exe));

        assert!(!apps.is_empty(), "sempre há processos de sistema rodando");
        assert!(
            apps.iter().all(|a| a.exe_path.is_absolute()),
            "links de /proc/PID/exe são absolutos"
        );
        assert!(
            !apps.iter().any(|a| a.exe_path == self_exe),
            "o próprio processo de teste deve ser excluído"
        );
    }

    #[test]
    fn dedup_por_caminho_real() {
        let apps = list_running_apps(None);
        let mut paths: Vec<&PathBuf> = apps.iter().map(|a| &a.exe_path).collect();
        paths.sort();
        let before = paths.len();
        paths.dedup();
        assert_eq!(before, paths.len(), "nenhum caminho pode aparecer duplicado");
    }

    #[test]
    fn normaliza_sufixo_deleted() {
        assert_eq!(
            normalize_proc_link(Path::new("/usr/bin/app (deleted)")),
            PathBuf::from("/usr/bin/app")
        );
        assert_eq!(
            normalize_proc_link(Path::new("/usr/bin/app")),
            PathBuf::from("/usr/bin/app")
        );
    }

    fn app_at(path: &str, comm: &str) -> RunningApp {
        RunningApp { pid: 1, comm: comm.into(), exe_path: PathBuf::from(path) }
    }

    #[test]
    fn classifica_daemons_por_caminho_e_nome() {
        assert!(is_likely_system_service(&app_at(
            "/usr/libexec/at-spi-bus-launcher", "at-spi-bus-laun")));
        assert!(is_likely_system_service(&app_at(
            "/usr/lib/systemd/systemd-resolved", "systemd-resolve")));
        assert!(is_likely_system_service(&app_at(
            "/usr/bin/akonadiserver", "akonadiserver")));
        assert!(is_likely_system_service(&app_at(
            "/usr/bin/dconf-service", "dconf-service")));
    }

    #[test]
    fn nao_classifica_apps_de_usuario_como_servico() {
        assert!(!is_likely_system_service(&app_at("/usr/bin/bash", "bash")));
        assert!(!is_likely_system_service(&app_at("/usr/bin/anydesk", "anydesk")));
        assert!(!is_likely_system_service(&app_at(
            "/home/lucas/projetos/app/target/debug/meuapp", "meuapp")));
        // App em /opt e flatpak também passam.
        assert!(!is_likely_system_service(&app_at(
            "/var/lib/flatpak/app/org.mozilla.firefox/x86_64/stable/.../firefox", "firefox")));
    }
}
