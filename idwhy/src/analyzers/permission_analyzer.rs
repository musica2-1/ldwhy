use serde::Serialize;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

#[derive(Debug, Serialize, Clone)]
pub struct PermissionAnalysis {
    pub mode: u32,
    pub file_uid: u32,
    pub file_gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub user_can_execute: bool,
}

/// Identidade efetiva do processo (euid/egid/grupos suplementares),
/// lida de /proc/self/status — sem depender da crate libc.
fn current_identity() -> Option<(u32, u32, Vec<u32>)> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let mut euid = None;
    let mut egid = None;
    let mut groups = Vec::new();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            euid = rest.split_whitespace().nth(1)?.parse().ok();
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            egid = rest.split_whitespace().nth(1)?.parse().ok();
        } else if let Some(rest) = line.strip_prefix("Groups:") {
            groups = rest.split_whitespace().filter_map(|g| g.parse().ok()).collect();
        }
    }
    Some((euid?, egid?, groups))
}

/// Reproduz a decisão do kernel (sem ACLs estendidas — limitação MVP):
/// dono usa bits de dono; grupo do arquivo (efetivo ou suplementar) usa
/// bits de grupo; demais usam bits de other. Root executa se QUALQUER
/// bit x estiver setado.
fn kernel_would_allow_exec(mode: u32, file_uid: u32, file_gid: u32, euid: u32, egid: u32, groups: &[u32]) -> bool {
    const OWNER_X: u32 = 0o100;
    const GROUP_X: u32 = 0o010;
    const OTHER_X: u32 = 0o001;
    const ANY_X: u32 = 0o111;

    if euid == 0 {
        return mode & ANY_X != 0;
    }
    if file_uid == euid {
        return mode & OWNER_X != 0;
    }
    if file_gid == egid || groups.contains(&file_gid) {
        return mode & GROUP_X != 0;
    }
    mode & OTHER_X != 0
}

/// Stat + simulação de permissão de execução para o usuário ATUAL.
/// None significa "não foi possível avaliar" (arquivo sumiu, /proc
/// indisponível) — o chamador simplesmente não gera evidência.
pub fn analyze_permissions(path: &Path) -> Option<PermissionAnalysis> {
    let md = fs::metadata(path).ok()?;
    let (euid, egid, groups) = current_identity()?;

    let mode = md.permissions().mode();
    let (file_uid, file_gid) = (md.uid(), md.gid());
    let user_can_execute =
        kernel_would_allow_exec(mode, file_uid, file_gid, euid, egid, &groups);

    Some(PermissionAnalysis { mode, file_uid, file_gid, euid, egid, user_can_execute })
}

fn oct3(mode: u32) -> String {
    format!("{:03o}", mode & 0o777)
}

impl std::fmt::Display for PermissionAnalysis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "modo {} · dono uid {} · você é uid {} → {}",
            oct3(self.mode),
            self.file_uid,
            self.euid,
            if self.user_can_execute { "executável" } else { "EXECUÇÃO NEGADA" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(mode: u32, fuid: u32, fgid: u32, euid: u32, egid: u32, extra: &[u32]) -> bool {
        kernel_would_allow_exec(mode, fuid, fgid, euid, egid, extra)
    }

    #[test]
    fn dono_precisa_do_bit_de_dono() {
        assert!(allow(0o755, 1000, 1000, 1000, 1000, &[]));
        assert!(!allow(0o644, 1000, 1000, 1000, 1000, &[]));
        assert!(!allow(0o600, 1000, 1000, 1000, 1000, &[]));
    }

    #[test]
    fn grupo_e_outros_usam_seus_bits_respectivos() {
        assert!(allow(0o750, 0, 1000, 2000, 1000, &[]));
        assert!(!allow(0o740, 0, 1000, 2000, 1000, &[]));
        assert!(allow(0o755, 0, 0, 2000, 2000, &[]));
        assert!(!allow(0o750, 0, 0, 2000, 2000, &[]));
    }

    #[test]
    fn grupo_suplementar_da_acesso_ao_bit_de_grupo() {
        assert!(allow(0o750, 0, 42, 1000, 9999, &[42]));
        assert!(!allow(0o750, 0, 42, 1000, 9999, &[]));
    }

    #[test]
    fn root_executa_com_qualquer_bit_x_mas_nao_sem_nenhum() {
        assert!(allow(0o744, 0, 0, 0, 0, &[]));
        assert!(!allow(0o644, 1000, 1000, 0, 0, &[]));
    }

    #[test]
    fn prioridade_do_dono_sobrepe_grupo() {
        // Dono com bit de dono zerado NÃO cai para bits de grupo/other.
        assert!(!allow(0o077, 1000, 1000, 1000, 1000, &[]));
    }

    #[test]
    fn display_formata_modo_octal_legivel() {
        let pa = PermissionAnalysis {
            mode: 0o100644,
            file_uid: 1000,
            file_gid: 1000,
            euid: 1000,
            egid: 1000,
            user_can_execute: false,
        };
        let text = pa.to_string();
        assert!(text.contains("644"), "modo deve aparecer como octal: {text}");
        assert!(text.contains("EXECUÇÃO NEGADA"));
    }
}
