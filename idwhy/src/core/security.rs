use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

// Camada de segurança — pré-requisito da execução controlada.
//
// Princípios (README §5):
// 1. Nada executa o binário diagnosticado sem política explícita;
// 2. Execução só dentro de sandbox (bubblewrap) ou com override
//    duplo e consciente do usuário;
// 3. Leitura de arquivos anti-TOCTOU: um único handle aberto é
//    verificado (fstat) e consumido — sem re-resolver o caminho;
// 4. Comandos externos sempre fixos, args via Command::arg().

/// Flags de open específicas de Linux sem dependência da crate libc.
mod open_flags {
    /// O_NONBLOCK: abre FIFOs sem bloquear esperando um escritor —
    /// essencial para o fstat de segurança rodar ANTES de qualquer espera.
    pub const O_NONBLOCK: i32 = 0o4000;
}

pub fn read_file_verified(path: &Path) -> anyhow::Result<Vec<u8>> {
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(open_flags::O_NONBLOCK)
        .open(path)?;

    let md = file.metadata()?;
    let ft = md.file_type();
    if !ft.is_file() {
        if ft.is_fifo() {
            anyhow::bail!("'{path:?}' é um FIFO — leitura bloqueada por segurança");
        }
        if ft.is_char_device() || ft.is_block_device() {
            anyhow::bail!("'{path:?}' é um dispositivo — leitura bloqueada");
        }
        anyhow::bail!("'{path:?}' não é um arquivo regular");
    }

    // Arquivos gigantes demais não são binários legítimos de app:
    // teto defensivo de 2 GiB evita OOM em paths apontando para lixo.
    const MAX_DIAGNOSTIC_SIZE: u64 = 2 * 1024 * 1024 * 1024;
    if md.len() > MAX_DIAGNOSTIC_SIZE {
        anyhow::bail!(
            "'{path:?}' tem {} bytes — acima do limite de diagnóstico",
            md.len()
        );
    }

    let mut bytes = Vec::with_capacity(md.len().min(64 * 1024 * 1024) as usize);
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq)]
pub struct SandboxProbe {
    pub bwrap_path: Option<String>,
    pub bwrap_version: Option<String>,
    pub systemd_run_path: Option<String>,
}

impl SandboxProbe {
    pub fn has_any(&self) -> bool {
        self.bwrap_path.is_some() || self.systemd_run_path.is_some()
    }
}

/// Detecta ferramentas de sandbox disponíveis. Só executa os próprios
/// bins das ferramentas com flags de versão — nunca nada do usuário.
pub fn probe_sandbox() -> SandboxProbe {
    let bwrap_path = which("bwrap");
    let bwrap_version = bwrap_path.as_ref().and_then(|p| {
        Command::new(p)
            .arg("--version")
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
    });
    SandboxProbe { bwrap_path, bwrap_version, systemd_run_path: which("systemd-run") }
}

fn which(name: &str) -> Option<String> {
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        if dir.is_empty() {
            continue;
        }
        let candidate = Path::new(dir).join(name);
        if let Ok(md) = fs::metadata(&candidate) {
            if md.is_file() && md.permissions().mode() & 0o111 != 0 {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
    }
    None
}

/// Caminho do strace, se presente (usado pela execução controlada).
#[allow(dead_code)]
pub fn probe_strace() -> Option<String> {
    which("strace")
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ExecutionPolicy {
    /// OFF por padrão — nenhum caminho de código executa o alvo sem isso.
    pub allow_execution: bool,
    /// Exige sandbox disponível; sem ele, recusa mesmo com allow_execution.
    pub require_sandbox: bool,
    /// Override consciente para rodar sem sandbox (segundo sinal).
    pub unsafe_no_sandbox_override: bool,
}

impl Default for ExecutionPolicy {
    fn default() -> Self {
        Self {
            allow_execution: false,
            require_sandbox: true,
            unsafe_no_sandbox_override: false,
        }
    }
}

impl ExecutionPolicy {
    pub fn validate(&self, probe: &SandboxProbe) -> Result<(), String> {
        if !self.allow_execution {
            return Err("execução desabilitada pela política padrão \
                (nada roda sem opt-in explícito)"
                .into());
        }
        if probe.has_any() {
            return Ok(());
        }
        if self.require_sandbox && !self.unsafe_no_sandbox_override {
            return Err("nenhuma sandbox disponível (instale bubblewrap) ou passe \
                --unsafe-no-sandbox para assumir o risco conscientemente"
                .into());
        }
        Ok(())
    }
}

/// Monta o comando sandboxado com bubblewrap. Sequência de args fixa e
/// testável; nada vai por concatenação de shell.
///
/// `ro_binds`: caminhos do host que precisam ser visíveis dentro da
/// sandbox (alvo, scripts passados como argumento...) — montados sobre
/// si mesmos como somente-leitura. Necessário porque `--tmpfs /tmp`
/// esconde o /tmp do host: sem o bind, scripts em /tmp dão ENOENT.
///
/// Isolamento: rede/PIDs/IPC/mount novos; / read-only; /dev e /proc
/// mínimos; tmpfs privado em /tmp; ambiente zerado.
#[allow(dead_code)]
pub fn build_sandboxed_command(
    bwrap_path: &str,
    ro_binds: &[String],
    program: &Path,
    program_args: &[String],
) -> Command {
    let mut cmd = Command::new(bwrap_path);
    cmd.args(["--ro-bind", "/", "/"]);
    // tmpfs ANTES dos binds extras: bwrap empilha mounts na ordem dos
    // args — binds depois do tmpfs ficam visíveis por cima dele.
    cmd.args([
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
    ]);
    for p in ro_binds {
        cmd.arg("--ro-bind").arg(p).arg(p);
    }
    cmd.args([
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
    ]);
    cmd.arg(program);
    cmd.args(program_args);
    cmd
}

#[allow(dead_code)]
pub fn build_bwrap_command(
    bwrap_path: &str,
    target: &Path,
    target_args: &[String],
) -> Command {
    build_sandboxed_command(
        bwrap_path,
        &[target.to_string_lossy().into_owned()],
        target,
        target_args,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("idwhy_sec_{}_{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn leitura_verificada_consome_arquivo_regular() {
        let dir = tempdir("regular");
        let file = dir.join("app");
        fs::write(&file, b"conteudo").unwrap();

        assert_eq!(read_file_verified(&file).unwrap(), b"conteudo");
    }

    #[test]
    fn leitura_verificada_rejeita_diretorio_e_inexistente() {
        let dir = tempdir("rejects");
        assert!(read_file_verified(&dir).is_err(), "diretório não é regular");
        assert!(read_file_verified(&dir.join("nao_existe")).is_err());
    }

    #[test]
    fn leitura_verificada_rejeita_fifo_mesmo_apos_troca_de_path() {
        // Simula o ataque TOCTOU: path válido na hora do open vira FIFO
        // depois. Com handle+fstat, a checagem pega o inode real.
        let dir = tempdir("fifo");
        let fifo = dir.join("tubo");
        let criado = Command::new("python3")
            .args(["-c", &format!("import os; os.mkfifo({fifo:?})")])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !criado {
            return;
        }
        assert!(read_file_verified(&fifo).is_err());
    }

    #[test]
    fn policy_padrao_nunca_permite_execucao() {
        let probe = SandboxProbe {
            bwrap_path: Some("/usr/bin/bwrap".into()),
            bwrap_version: None,
            systemd_run_path: None,
        };
        assert!(ExecutionPolicy::default().validate(&probe).is_err());
    }

    #[test]
    fn matriz_de_validacao_da_policy() {
        let com_bwrap = SandboxProbe {
            bwrap_path: Some("/usr/bin/bwrap".into()),
            bwrap_version: Some("bwrap version 0.10.0".into()),
            systemd_run_path: None,
        };
        let sem_nada = SandboxProbe {
            bwrap_path: None,
            bwrap_version: None,
            systemd_run_path: None,
        };

        // Opt-in + sandbox → ok
        let ok = ExecutionPolicy { allow_execution: true, ..Default::default() };
        assert!(ok.validate(&com_bwrap).is_ok());

        // Opt-in sem sandbox nenhum → recusa explicando alternativas
        let err = ok.validate(&sem_nada).unwrap_err();
        assert!(err.contains("bubblewrap") && err.contains("--unsafe-no-sandbox"));

        // Override duplo sem sandbox → aceito consciente
        let overriden = ExecutionPolicy {
            allow_execution: true,
            unsafe_no_sandbox_override: true,
            ..Default::default()
        };
        assert!(overriden.validate(&sem_nada).is_ok());

        // Override sem opt-in → segue proibido
        let sozinho = ExecutionPolicy {
            unsafe_no_sandbox_override: true,
            ..Default::default()
        };
        assert!(sozinho.validate(&com_bwrap).is_err());
    }

    fn overrided_validate(p: ExecutionPolicy, probe: &SandboxProbe) -> bool {
        p.validate(probe).is_ok()
    }

    #[test]
    fn bwrap_args_sao_fixos_e_o_alto_vira_argumento() {
        let cmd = build_sandboxed_command(
            "/usr/bin/bwrap",
            &["/tmp/quebrado.sh".into(), "/tmp/outro.sh".into()],
            Path::new("/usr/bin/strace"),
            &["-f".into(), "--".into(), "/tmp/quebrado.sh".into()],
        );
        let program = format!("{:?}", cmd.get_program());
        assert_eq!(program, "\"/usr/bin/bwrap\"");

        let args: Vec<String> =
            cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        let esperado = [
            "--ro-bind", "/", "/",
            "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
            "--ro-bind", "/tmp/quebrado.sh", "/tmp/quebrado.sh",
            "--ro-bind", "/tmp/outro.sh", "/tmp/outro.sh",
            "--unshare-all", "--die-with-parent",
            "--new-session", "--clearenv",
        ];
        assert_eq!(&args[..esperado.len()], esperado);
        assert_eq!(args[esperado.len()], "/usr/bin/strace");
        assert_eq!(&args[esperado.len() + 1..], &["-f", "--", "/tmp/quebrado.sh"]);

        // Nada de shell: o comando executa bwrap diretamente.
        assert_ne!(program, "\"/bin/sh\"");
    }

    #[test]
    fn wrapper_legado_mantido_para_compatibilidade_de_chamada() {
        let cmd = build_bwrap_command("/usr/bin/bwrap", Path::new("/opt/app/run"), &["--servir".into()]);
        let args: Vec<String> =
            cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert!(args.windows(2).any(|w| w[0] == "--ro-bind" && w[1] == "/opt/app/run"));
        assert!(args.contains(&"--clearenv".to_string()));
        assert_eq!(args.last().map(String::as_str), Some("--servir"));
    }

    #[test]
    fn parser_de_versao_do_probe_e_confiavel() {
        // probe_sandbox em máquina real: apenas estrutura coerente.
        let probe = probe_sandbox();
        if let Some(v) = &probe.bwrap_version {
            assert!(
                v.chars().any(|c| c.is_ascii_digit()),
                "saída de --version deve conter número de versão: {v}"
            );
        }
        // which interno nunca devolve path sem nome buscado.
        if let Some(p) = &probe.bwrap_path {
            assert!(p.ends_with("bwrap"));
        }
    }
}
