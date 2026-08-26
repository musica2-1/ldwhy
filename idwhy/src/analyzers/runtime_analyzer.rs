use crate::core::security::{self, ExecutionPolicy, SandboxProbe};
use crate::core::types::{FailedSyscall, RuntimeResult};
use std::io::Read;
use std::path::Path;
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub struct RunOutcome {
    pub result: RuntimeResult,
    /// Texto bruto do strace — reservado para a correlação temporal da
    /// próxima etapa (journalctl por PID/janela).
    #[allow(dead_code)]
    pub strace_stderr: String,
}

/// Executa o alvo sob bubblewrap + strace (somente syscalls de arquivo),
/// com timeout e captura limitada. Só chega aqui depois da
/// `ExecutionPolicy::validate()` passar.
pub fn run_controlled(
    target: &Path,
    exec_args: &[String],
    policy: &ExecutionPolicy,
    probe: &SandboxProbe,
    strace_path: &str,
    timeout: Duration,
) -> anyhow::Result<RunOutcome> {
    policy
        .validate(probe)
        .map_err(|e| anyhow::anyhow!("política de execução: {e}"))?;

    let Some(bwrap) = probe.bwrap_path.as_deref() else {
        anyhow::bail!(
            "sandbox indisponível e override não fornecido — nada foi executado"
        );
    };

    // bwrap [fixos + binds] strace -f -q -e trace=%file -- <alvo> [args]
    // %file captura open*/stat*/access*/exec* — exatamente o que
    // diagnostica "não achou arquivo/lib em runtime" sem ruído.
    //
    // Binds explícitos para o alvo e argumentos-path: o --tmpfs /tmp
    // esconde o /tmp do host; sem eles, scripts em /tmp dão ENOENT.
    let mut ro_binds: Vec<String> = vec![target.to_string_lossy().into_owned()];
    for a in exec_args {
        let p = Path::new(a);
        if p.is_absolute() && p.is_file() && !ro_binds.contains(a) {
            ro_binds.push(a.clone());
        }
    }

    let mut strace_args: Vec<String> =
        vec!["-f".into(), "-q".into(), "-e".into(), "trace=%file".into(), "--".into()];
    strace_args.push(target.to_string_lossy().into_owned());
    strace_args.extend(exec_args.iter().cloned());

    let mut cmd = security::build_sandboxed_command(
        bwrap,
        &ro_binds,
        Path::new(strace_path),
        &strace_args,
    );

    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/bin");
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let started = Instant::now();
    let mut child = cmd.spawn()?;

    // Captura em threads com teto de bytes: evita deadlock de pipe
    // (filho bloqueado com buffer cheio enquanto esperamos o exit).
    let mut stdout_pipe = child.stdout.take().expect("stdout piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr piped");
    let (tx_out, rx_out) = mpsc::channel();
    let (tx_err, rx_err) = mpsc::channel();

    std::thread::scope(|s| {
        s.spawn(move || {
            tx_out.send(read_capped(&mut stdout_pipe)).ok();
        });
        s.spawn(move || {
            tx_err.send(read_capped(&mut stderr_pipe)).ok();
        });

        // true = morto por timeout; false = saiu sozinho (retorno direto).
        let killed_by_timeout: bool = loop {
            match child.try_wait()? {
                Some(status) => {
                    let _stdout = rx_out.recv_timeout(Duration::from_secs(2));
                    let stderr = rx_err
                        .recv_timeout(Duration::from_secs(2))
                        .unwrap_or_default();

                    let result = RuntimeResult {
                        ran_in_sandbox: true,
                        exit_code: status.code(),
                        killed_by_timeout: false,
                        duration_ms: started.elapsed().as_millis() as u64,
                        failed_syscalls: parse_strace_failures(&stderr),
                    };
                    return Ok(RunOutcome { result, strace_stderr: stderr });
                }
                None => {
                    if started.elapsed() > timeout {
                        child.kill()?;
                        child.wait()?;
                        break true;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };

        let _stdout = rx_out.recv_timeout(Duration::from_secs(2));
        let stderr = rx_out.recv_timeout(Duration::from_secs(2)).unwrap_or_default();

        Ok(RunOutcome {
            result: RuntimeResult {
                ran_in_sandbox: true,
                exit_code: None,
                killed_by_timeout,
                duration_ms: started.elapsed().as_millis() as u64,
                failed_syscalls: parse_strace_failures(&stderr),
            },
            strace_stderr: stderr,
        })
    })
}

fn read_capped(pipe: &mut impl Read) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let rest = MAX_CAPTURE_BYTES.saturating_sub(buf.len());
                buf.extend_from_slice(&chunk[..n.min(rest)]);
                if buf.len() >= MAX_CAPTURE_BYTES {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Converte linhas do strace em falhas estruturadas.
///
/// Formato típico (com -f, PIDs prefixam):
///   1234  openat(AT_FDCWD, "/lib/libx.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
/// Linhas bem-sucedidas (= 0 / = fd) e resumos são ignoradas.
pub fn parse_strace_failures(stderr_text: &str) -> Vec<FailedSyscall> {
    const KNOWN_ERRNOS: &[&str] = &[
        "ENOENT", "EACCES", "EPERM", "ELOOP", "ENAMETOOLONG",
        "ENOEXEC", "EFAULT", "ETXTBSY", "EISDIR",
    ];

    let mut out = Vec::new();
    for line in stderr_text.lines() {
        let Some(eq_pos) = line.rfind("= -1 ") else { continue };
        let (head, tail) = line.split_at(eq_pos + 4);
        let mut errno_parts = tail.trim_start().splitn(2, ' ');
        let errno = match errno_parts.next() {
            Some(e) => e.to_string(),
            None => continue,
        };
        if !KNOWN_ERRNOS.contains(&errno.as_str()) {
            continue;
        }
        let desc = errno_parts
            .next()
            .unwrap_or("")
            .trim_start_matches('(')
            .trim_end_matches(')')
            .to_string();

        // Primeiro argumento string entre aspas é o path alvo da syscall.
        let path = head.split('"').nth(1).unwrap_or("").to_string();

        // Nome da syscall: identificador imediatamente antes do primeiro '('.
        let call = match head.find('(') {
            Some(open) => {
                let bytes = head.as_bytes();
                let mut start = open;
                while start > 0
                    && (bytes[start - 1].is_ascii_alphanumeric()
                        || bytes[start - 1] == b'_')
                {
                    start -= 1;
                }
                if start == open { "unknown".to_string() } else { head[start..open].to_string() }
            }
            None => "unknown".to_string(),
        };

        out.push(FailedSyscall { call, path, errno, errno_desc: desc });
    }
    out
}

/// Classificação de falha → severidade/peso para o rule engine:
/// ENOENT em *.so* é candidato real a causa raiz; outros ENOENT são
/// probes normais de aplicação (Info); EACCES é grave.
pub fn severity_for_failure(f: &FailedSyscall) -> Option<(crate::core::types::Severity, i32)> {
    use crate::core::types::Severity;
    let is_library = f.path.contains(".so");
    match f.errno.as_str() {
        "ENOENT" if is_library && is_loadable_path(f) => Some((Severity::Warning, 25)),
        "ENOENT" => None, // probe normal — não vira evidência
        "EACCES" | "EPERM" => Some((Severity::Error, 35)),
        "ELOOP" | "ENAMETOOLONG" => Some((Severity::Warning, 15)),
        _ => None,
    }
}

fn is_loadable_path(f: &FailedSyscall) -> bool {
    matches!(
        f.call.as_str(),
        "openat" | "open" | "stat" | "lstat" | "statx" | "access" | "readlink"
    ) && (f.path.contains("/lib") || f.path.contains("/.libs") || starts_relative_lib(f))
}

fn starts_relative_lib(f: &FailedSyscall) -> bool {
    let base = f.path.rsplit('/').next().unwrap_or("");
    base.starts_with("lib")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_extrai_apenas_falhas_estruturadas() {
        let text = "\
1234  execve(\"/opt/app/run\", [\"/opt/app/run\"], 0xfff) = 0
1234  openat(AT_FDCWD, \"/etc/ld.so.cache\", O_RDONLY|O_CLOEXEC) = 3
1234  openat(AT_FDCWD, \"/usr/lib/libreal.so.1\", O_RDONLY|O_CLOEXEC) = 3
1234  openat(AT_FDCWD, \"/usr/lib/libfalta.so.2\", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
1234  access(\"/opt/app/config.toml\", R_OK) = -1 EACCES (Permission denied)
1235  stat(\"/tmp/probe.txt\", 0xabc) = -1 ENOENT (No such file or directory)
+++ exited with 127 +++";
        let fails = parse_strace_failures(text);
        assert_eq!(fails.len(), 3, "sucessos e resumo saem; falhas ficam");

        assert_eq!(fails[0].path, "/usr/lib/libfalta.so.2");
        assert_eq!(fails[0].errno, "ENOENT");
        assert_eq!(fails[0].errno_desc, "No such file or directory");
        assert_eq!(fails[0].call, "openat");

        assert_eq!(fails[1].errno, "EACCES");
        assert_eq!(fails[2].call, "stat");
    }

    #[test]
    fn severidade_so_enoent_e_warning_outros_probes_sao_ignorados() {
        let so = FailedSyscall {
            call: "openat".into(),
            path: "/usr/lib64/libfalsa.so.9".into(),
            errno: "ENOENT".into(),
            errno_desc: String::new(),
        };
        assert_eq!(severity_for_failure(&so), Some((crate::core::types::Severity::Warning, 25)));

        let config_probe = FailedSyscall {
            call: "openat".into(),
            path: "/home/u/.config/app.conf".into(),
            errno: "ENOENT".into(),
            errno_desc: String::new(),
        };
        assert_eq!(severity_for_failure(&config_probe), None, "probe de config é normal");
    }

    #[test]
    fn eacces_vira_error_independente_do_tipo_de_arquivo() {
        let denied = FailedSyscall {
            call: "openat".into(),
            path: "/etc/shadow".into(),
            errno: "EACCES".into(),
            errno_desc: String::new(),
        };
        assert_eq!(severity_for_failure(&denied), Some((crate::core::types::Severity::Error, 35)));
    }

    #[test]
    fn texto_sem_falhas_produz_lista_vazia_sem_panico() {
        assert!(parse_strace_failures("").is_empty());
        assert!(parse_strace_failures("lixo aleatório").is_empty());
        assert!(parse_strace_failures("= -1 sem errno conhecido").is_empty());
        assert!(parse_strace_failures("+++ exited with 1 +++").is_empty());
    }
}
