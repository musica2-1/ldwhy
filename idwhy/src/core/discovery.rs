use crate::core::types::WrapperStep;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const MAX_WRAPPER_DEPTH: usize = 5;

/// Um alvo resolvido: o executável final + os wrappers atravessados.
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub final_executable: PathBuf,
    pub chain: Vec<WrapperStep>,
}

/// Arquivo regular e legível? (leitura basta para a análise estática;
/// ausência do bit de execução é um cenário de diagnóstico válido,
/// tratado como evidência própria na etapa de permission check).
fn is_readable_file(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(md) => md.is_file(),
        Err(_) => false,
    }
}

/// Como o shell: candidato em $PATH precisa ter bit de execução.
fn is_executable_file(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(md) => md.is_file() && md.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// Resolve o input do usuário para um caminho base (sem seguir wrappers).
fn basic_resolve(input: &str) -> anyhow::Result<PathBuf> {
    let direct = PathBuf::from(input);
    if direct.exists() && !is_readable_file(&direct) {
        anyhow::bail!("'{}' existe mas não é um arquivo regular legível", input);
    }
    if is_readable_file(&direct) {
        return Ok(direct.canonicalize()?);
    }

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            if dir.is_empty() {
                continue;
            }
            let candidate = PathBuf::from(dir).join(input);
            if is_executable_file(&candidate) {
                return Ok(candidate.canonicalize()?);
            }
        }
    }

    anyhow::bail!(
        "Não foi possível localizar o executável '{}' (nem como path, nem em $PATH)",
        input
    )
}

struct ShebangParse {
    interpreter: String,
    arg: Option<String>,
}

/// Interpreta a linha shebang com as regras do kernel Linux:
/// tudo após o interpretador vira UM único argumento; CRLF e caminho
/// relativo quebram a execução real (ENOENT) — ou seja, são achados
/// de diagnóstico valiosos.
fn parse_shebang(bytes: &[u8]) -> Option<(ShebangParse, Option<String>)> {
    if !bytes.starts_with(b"#!") {
        return None;
    }
    let line_end = bytes.iter().position(|&b| b == b'\n').unwrap_or(bytes.len());
    let raw = String::from_utf8_lossy(&bytes[2..line_end]);
    let mut issue = None;

    let trimmed = raw.trim_end_matches('\r');
    if raw.ends_with('\r') {
        issue = Some(
            "shebang termina com CRLF ('\\r') — o kernel procura um \
             interpretador com nome terminado em '\\r' e falha com ENOENT"
                .to_string(),
        );
    }

    let content = trimmed.trim_start();
    if content.is_empty() {
        return Some((ShebangParse { interpreter: String::new(), arg: None }, issue));
    }

    let mut parts = content.split_whitespace();
    let interp = parts.next().unwrap_or("").to_string();
    let arg = parts.collect::<Vec<_>>().join(" ");
    Some((
        ShebangParse {
            interpreter: interp,
            arg: (!arg.is_empty()).then_some(arg),
        },
        issue,
    ))
}

enum Classification {
    Elf,
    AppImage(u8),
    Script((ShebangParse, Option<String>)),
    Other,
}

fn classify(path: &Path) -> Classification {
    use std::io::Read;
    // Mesmo tamanho do buffer de shebang do kernel (BINPRM_BUF_SIZE = 256):
    // linhas longas (#!/usr/bin/env python3) não podem ser truncadas.
    let mut buf = [0u8; 256];
    let len = fs::File::open(path).and_then(|mut f| f.read(&mut buf)).unwrap_or(0);

    if len < 4 || !buf[..len].starts_with(&[0x7f, b'E', b'L', b'F']) {
        return match parse_shebang(&buf[..len]) {
            Some(parsed) => Classification::Script(parsed),
            None => Classification::Other,
        };
    }

    if buf[8] == 0x41 && buf[9] == 0x49 && matches!(buf[10], 1 | 2) {
        return Classification::AppImage(buf[10]);
    }
    Classification::Elf
}

/// Resolve o input do usuário até o executável real, atravessando
/// wrappers (scripts com shebang, env, AppImage) sem nunca executar nada.
///
/// - Scripts: seguimos estaticamente o mesmo interpretador que o kernel
///   executaria. `#!/usr/bin/env X` resolve X via $PATH (comportamento
///   real do env).
/// - AppImage: o payload só existe montado/executando; paramos nele e
///   registramos o tipo pela mágica AI\x01/AI\x02 no offset 8.
pub fn resolve_target(input: &str) -> anyhow::Result<ResolvedTarget> {
    let mut current = basic_resolve(input)?;
    let mut chain = Vec::new();
    let mut visited: Vec<PathBuf> = vec![current.clone()];

    for _ in 0..MAX_WRAPPER_DEPTH {
        match classify(&current) {
            Classification::Elf | Classification::Other => break,
            Classification::AppImage(version) => {
                chain.push(WrapperStep {
                    kind: "appimage".into(),
                    detail: format!("mágica AI\\x{version:02} (AppImage tipo {version})"),
                    points_to: current.to_string_lossy().into_owned(),
                    issue: Some(
                        "payload interno só existe montado/executando — a análise \
                         estática não alcança o binário dentro do squashfs"
                            .into(),
                    ),
                });
                break;
            }
            Classification::Script((shebang, issue)) => {
                if shebang.interpreter.is_empty() {
                    chain.push(WrapperStep {
                        kind: "script_shebang".into(),
                        detail: "shebang '#!' sem interpretador".into(),
                        points_to: current.to_string_lossy().into_owned(),
                        issue: issue.or_else(|| Some("linha shebang vazia".into())),
                    });
                    break;
                }

                if !shebang.interpreter.starts_with('/') {
                    chain.push(WrapperStep {
                        kind: "script_shebang".into(),
                        detail: format!("#!{}", shebang.interpreter),
                        points_to: current.to_string_lossy().into_owned(),
                        issue: Some(format!(
                            "interpretador '{}' sem caminho absoluto — o kernel exige \
                             path absoluto no shebang e falha com ENOENT",
                            shebang.interpreter
                        )),
                    });
                    break;
                }

                let is_env = shebang.interpreter == "/usr/bin/env"
                    || shebang.interpreter.ends_with("/env");
                let next = if is_env {
                    let Some(target) = shebang.arg.as_deref() else {
                        chain.push(WrapperStep {
                            kind: "script_shebang".into(),
                            detail: "#!/usr/bin/env sem comando".into(),
                            points_to: current.to_string_lossy().into_owned(),
                            issue: Some("env sem comando a resolver".into()),
                        });
                        break;
                    };
                    basic_resolve(target)?
                } else if Path::new(&shebang.interpreter).is_file() {
                    Path::new(&shebang.interpreter).canonicalize()?
                } else {
                    anyhow::bail!(
                        "shebang aponta para interpretador inexistente: '{}'",
                        shebang.interpreter
                    );
                };

                chain.push(WrapperStep {
                    kind: wrapper_kind_for(&next),
                    detail: format!(
                        "#!{}{}",
                        shebang.interpreter,
                        shebang
                            .arg
                            .as_deref()
                            .map(|a| format!(" {a}"))
                            .unwrap_or_default()
                    ),
                    points_to: next.to_string_lossy().into_owned(),
                    issue,
                });

                if visited.contains(&next) {
                    anyhow::bail!("loop de wrappers detectado em {:?}", next);
                }
                visited.push(next.clone());
                current = next;
            }
        }
    }

    Ok(ResolvedTarget { final_executable: current, chain })
}

fn wrapper_kind_for(resolved: &Path) -> String {
    let text = resolved.to_string_lossy();
    if text.contains("flatpak") {
        "flatpak".into()
    } else {
        "script_shebang".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("idwhy_disc6_{}_{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let file = dir.join(name);
        fs::write(&file, content).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
        file
    }

    #[test]
    fn rejeita_path_inexistente() {
        assert!(resolve_target("/definitivamente/nao/existe-xyz").is_err());
    }

    #[test]
    fn shebang_simples_resolve_para_o_interpretador() {
        let dir = tempdir("simple");
        let script = write_file(&dir, "run.sh", b"#!/bin/sh\necho oi\n");

        let target = resolve_target(script.to_str().unwrap()).unwrap();
        assert_eq!(target.chain.len(), 1);
        assert_eq!(target.chain[0].kind, "script_shebang");
        // /bin/sh costuma ser symlink (→ bash); canonicalize revela o real.
        assert!(
            target.final_executable.to_string_lossy().ends_with("/bash")
                || target.final_executable.to_string_lossy().ends_with("/sh"),
            "veio {:?}",
            target.final_executable
        );
    }

    #[test]
    fn shebang_com_env_resolve_o_comando_via_path() {
        let dir = tempdir("env");
        if basic_resolve("python3").is_err() {
            return;
        }
        let script =
            write_file(&dir, "tool.py", b"#!/usr/bin/env python3\nprint('oi')\n");
        let target = resolve_target(script.to_str().unwrap()).unwrap();
        assert!(
            target.final_executable.to_string_lossy().contains("python"),
            "veio {:?}",
            target.final_executable
        );
    }

    #[test]
    fn argumento_do_interpretador_e_preservado_no_chain() {
        let dir = tempdir("arg");
        let script = write_file(&dir, "run.sh", b"#!/bin/bash -eu\necho oi\n");
        let target = resolve_target(script.to_str().unwrap()).unwrap();
        assert!(target.chain[0].detail.contains("-eu"), "veio {:?}", target.chain[0].detail);
    }

    #[test]
    fn crlf_no_shebang_vira_issue_mas_continua_resolucao() {
        let dir = tempdir("crlf");
        let script = write_file(&dir, "win.sh", b"#!/bin/sh\r\necho oi\r\n");
        let target = resolve_target(script.to_str().unwrap()).unwrap();

        let step = target.chain.first().expect("deve registrar o salto");
        assert!(step.issue.as_deref().unwrap_or("").contains("CRLF"));
        let final_path = target.final_executable.to_string_lossy();
        assert!(
            final_path.ends_with("/bash") || final_path.ends_with("/sh"),
            "veio {final_path}"
        );
    }

    #[test]
    fn interpretador_sem_caminho_absoluto_e_registrado_como_issue() {
        let dir = tempdir("relpath");
        let script = write_file(&dir, "broken.py", b"#!python3\nprint('oi')\n");
        let target = resolve_target(script.to_str().unwrap()).unwrap();

        let step = target.chain.first().unwrap();
        assert_eq!(step.kind, "script_shebang");
        assert!(step.issue.as_deref().unwrap_or("").contains("absoluto"));
        assert_eq!(target.final_executable, script);
    }

    #[test]
    fn interpretador_inexistente_falha_com_mensagem_clara() {
        let dir = tempdir("missing");
        let script = write_file(&dir, "x.sh", b"#!/caminho/inexistente/interp\n");
        let err = resolve_target(script.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("inexistente"));
    }

    #[test]
    fn appimage_detectado_pela_magica_no_offset_8() {
        let dir = tempdir("appimage");
        let mut bytes = vec![0x7f, b'E', b'L', b'F'];
        bytes.extend_from_slice(&[0u8; 4]);
        bytes.extend_from_slice(&[0x41, 0x49, 0x02]);
        bytes.extend_from_slice(&[0u8; 64]);
        let file = write_file(&dir, "MeuApp.AppImage", &bytes);

        let target = resolve_target(file.to_str().unwrap()).unwrap();
        assert_eq!(target.chain.len(), 1);
        assert_eq!(target.chain[0].kind, "appimage");
        assert!(target.chain[0].detail.contains("tipo 2"));
        assert_eq!(target.final_executable, file);
    }

    #[test]
    fn arquivo_texto_sem_shebang_passa_inalterado_para_analise() {
        let dir = tempdir("text");
        let file = write_file(&dir, "notbinary.txt", b"apenas texto\n");
        let target = resolve_target(file.to_str().unwrap()).unwrap();
        assert!(target.chain.is_empty());
        assert_eq!(target.final_executable, file);
    }

    #[test]
    fn cadeia_de_scripts_registra_cada_salto_ate_o_interpretador() {
        let dir = tempdir("chain");
        let c = write_file(&dir, "c.sh", b"#!/bin/bash\necho fim\n");
        let b_path = dir.join("b.sh");
        fs::write(&b_path, format!("#!/bin/bash {}\n", c.display())).unwrap();
        fs::set_permissions(&b_path, fs::Permissions::from_mode(0o755)).unwrap();
        let a_path = dir.join("a.sh");
        fs::write(&a_path, format!("#!/bin/bash {}\n", b_path.display())).unwrap();
        fs::set_permissions(&a_path, fs::Permissions::from_mode(0o755)).unwrap();

        // Semântica do kernel: '#!/bin/bash script.sh' executa o BASH
        // (script vira argumento). O executável real é sempre o bash;
        // os saltos ficam documentados no detail da cadeia.
        let target = resolve_target(a_path.to_str().unwrap()).unwrap();
        assert_eq!(target.chain.len(), 1);
        assert!(
            target.chain[0].detail.contains(b_path.to_string_lossy().as_ref()),
            "o salto de a.sh deve citar b.sh como argumento; veio {:?}",
            target.chain[0].detail
        );
        assert!(target.final_executable.to_string_lossy().ends_with("/bash"));
    }

    #[test]
    fn helpers_de_classificacao_de_arquivo_comum() {
        let dir = tempdir("helpers");
        let no_exec = dir.join("semx");
        fs::write(&no_exec, b"x").unwrap();
        let yes_exec = dir.join("comx");
        fs::write(&yes_exec, b"x").unwrap();
        fs::set_permissions(&yes_exec, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(!is_executable_file(&no_exec));
        assert!(is_executable_file(&yes_exec));
        assert!(!is_readable_file(&dir.join("nao_existe")));
        assert!(!is_executable_file(&dir));
    }
}
