use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

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

/// Resolve o input do usuário para um caminho real de executável.
/// Aceita: path absoluto/relativo, ou nome de comando (procura em $PATH).
/// Segue symlinks via canonicalize() — nunca executa o binário.
pub fn resolve_executable(input: &str) -> anyhow::Result<PathBuf> {
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

    anyhow::bail!("Não foi possível localizar o executável '{}' (nem como path, nem em $PATH)", input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tempdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("diag_disc_test_{}_{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn rejeita_path_inexistente() {
        let err = resolve_executable("/definitivamente/inexistente-xyz-12345").unwrap_err();
        assert!(err.to_string().contains("Não foi possível localizar"));
    }

    #[test]
    fn rejeita_diretorio_como_path_direto() {
        let dir = tempdir("dir_as_target");
        assert!(resolve_executable(&dir.to_string_lossy()).is_err());
    }

    #[test]
    fn aceita_arquivo_legivel_sem_bit_de_execucao_em_path_direto() {
        let dir = tempdir("noexec");
        let file = dir.join("app_sem_x");
        fs::write(&file, b"data").unwrap();

        let resolved = resolve_executable(&file.to_string_lossy()).unwrap();
        assert_eq!(resolved, file.canonicalize().unwrap());
    }

    #[test]
    fn path_search_exige_bit_de_execucao() {
        // Sem mexer no $PATH do processo: valida apenas os helpers.
        let dir = tempdir("exec_bits");
        let no_exec = dir.join("a");
        fs::write(&no_exec, b"x").unwrap();
        let yes_exec = dir.join("b");
        fs::write(&yes_exec, b"x").unwrap();
        fs::set_permissions(&yes_exec, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(!is_executable_file(&no_exec));
        assert!(is_executable_file(&yes_exec));
        assert!(!is_readable_file(&dir.join("nao_existe")));
        assert!(!is_executable_file(&dir)); // diretório não é executável-arquivo
    }
}
