use std::path::PathBuf;

/// Resolve o input do usuário para um caminho de executável real.
/// Aceita: path absoluto/relativo, ou nome de comando (procura em $PATH).
/// Segue symlinks via canonicalize() — nunca executa o binário.
pub fn resolve_executable(input: &str) -> anyhow::Result<PathBuf> {
    let direct = PathBuf::from(input);
    if direct.is_file() {
        return Ok(direct.canonicalize()?);
    }

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let candidate = PathBuf::from(dir).join(input);
            if candidate.is_file() {
                return Ok(candidate.canonicalize()?);
            }
        }
    }

    anyhow::bail!("Não foi possível localizar o executável '{}' (nem como path, nem em $PATH)", input)
}
