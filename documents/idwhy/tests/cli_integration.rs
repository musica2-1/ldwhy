use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_idwhy");

fn run_diag(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(BIN).args(args).output().expect("binário de teste deve executar");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn diagnostica_binario_real_em_texto() {
    let (code, stdout, _stderr) = run_diag(&["diagnose", "/bin/true"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("STATIC ANALYSIS"));
    assert!(stdout.contains("ELF header válido") || stdout.contains("ELF header v\u{e1}lido"));
    assert!(stdout.contains("EVIDENCE"));
    assert!(stdout.contains("DIAGNOSIS"));
}

#[test]
fn json_e_valido_e_tem_profile() {
    let (code, stdout, _stderr) = run_diag(&["diagnose", "--json", "/bin/true"]);
    assert_eq!(code, 0);
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("saída --json deve ser JSON válido");
    assert!(value.get("profile").is_some());
    assert!(value.get("evidences").is_some());
    assert!(value.get("candidates").is_some());
}

#[test]
fn alvo_inexistente_produz_relatorio_com_path_not_found() {
    let (code, stdout, _stderr) = run_diag(&["diagnose", "/caminho/que/nao/existe-xyz"]);
    assert_eq!(code, 0, "relatório é gerado mesmo sem encontrar o alvo");
    assert!(stdout.contains("não pôde ser lido"), "evidência de path ausente deve aparecer; veio:\n{stdout}");

    let (_code, json_out, _stderr) = run_diag(&["diagnose", "--json", "/caminho/que/nao/existe-xyz"]);
    let value: serde_json::Value = serde_json::from_str(&json_out).unwrap();
    assert_eq!(
        value["evidences"][0]["kind"].as_str(),
        Some("path_not_found")
    );
}

#[test]
fn resolve_por_nome_via_path_do_sistema() {
    let (code, stdout, _stderr) = run_diag(&["diagnose", "sh"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Executable:"));
}

#[test]
fn modo_interativo_sem_tty_falha_com_dica() {
    use std::process::Stdio;
    let out = Command::new(BIN)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("binário de teste deve executar");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("diagnose"),
        "mensagem deve sugerir `diag diagnose <alvo>`; veio: {stderr}"
    );
}
