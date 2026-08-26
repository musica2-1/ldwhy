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
fn script_com_shebang_crlf_gera_evidencia_de_wrapper_quebrado() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("idwhy_crlf_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let alvo = dir.join("quebrado.sh");
    std::fs::write(&alvo, b"#!/bin/sh\r\necho oi\r\n").unwrap();
    std::fs::set_permissions(&alvo, std::fs::Permissions::from_mode(0o755)).unwrap();

    let (_code, json_out, _stderr) =
        run_diag(&["diagnose", "--json", alvo.to_string_lossy().as_ref()]);
    let value: serde_json::Value = serde_json::from_str(&json_out).unwrap();

    assert!(
        value["evidences"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "broken_wrapper"),
        "CRLF no shebang deve virar evidência: {json_out}"
    );
    assert!(
        value["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["cause_id"] == "cc_broken_wrapper")
    );
    assert!(value["profile"]["wrapper_chain"].as_array().map_or(false, |c| !c.is_empty()));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ld_preload_injetado_aparece_como_evidencia_info() {
    let out = Command::new(BIN)
        .args(["diagnose", "--json", "/bin/true"])
        .env("LD_PRELOAD", "/tmp/idwhy_hook_fake.so")
        .output()
        .expect("binário de teste deve executar");
    assert_eq!(out.status.code(), Some(0));

    let value: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let evidences = value["evidences"].as_array().unwrap();
    let preload = evidences
        .iter()
        .find(|e| e["kind"] == "ld_preload_active")
        .expect("LD_PRELOAD setado deve gerar evidência");
    assert_eq!(preload["severity"], "Info");
    assert_eq!(
        preload["data"]["value"].as_str(),
        Some("/tmp/idwhy_hook_fake.so")
    );

    let causes = value["candidates"].as_array().unwrap();
    assert!(causes.iter().any(|c| c["cause_id"] == "cc_suspicious_ld_env"));
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
        "mensagem deve sugerir `diagnose`; veio: {stderr}"
    );
}

#[test]
fn binario_sem_bit_de_execucao_gera_evidencia_e_causa() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("idwhy_perm_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let alvo = dir.join("app_sem_x");
    std::fs::copy("/bin/true", &alvo).unwrap();
    std::fs::set_permissions(&alvo, std::fs::Permissions::from_mode(0o644)).unwrap();

    let (code, stdout, _stderr) =
        run_diag(&["diagnose", "--json", alvo.to_string_lossy().as_ref()]);
    assert_eq!(code, 0);

    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        value["evidences"][0]["kind"].as_str(),
        Some("exec_permission_denied"),
        "evidência de permissão deve existir; veio: {stdout}"
    );
    assert_eq!(value["evidences"][0]["data"]["mode"].as_str(), Some("644"));

    let causes = value["candidates"].as_array().unwrap();
    assert!(
        causes.iter().any(|c| c["cause_id"] == "cc_exec_permission"),
        "causa cc_exec_permission deve ser candidata: {stdout}"
    );

    let (_code, text_out, _stderr) = run_diag(&["diagnose", alvo.to_string_lossy().as_ref()]);
    assert!(text_out.contains("chmod +x"), "remediação chmod +x esperada:\n{text_out}");

    let _ = std::fs::remove_dir_all(&dir);
}
