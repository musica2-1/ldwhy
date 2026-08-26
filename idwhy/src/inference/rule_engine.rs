use crate::analyzers::package_analyzer;
use crate::core::types::{ApplicationProfile, CauseCandidate, Evidence, Remediation, Severity};

/// Calibração de confiança por categoria de causa.
///
/// `score_full` é a soma de pesos que constitui "prova completa" da
/// categoria; `cap` é o teto honesto de confiança. Categorias com
/// evidência inequívoca (a lib existe no disco ou não) têm cap alto;
/// categorias ambíguas (ex: ambiente) terão cap baixo e full maior,
/// preservando gradiente entre uma e várias evidências.
struct Calibration {
    score_full: f64,
    cap: f64,
}

const CALIBRATIONS: &[(&str, Calibration)] = &[
    // Uma única lib ausente já é praticamente conclusiva.
    ("dependency", Calibration { score_full: 45.0, cap: 0.95 }),
    // Header ELF inválido não tem interpretação alternativa.
    ("binary_integrity", Calibration { score_full: 60.0, cap: 0.95 }),
    // Alvo inexistente em path e $PATH é fato, não hipótese.
    ("target_resolution", Calibration { score_full: 50.0, cap: 0.95 }),
    // Reservado à Etapa 3 (environment): evidências podem ser falso positivo.
    ("environment", Calibration { score_full: 40.0, cap: 0.60 }),
    // Sem bit x aplicável ao usuário é inequívoco (o próprio kernel negaria).
    ("permission", Calibration { score_full: 40.0, cap: 0.95 }),
    // Runtime sob sandbox: ENOENT em .so é forte, mas apps fazem probes
    // legítimos — teto menor que categorias inequívocas.
    ("runtime", Calibration { score_full: 50.0, cap: 0.85 }),
];

fn calibration_for(category: &str) -> Option<&'static Calibration> {
    CALIBRATIONS
        .iter()
        .find(|(cat, _)| *cat == category)
        .map(|(_, cal)| cal)
}

fn calibrated_confidence(category: &str, score: f64) -> f64 {
    match calibration_for(category) {
        Some(cal) => (score / cal.score_full).min(1.0) * cal.cap,
        None => 0.0,
    }
}

pub fn collect_evidence(profile: &ApplicationProfile) -> Vec<Evidence> {
    let mut evidences = Vec::new();
    let mut counter = 0;
    let mut next_id = || {
        counter += 1;
        format!("ev_{:03}", counter)
    };

    let binary = match &profile.binary {
        Some(b) => b,
        None => {
            evidences.push(Evidence {
                id: next_id(),
                source: "static_analyzer".into(),
                kind: "path_not_found".into(),
                severity: Severity::Critical,
                weight: 50,
                description: "O caminho informado não pôde ser lido".into(),
                data: serde_json::json!({ "path": profile.input_path }),
            });
            return evidences;
        }
    };

    if !binary.elf_valid {
        evidences.push(Evidence {
            id: next_id(),
            source: "static_analyzer".into(),
            kind: "elf_invalid".into(),
            severity: Severity::Critical,
            weight: 60,
            description: "Arquivo não é um ELF válido (corrompido ou não é um binário)".into(),
            data: serde_json::json!({}),
        });
        return evidences; // não faz sentido seguir analisando dependências
    }

    // Permissão de execução simulada para o usuário atual (Etapa 2).
    if let Some(perm) = &profile.permissions {
        if !perm.user_can_execute {
            evidences.push(Evidence {
                id: next_id(),
                source: "permission_analyzer".into(),
                kind: "exec_permission_denied".into(),
                severity: Severity::Critical,
                weight: 40,
                description: format!(
                    "Sem permissão de execução para o usuário atual (modo {:03o}, \
                    dono uid {}, você é uid {})",
                    perm.mode & 0o777,
                    perm.file_uid,
                    perm.euid
                ),
                data: serde_json::json!({
                    "mode": format!("{:03o}", perm.mode & 0o777),
                    "file_uid": perm.file_uid,
                    "file_gid": perm.file_gid,
                    "euid": perm.euid,
                }),
            });
        }
    }

    // Execução controlada (Etapa 8): falhas de syscall sob sandbox.
    if let Some(rt) = &profile.runtime {
        for f in &rt.failed_syscalls {
            if let Some((severity, weight)) =
                crate::analyzers::runtime_analyzer::severity_for_failure(f)
            {
                let kind = match f.errno.as_str() {
                    "ENOENT" => "runtime_missing_library",
                    "EACCES" | "EPERM" => "runtime_permission_denied",
                    _ => "runtime_path_issue",
                };
                evidences.push(Evidence {
                    id: next_id(),
                    source: "runtime_analyzer".into(),
                    kind: kind.into(),
                    severity,
                    weight,
                    description: format!(
                        "{} em '{}' retornou {} ({}) durante execução sandboxada",
                        f.call, f.path, f.errno, f.errno_desc
                    ),
                    data: serde_json::json!({
                        "call": f.call, "path": f.path, "errno": f.errno,
                    }),
                });
            }
        }

        if rt.killed_by_timeout {
            evidences.push(Evidence {
                id: next_id(),
                source: "runtime_analyzer".into(),
                kind: "runtime_timeout".into(),
                severity: Severity::Info,
                weight: 5,
                description: format!(
                    "Processo excedeu o timeout ({} ms) e foi encerrado",
                    rt.duration_ms
                ),
                data: serde_json::json!({ "duration_ms": rt.duration_ms }),
            });
        } else if rt.exit_code == Some(0) {
            evidences.push(Evidence {
                id: next_id(),
                source: "runtime_analyzer".into(),
                kind: "runtime_clean_exit".into(),
                severity: Severity::Info,
                weight: 0,
                description: format!(
                    "Executou sob sandbox e saiu limpo ({} ms)",
                    rt.duration_ms
                ),
                data: serde_json::json!({ "duration_ms": rt.duration_ms }),
            });
        }
    }

    // Wrappers com problema (Etapa 6): shebang CRLF/caminho relativo
    // impedem a execução real com ENOENT — crítico e inequívoco.
    for step in &profile.wrapper_chain {
        if let Some(issue) = &step.issue {
            evidences.push(Evidence {
                id: next_id(),
                source: "discovery".into(),
                kind: "broken_wrapper".into(),
                severity: Severity::Critical,
                weight: 45,
                description: format!("{}: {}", step.detail, issue),
                data: serde_json::json!({
                    "kind": step.kind,
                    "detail": step.detail,
                    "issue": issue,
                }),
            });
        }
    }

    // Interpretador ausente (ld.so) -> binário não vai nem iniciar
    if binary.interpreter.is_none() && !binary.is_pie {
        evidences.push(Evidence {
            id: next_id(),
            source: "static_analyzer".into(),
            kind: "no_interpreter".into(),
            severity: Severity::Warning,
            weight: 10,
            description: "Binário estático (sem PT_INTERP) — dependências dinâmicas não se aplicam".into(),
            data: serde_json::json!({}),
        });
    }

    // Dependências ausentes
    let missing: Vec<&String> = profile
        .dependency_graph
        .values()
        .filter(|n| !n.found)
        .map(|n| &n.name)
        .collect();

    for lib in &missing {
        let node = &profile.dependency_graph[*lib];
        evidences.push(Evidence {
            id: next_id(),
            source: "dependency_analyzer".into(),
            kind: "missing_shared_library".into(),
            severity: Severity::Critical,
            weight: 45,
            description: format!(
                "Biblioteca compartilhada '{}' não encontrada (requerida por {})",
                lib,
                node.needed_by.join(", ")
            ),
            data: serde_json::json!({ "library": lib, "needed_by": node.needed_by }),
        });
    }

    // Integridade vs gerenciador de pacotes (Etapa 5).
    if let Some(check) = &profile.integrity {
        if check.matches == Some(false) {
            evidences.push(Evidence {
                id: next_id(),
                source: "package_analyzer".into(),
                kind: "binary_modified_from_package".into(),
                severity: Severity::Error,
                weight: 35,
                description: format!(
                    "Arquivo difere do hash {} registrado pelo gerenciador na instalação",
                    check.algo
                ),
                data: serde_json::json!({
                    "algo": check.algo,
                    "recorded_prefix": &check.recorded[..check.recorded.len().min(16)],
                    "computed_sha256_prefix": &profile.binary.as_ref().map(|b| b.sha256[..16].to_string()),
                }),
            });
        }
    }

    // Ambiente (Etapa 3): só alerta falta de display em app gráfico —
    // apps de terminal não podem gerar falso positivo aqui.
    if let Some(env) = &profile.environment {
        if env.is_graphical() && !env.has_display_server() {
            evidences.push(Evidence {
                id: next_id(),
                source: "environment_analyzer".into(),
                kind: "missing_display_env".into(),
                severity: Severity::Warning,
                weight: 20,
                description: format!(
                    "Aplicação gráfica ({}) sem DISPLAY nem WAYLAND_DISPLAY no ambiente",
                    crate::analyzers::environment_analyzer::summarize_libraries(&env.gui_libraries, 3)
                ),
                data: serde_json::json!({ "gui_libraries": env.gui_libraries }),
            });
        }
        if let Some(preload) = &env.ld_preload {
            evidences.push(Evidence {
                id: next_id(),
                source: "environment_analyzer".into(),
                kind: "ld_preload_active".into(),
                severity: Severity::Info,
                weight: 10,
                description: format!(
                    "LD_PRELOAD ativo ('{preload}') — pode alterar ou mascarar o comportamento real"
                ),
                data: serde_json::json!({ "value": preload }),
            });
        }
        if !env.ld_library_path.is_empty() {
            evidences.push(Evidence {
                id: next_id(),
                source: "environment_analyzer".into(),
                kind: "ld_library_path_active".into(),
                severity: Severity::Info,
                weight: 10,
                description: format!(
                    "LD_LIBRARY_PATH ativo ({}) — pode sombrear bibliotecas do cache do sistema",
                    env.ld_library_path.join(":")
                ),
                data: serde_json::json!({ "paths": env.ld_library_path }),
            });
        }
    }

    evidences
}

pub fn rank_causes(profile: &ApplicationProfile, evidences: &[Evidence]) -> Vec<CauseCandidate> {
    let mut candidates = Vec::new();

    let not_found_evs: Vec<&Evidence> = evidences
        .iter()
        .filter(|e| e.kind == "path_not_found")
        .collect();
    if !not_found_evs.is_empty() {
        let score: f64 = not_found_evs.iter().map(|e| e.weight as f64).sum();
        // Etapa 4: se algum pacote conhecido fornece o nome, oferecer install direto.
        let provider = package_analyzer::find_provider(&profile.input_path, None);
        let suggested = provider.as_ref().map(|pkg| {
            let pm = if pkg.manager == "apt" {
                package_analyzer::PackageManager::Apt
            } else {
                package_analyzer::PackageManager::Dnf
            };
            pm.install_cmd(&pkg.name)
        });
        candidates.push(CauseCandidate {
            cause_id: "cc_target_not_found".into(),
            description: format!(
                "Alvo '{}' não encontrado nem como path nem em $PATH",
                profile.input_path
            ),
            category: "target_resolution".into(),
            evidence_ids: not_found_evs.iter().map(|e| e.id.clone()).collect(),
            score,
            confidence: calibrated_confidence("target_resolution", score),
            suggested_fix: Some(Remediation {
                description: match &provider {
                    Some(pkg) => format!(
                        "O nome corresponde ao pacote '{}' ({}) — instalar pode resolver",
                        pkg.name, pkg.manager
                    ),
                    None => "Verificar a grafia do nome ou instalar o pacote que fornece o executável".into(),
                },
                investigation_command: Some(format!(
                    "command -v {} # e verifique se está no $PATH",
                    profile.input_path
                )),
                suggested_command: suggested,
                risk: "low".into(),
                automated_safe: false,
            }),
        });
    }

    let broken_wrapper_evs: Vec<&Evidence> = evidences
        .iter()
        .filter(|e| e.kind == "broken_wrapper")
        .collect();
    if !broken_wrapper_evs.is_empty() {
        let score: f64 = broken_wrapper_evs.iter().map(|e| e.weight as f64).sum();
        candidates.push(CauseCandidate {
            cause_id: "cc_broken_wrapper".into(),
            description: "Script/wrapper com shebang quebrado — o kernel falha \
                antes de chegar à aplicação"
                .into(),
            category: "target_resolution".into(),
            evidence_ids: broken_wrapper_evs.iter().map(|e| e.id.clone()).collect(),
            score,
            confidence: calibrated_confidence("target_resolution", score),
            suggested_fix: Some(Remediation {
                description: "Corrigir a linha shebang do script".into(),
                investigation_command: Some(format!(
                    "head -1 {} | cat -A # procure ^M (CRLF) ou caminho relativo",
                    profile.input_path
                )),
                suggested_command: Some(format!(
                    "sed -i '1s/\\r$//' {} # remove CRLF da primeira linha",
                    profile.input_path
                )),
                risk: "low".into(),
                automated_safe: false,
            }),
        });
    }

    let missing_lib_evs: Vec<&Evidence> = evidences
        .iter()
        .filter(|e| e.kind == "missing_shared_library")
        .collect();

    if !missing_lib_evs.is_empty() {
        let score: f64 = missing_lib_evs.iter().map(|e| e.weight as f64).sum();
        // fator de diversidade: mais de uma lib ausente ainda é a "mesma causa raiz"
        // se todas forem transitivamente requeridas pela mesma lib de topo — aqui
        // simplificamos e tratamos como um único candidato agregado.
        let libs: Vec<String> = missing_lib_evs
            .iter()
            .filter_map(|e| e.data.get("library").and_then(|v| v.as_str()).map(String::from))
            .collect();

        // Etapa 4: pacote conhecido → comando de instalação concreto.
        let confidence = calibrated_confidence("dependency", score);
        let arch = profile.binary.as_ref().map(|b| b.arch.as_str());
        let provider = libs
            .first()
            .and_then(|l| package_analyzer::find_provider(l, arch));
        let (investigation, suggested) = match &provider {
            Some(pkg) => {
                let pm = if pkg.manager == "apt" {
                    package_analyzer::PackageManager::Apt
                } else {
                    package_analyzer::PackageManager::Dnf
                };
                (None, Some(pm.install_cmd(&pkg.name)))
            }
            None => (
                libs.first()
                    .map(|l| format!("dnf provides '*/{l}' # ou: apt-file search {l}")),
                None,
            ),
        };

        candidates.push(CauseCandidate {
            cause_id: "cc_missing_lib".into(),
            description: format!(
                "Dependência(s) compartilhada(s) ausente(s): {}",
                libs.join(", ")
            ),
            category: "dependency".into(),
            evidence_ids: missing_lib_evs.iter().map(|e| e.id.clone()).collect(),
            score,
            confidence,
            suggested_fix: Some(Remediation {
                description: match &provider {
                    Some(pkg) => format!(
                        "A biblioteca é fornecida pelo pacote '{}' ({})",
                        pkg.name, pkg.manager
                    ),
                    None => "Instalar o pacote que fornece a biblioteca ausente".into(),
                },
                investigation_command: investigation,
                suggested_command: suggested,
                risk: "low".into(),
                automated_safe: false,
            }),
        });
    }

    let elf_invalid_evs: Vec<&Evidence> = evidences
        .iter()
        .filter(|e| e.kind == "elf_invalid")
        .collect();
    if !elf_invalid_evs.is_empty() {
        // Score derivado das evidências — nunca duplicar peso em hardcode,
        // senão mudar o weight desalinha o ranking silenciosamente.
        let score: f64 = elf_invalid_evs.iter().map(|e| e.weight as f64).sum();
        // Etapa 4: se o binário pertence a um pacote, sugerir reinstalação concreta.
        let reinstall = profile
            .package_owner
            .as_ref()
            .map(|pkg| {
                let pm = if pkg.manager == "apt" {
                    package_analyzer::PackageManager::Apt
                } else {
                    package_analyzer::PackageManager::Dnf
                };
                pm.reinstall_cmd(&pkg.name)
            });
        candidates.push(CauseCandidate {
            cause_id: "cc_elf_invalid".into(),
            description: "Binário corrompido ou não é um executável ELF válido".into(),
            category: "binary_integrity".into(),
            evidence_ids: elf_invalid_evs.iter().map(|e| e.id.clone()).collect(),
            score,
            confidence: calibrated_confidence("binary_integrity", score),
            suggested_fix: Some(Remediation {
                description: match &profile.package_owner {
                    Some(pkg) => format!(
                        "Arquivo pertence ao pacote '{}' — reinstalar restaura o original",
                        pkg.name
                    ),
                    None => "Reinstalar o pacote ou verificar integridade do download".into(),
                },
                investigation_command: Some(format!("file {}", profile.resolved_executable)),
                suggested_command: reinstall,
                risk: "low".into(),
                automated_safe: false,
            }),
        });
    }

    let exec_denied_evs: Vec<&Evidence> = evidences
        .iter()
        .filter(|e| e.kind == "exec_permission_denied")
        .collect();
    if !exec_denied_evs.is_empty() {
        let score: f64 = exec_denied_evs.iter().map(|e| e.weight as f64).sum();
        let alvo = &profile.resolved_executable;
        candidates.push(CauseCandidate {
            cause_id: "cc_exec_permission".into(),
            description: "Permissão de execução negada para o usuário atual".into(),
            category: "permission".into(),
            evidence_ids: exec_denied_evs.iter().map(|e| e.id.clone()).collect(),
            score,
            confidence: calibrated_confidence("permission", score),
            suggested_fix: Some(Remediation {
                description: "Conceder permissão de execução ao arquivo".into(),
                investigation_command: Some(format!("ls -l {alvo}")),
                suggested_command: Some(format!("chmod +x {alvo}")),
                risk: "low".into(),
                automated_safe: false,
            }),
        });
    }

    let display_evs: Vec<&Evidence> = evidences
        .iter()
        .filter(|e| e.kind == "missing_display_env")
        .collect();
    if !display_evs.is_empty() {
        let score: f64 = display_evs.iter().map(|e| e.weight as f64).sum();
        candidates.push(CauseCandidate {
            cause_id: "cc_missing_display_env".into(),
            description: "Aplicação gráfica executada sem servidor de exibição acessível".into(),
            category: "environment".into(),
            evidence_ids: display_evs.iter().map(|e| e.id.clone()).collect(),
            score,
            confidence: calibrated_confidence("environment", score),
            suggested_fix: Some(Remediation {
                description: "Executar dentro de uma sessão gráfica ativa (X11 ou Wayland)".into(),
                investigation_command: Some(
                    "echo \"DISPLAY=$DISPLAY WAYLAND_DISPLAY=$WAYLAND_DISPLAY\"".into(),
                ),
                suggested_command: None,
                risk: "low".into(),
                automated_safe: false,
            }),
        });
    }

    let ld_env_evs: Vec<&Evidence> = evidences
        .iter()
        .filter(|e| e.kind == "ld_preload_active" || e.kind == "ld_library_path_active")
        .collect();
    if !ld_env_evs.is_empty() {
        let score: f64 = ld_env_evs.iter().map(|e| e.weight as f64).sum();
        candidates.push(CauseCandidate {
            cause_id: "cc_suspicious_ld_env".into(),
            description: "Variáveis LD_* ativas podem sombrear ou mascarar bibliotecas reais".into(),
            category: "environment".into(),
            evidence_ids: ld_env_evs.iter().map(|e| e.id.clone()).collect(),
            score,
            confidence: calibrated_confidence("environment", score),
            suggested_fix: Some(Remediation {
                description: "Testar novamente sem as variáveis para descartar interferência".into(),
                investigation_command: Some("env | grep '^LD_'".into()),
                suggested_command: Some(
                    "env -u LD_PRELOAD -u LD_LIBRARY_PATH <comando_do_app>".into(),
                ),
                risk: "low".into(),
                automated_safe: false,
            }),
        });
    }

    let tampered_evs: Vec<&Evidence> = evidences
        .iter()
        .filter(|e| e.kind == "binary_modified_from_package")
        .collect();
    if !tampered_evs.is_empty() {
        let score: f64 = tampered_evs.iter().map(|e| e.weight as f64).sum();
        let reinstall = profile.package_owner.as_ref().map(|pkg| {
            let pm = if pkg.manager == "apt" {
                package_analyzer::PackageManager::Apt
            } else {
                package_analyzer::PackageManager::Dnf
            };
            pm.reinstall_cmd(&pkg.name)
        });
        candidates.push(CauseCandidate {
            cause_id: "cc_binary_tampered".into(),
            description: format!(
                "Binário modificado após a instalação (não confere com o registro do gerenciador){}",
                profile
                    .package_owner
                    .as_ref()
                    .map(|p| format!(" — pacote '{}'", p.name))
                    .unwrap_or_default()
            ),
            category: "binary_integrity".into(),
            evidence_ids: tampered_evs.iter().map(|e| e.id.clone()).collect(),
            score,
            confidence: calibrated_confidence("binary_integrity", score),
            suggested_fix: Some(Remediation {
                description: match &profile.package_owner {
                    Some(pkg) => format!(
                        "Restaurar o arquivo original reinstalando o pacote '{}'",
                        pkg.name
                    ),
                    None => "Reinstalar o pacote ou verificar integridade do download".into(),
                },
                investigation_command: Some(format!("rpm -V {} # ou: debsums -c", profile.input_path)),
                suggested_command: reinstall,
                risk: "medium".into(),
                automated_safe: false,
            }),
        });
    }

    let runtime_lib_evs: Vec<&Evidence> = evidences
        .iter()
        .filter(|e| e.kind == "runtime_missing_library")
        .collect();
    if !runtime_lib_evs.is_empty() {
        let score: f64 = runtime_lib_evs.iter().map(|e| e.weight as f64).sum();
        let paths: Vec<String> = runtime_lib_evs
            .iter()
            .filter_map(|e| e.data.get("path").and_then(|v| v.as_str()).map(String::from))
            .collect();
        candidates.push(CauseCandidate {
            cause_id: "cc_runtime_dependency_miss".into(),
            description: format!(
                "Falha ao carregar biblioteca(s) em runtime (sandbox): {}",
                paths.join(", ")
            ),
            category: "runtime".into(),
            evidence_ids: runtime_lib_evs.iter().map(|e| e.id.clone()).collect(),
            score,
            confidence: calibrated_confidence("runtime", score),
            suggested_fix: Some(Remediation {
                description: "Biblioteca requerida em execução não foi encontrada pelo loader".into(),
                investigation_command: Some(format!(
                    "ldd {} # confirme o que falta carregar",
                    profile.resolved_executable
                )),
                suggested_command: None,
                risk: "low".into(),
                automated_safe: false,
            }),
        });
    }

    // Sem nenhuma evidência crítica -> nada encontrado nesta camada estática
    if candidates.is_empty() {
        candidates.push(CauseCandidate {
            cause_id: "cc_no_static_issue".into(),
            description: "Nenhum problema detectado na análise estática (ELF + dependências). \
                O problema provavelmente está em runtime, permissões, ambiente gráfico ou lógica da aplicação — \
                fora do escopo desta versão do MVP.".into(),
            category: "inconclusive".into(),
            evidence_ids: vec![],
            score: 0.0,
            confidence: 0.0,
            suggested_fix: None,
        });
    }

    candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{ApplicationProfile, BinaryInfo};
    use std::collections::HashMap;

    fn ev(id: &str, kind: &str, weight: i32, library: Option<&str>) -> Evidence {
        Evidence {
            id: id.into(),
            source: "test".into(),
            kind: kind.into(),
            severity: Severity::Critical,
            weight,
            description: "teste".into(),
            data: match library {
                Some(lib) => serde_json::json!({ "library": lib }),
                None => serde_json::json!({}),
            },
        }
    }

    fn empty_profile() -> ApplicationProfile {
        ApplicationProfile {
            input_path: "/tmp/app".into(),
            resolved_executable: "/tmp/app".into(),
            binary: Some(BinaryInfo {
                elf_valid: true,
                arch: "x86_64".into(),
                is_pie: false,
                interpreter: None,
                needed: vec![],
                rpath: vec![],
                runpath: vec![],
                sha256: "0".repeat(64),
            }),
            dependency_graph: HashMap::new(),
            permissions: None,
            environment: None,
            package_owner: None,
            integrity: None,
            runtime: None,
            wrapper_chain: Vec::new(),
        }
    }

    #[test]
    fn uma_lib_ausente_atinge_o_cap_da_categoria_dependency() {
        let profile = empty_profile();
        let evidences = vec![ev("ev_001", "missing_shared_library", 45, Some("libfalsa.so.3"))];
        let causes = rank_causes(&profile, &evidences);
        let dep = causes.iter().find(|c| c.cause_id == "cc_missing_lib").unwrap();
        assert!((dep.confidence - 0.95).abs() < 1e-9, "era 45% na fórmula antiga; agora deve ser o cap 95%: {}", dep.confidence);
    }

    #[test]
    fn elf_invalid_calibra_pela_categoria() {
        let profile = empty_profile();
        let evidences = vec![ev("ev_001", "elf_invalid", 60, None)];
        let causes = rank_causes(&profile, &evidences);
        let cc = causes.iter().find(|c| c.cause_id == "cc_elf_invalid").unwrap();
        assert_eq!(cc.score, 60.0, "score vem do peso da evidência");
        assert!((cc.confidence - 0.95).abs() < 1e-9);
    }

    #[test]
    fn alvo_nao_encontrado_calibra_pela_categoria() {
        let mut profile = empty_profile();
        profile.binary = None;
        let evidences = vec![ev("ev_001", "path_not_found", 50, None)];
        let causes = rank_causes(&profile, &evidences);
        let cc = causes.iter().find(|c| c.cause_id == "cc_target_not_found").unwrap();
        assert!((cc.confidence - 0.95).abs() < 1e-9);
    }

    #[test]
    fn categorias_ambiguas_preservam_gradiente_sem_bater_no_cap() {
        // Etapa 3 usará isto: uma evidência fraca não pode fingir certeza.
        assert!((calibrated_confidence("environment", 20.0) - 0.30).abs() < 1e-9);
        assert!((calibrated_confidence("environment", 40.0) - 0.60).abs() < 1e-9);
        assert!((calibrated_confidence("environment", 80.0) - 0.60).abs() < 1e-9, "nunca passa do cap");
    }

    #[test]
    fn categoria_desconhecida_retorna_zero() {
        assert_eq!(calibrated_confidence("categoria_inexistente", 999.0), 0.0);
    }

    #[test]
    fn sem_evidencias_permenece_inconclusivo_com_confianca_zero() {
        let profile = empty_profile();
        let causes = rank_causes(&profile, &[]);
        assert_eq!(causes[0].cause_id, "cc_no_static_issue");
        assert_eq!(causes[0].confidence, 0.0);
    }

    #[test]
    fn exec_permission_denied_gera_causa_com_chmod() {
        let mut profile = empty_profile();
        profile.permissions = Some(crate::analyzers::permission_analyzer::PermissionAnalysis {
            mode: 0o100644,
            file_uid: 1000,
            file_gid: 1000,
            euid: 1000,
            egid: 1000,
            user_can_execute: false,
        });

        let evidences = collect_evidence(&profile);
        assert!(
            evidences.iter().any(|e| e.kind == "exec_permission_denied"),
            "collect_evidence deve emitir a evidência: {:?}",
            evidences
        );

        let causes = rank_causes(&profile, &evidences);
        let cc = causes
            .iter()
            .find(|c| c.cause_id == "cc_exec_permission")
            .expect("causa de permissão deve ser candidata");

        assert!((cc.confidence - 0.95).abs() < 1e-9);
        let fix = cc.suggested_fix.as_ref().unwrap();
        assert_eq!(
            fix.suggested_command.as_deref(),
            Some("chmod +x /tmp/app")
        );
    }

    #[test]
    fn permissao_ok_nao_gera_evidencia() {
        let mut profile = empty_profile();
        profile.permissions = Some(crate::analyzers::permission_analyzer::PermissionAnalysis {
            mode: 0o100755,
            file_uid: 1000,
            file_gid: 1000,
            euid: 1000,
            egid: 1000,
            user_can_execute: true,
        });
        let evidences = collect_evidence(&profile);
        assert!(
            !evidences.iter().any(|e| e.kind == "exec_permission_denied"),
            "perfil com execução permitida não deve alertar"
        );
    }

    use crate::analyzers::environment_analyzer::EnvironmentAnalysis;
    use crate::analyzers::package_analyzer::IntegrityCheck;

    fn env_analysis(gui: &[&str], display: bool, wayland: bool, preload: Option<&str>, ld_path: &[&str]) -> EnvironmentAnalysis {
        EnvironmentAnalysis {
            gui_libraries: gui.iter().map(|s| s.to_string()).collect(),
            display_set: display,
            wayland_set: wayland,
            ld_preload: preload.map(String::from),
            ld_library_path: ld_path.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn tampered_profile() -> ApplicationProfile {
        let mut profile = empty_profile();
        profile.package_owner = Some(crate::analyzers::package_analyzer::PackageInfo {
            manager: "dnf".into(),
            name: "meupacote".into(),
            version: Some("1.0-1.fc44".into()),
        });
        profile.integrity = Some(IntegrityCheck {
            matches: Some(false),
            algo: "sha256".into(),
            recorded: "a".repeat(64),
        });
        profile
    }

    #[test]
    fn hash_divergente_gera_evidencia_error_e_causa_com_reinstall() {
        let profile = tampered_profile();
        let evidences = collect_evidence(&profile);

        let ev = evidences
            .iter()
            .find(|e| e.kind == "binary_modified_from_package")
            .expect("evidência de divergência deve existir");
        assert_eq!(ev.severity, Severity::Error, "adulteração é Error, não Warning");

        let causes = rank_causes(&profile, &evidences);
        let cc = causes
            .iter()
            .find(|c| c.cause_id == "cc_binary_tampered")
            .expect("causa de adulteração deve existir");
        assert!((cc.confidence - 35.0 / 60.0 * 0.95).abs() < 1e-9);

        let fix = cc.suggested_fix.as_ref().unwrap();
        assert_eq!(
            fix.suggested_command.as_deref(),
            Some("sudo dnf reinstall meupacote")
        );
        assert_eq!(fix.risk, "medium");
    }

    #[test]
    fn integridade_ok_ou_incomparavel_nao_alerta() {
        let mut profile = empty_profile();
        profile.integrity =
            Some(IntegrityCheck { matches: Some(true), algo: "sha256".into(), recorded: "b".repeat(64) });
        assert!(
            !collect_evidence(&profile)
                .iter()
                .any(|e| e.kind == "binary_modified_from_package")
        );

        profile.integrity =
            Some(IntegrityCheck { matches: None, algo: "desconhecido".into(), recorded: String::new() });
        assert!(
            !collect_evidence(&profile)
                .iter()
                .any(|e| e.kind == "binary_modified_from_package")
        );
    }

    #[test]
    fn elf_invalid_e_tampered_agregam_na_mesma_categoria_ate_o_cap() {
        let mut profile = tampered_profile();
        if let Some(b) = profile.binary.as_mut() {
            b.elf_valid = false;
        }
        let evidences = collect_evidence(&profile);
        let causes = rank_causes(&profile, &evidences);
        let cc = causes.iter().find(|c| c.category == "binary_integrity").unwrap();
        assert!(
            (cc.confidence - 0.95).abs() < 1e-9,
            "60+35 pesos estouram score_full=60 → cap 0.95; veio {}",
            cc.confidence
        );
    }

    #[test]
    fn variaveis_ld_geram_info_e_causa_unica() {
        let mut profile = empty_profile();
        profile.environment = Some(env_analysis(
            &[],
            true,
            false,
            Some("/tmp/hook.so"),
            &["/opt/custom/lib"],
        ));

        let evidences = collect_evidence(&profile);
        assert_eq!(
            evidences.iter().filter(|e| e.source == "environment_analyzer").count(),
            2,
            "ld_preload + ld_library_path = duas infos"
        );
        assert!(
            evidences
                .iter()
                .filter(|e| e.source == "environment_analyzer")
                .all(|e| e.severity == Severity::Info),
            "evidências de ambiente são informativas, nunca críticas"
        );

        let causes = rank_causes(&profile, &evidences);
        let cc = causes
            .iter()
            .find(|c| c.cause_id == "cc_suspicious_ld_env")
            .expect("causa LD_* agregada deve existir");
        assert_eq!(cc.evidence_ids.len(), 2, "duas evidências numa causa só");
        assert!((cc.confidence - 0.30).abs() < 1e-9, "10+10=20 → 20/40 × 0.60");
    }
}
