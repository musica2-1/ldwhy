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
                description: "Verificar a grafia do nome ou instalar o pacote que fornece o executável".into(),
                investigation_command: Some(format!(
                    "command -v {} # e verifique se está no $PATH",
                    profile.input_path
                )),
                suggested_command: None,
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

        let confidence = calibrated_confidence("dependency", score);

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
                description: "Instalar o pacote que fornece a biblioteca ausente".into(),
                investigation_command: libs
                    .first()
                    .map(|l| format!("dnf provides '*/{}' # ou: apt-file search {}", l, l)),
                suggested_command: None,
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
        candidates.push(CauseCandidate {
            cause_id: "cc_elf_invalid".into(),
            description: "Binário corrompido ou não é um executável ELF válido".into(),
            category: "binary_integrity".into(),
            evidence_ids: elf_invalid_evs.iter().map(|e| e.id.clone()).collect(),
            score,
            confidence: calibrated_confidence("binary_integrity", score),
            suggested_fix: Some(Remediation {
                description: "Reinstalar o pacote ou verificar integridade do download".into(),
                investigation_command: Some(format!("file {}", profile.resolved_executable)),
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
}
