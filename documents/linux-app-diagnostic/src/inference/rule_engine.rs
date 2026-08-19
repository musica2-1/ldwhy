use crate::core::types::{ApplicationProfile, CauseCandidate, Evidence, Remediation, Severity};

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

        let confidence = (score / 100.0).min(0.97);

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

    let elf_invalid = evidences.iter().any(|e| e.kind == "elf_invalid");
    if elf_invalid {
        candidates.push(CauseCandidate {
            cause_id: "cc_elf_invalid".into(),
            description: "Binário corrompido ou não é um executável ELF válido".into(),
            category: "binary_integrity".into(),
            evidence_ids: evidences
                .iter()
                .filter(|e| e.kind == "elf_invalid")
                .map(|e| e.id.clone())
                .collect(),
            score: 60.0,
            confidence: 0.95,
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
