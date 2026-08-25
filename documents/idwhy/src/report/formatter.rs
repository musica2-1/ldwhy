use crate::core::types::DiagnosticReport;

const LINE: &str = "───────────────────────────────────────────────────────";
const DLINE: &str = "═══════════════════════════════════════════════════════";

pub fn print_report(report: &DiagnosticReport) {
    println!("{DLINE}");
    println!("  idwhy — Linux Application Diagnostic");
    println!("{DLINE}\n");

    println!("Input:       {}", report.profile.input_path);
    println!("Executable:  {}", report.profile.resolved_executable);

    println!("\n{LINE}");
    println!("STATIC ANALYSIS");
    println!("{LINE}");

    match &report.profile.binary {
        None => println!("  [✗] Não foi possível ler o arquivo"),
        Some(b) => {
            println!("  [{}] ELF header válido", mark(b.elf_valid));
            println!("  Arquitetura: {}", b.arch);
            println!("  SHA-256: {}", &b.sha256[..16]);
            match &b.interpreter {
                Some(i) =>             println!("  Interpretador: {i}"),
                None => println!("  Interpretador: (nenhum — binário estático)"),
            }

            if let Some(p) = &report.profile.permissions {
                println!("  Permissões:   {p}");
            }

            if !b.needed.is_empty() {
                println!("\n  Dependency Graph:");
                let mut names: Vec<&String> = report.profile.dependency_graph.keys().collect();
                names.sort();
                for name in names {
                    let node = &report.profile.dependency_graph[name];
                    let m = if node.found { "✓" } else { "✗" };
                    match &node.resolved_path {
                        Some(p) => println!("    [{m}] {name} → {p}"),
                        None => println!("    [{m}] {name} → NOT FOUND"),
                    }
                }
            }
        }
    }

    println!("\n{LINE}");
    println!("EVIDENCE");
    println!("{LINE}");
    if report.evidences.is_empty() {
        println!("  (nenhuma evidência coletada)");
    }
    for ev in &report.evidences {
        println!("  [{}] {:?} — {}", ev.id, ev.severity, ev.description);
    }

    println!("\n{LINE}");
    println!("DIAGNOSIS");
    println!("{LINE}\n");

    if let Some(top) = report.candidates.first() {
        println!("  Most Probable Cause: {}", top.description);
        println!("  Confidence: {:.0}%", top.confidence * 100.0);
        println!("  Score: {:.1} (soma dos pesos das evidências; confiança com teto por categoria)", top.score);

        if !top.evidence_ids.is_empty() {
            println!("\n  Evidence:");
            for eid in &top.evidence_ids {
                if let Some(ev) = report.evidences.iter().find(|e| &e.id == eid) {
                    println!("    - [{eid}] {}", ev.description);
                }
            }
        }

        if let Some(fix) = &top.suggested_fix {
            println!("\n{LINE}");
            println!("REMEDIATION");
            println!("{LINE}\n");
            println!("  {}", fix.description);
            if let Some(cmd) = &fix.investigation_command {
                println!("\n  Investigation command:\n    $ {cmd}");
            }
            if let Some(cmd) = &fix.suggested_command {
                println!("\n  Suggested command:\n    $ {cmd}");
            }
            println!("\n  Risk: {}", fix.risk.to_uppercase());
            println!("  Automated: {}", if fix.automated_safe { "yes" } else { "no (requer confirmação)" });
        }

        if report.candidates.len() > 1 {
            println!("\n  Outras hipóteses consideradas:");
            for c in &report.candidates[1..] {
                println!("    - {} (score {:.1})", c.description, c.score);
            }
        }
    } else {
        println!("  Nenhum candidato gerado.");
    }

    println!("\n{DLINE}");
}

fn mark(b: bool) -> &'static str {
    if b { "✓" } else { "✗" }
}
