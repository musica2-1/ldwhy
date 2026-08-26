use crate::core::types::DiagnosticReport;

const LINE: &str = "───────────────────────────────────────────────────────";
const DLINE: &str = "═══════════════════════════════════════════════════════";

pub fn print_report(report: &DiagnosticReport) {
    println!("{DLINE}");
    println!("  idwhy — Linux Application Diagnostic");
    println!("{DLINE}\n");

    println!("Input:       {}", report.profile.input_path);
    println!("Executable:  {}", report.profile.resolved_executable);

    for (i, step) in report.profile.wrapper_chain.iter().enumerate() {
        let prefix = if i == 0 { "Wrapper:     " } else { "             " };
        println!(
            "{prefix}[{i}] {} {} → {}",
            step.kind, step.detail, step.points_to
        );
        if let Some(issue) = &step.issue {
            println!("             ⚠ {issue}");
        }
    }

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

            if let Some(pkg) = &report.profile.package_owner {
                println!("  Pacote:       {} ({})", pkg.name, pkg.manager);
            }

            if let Some(check) = &report.profile.integrity {
                let status = match check.matches {
                    Some(true) => "✓ confere com o registro do gerenciador".to_string(),
                    Some(false) => "✗ DIFERE do registrado pelo gerenciador".to_string(),
                    None => "(não comparável — algoritmo diferente)".to_string(),
                };
                println!("  Integridade:  {} [{status}]", check.algo);
            }

            if let Some(env) = &report.profile.environment {
                let mut parts = Vec::new();
                if env.is_graphical() {
                    parts.push(format!(
                        "gráfica ({})",
                        crate::analyzers::environment_analyzer::summarize_libraries(&env.gui_libraries, 3)
                    ));
                }
                match (env.display_set, env.wayland_set) {
                    (true, true) => parts.push("DISPLAY + Wayland".into()),
                    (true, false) => parts.push("DISPLAY ativo".into()),
                    (false, true) => parts.push("Wayland ativo".into()),
                    (false, false) => parts.push("sem display".into()),
                }
                if env.ld_preload.is_some() || !env.ld_library_path.is_empty() {
                    parts.push("LD_* personalizados ativos".into());
                }
                println!("  Ambiente:     {}", parts.join(" · "));
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

    if let Some(rt) = &report.profile.runtime {
        println!("\n{LINE}");
        println!("RUNTIME (sandbox: {})", if rt.ran_in_sandbox { "bubblewrap" } else { "sem sandbox!" });
        println!("{LINE}");
        let fim = match (rt.exit_code, rt.killed_by_timeout) {
            (_, true) => format!("morto por timeout após {} ms", rt.duration_ms),
            (Some(0), _) => format!("saiu limpo em {} ms", rt.duration_ms),
            (Some(c), _) => format!("exit {c} em {} ms", rt.duration_ms),
            (None, _) => "finalizado sem código de saída".into(),
        };
        println!("  Resultado:  {fim}");

        let relevantes: Vec<_> = rt
            .failed_syscalls
            .iter()
            .filter(|f| {
                crate::analyzers::runtime_analyzer::severity_for_failure(f).is_some()
            })
            .collect();
        if relevantes.is_empty() {
            println!("  Falhas relevantes: (nenhuma — probes ENOENT normais foram filtrados)");
        } else {
            println!("  Falhas relevantes:");
            for f in relevantes.iter().take(10) {
                println!("    [{}] {} {} → {} ({})", f.errno, f.call, f.path, f.errno, f.errno_desc);
            }
            if relevantes.len() > 10 {
                println!("    … e mais {}", relevantes.len() - 10);
            }
        }
    }

    println!("\n{LINE}");
    println!("EVIDENCE");
    println!("{LINE}");    if report.evidences.is_empty() {
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
