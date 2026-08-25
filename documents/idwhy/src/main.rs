mod analyzers;
mod core;
mod inference;
mod report;

use clap::{Parser, Subcommand};
use std::io::{self, IsTerminal, Write};

use crate::core::types::{ApplicationProfile, DiagnosticReport};

const DLINE: &str = "═══════════════════════════════════════════════════════";

#[derive(Parser)]
#[command(name = "idwhy", version, about = "idwhy — diagnóstico causal de aplicações Linux (causa raiz ranqueada + confiança)")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Diagnostica uma aplicação a partir de um path ou nome de comando
    Diagnose {
        /// Path do executável ou nome de comando (ex: firefox, /usr/bin/vim)
        target: String,
        /// Emitir relatório em JSON em vez de texto formatado
        #[arg(long)]
        json: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Diagnose { target, json }) => {
            run_and_print(&target, json)?;
        }
        None => {
            let target = select_target_interactively()?;
            println!();
            run_and_print(&target, false)?;
        }
    }

    Ok(())
}

fn run_diagnosis(target: &str) -> anyhow::Result<DiagnosticReport> {
    let resolved = core::discovery::resolve_executable(target);

    let (resolved_executable, binary, dependency_graph, permissions) = match resolved {
        Ok(path) => {
            let binary = analyzers::static_analyzer::analyze_binary(&path).ok();

            let dependency_graph = match &binary {
                Some(b) if b.elf_valid => {
                    analyzers::dependency_analyzer::build_dependency_graph(b, &path)
                }
                _ => Default::default(),
            };

            let permissions =
                analyzers::permission_analyzer::analyze_permissions(&path);

            (
                path.to_string_lossy().to_string(),
                binary,
                dependency_graph,
                permissions,
            )
        }
        Err(_) => (target.to_string(), None, Default::default(), None),
    };

    let profile = ApplicationProfile {
        input_path: target.to_string(),
        resolved_executable,
        binary,
        dependency_graph,
        permissions,
    };

    let evidences = inference::rule_engine::collect_evidence(&profile);
    let candidates = inference::rule_engine::rank_causes(&profile, &evidences);

    Ok(DiagnosticReport {
        profile,
        evidences,
        candidates,
    })
}

fn run_and_print(target: &str, json: bool) -> anyhow::Result<()> {
    let report = run_diagnosis(target)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        report::formatter::print_report(&report);
    }
    Ok(())
}

/// Modo interativo: lista os aplicativos em execução (serviços de sistema
/// ocultos por padrão) com paginação, e permite escolher pelo número,
/// digitar um caminho/nome direto, ou usar a opção manual.
const PAGE_SIZE: usize = 20;

fn select_target_interactively() -> anyhow::Result<String> {
    if !io::stdin().is_terminal() {
        anyhow::bail!(
            "O modo interativo precisa de um terminal. Use: cargo run -- diagnose <alvo>"
        );
    }

    let all_apps = core::process_scan::list_running_apps(std::env::current_exe().ok().as_deref());
    let total = all_apps.len();

    println!("{DLINE}");
    println!("  Diagnóstico interativo");
    println!("{DLINE}\n");

    if all_apps.is_empty() {
        return prompt_manual_target("  Nenhum aplicativo em execução detectado.\n\n  Caminho do executável ou nome do comando: ");
    }

    let mut include_system = false;
    loop {
        let pool: Vec<&core::process_scan::RunningApp> = all_apps
            .iter()
            .filter(|a| include_system || !core::process_scan::is_likely_system_service(a))
            .collect();
        let ocultos = total - pool.len();

        println!(
            "  Aplicações em execução ({} de {} processos{}):",
            pool.len(),
            total,
            if ocultos > 0 {
                format!("; {ocultos} serviços do sistema ocultos")
            } else {
                String::new()
            }
        );
        println!();

        let mut shown = 0usize;
        loop {
            let end = (shown + PAGE_SIZE).min(pool.len());
            for (i, app) in pool[shown..end].iter().enumerate() {
                println!(
                    "   [{:>2}] {:<28} {}",
                    shown + i + 1,
                    truncate(&app.comm, 26),
                    app.exe_path.display()
                );
            }
            shown = end;

            println!("   [ 0] Outro — informar caminho ou nome manualmente");
            match (include_system, ocultos) {
                (false, n) if n > 0 => println!("   [ t] Mostrar também os {n} serviços do sistema"),
                (true, _) => println!("   [ t] Ocultar serviços do sistema"),
                _ => {}
            }
            println!();

            print!("  Selecione o número ou digite um caminho/nome");
            if shown < pool.len() {
                print!(" (Enter = mostrar mais)");
            }
            print!(": ");
            io::stdout().flush()?;

            match handle_menu_input(&pool, &mut shown)? {
                MenuOutcome::Target(t) => return Ok(t),
                MenuOutcome::ToggleSystem => {
                    include_system = !include_system;
                    break;
                }
                MenuOutcome::Reprompt => {}
            }
        }
    }
}

enum MenuOutcome {
    Target(String),
    ToggleSystem,
    Reprompt,
}

fn handle_menu_input(
    pool: &[&core::process_scan::RunningApp],
    shown: &mut usize,
) -> anyhow::Result<MenuOutcome> {
    let choice = read_line_trimmed()?;

    if choice.is_empty() {
        if *shown >= pool.len() {
            println!("  Toda a lista já está visível.");
        }
        return Ok(MenuOutcome::Reprompt);
    }

    if choice.eq_ignore_ascii_case("t") {
        return Ok(MenuOutcome::ToggleSystem);
    }

    match choice.parse::<usize>() {
        Ok(0) => prompt_manual_target("  Caminho do executável ou nome do comando: ")
            .map(MenuOutcome::Target),
        Ok(n) if n >= 1 && n <= pool.len() => {
            Ok(MenuOutcome::Target(pool[n - 1].exe_path.to_string_lossy().into_owned()))
        }
        Ok(_) => {
            println!("  Número fora da lista (1–{}). Tente novamente.", pool.len());
            Ok(MenuOutcome::Reprompt)
        }
        Err(_) => Ok(MenuOutcome::Target(choice)),
    }
}

fn prompt_manual_target(prompt: &str) -> anyhow::Result<String> {
    loop {
        print!("{prompt}");
        io::stdout().flush()?;
        let manual = read_line_trimmed()?;
        if !manual.is_empty() {
            return Ok(manual);
        }
    }
}

fn read_line_trimmed() -> anyhow::Result<String> {
    let mut buf = String::new();
    let bytes_read = io::stdin().read_line(&mut buf)?;
    if bytes_read == 0 {
        anyhow::bail!("\nEntrada encerrada (EOF). Abortando.");
    }
    Ok(buf.trim().to_string())
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let cut: String = text.chars().take(max.saturating_sub(1)).collect();
    format!("{cut}…")
}
