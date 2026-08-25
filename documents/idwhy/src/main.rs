mod analyzers;
mod core;
mod inference;
mod report;

use clap::{Parser, Subcommand};
use std::io::{self, IsTerminal, Write};

use crate::core::types::{ApplicationProfile, DiagnosticReport};

const DLINE: &str = "═══════════════════════════════════════════════════════";

#[derive(Parser)]
#[command(name = "diag", version, about = "Motor de diagnóstico de aplicações Linux (núcleo estático do MVP)")]
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

    let (resolved_executable, binary, dependency_graph) = match resolved {
        Ok(path) => {
            let binary = analyzers::static_analyzer::analyze_binary(&path).ok();

            let dependency_graph = match &binary {
                Some(b) if b.elf_valid => {
                    analyzers::dependency_analyzer::build_dependency_graph(b, &path)
                }
                _ => Default::default(),
            };

            (path.to_string_lossy().to_string(), binary, dependency_graph)
        }
        Err(_) => (target.to_string(), None, Default::default()),
    };

    let profile = ApplicationProfile {
        input_path: target.to_string(),
        resolved_executable,
        binary,
        dependency_graph,
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

/// Modo interativo: lista os aplicativos em execução e permite escolher
/// pelo número, escolher a opção manual, ou digitar um caminho/nome direto.
fn select_target_interactively() -> anyhow::Result<String> {
    if !io::stdin().is_terminal() {
        anyhow::bail!(
            "O modo interativo precisa de um terminal. Use: diag diagnose <alvo>"
        );
    }

    let apps = core::process_scan::list_running_apps(std::env::current_exe().ok().as_deref());

    println!("{DLINE}");
    println!("  Diagnóstico interativo");
    println!("{DLINE}\n");

    if !apps.is_empty() {
        println!("  Aplicações em execução:\n");
        for (idx, app) in apps.iter().enumerate() {
            println!(
                "   [{:>2}] {:<28} {}",
                idx + 1,
                truncate(&app.comm, 26),
                app.exe_path.display()
            );
        }
    } else {
        println!("  Nenhum aplicativo em execução detectado.\n");
    }
    println!("   [ 0] Outro — informar caminho ou nome manualmente\n");

    loop {
        print!("  Selecione o número da aplicação ou digite um caminho/nome: ");
        io::stdout().flush()?;

        let choice = read_line_trimmed()?;
        if choice.is_empty() {
            continue;
        }

        match choice.parse::<usize>() {
            Ok(0) => {
                loop {
                    print!("  Caminho do executável ou nome do comando: ");
                    io::stdout().flush()?;
                    let manual = read_line_trimmed()?;
                    if !manual.is_empty() {
                        return Ok(manual);
                    }
                }
            }
            Ok(n) if n >= 1 && n <= apps.len() => {
                return Ok(apps[n - 1].exe_path.to_string_lossy().into_owned());
            }
            Ok(_) => {
                println!("  Número fora da lista (1–{}). Tente novamente.", apps.len());
            }
            Err(_) => {
                // Não é número: trata como alvo direto (ex: "vim" ou "/usr/bin/vim").
                return Ok(choice);
            }
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
