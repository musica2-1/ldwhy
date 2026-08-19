mod core;
mod analyzers;
mod inference;
mod report;

use clap::{Parser, Subcommand};
use core::types::{ApplicationProfile, DiagnosticReport};

#[derive(Parser)]
#[command(name = "diag", version, about = "Motor de diagnóstico de aplicações Linux (núcleo estático do MVP)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
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
        Commands::Diagnose { target, json } => {
            let report = run_diagnosis(&target)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                report::formatter::print_report(&report);
            }
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
                Some(b) if b.elf_valid => analyzers::dependency_analyzer::build_dependency_graph(b),
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
