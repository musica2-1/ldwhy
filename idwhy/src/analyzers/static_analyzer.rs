use crate::core::types::BinaryInfo;
use goblin::elf::Elf;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub fn analyze_binary(path: &Path) -> anyhow::Result<BinaryInfo> {
    let buffer = fs::read(path)?;

    // Hash SHA-256 sempre calculado — usado depois para checar integridade
    // contra o package manager, e é seguro pois nunca executamos o binário.
    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let sha256 = format!("{:x}", hasher.finalize());

    let elf = match Elf::parse(&buffer) {
        Ok(e) => e,
        Err(_) => {
            return Ok(BinaryInfo {
                elf_valid: false,
                arch: "unknown".into(),
                is_pie: false,
                interpreter: None,
                needed: vec![],
                rpath: vec![],
                runpath: vec![],
                sha256,
            });
        }
    };

    let arch = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => "x86_64",
        goblin::elf::header::EM_AARCH64 => "aarch64",
        goblin::elf::header::EM_386 => "i386",
        goblin::elf::header::EM_ARM => "arm",
        _ => "unknown",
    }
    .to_string();

    let needed: Vec<String> = elf.libraries.iter().map(|s| s.to_string()).collect();

    let rpath: Vec<String> = elf
        .rpaths
        .iter()
        .flat_map(|p| p.split(':').map(|s| s.to_string()))
        .collect();
    let runpath: Vec<String> = elf
        .runpaths
        .iter()
        .flat_map(|p| p.split(':').map(|s| s.to_string()))
        .collect();

    Ok(BinaryInfo {
        elf_valid: true,
        arch,
        is_pie: elf.is_lib, // ET_DYN (PIE executables e .so compartilham este tipo)
        interpreter: elf.interpreter.map(|s| s.to_string()),
        needed,
        rpath,
        runpath,
        sha256,
    })
}
