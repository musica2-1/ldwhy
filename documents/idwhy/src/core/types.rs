use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Serialize, Clone)]
pub struct DependencyNode {
    pub name: String,
    pub found: bool,
    pub resolved_path: Option<String>,
    pub needed_by: Vec<String>, // quem depende deste nó (para achar a causa raiz na árvore)
}

#[derive(Debug, Serialize, Clone)]
pub struct BinaryInfo {
    pub elf_valid: bool,
    pub arch: String,
    pub is_pie: bool,
    pub interpreter: Option<String>,
    pub needed: Vec<String>,
    pub rpath: Vec<String>,
    pub runpath: Vec<String>,
    pub sha256: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct ApplicationProfile {
    pub input_path: String,
    pub resolved_executable: String,
    pub binary: Option<BinaryInfo>,
    pub dependency_graph: HashMap<String, DependencyNode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<crate::analyzers::permission_analyzer::PermissionAnalysis>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq, Hash)]
#[allow(dead_code)] // Info/Error entram quando adicionarmos permission_check e runtime_analyzer
pub enum Severity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Serialize, Clone)]
pub struct Evidence {
    pub id: String,
    pub source: String, // "elf_analysis" | "dependency_resolution" | "environment" | "permissions"
    pub kind: String,   // ex: "missing_shared_library"
    pub severity: Severity,
    pub weight: i32,
    pub description: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Serialize, Clone)]
pub struct CauseCandidate {
    pub cause_id: String,
    pub description: String,
    pub category: String,
    pub evidence_ids: Vec<String>,
    pub score: f64,
    pub confidence: f64,
    pub suggested_fix: Option<Remediation>,
}

#[derive(Debug, Serialize, Clone)]
pub struct Remediation {
    pub description: String,
    pub investigation_command: Option<String>,
    pub suggested_command: Option<String>,
    pub risk: String, // low | medium | high
    pub automated_safe: bool,
}

#[derive(Debug, Serialize, Clone)]
pub struct DiagnosticReport {
    pub profile: ApplicationProfile,
    pub evidences: Vec<Evidence>,
    pub candidates: Vec<CauseCandidate>,
}
