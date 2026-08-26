use serde::Serialize;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Dnf,
    Apt,
}

impl PackageManager {
    pub fn install_cmd(self, pkg: &str) -> String {
        match self {
            PackageManager::Dnf => format!("sudo dnf install {pkg}"),
            PackageManager::Apt => format!("sudo apt install {pkg}"),
        }
    }

    pub fn reinstall_cmd(self, pkg: &str) -> String {
        match self {
            PackageManager::Dnf => format!("sudo dnf reinstall {pkg}"),
            PackageManager::Apt => format!("sudo apt install --reinstall {pkg}"),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct PackageInfo {
    /// "dnf" | "apt"
    pub manager: String,
    pub name: String,
    pub version: Option<String>,
}

/// Resultado da comparação entre o arquivo no disco e o hash registrado
/// pelo gerenciador de pacotes na instalação.
#[derive(Debug, Serialize, Clone)]
pub struct IntegrityCheck {
    /// true = idêntico ao registrado; false = MODIFICADO;
    /// None = não foi possível comparar honestamente.
    pub matches: Option<bool>,
    pub algo: String,
    pub recorded: String,
}

/// Detecta o gerenciador pelo ID (ou ID_LIKE) do /etc/os-release.
pub fn detect_manager(os_release_content: &str) -> Option<PackageManager> {
    let mut id = None;
    let mut id_like = None;
    for line in os_release_content.lines() {
        if let Some(v) = line.strip_prefix("ID=") {
            id = Some(unquote(v));
        } else if let Some(v) = line.strip_prefix("ID_LIKE=") {
            id_like = Some(unquote(v));
        }
    }

    let matches = |field: &str| match field {
        "fedora" | "rhel" | "centos" | "rocky" | "almalinux" | "suse" | "opensuse" => {
            Some(PackageManager::Dnf)
        }
        "debian" | "ubuntu" | "mint" | "pop" => Some(PackageManager::Apt),
        _ => None,
    };

    id.as_deref()
        .and_then(matches)
        .or_else(|| id_like.as_deref().and_then(|like| like.split_whitespace().find_map(matches)))
}

fn unquote(value: &str) -> String {
    value.trim().trim_matches('"').to_string()
}

/// Pacote que POSSUI um arquivo já presente no disco.
pub fn find_owner(path: &Path) -> Option<PackageInfo> {
    match detect_system_manager()? {
        PackageManager::Dnf => run(Command::new("rpm").args([
            "-qf",
            "--queryformat",
            "%{NAME}|%{VERSION}-%{RELEASE}",
            path.to_str()?,
        ]))
        .and_then(|out| parse_rpm_qf(&out)),
        PackageManager::Apt => run(Command::new("dpkg").arg("-S").arg(path.to_str()?))
            .and_then(|out| parse_dpkg_s(&out)),
    }
}

/// Pacote que FORNECE uma lib/arquivo ausente. Política sem rede:
/// dnf consulta apenas o cache local (--cacheonly); dpkg -S consulta
/// a base instalada. Sem resultado, o chamador cai na sugestão genérica.
/// `preferred_arch` (ex: Some("x86_64")) prioriza candidatos da mesma
/// arquitetura do binário diagnosticado — sem isso o dnf pode casar i686.
pub fn find_provider(lib_name: &str, preferred_arch: Option<&str>) -> Option<PackageInfo> {
    match detect_system_manager()? {
        PackageManager::Dnf => {
            let out = run(Command::new("dnf").args(["-q", "--cacheonly", "provides", lib_name]))?;
            parse_dnf_provides(&out, preferred_arch)
        }
        PackageManager::Apt => {
            let out = run(Command::new("dpkg").arg("-S").arg(lib_name))?;
            parse_dpkg_s(&out)
        }
    }
}

fn detect_system_manager() -> Option<PackageManager> {
    let content = std::fs::read_to_string("/etc/os-release").ok()?;
    detect_manager(&content)
}

/// Compara o SHA-256 já calculado do binário com o hash que o
/// gerenciador registrou na instalação.
///
/// - RPM: `rpm -q --queryformat '[%{FILENAMES}|%{FILEDIGESTS}\n]' <pkg>`
///   (digest hex; em Fedora moderno é sha256 — se o digest registrado não
///   tiver 64 hex chars, retorna matches: None em vez de comparar errado).
/// - Debian: `/var/lib/dpkg/info/<pkg>.md5sums` registra MD5; o hash local
///   é obtido com `md5sum` (comando fixo somente leitura).
pub fn verify_integrity(
    path: &Path,
    pkg_name: &str,
    computed_sha256_hex: &str,
) -> Option<IntegrityCheck> {
    match detect_system_manager()? {
        PackageManager::Dnf => {
            let out = run(Command::new("rpm").args([
                "-q",
                "--queryformat",
                "[%{FILENAMES}|%{FILEDIGESTS}\n]",
                pkg_name,
            ]))?;
            parse_rpm_file_digests(&out).and_then(|entries| {
                let wanted = path.to_str()?;
                entries
                    .iter()
                    .find(|(file, _)| file == wanted)
                    .map(|(_, recorded)| classify_digest(recorded, computed_sha256_hex))
            })
        }
        PackageManager::Apt => {
            let md5sums =
                std::fs::read_to_string(format!("/var/lib/dpkg/info/{pkg_name}.md5sums")).ok()?;
            let rel = path.to_str()?.trim_start_matches('/').to_string();
            let entries = parse_deb_md5sums(&md5sums)?;
            let recorded = entries
                .iter()
                .find(|(file, _)| file == &rel || file == &format!("./{rel}"))
                .map(|(_, hash)| hash.clone())?;

            let out = run(Command::new("md5sum").arg(path.to_str()?))?;
            let local = out.split_whitespace().next()?;

            Some(IntegrityCheck {
                matches: Some(local.eq_ignore_ascii_case(&recorded)),
                algo: "md5".into(),
                recorded,
            })
        }
    }
}

fn classify_digest(recorded: &str, computed_sha256_hex: &str) -> IntegrityCheck {
    if recorded.len() == 64 && recorded.chars().all(|c| c.is_ascii_hexdigit()) {
        IntegrityCheck {
            matches: Some(recorded.eq_ignore_ascii_case(computed_sha256_hex)),
            algo: "sha256".into(),
            recorded: recorded.into(),
        }
    } else {
        // Algoritmo desconhecido (ex: md5 legado no rpm): comparação honesta
        // exige o mesmo algoritmo — não dá para afirmar nada.
        IntegrityCheck { matches: None, algo: "desconhecido".into(), recorded: recorded.into() }
    }
}

/// Linhas "path|hex" do dump do rpm → [(path, digest)]
fn parse_rpm_file_digests(output: &str) -> Option<Vec<(String, String)>> {
    let entries: Vec<(String, String)> = output
        .lines()
        .filter_map(|l| l.split_once('|'))
        .map(|(f, d)| (f.to_string(), d.to_string()))
        .collect();
    (!entries.is_empty()).then_some(entries)
}

/// Conteúdo de /var/lib/dpkg/info/<pkg>.md5sums → [(caminho_relativo, md5)]
fn parse_deb_md5sums(content: &str) -> Option<Vec<(String, String)>> {
    let entries: Vec<(String, String)> = content
        .lines()
        .filter_map(|l| l.split_once(char::is_whitespace))
        .map(|(hash, file)| (file.trim().to_string(), hash.trim().to_string()))
        .filter(|(f, h)| !f.is_empty() && h.len() == 32)
        .collect();
    (!entries.is_empty()).then_some(entries)
}

fn run(cmd: &mut Command) -> Option<String> {
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(trimmed.to_string())
}

/// "%{NAME}|%{VERSION}-%{RELEASE}" → ("coreutils", Some("9.5-1.fc40"))
fn parse_rpm_qf(output: &str) -> Option<PackageInfo> {
    let (name, version) = output.trim().split_once('|')?;
    if name.is_empty() {
        return None;
    }
    Some(PackageInfo {
        manager: "dnf".into(),
        name: name.into(),
        version: (!version.is_empty()).then(|| version.into()),
    })
}

/// dpkg -S: "libc6:amd64: /usr/bin/foo" ou multi-linha; pega 1º campo
/// antes de ": " e remove sufixo de arquitetura.
fn parse_dpkg_s(output: &str) -> Option<PackageInfo> {
    let first_line = output.lines().next()?.split_once(": ")?;
    let pkg_field = first_line.0;
    let name = pkg_field.split(':').next()?.trim();
    if name.is_empty() || name.contains(' ') {
        return None;
    }
    Some(PackageInfo { manager: "apt".into(), name: name.into(), version: None })
}

/// dnf provides: linhas tipo
/// "libfoo-devel-1.2-3.fc40.x86_64 : Descrição qualquer"
/// Guarda o NEVRA completo (dnf install aceita) — tentar separar
/// nome/versão por heurística quebra pacotes com '-' no nome.
/// Com `preferred_arch`, prioriza o candidato terminado em ".<arch>"
/// (o dnf costuma listar i686 antes de x86_64).
fn parse_dnf_provides(output: &str, preferred_arch: Option<&str>) -> Option<PackageInfo> {
    let mut fallback = None;
    for line in output.lines() {
        let Some((pkg_part, _desc)) = line.split_once(" : ") else {
            continue;
        };
        let nevra = pkg_part.split_whitespace().next().unwrap_or("");
        if !is_valid_nevra(nevra) {
            continue;
        }
        if let Some(arch) = preferred_arch {
            if nevra.ends_with(&format!(".{arch}")) {
                return Some(PackageInfo { manager: "dnf".into(), name: nevra.into(), version: None });
            }
        }
        if fallback.is_none() {
            fallback = Some(PackageInfo { manager: "dnf".into(), name: nevra.into(), version: None });
        }
    }
    fallback
}

fn is_valid_nevra(token: &str) -> bool {
    token.contains('-') && token.contains('.') && !token.starts_with("Erro")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_mapeia_distros_para_gerenciadores() {
        let fedora = "NAME=\"Fedora Linux\"\nID=fedora\nID_LIKE=\"rhel fedora\"\n";
        assert_eq!(detect_manager(fedora), Some(PackageManager::Dnf));

        let ubuntu = "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\n";
        assert_eq!(detect_manager(ubuntu), Some(PackageManager::Apt));

        // ID desconhecido cai no ID_LIKE.
        let manjaro = "ID=manjaro\nID_LIKE=\"arch debian\"\n";
        assert_eq!(detect_manager(manjaro), Some(PackageManager::Apt));

        assert_eq!(detect_manager("ID=arch\n"), None);
        assert_eq!(detect_manager(""), None);
    }

    #[test]
    fn parse_rpm_qf_extrai_nome_e_versao() {
        let info = parse_rpm_qf("coreutils|9.5-1.fc40").unwrap();
        assert_eq!(info.name, "coreutils");
        assert_eq!(info.version.as_deref(), Some("9.5-1.fc40"));
        assert_eq!(info.manager, "dnf");
        assert!(parse_rpm_qf("|1.0").is_none());
    }

    #[test]
    fn parse_dpkg_s_lida_com_arquitetura_e_multilinha() {
        let info = parse_dpkg_s("libc6:amd64: /usr/lib/x86_64-linux-gnu/libc.so.6\nlibc6: /other\n")
            .unwrap();
        assert_eq!(info.name, "libc6");
        assert_eq!(info.manager, "apt");

        assert!(parse_dpkg_s("no package found matching pattern\n").is_none());
    }

    #[test]
    fn parse_dnf_provides_pega_primeiro_pacote_valido() {
        let output = "\
Erro: não há correspondência
1:openssl-libs-3.2.2-3.fc40.x86_64 : Bibliotecas criptográficas
openssl-libs-3.2.2-3.fc40.i686 : Bibliotecas criptográficas";
        let info = parse_dnf_provides(output, None).unwrap();
        assert_eq!(info.name, "1:openssl-libs-3.2.2-3.fc40.x86_64");
        assert!(info.version.is_none());
    }

    #[test]
    fn parse_dnf_provides_prefere_a_arquitetura_do_binario() {
        let output = "\
cups-libs-1:2.4.19-3.fc44.i686 : CUPS printing system - libraries
cups-libs-1:2.4.19-3.fc44.x86_64 : CUPS printing system - libraries";

        let com_arch = parse_dnf_provides(output, Some("x86_64")).unwrap();
        assert!(
            com_arch.name.ends_with(".x86_64"),
            "deve escolher x86_64 mesmo listado depois do i686: {}",
            com_arch.name
        );

        let sem_arch = parse_dnf_provides(output, None).unwrap();
        assert!(sem_arch.name.ends_with(".i686"), "sem preferência, mantém ordem do dnf");
    }

    #[test]
    fn parse_dnf_provides_sem_candidato_da_arquitetura_cai_no_fallback() {
        let output = "cups-libs-1:2.4.19-3.fc44.i686 : CUPS printing";
        let info = parse_dnf_provides(output, Some("x86_64")).unwrap();
        assert_eq!(info.name, "cups-libs-1:2.4.19-3.fc44.i686");
    }

    #[test]
    fn parse_dnf_provides_preserva_nome_com_hifen() {
        let info =
            parse_dnf_provides("gtk4-devel-4.14.4-1.fc40.x86_64 : Arquivos de desenvolvimento", None)
                .unwrap();
        assert_eq!(
            info.name, "gtk4-devel-4.14.4-1.fc40.x86_64",
            "NEVRA completo garante install correto de subpacotes"
        );
    }

    #[test]
    fn parse_dnf_provides_rejeita_saida_vazia_ou_sem_pacote() {
        assert!(parse_dnf_provides("", None).is_none());
        assert!(parse_dnf_provides("Erro: nenhuma correspondência encontrada", None).is_none());
        assert!(parse_dnf_provides("texto solto sem formato de pacote", None).is_none());
    }

    #[test]
    fn comandos_de_instalacao_por_gerenciador() {
        assert_eq!(
            PackageManager::Dnf.install_cmd("libfoo"),
            "sudo dnf install libfoo"
        );
        assert_eq!(
            PackageManager::Apt.reinstall_cmd("coreutils"),
            "sudo apt install --reinstall coreutils"
        );
    }

    #[test]
    fn find_owner_em_maquina_real_encontra_coreutils() {
        // Tolerante: só valida quando há gerenciador e rpm/dpkg presentes.
        if detect_system_manager().is_none() {
            return;
        }
        if let Some(info) = find_owner(Path::new("/bin/true")) {
            assert!(!info.name.is_empty());
            assert!(matches!(info.manager.as_str(), "dnf" | "apt"));
        }
    }

    #[test]
    fn parse_rpm_dump_extrai_pares_caminho_digest() {
        let dump = "/usr/bin/[|66b30930...\n/usr/bin/true|b639fd49da0eeaffe498316c9788a081d41d2e009d343f8e75d7e5a219e82921\n";
        let entries = parse_rpm_file_digests(dump).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[1],
            (
                "/usr/bin/true".to_string(),
                "b639fd49da0eeaffe498316c9788a081d41d2e009d343f8e75d7e5a219e82921".to_string()
            )
        );
        assert!(parse_rpm_file_digests("").is_none());
    }

    #[test]
    fn parse_deb_md5sums_extrai_pares_e_filtra_lixo() {
        let content = "\
5c1a1f4b2e0d9a8b7c6d5e4f3a2b1c0d  usr/bin/true
ffeeddccbbaa99887766554433221100  ./usr/share/doc/pkg/readme
linha_invalida_sem_hash
zz (hash curto demais)  usr/bin/outro";
        let entries = parse_deb_md5sums(content).unwrap();
        assert_eq!(entries.len(), 2, "linhas sem hash de 32 chars são descartadas");
        assert_eq!(entries[0].0, "usr/bin/true");
        assert_eq!(entries[1].0, "./usr/share/doc/pkg/readme");
    }

    #[test]
    fn digest_sha256_compara_case_insensitive_e_rejeita_algo_desconhecido() {
        let sha = "B639FD49DA0EEAFFE498316C9788A081D41D2E009D343F8E75D7E5A219E82921";
        let ok = classify_digest(
            "b639fd49da0eeaffe498316c9788a081d41d2e009d343f8e75d7e5a219e82921",
            sha,
        );
        assert_eq!(ok.matches, Some(true));
        assert_eq!(ok.algo, "sha256");

        let divergente = classify_digest(&"a".repeat(64), sha);
        assert_eq!(divergente.matches, Some(false));

        // rpm legado com md5 no FILEDIGESTS: não dá para comparar com sha256.
        let md5_legado = classify_digest("d41d8cd98f00b204e9800998ecf8427e", sha);
        assert_eq!(md5_legado.matches, None);
        assert_eq!(md5_legado.algo, "desconhecido");
    }

    #[test]
    fn integridade_em_maquina_real_arquivo_de_sistema_intacto() {
        if detect_system_manager().is_none() {
            return;
        }
        let Some(owner) = find_owner(Path::new("/usr/bin/true")) else {
            return;
        };
        let sha = std::fs::read("/usr/bin/true")
            .map(|bytes| {
                use sha2::{Digest, Sha256};
                format!("{:x}", Sha256::digest(&bytes))
            })
            .ok();
        if let Some(sha) = sha {
            if let Some(check) = verify_integrity(Path::new("/usr/bin/true"), &owner.name, &sha)
            {
                assert_eq!(
                    check.matches,
                    Some(true),
                    "/usr/bin/true intacto deve casar com o hash do pacote"
                );
            }
        }
    }
}
