### idwhy

*idwhy* — motor de diagnóstico causal para aplicações
Linux. Em vez de despejar logs brutos (como `strace` ou `journalctl` fazem),
essa ferramenta correlaciona as evidências de múltiplas camadas do sistema e
produz um diagnóstico com **causa raiz ranqueada + nível de confiança**.

Este README documenta a lógica de funcionamento do que já está implementado
e o que falta para chegar ao MVP completo.

---

## 1. Ideia central

Nenhuma ferramenta isolada (`ldd`, `strace`, `journalctl`, `coredumpctl`)
sabe dizer "a causa do problema é X, com 90% de confiança". Elas só
mostram dados. O diferencial deste projeto é a **camada de correlação e
inferência** entre essas fontes — isso é o que não existe pronto em
nenhuma ferramenta hoje.

Fluxo geral:

```
input (nome do app ou path)
        │
        ▼
   Discovery ──────► resolve o executável real
        │
        ▼
 Static Analyzer ───► lê o ELF (nunca executa o binário)
        │
        ▼
Dependency Analyzer ─► resolve o grafo de bibliotecas (found/not found)
        │
        ▼
 Evidence Collector ─► converte achados em Evidence{} tipada
        │
        ▼
   Rule Engine ──────► casa evidências com causas conhecidas + score
        │
        ▼
    Report ──────────► causa mais provável, confiança, evidências, fix sugerido
```

Cada etapa é isolada em seu próprio módulo (`src/core`, `src/analyzers`,
`src/inference`, `src/report`) para poder trocar/expandir peças sem mexer
no resto.

---

## 2. O que já está implementado

### 2.1 Discovery (`src/core/discovery.rs`)
Resolve o `target` informado pelo usuário para um caminho real de
executável:
- Se for um path (`/usr/bin/app` ou `./app`), verifica se é um arquivo
  regular legível (o bit de execução não é exigido aqui, pois "arquivo sem +x"
  é justamente um cenário de diagnóstico — será evidência própria na etapa de
  permission check).
- Se for um nome (`firefox`), procura em cada diretório do `$PATH`, exigindo
  bit de execução (mesma semântica do shell).
- Segue symlinks via `canonicalize()`.

**Modo interativo:** rodar `idwhy` sem subcomando (ou `cargo run`) lista os aplicativos
atualmente em execução (varredura de `/proc/*/exe` via
`src/core/process_scan.rs`, deduplicada por caminho real). Serviços do
sistema (daemons, infra de desktop) ficam **ocultos por padrão** — a lista
mostra só apps de usuário — com paginação de 20 em 20 (`Enter` = mostrar
mais) e atalho `[t]` para exibir/ocultar os serviços. Também dá para
selecionar pelo número, usar `[0] Outro` para digitar um caminho/nome, ou
simplesmente digitar um caminho/nome direto no prompt. Sem TTY, a
ferramenta orienta o uso de `cargo run -- diagnose <alvo>`.

**Wrapper detection (Etapa 6):** `resolve_target()` atravessa wrappers
até o binário real, com profundidade máx. 5 e guard contra loops:
- **Shebang**: segue o mesmo interpretador que o kernel executaria
  (regras do kernel: argumento único; buffer de 256 bytes). Scripts de
  export do Flatpak caem aqui naturalmente e são rotulados `flatpak`.
- **`#!/usr/bin/env X`**: resolve X pelo `$PATH`, como o env faz.
- **AppImage**: mágica `AI\x01/AI\x02` no offset 8; a análise para nele
  (o payload dentro do squashfs só existe montado/executando).
- **Shebang quebrado vira diagnóstico**: CRLF na linha (`#!bin/sh\r`) e
  interpretador sem caminho absoluto geram evidência crítica
  `broken_wrapper` + causa `cc_broken_wrapper` com correção concreta.

Limitação atual: não desmonta AppImage/squashfs; não rastreia wrappers
que exigem execução (ex.: `flatpak run` como comando, fora de script).

### 2.2 Static Analyzer (`src/analyzers/static_analyzer.rs`)
Usa a crate `goblin` para ler o ELF **sem nunca executar o binário**:
- Valida se o header ELF é válido.
- Extrai arquitetura (x86_64, aarch64, etc).
- Extrai o interpretador (`PT_INTERP`, ex: `/lib64/ld-linux-x86-64.so.2`).
- Extrai a lista `NEEDED` (bibliotecas requeridas).
- Extrai `RPATH`/`RUNPATH`.
- Calcula SHA-256 do arquivo (para futura checagem de integridade contra
  o gerenciador de pacotes).

### 2.3 Dependency Analyzer (`src/analyzers/dependency_analyzer.rs`)
Constrói o grafo de dependências via BFS a partir do `NEEDED` do binário
raiz, seguindo a **ordem real de resolução do dynamic linker** (ld.so(8)),
com contexto de busca **por objeto** — cada lib resolvida usa os próprios
RPATH/RUNPATH (com expansão de `$ORIGIN`) para resolver as dependências
dela, e não mais os caminhos do binário raiz:

```
RPATH do objeto (se não houver RUNPATH) > LD_LIBRARY_PATH > RUNPATH do objeto > cache do ldconfig > diretórios padrão
```

Para cada lib resolvida, lê o `NEEDED` dela também (resolução
transitiva). Marca cada nó como `found: true/false`.

A única chamada de comando externo é `ldconfig -p` — segura, porque lê o
cache do sistema, não o binário sendo diagnosticado.

### 2.4 Rule Engine (`src/inference/rule_engine.rs`)
Duas funções:
- `collect_evidence()`: converte o `ApplicationProfile` em uma lista de
  `Evidence` tipada (hoje: `path_not_found`, `elf_invalid`,
  `missing_shared_library`, `no_interpreter`, `exec_permission_denied`,
  `missing_display_env`, `ld_preload_active`, `ld_library_path_active`,
  `broken_wrapper`, `binary_modified_from_package`, `runtime_missing_library`,
  `runtime_permission_denied`, `runtime_timeout`, `runtime_clean_exit`).
- `rank_causes()`: agrupa evidências relacionadas em `CauseCandidate`
  (score derivado da soma dos pesos das evidências — sem pesos
  duplicados em hardcode), calcula uma `confidence` (heurística — ver
  seção 4) e ordena por score decrescente. Alvo não encontrado agora tem
  causa própria (`cc_target_not_found`) em vez de cair no genérico
  "nenhum problema".

### 2.5 Report (`src/report/formatter.rs`)
Imprime o relatório em texto formatado (estilo `coreutils`/`strace`) ou
em JSON (`--json`), no formato inspirado no protótipo original de
pesquisa.

### 2.6 Permission Check (`src/analyzers/permission_analyzer.rs`)
Simula a **decisão do kernel** ao tentar executar o arquivo com o usuário
atual — sem depender da crate `libc` (identidade lida de `/proc/self/status`,
incluindo grupos suplementares):
- dono do arquivo → bits de dono;
- grupo efetivo/suplementar → bits de grupo;
- demais → bits de other; `root` precisa de qualquer bit x.

Se o usuário atual não pode executar, emite evidência crítica
`exec_permission_denied` com modo octal e uids envolvidos, e a causa
`cc_exec_permission` sugere `chmod +x`. Limitação MVP: ACLs estendidas
(`getfacl`) ainda não são consideradas.

### 2.7 Environment Scan (`src/analyzers/environment_analyzer.rs`)
Lê o ambiente **do processo diag** (herdado do shell do usuário) e o cruza
com a análise estática:

- **Correlação gráfica**: identifica libs gráficas no NEEDED/grafo
  (`libX11`, `libxcb`, `libwayland`, `libgtk*`, `libQt5/6`, `libSDL2`,
  `libEGL`/`libGL`). **Só um app gráfico sem `DISPLAY` nem
  `WAYLAND_DISPLAY` gera evidência** (`missing_display_env`) — apps de
  terminal não podem gerar falso positivo.
- **Variáveis LD_***: `LD_PRELOAD` ativo ou `LD_LIBRARY_PATH` definido
  geram evidências informativas (podem sombrear/mascarar bibliotecas) e
  uma causa única `cc_suspicious_ld_env` sugerindo re-teste com
  `env -u`.

Limitação MVP documentada: serviços iniciados pelo systemd têm ambiente
diferente do interativo; ler `/proc/<pid>/environ` do alvo é evolução
natural quando o modo interativo passar o PID.

### 2.8 Package ID (`src/analyzers/package_analyzer.rs`)
Detecta o gerenciador de pacotes via `/etc/os-release` (`ID`/`ID_LIKE`;
fedora/rhel/suse → dnf/rpm, debian/ubuntu/mint/pop → apt/dpkg) e consulta:

- **Dono de arquivo presente**: `rpm -qf --queryformat` ou `dpkg -S` →
  alimenta a linha `Pacote:` do relatório e habilita reinstalação concreta
  quando o ELF está inválido.
- **Fornecedor de lib ausente**: `dnf -q --cacheonly provides` (somente
  cache local, **sem rede**) ou `dpkg -S`. Quando encontra, a remediação
  vira comando direto — ex.: `sudo dnf install vim-enhanced-2:9.2...`.
  Sem preferência de arquitetura o dnf costuma casar i686 primeiro; por
  isso a consulta prioriza o candidato com o mesmo arch do binário.

Limitações MVP: sem timeouts nos subprocessos (comandos locais rápidos);
pacman não implementado; `apt-file` não é requisitado (não é padrão).

### 2.9 File Integrity (`package_analyzer::verify_integrity`)
Compara o SHA-256 já calculado na análise estática com o hash registrado
pelo gerenciador na instalação:

- **RPM**: dump `FILENAMES|FILEDIGESTS` do pacote dono; digest de 64 hex é
  tratado como sha256 e comparado case-insensitive.
- **Debian**: `/var/lib/dpkg/info/<pkg>.md5sums` registra MD5 — o hash
  local é obtido com `md5sum` (comando fixo somente leitura).

Semântica honesta em três estados no JSON (`integrity.matches`):
`true` confere · `false` **MODIFICADO** → evidência `Error`
`binary_modified_from_package` + causa `cc_binary_tampered` sugerindo
reinstalação concreta · `null` não comparável (algoritmo diferente, ex:
rpm legado com md5) — **nunca vira alerta**.

### 2.10 Execução controlada (`src/analyzers/runtime_analyzer.rs`)

Opt-in explícito: `idwhy diagnose --allow-exec <alvo>`. **Sem essa flag
nada é executado, nunca.**

Fluxo: `ExecutionPolicy::validate()` → bwrap (args fixos da seção 5) →
`strace -f -q -e trace=%file -- <alvo>` → parser de falhas.

- `%file` captura só syscalls de arquivo (open*/stat*/access*/exec*) —
  exatamente o que diagnostica "não achou lib em runtime", sem ruído.
- **Timeout** (`--exec-timeout`, padrão 10s) mata o processo; captura de
  stdout/stderr em threads com teto de 1 MiB cada (evita deadlock de
  pipe); ambiente zerado (`--clearenv`) com PATH mínimo.
- **Classificação anti-falso-positivo**: ENOENT em `*.so*` carregável vira
  evidência Warning (`runtime_missing_library` → causa
  `cc_runtime_dependency_miss`, cap 0.85); outros ENOENT são probes
  normais de app e são descartados; EACCES/EPERM viram Error.
- Saída limpa vira evidência Info informativa; timeout idem.
- O texto bruto do strace fica preservado no `RunOutcome` para a
  correlação temporal da Etapa 9 (journalctl por PID/janela).

Requisitos na máquina: `bubblewrap` e `strace` instalados (o tool recusa
com dica de instalação caso falte qualquer um).

---

## 3. O que NÃO está implementado ainda

Em ordem sugerida de prioridade (do mais barato/seguro pro mais
arriscado):

| # | Componente | Por que ainda não entrou | Complexidade |
|---|---|---|---|
| ~~1~~ | ~~Permission Check~~ | **Implementado (seção 2.6)** — falta refinar com ACLs estendidas | Baixa |
| ~~2~~ | ~~Environment Scan~~ | **Implementado (seção 2.7)** — falta ler `/proc/<pid>/environ` do alvo | Baixa |
| ~~3~~ | ~~Package ID~~ | **Implementado (seção 2.8)** — dnf/rpm e apt/dpkg; pacman ficou para depois | Média |
| ~~4~~ | ~~File Integrity~~ | **Implementado (seção 2.9)** — rpm via FILEDIGESTS; debian via md5sums+md5sum | Média |
| ~~5~~ | ~~Script/wrapper detection~~ | **Implementado (seção 2.1)** — shebang/env/AppImage; AppImage para no wrapper (payload só existe montado) | Média |
| ~~6~~ | ~~Controlled Execution~~ | **Implementado (seção 2.10)** — opt-in explícito `--allow-exec`, sempre sob bwrap da seção 5 | Alta |
| 7 | **Log Collection (journalctl)** | Buscar logs por PID/tempo depois da execução controlada | Alta (depende do item 6 para ter PID/tempo) |
| 8 | **Evidence Correlation temporal/espacial** | Algoritmo de agrupamento por janela de tempo — só faz sentido quando existir mais de uma fonte com timestamp (strace + journal + coredump) | Alta |
| 9 | **Flatpak/sandbox analyzer** | `flatpak info`, overrides de permissão | Média |
| 10 | **GPU stack check** | `vulkaninfo`, versão do Mesa/driver NVIDIA | Média |
| 11 | **Knowledge base em SQLite** | Hoje as regras estão hardcoded em Rust; mover para tabelas (`causes`, `evidence_patterns`, `remediations`) permite adicionar regras sem recompilar | Média |
| 12 | **Confidence calibration real** | Ver seção 4 abaixo — hoje é heurística, não calibrada com dados reais | Depende de uso em produção |

---

## 4. Fórmula de confiança (decidida)

A fórmula antiga (`score / 100.0`, limitada a 0.97) era arbitrária: no teste
real (lib ausente, evidência única de peso 45), a confiança saía em **45%**,
bem abaixo do esperado para algo praticamente inequívoco.

**Decisão adotada (Etapa 1):** calibração por categoria de causa, em
`src/inference/rule_engine.rs`:

```text
confidence = min(score / score_full, 1.0) × cap
```

| Categoria | `score_full` | `cap` | Racional |
|---|---|---|---|
| `dependency` | 45 | 0.95 | Uma única lib ausente já é conclusiva (existe no disco ou não) |
| `binary_integrity` | 60 | 0.95 | Header ELF inválido não tem interpretação alternativa |
| `target_resolution` | 50 | 0.95 | Alvo inexistente é fato, não hipótese |
| `environment` | 40 | **0.60** | Reservado à Etapa 3: evidência de ambiente pode ser falso positivo |

Efeito: uma lib ausente agora reporta **95%** de confiança; categorias
ambíguas mantêm gradiente (uma evidência fraca ≠ certeza) e nunca passam do
cap da própria categoria. Categoria desconhecida → 0.0 (falha segura).

A calibração estatística com dados reais de acerto/erro (histórico de uso)
continua como meta futura — o cap por categoria é o modelo honesto possível
enquanto esse histórico não existe.

---

## 5. Modelo de segurança (implementado em `src/core/security.rs`)

Já implementado:
- **Nunca executa o binário diagnosticado** na análise estática.
- Chamadas externas somente leitura e fixas: `ldconfig -p`, `rpm -qf`,
  `dpkg -S`, `dnf --cacheonly provides`, `md5sum <arquivo>` — sem rede,
  sempre `Command::arg(...)`, nunca concatenação de string.
- **Leitura anti-TOCTOU** (`read_file_verified`): abre um único handle
  com `O_NONBLOCK`, valida via fstat que é arquivo regular ANTES de
  consumir e lê só desse handle — FIFOs são rejeitados sem travar a
  ferramenta; teto de 2 GiB contra OOM.
- **Probe de sandbox**: `idwhy security-check` mostra bwrap/systemd-run
  disponíveis e o estado da política.
- **ExecutionPolicy**: execução do alvo OFF por padrão; sandbox ausente
  só passa com override duplo consciente (`--unsafe-no-sandbox`).
- **Builder do bubblewrap** (consumido pela execução controlada): args
  fixos e testáveis — `--ro-bind / / --dev /dev --proc /proc --tmpfs
  /tmp --unshare-all --die-with-parent --new-session --clearenv` + alvo
  como argumento.

A execução controlada (seção 2.10) consome exatamente este módulo:
builder do bwrap + validação de política antes de qualquer spawn.

## 6. Como estender

Para adicionar uma nova regra de diagnóstico hoje (antes da knowledge
base em SQLite existir):

1. Em `collect_evidence()` (`src/inference/rule_engine.rs`), adicione a
   lógica que gera a nova `Evidence` a partir do `ApplicationProfile`.
2. Em `rank_causes()`, adicione o `CauseCandidate` correspondente, com
   peso e remediação sugerida.
3. Se a evidência vier de uma nova fonte de dados (ex: permissões,
   ambiente), crie um novo módulo em `src/analyzers/` e chame-o em
   `run_diagnosis()` (`src/main.rs`).

Para rodar os testes artificiais da tabela de testes original (T01–T15),
o padrão usado no teste manual foi:

```bash
# Simula lib ausente (T01) sem precisar linkar de verdade:
patchelf --add-needed libnome_falso.so.3 /caminho/para/binario_copia
cargo run -- diagnose /caminho/para/binario_copia
```

---

## 7. Estrutura de arquivos

```
src/
├── main.rs                        # CLI (clap) + orquestração do pipeline + modo interativo
├── core/
│   ├── types.rs                   # Evidence, CauseCandidate, ApplicationProfile
│   ├── discovery.rs               # Resolve nome/path -> executável real
│   ├── process_scan.rs            # Lista aplicações em execução via /proc/*/exe
│   └── security.rs                # Anti-TOCTOU, probe de sandbox, ExecutionPolicy
├── analyzers/
│   ├── static_analyzer.rs         # Parsing ELF (goblin), nunca executa o binário
│   ├── dependency_analyzer.rs     # Grafo de dependências (BFS por objeto + ldconfig)
│   ├── permission_analyzer.rs     # Simula decisão do kernel sobre execução
│   ├── environment_analyzer.rs    # Display/LD_* correlacionado com libs gráficas
│   ├── package_analyzer.rs        # Dono/fornecedor de arquivos via rpm/dpkg/dnf
│   └── runtime_analyzer.rs        # Execução sandboxada + parser de strace
├── inference/
│   └── rule_engine.rs             # Evidence -> CauseCandidate, scoring
└── report/
    └── formatter.rs               # Saída em texto/JSON

tests/
└── cli_integration.rs             # Testes de integração da CLI (spawnam o binário)
```
