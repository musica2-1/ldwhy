# idwhy

*Linux Application Diagnostic* — motor de diagnóstico causal para aplicações
Linux. Em vez de despejar logs brutos (como `strace` ou `journalctl` fazem),
a ferramenta correlaciona evidências de múltiplas camadas do sistema e
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
`src/core/process_scan.rs`, deduplicada por caminho real) e permite
selecionar pelo número, escolher "[0] Outro" para digitar um caminho/nome,
ou simplesmente digitar um caminho/nome direto no prompt. Sem TTY, a
ferramenta orienta o uso de `cargo run -- diagnose <alvo>`.

**Limitação atual:** só entende binários ELF diretos. Não detecta scripts
(shebang `#!/bin/bash`), nem resolve o executável real por trás de
wrappers como `flatpak run` ou AppImage.

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
  `missing_shared_library`, `no_interpreter`).
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

---

## 3. O que NÃO está implementado ainda

Em ordem sugerida de prioridade (do mais barato/seguro pro mais
arriscado):

| # | Componente | Por que ainda não entrou | Complexidade |
|---|---|---|---|
| 1 | **Permission Check** | Fácil: `stat()` no binário + ACL básico | Baixa |
| 2 | **Environment Scan** | Fácil: ler `DISPLAY`, `WAYLAND_DISPLAY`, `XDG_*`, comparar com o esperado | Baixa |
| 3 | **Package ID** | Precisa abstrair `rpm -qf` / `dpkg -S` / `pacman -Qo` por distro | Média |
| 4 | **File Integrity** | Comparar SHA-256 (já calculado) contra o hash que o gerenciador de pacotes registrou | Média |
| 5 | **Script/wrapper detection** | Ler shebang, detectar `flatpak run`, resolver o binário real por trás | Média |
| 6 | **Controlled Execution (strace)** | Executar o app com `strace` filtrado dentro de sandbox (`bubblewrap`) e capturar exit code + syscalls com erro | Alta — mexe com execução real, precisa do modelo de segurança da seção J |
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

## 5. Modelo de segurança (o que já é respeitado, o que falta)

Já implementado:
- Nunca executa o binário sendo diagnosticado (só lê ELF com `goblin`).
- `ldconfig -p` é a única chamada externa, e é somente leitura do cache
  do sistema.

Falta implementar antes de adicionar `strace`/execução controlada
(componente 6 da tabela acima):
- Sandbox via `bubblewrap` (`bwrap --ro-bind / / --unshare-all ...`) ou
  `systemd-run --property=ProtectSystem=strict`.
- Validação de path com `realpath()` + `stat()` antes de qualquer
  operação (TOCTOU protection).
- Nunca montar comandos por concatenação de string — sempre
  `Command::new(...).arg(...)` (já seguido no código atual).

---

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
│   └── process_scan.rs            # Lista aplicações em execução via /proc/*/exe
├── analyzers/
│   ├── static_analyzer.rs         # Parsing ELF (goblin), nunca executa o binário
│   └── dependency_analyzer.rs     # Grafo de dependências (BFS por objeto + ldconfig)
├── inference/
│   └── rule_engine.rs             # Evidence -> CauseCandidate, scoring
└── report/
    └── formatter.rs               # Saída em texto/JSON

tests/
└── cli_integration.rs             # Testes de integração da CLI (spawnam o binário)
```
