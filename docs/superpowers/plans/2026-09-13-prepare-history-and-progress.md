# A fase determinística num repositório grande: plano

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use checkbox syntax.

**Goal:** a fase determinística de uma análise (`agentloop security prepare`) acaba no tempo do scanner mais lento e não na soma; o histórico git de um repositório grande fica coberto ao longo das análises em vez de bater no tecto em todas; o operador vê em que fase está enquanto corre; e a nota do pré-passe SAST nomeia os ficheiros que o semgrep não conseguiu ler.

**O que se mediu (2026-09-13, ATDCore: 21 607 commits, 372 MB, 969 185 linhas, os quatro motores instalados):** `prepare` levou 1 721 s; 1 200 desses foram os dois sweeps de histórico (gitleaks `git` e o interno) a bater cada um no tecto de 600 s, em série, sem resultado; o `git log -p -U0` sozinho leva 55 s e o sweep interno reescrito ~277–390 s; o semgrep 1 176 deixou 10 ficheiros por parsear e a nota só diz o número.

**Arquitectura:** `bin/security/cli.py` `cmd_prepare` orquestra fases independentes através de `concurrent.futures.ThreadPoolExecutor` (cada fase é um subprocesso, threads chegam); a ordem das notas e da tabela de cobertura é montada depois, como hoje. O histórico ganha um orçamento próprio (`engines.HISTORY_TIMEOUT`, env `AGENTLOOP_SECURITY_HISTORY_TIMEOUT`, 1800 s) e um cursor por (projecto, repo, scanner) no ledger, com a cache dos findings de histórico já encontrados: cada análise varre só `cursor..HEAD`, junta a cache, e avança o cursor até onde chegou. O progresso vai por `stderr` com flush (o motor já redirecciona o `prepare` para `<log>.prepare`), e o servidor lê a última linha desse ficheiro para o modal do run.

**Tech Stack:** python 3 stdlib (`bin/security/*`), sqlite (ledger), bash 3.2 (`bin/agentloop`, só se precisar), o servidor python stdlib, `bin/dashboard.html`.

## Global Constraints

- Código, comentários, strings e CHANGELOG em inglês; nenhum `/Users/<nome>` real em ficheiro versionado.
- CHANGELOG move com cada commit que toque `bin/`, `skills/`, `test/` (entrada `### Fixed` em Unreleased).
- Nunca correr o motor contra `config/`/`data/` reais; os testes de `tests/security` usam `tmp_path` e os seus próprios repositórios git.
- Nunca imprimir, guardar ou testar com o VALOR de uma credencial; os findings continuam a não o transportar.
- As quatro suites verdes antes de cada push: `python3.13 -m pytest tests --ignore=tests/security -q`, `bash bin/agentloop selftest`, `bash test/e2e.test.sh`, `python3.13 -m pytest tests/security -q` (aqui com os quatro motores instalados: gitleaks 8.30.1, trivy 0.74.0, semgrep 1.176.0, syft 1.51.1, por isso os testes que os pedem correm).
- Nunca selftest e e2e ao mesmo tempo (partilham `test/sandbox`). Nunca correr suites em segundo plano.
- `git` só com `/usr/bin/git`, um comando por chamada, add por caminho, nunca `--no-verify`.

---

### Task 1: O histórico com orçamento próprio, cursor e cache

**Files:**
- Modify: `bin/security/engines.py` (`HISTORY_TIMEOUT`)
- Modify: `bin/security/secrets.py` (`scan_history`: `--reverse`, budget, `reached`, progresso)
- Modify: `bin/security/ledger.py` (tabela `history_sweep`, leitura/escrita)
- Modify: `bin/security/adapters.py` (`gitleaks_scan`: `--log-opts`, budget do passo `git`)
- Modify: `bin/security/cli.py` (`_scan_secrets` lê e escreve o cursor e a cache)
- Test: `tests/security/test_secrets.py`, `tests/security/test_ledger.py` (ou o ficheiro onde o ledger é testado), `tests/security/test_cli.py`, `tests/security/test_adapters.py`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Produces: `engines.HISTORY_TIMEOUT: int`; `secrets.scan_history(root, since_sha, ignore=(), rename=None, budget=None) -> (findings, note, swept, reached)`; `ledger.history_sweep(conn, project, repo, scanner) -> (sha | None, findings: list[dict])`; `ledger.save_history_sweep(conn, project, repo, scanner, sha, findings)`; `cli._scan_secrets(root, ignore, sweeps=None)` onde `sweeps` é um dict `{scanner: {"since": sha|None, "cached": [...]}}` que a função devolve actualizado em `sweeps[scanner]["reached"]`/`["findings"]` (ou a forma equivalente que o implementador documentar), para `cmd_prepare` gravar.

- [ ] **Step 1: `HISTORY_TIMEOUT`.** Em `engines.py`, ao lado de `SCAN_TIMEOUT`: `HISTORY_TIMEOUT = int(os.environ.get("AGENTLOOP_SECURITY_HISTORY_TIMEOUT", "1800"))` com um comentário que diga porquê (um repositório de 21 607 commits gastou dois tectos de 600 s em série sem cobrir nada). Teste: o default é 1800 e o env manda.

- [ ] **Step 2: `scan_history` com `--reverse`, orçamento e `reached`.** A varredura passa a `git log -p -U0 --reverse …`, do commit mais antigo para o mais recente, para que um corte pelo orçamento deixe um cursor útil. A função devolve um quarto valor, `reached`: o sha do último commit cujo patch foi lido por inteiro (o cabeçalho `commit X` seguinte marca o anterior como completo; no EOF normal é o último commit visto). `budget` substitui `SCAN_TIMEOUT` no prazo (default `HISTORY_TIMEOUT`). A nota de corte muda para: `HISTORY_GAP` com reason `"it stopped at its {budget}s budget after {n} commits, at {sha7}; the next analysis continues from there"`. Progresso: a cada 2 000 commits, `print(f"prepare: history {n}/{total} commits", file=sys.stderr, flush=True)` com `total` de `git rev-list --count <rev>` (uma chamada, barata). Testes: o repositório de 3 commits com o segredo no 2.º: com um `budget` que o relógio (monkeypatch de `time.monotonic`) esgota depois do 1.º commit, `reached` é o sha do 1.º, `swept` False, a nota diz o sha e o número; sem corte, `reached` é HEAD e `swept` True; `since_sha` = 1.º commit varre só `2..HEAD` (o segredo do 2.º aparece, um segredo só no 1.º não). Os testes existentes que desempacotam três valores passam a quatro.

- [ ] **Step 3: o ledger.** `CREATE TABLE IF NOT EXISTS history_sweep (project TEXT NOT NULL, repo TEXT NOT NULL, scanner TEXT NOT NULL, sha TEXT NOT NULL, findings TEXT NOT NULL DEFAULT '[]', at INTEGER NOT NULL, PRIMARY KEY (project, repo, scanner))` no `_SCHEMA` (tabela nova: `IF NOT EXISTS` chega, ao contrário de uma coluna). `history_sweep(conn, project, repo, scanner)` devolve `(sha, findings)` ou `(None, [])`; `save_history_sweep(...)` substitui a linha (`INSERT OR REPLACE`), `findings` como JSON dos dicts de finding (sem valores de credencial: os dicts nunca os têm). Testes: gravar, ler, substituir, um scanner não interfere no outro.

- [ ] **Step 4: `_scan_secrets` incremental.** Para cada scanner de histórico (`secrets` sempre; `gitleaks` quando existe): lê o cursor; se existir, confirma que é antepassado de HEAD (`git merge-base --is-ancestor <sha> HEAD`, rc 0); se não for (histórico reescrito, outro repo com o mesmo nome), começa do zero e descarta a cache, com uma nota. Varre `since..HEAD`; junta os findings novos à cache pela chave `(rule, path)` — o `commit_count` soma — e devolve a união como os findings de histórico desta análise; o cursor avança para `reached` (interno) ou para HEAD (gitleaks, só quando o passo completou: `history is not None`). `swept` da fase = o passo desta análise completou (a cache cobre o resto por construção). Para o gitleaks: `["git", ".", "--log-opts", f"{since}..HEAD", *common]` quando há cursor, e o passo `git` com `timeout=engines.HISTORY_TIMEOUT`. `cmd_prepare` chama `ledger.history_sweep` antes e `save_history_sweep` depois, dentro do mesmo `conn`. Testes em `test_cli.py` (engines off, o interno): duas análises sobre o mesmo repositório de 3 commits com o relógio a cortar a primeira depois do 1.º commit: a 1.ª grava cursor=commit 1 e `secrets partly`; a 2.ª varre só `2..HEAD`, carrega o finding do 1.º da cache, grava cursor=HEAD, `secrets ran`, e o finding do 1.º continua `open` na 2.ª (não `fixed`). Um teste do caminho "cursor não é antepassado": cache descartada, varredura completa. Em `test_adapters.py`: o `--log-opts` só com cursor (verificar o argv do `run_json` com um fake) e o `timeout` do passo `git`.

- [ ] **Step 5: CHANGELOG, suites, commit.** `### Fixed`: "The history sweeps of the deterministic phase have a budget of their own (`AGENTLOOP_SECURITY_HISTORY_TIMEOUT`, 1800 s) and a cursor: each analysis sweeps only the commits since the last one it reached, carries the history findings already found, and a sweep cut by its budget continues in the next analysis instead of starting over. Measured: 21,607 commits spent two 600 s budgets in series on every analysis and covered nothing." Commit: `feat(security): the history sweep continues where the last analysis stopped`.

### Task 2: As fases em paralelo, e o progresso no ecrã

**Files:**
- Modify: `bin/security/cli.py` (`cmd_prepare`, `_scan_secrets`)
- Modify: `bin/agentloop-server` (`load_live_detail`: `phase_detail`)
- Modify: `bin/dashboard.html` (o texto do Terminal na fase `prepare`)
- Test: `tests/security/test_cli.py`, `tests/test_platform_runs.py`, `tests/test_page_contract.py`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: `cmd_prepare` em paralelo.** `deps.inventory(root)` primeiro (leitura local, rápida). Depois, com `concurrent.futures.ThreadPoolExecutor(max_workers=5)`: `secrets = pool.submit(_scan_secrets, …)`, `hyg = pool.submit(hygiene.scan, root, ignore)`, `trivy_chain = pool.submit(lambda: (_scan_dependencies(...), _scan_iac(...)))` (os dois passos do trivy em série na mesma thread: dois trivy ao mesmo tempo disputam a cache da base de dados), `sbom = pool.submit(_scan_sbom, root, components)`, `sast = pool.submit(_scan_sast, …)`. `.result()` por ordem: secrets, hygiene, deps, sbom, iac, sast; o código que monta `findings`, `notes` e `phases` fica como está (só lê variáveis). Uma excepção numa fase propaga como hoje (o `prepare` falha inteiro), depois de esperar as outras (`wait`). Dentro de `_scan_secrets`, os quatro passos (gitleaks `git`, gitleaks `dir`, interno histórico, interno árvore) também em paralelo, recolhidos pela ordem de hoje (histórico antes da árvore, como o comentário de `cmd_prepare` exige). Teste: com fakes que dormem 0,3 s cada, `cmd_prepare` acaba em menos de 0,8 s (não 1,5 s) e a tabela de cobertura sai pela mesma ordem (`scope, secrets, hygiene, dependencies, sbom, iac, sast-prepass`); o teste `test_every_phases_prose_is_a_substring_of_the_paragraph` continua a passar.

- [ ] **Step 2: progresso.** Em `cmd_prepare`, `print(f"prepare: started {', '.join(names)}", file=sys.stderr, flush=True)` no arranque e `print(f"prepare: {name} done ({secs}s)", …)` quando cada future acaba (usar `as_completed` só para o log; a recolha continua pela ordem), e no fim `prepare: all phases done ({total}s)`. No servidor, `load_live_detail`: quando `phase == "prepare"`, `phase_detail` = a última linha não vazia de `<log>.prepare` (até 200 caracteres; vazio se não houver). No `bin/dashboard.html`, o Terminal na fase `prepare` acrescenta a linha: "Running the deterministic phase before the agent … · <phase_detail>". Testes: pytest do servidor com um `.prepare` de três linhas → `phase_detail` é a última; page-contract afirma `d.phase_detail` no texto.

- [ ] **Step 3: CHANGELOG, suites, commit.** "The deterministic phase runs its independent scanners in parallel (the secret sweeps, hygiene, the trivy pair, syft, semgrep), so it lasts the slowest one rather than the sum; it writes a progress line per phase and every 2,000 history commits to the run's `.prepare` file, and the run dialog shows the last one." Commit: `perf(security): the deterministic phase runs its scanners in parallel and says where it is`.

### Task 3: Os ficheiros que o semgrep não leu, nomeados

**Files:**
- Modify: `bin/security/adapters.py` (`SAST_PARSE_NOTE` e onde se conta `PartialParsing`)
- Test: `tests/security/test_adapters.py`
- Modify: `CHANGELOG.md`

- [ ] **Step 1.** Onde o adaptador conta os erros `PartialParsing`, recolher os `path` (relativos ao root, ordenados, únicos). A nota passa a: `"{count} {files} could not be fully parsed by Semgrep ({listed}), so part of what they hold was not analysed at all; a generated or vendored file among them belongs in the project's ignore_paths."` com `listed` = até 8 caminhos separados por `, ` e `… and N more` quando há mais. Só caminhos, nunca conteúdo. Testes: 3 ficheiros → os três nomeados; 12 → 8 e "and 4 more"; 0 → sem nota (como hoje).

- [ ] **Step 2.** CHANGELOG: "The SAST pre-pass note names the files Semgrep could not fully parse (up to eight, and how many more), so a generated or vendored file among them can go to `ignore_paths`." Commit: `fix(security): the SAST pre-pass note names the files semgrep could not parse`.
