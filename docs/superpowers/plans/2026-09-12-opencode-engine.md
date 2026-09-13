# O motor OpenCode: plano de implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** um job, um projecto e o bloco `security` de um projecto correm na plataforma `opencode` com os modelos que o operador configurou nesse CLI, e tudo o que o scheduler já faz para as outras duas plataformas (dashboard, journal, tectos, resume, análises de segurança) funciona nesta, sem que nenhum job Anthropic ou OpenAI mude de comportamento.

**Architecture:** o OpenCode é traduzido na fronteira. `bin/platforms/opencode_stream.py` lê o JSON de `opencode run --format json` por um FIFO e escreve o `stream-json` canónico, uma linha por evento, escoada de imediato. A tabela de plataformas em `bin/agentloop` ganha um ramo `opencode` em cada função, mais três coisas novas: `platform_normalizer` (o `run_job` pergunta "tem normalizador?" em vez de `[ "$platform" = "openai" ]`), a capacidade `prepare_inline` (só Anthropic corre o `prepare` da análise de segurança dentro do agente), e `opencode_config_content`, que gera o bloco `permission` (dois modos honestos mais as listas de ferramentas do job) entregue por `OPENCODE_CONFIG_CONTENT`. O custo é o número do CLI quando o catálogo tem preço, estimado da tabela do operador quando não tem, e desconhecido (nunca zero) no resto. O watchdog ganha, em commit próprio, uma regra estreita: um stream ainda vazio ao fim de `stall_timeout_seconds` é um run morto.

**Tech Stack:** bash 3.2 (macOS), jq, Python 3 stdlib (normalizador e servidor), pytest em `python3.13`, esbuild pelo `build/build-ui.sh`, OpenCode CLI 1.18.30 (medido), `test/fake-opencode` como stand-in offline.

**Spec:** [`docs/superpowers/specs/2026-09-12-opencode-engine-design.md`](../specs/2026-09-12-opencode-engine-design.md). Evidência: [`docs/superpowers/specs/2026-09-12-opencode-measurements/`](../specs/2026-09-12-opencode-measurements/README.md). Onde este plano, a spec e a evidência divergirem, a evidência manda; depois a spec.

## Global Constraints

- **Bash 3.2:** sem arrays associativos, sem `${var,,}`, sem `mapfile`; um `case` (ou um apóstrofo num comentário) **dentro de `$( )`** parte o ficheiro em runtime e o `bash -n` passa à mesma: validar a correr (`bash bin/agentloop selftest`), nunca só a compilar. `local` em todas as variáveis de função. Uma função que "devolve" uma lista devolve-a por stdout (uma por linha) ou numa global nomeada (`PLATFORM_ARGV`, `PF_MODEL_ID`).
- **`bin/agentloop-server` é python 3, só stdlib.** O normalizador também.
- **A UI é compilada e o resultado é versionado:** editar `ui/` obriga a `bash build/build-ui.sh` **no mesmo commit**; o `selftest` recusa a árvore se `bin/static/` estiver desactualizado. `build/ui-digest.sh` carimba **todos** os ficheiros debaixo de `ui/`, não só os `.js`: nada de rascunhos lá dentro.
- **O CHANGELOG move-se com cada commit de código:** o `selftest` falha quando o último commit (sem merges) que tocou `bin/`, `skills/` ou `test/` é mais novo do que o último que tocou `CHANGELOG.md`. Toda a tarefa que toque `bin/` ou `test/` (fixtures incluídas) acrescenta a sua linha à entrada *OpenCode engine* sob `## [Unreleased]` → `### Added`, que a Tarefa 1 abre. Uma entrada diz *o que mudou e o que custava não ter*.
- **Nenhum ficheiro versionado pode conter um directório home real** (`/Users/<nome>`): o `selftest` recusa-o. Usa `/Users/me`, `jane@example.org`. As fixtures copiadas da evidência já vêm limpas (`/tmp/probe`).
- **O ramo Anthropic do `run_job` não muda** (`args="-p --output-format stream-json …"`, `toolargs`, os ramos interactivo e normal ficam byte a byte). O ramo OpenAI muda de **condição** (`platform_normalizer`) e de **despacho** (um `case` para o argv e a linha do normalizador), não de forma.
- **Nunca correr o motor contra `config/` ou `data/` reais** numa experiência: `AGENTLOOP_CONFIG=/tmp/… AGENTLOOP_DATA=/tmp/…`, stand-ins por `AGENTLOOP_CLAUDE_BIN`, `AGENTLOOP_CODEX_BIN`, `AGENTLOOP_OPENCODE_BIN`; um servidor de rascunho numa porta que não seja a 8787. **Não correr `install.sh`.**
- **Factos medidos do OpenCode CLI 1.18.30, que o código segue e nunca contradiz** (números = ficheiros da pasta de evidência):
  - `opencode run --format json --pure --auto --print-logs --log-level ERROR -m <provider/model> [--variant <v>] --dir <d> [--title <t>] [-s <id>] -- <prompt> </dev/null`. Sem `</dev/null` o processo lê o stdin até ao EOF antes de arrancar e pendura-se sem um byte (13a); texto no stdin é anexado ao prompt (13b). `--` antes do prompt é aceite (33).
  - Eventos, um por linha, todos com `sessionID`: `step_start`, `text{part.text}`, `tool_use{part.tool, part.callID, part.state{status, input, output, metadata, error, title, time}}` (sai **uma vez, já concluído**), `step_finish{part.reason, part.tokens{total,input,output,reasoning,cache{read,write}}, part.cost}`, `error{error{name, data}}`. Sem modelo no stream. `step_finish.reason` é `tool-calls` entre ferramentas e `stop` no último passo; o fim do run é o fim do processo, exit 0 (01, 02, 03, 05).
  - O primeiro byte só sai quando o modelo começa a responder (21b: 19 s). Um provider que não responde deixa o CLI pendurado sem timeout, sem erro e sem um byte (34b); esse processo pendurado soma ~1 s de CPU a cada 75 s de ralenti (35).
  - `-s <id>` retoma a mesma sessão **só com `--dir` no directório em que ela nasceu** (08b); noutro directório o CLI corre o turno numa instância que o `run` não ouve e pendura-se para sempre sem um byte (08c, 08d). SIGTERM: exit 143 em 1 s, sem órfãos, a sessão retoma (12, 12b). `--dir` inexistente: exit 1 em 0 s, `Error: Failed to change directory to …` (29).
  - Permissões por `OPENCODE_CONFIG_CONTENT='{"permission":{…}}'`: ferramenta → `allow`·`ask`·`deny`, padrões por comando em `bash` (`{"*":"allow","echo *":"deny"}`); `--auto` aprova o que é `ask` (04, 05, 06, 23). `ask` sem `--auto` → stderr `! permission requested: bash (ls); auto-rejecting`, `tool_use` com `state.status:"error"` e `state.error:"The user rejected permission to use this specific tool call."`, e o turno **acaba** (`step_finish.reason: tool-calls`, exit 0) (04, 18). `deny` numa ferramenta tira-a do roster: o modelo recebe `tool:"invalid"` com `input.error:"Model tried to call unavailable tool 'bash'. Available tools: …"` e continua (06); `deny` por padrão → `state.error:"The user has specified a rule which prevents you from using this specific tool call. Here are some of the relevant rules […]"` e o turno continua (23); `task: deny` fecha os subagentes (22).
  - Por omissão em `run` (agente `build`, 32): `*: allow`, `doom_loop: ask`, `external_directory: ask` (só ferramentas de ficheiro), `read *.env: ask`, `question`/`plan_enter`/`plan_exit: deny`. **Sem sandbox do SO**: `bash` escreve fora do directório e faz `git commit` num worktree sem perguntar (19, 20). O agente `plan` embutido não é read-only (mantém `bash`) (31, 32).
  - Tokens por passo: `total = input + output + reasoning + cache.read + cache.write`, `input` sem a cache, `reasoning` separado do `output` (11, 24b). Custo: o CLI calcula `(input×in + (output+reasoning)×out + cache.read×cr + cache.write×cw) / 10⁶` do preço do catálogo (24b, 24c, 34: `0.000426176016`); preço 0 no catálogo dá `0`, indistinguível de "sem preço".
  - `--variant` é o esforço; os valores válidos são as chaves de `variants` do modelo no catálogo; um valor inválido é aceite em silêncio (11, 11b). `--pure` desliga os plugins do operador e mantém as skills (`~/.claude/skills/`, `.opencode/skills/` do run) (03, 26, 27). `--title` evita a chamada extra ao modelo pequeno do título (30). `--print-logs --log-level ERROR` não escreve nada num run que não repetiu pedidos e é onde a razão de um `UnknownError` aparece (09b, 30); um pedido repetido escreve uma linha de erro e o run acaba bem (24c).
  - Erros: modelo/provider desconhecido → exit 1, `error{name:"UnknownError",data{message:"Unexpected server error. Check server logs for details.",ref}}` (09, 10); chave inválida → exit 1, `error{name:"APIError",data{message,statusCode:401,isRetryable,responseHeaders}}` (16); um 429 chegaria com a mesma forma e `statusCode: 429` (inferido, não medido).
  - `opencode export <id>` (do directório da sessão): `{info{id, directory, model{id, providerID, variant}, version, cost, tokens, permission, …}, messages[…]}` (14). `opencode models --verbose`: linha `provider/model` seguida de um JSON por modelo com `cost{input,output,cache{read,write}}`, `limit{context,output}`, `capabilities{toolcall,reasoning,…}`, `variants`, `status` (`models-verbose-after-provider-change.txt`); um id pode ter barra dentro (`pdm_ai/openai/gpt-oss-120b`): **a primeira barra separa o provider**. `opencode auth list`: caixa com cores ANSI, `N credentials` (`auth-list.txt`). `share: "disabled"` em `OPENCODE_CONFIG_CONTENT` é aceite (33).
- **Nomes, verbatim:** campo `platform` ∈ {`anthropic`,`openai`,`opencode`}; `AGENTLOOP_OPENCODE_BIN` (override), `OPENCODE_BIN`; `bin/platforms/opencode_stream.py` com `--model --permission --cwd --catalog --pricing --raw-out`; funções `platform_normalizer`, `opencode_config_content`, `platform_argv_opencode` (enche `PLATFORM_ARGV`), `opencode_catalog_available`, `opencode_catalog_ensure`, `opencode_catalog_ids`, `opencode_catalog_visible`, `opencode_catalog_efforts`, `opencode_catalog_all_efforts`, `opencode_catalog_priced`, `opencode_catalog_tools`, `opencode_unpriced`, `resolve_models_opencode`, `opencode_export_model`; capacidade `prepare_inline`; permissões OpenCode `full-access read-only`; `cost_basis` `reported|estimated|none`; `WATCHDOG_POLL` com `AGENTLOOP_WATCHDOG_POLL`; stand-in `test/fake-opencode` (`FAKE_SESSION`, `FAKE_MODE` complete|undeclared|dirty|hang|reject|deny|error|quota, `FAKE_ARGV_OUT`, `FAKE_PROMPT_OUT`, `FAKE_CONFIG_OUT`, `FAKE_DIR_OUT`, `FAKE_COST`, `FAKE_RAN_MODEL`, `FAKE_OPENCODE_NO_MODELS`); fixtures em `test/fixtures/opencode/`; servidor `PLATFORM_PERMISSIONS["opencode"]`, `_opencode_platform()`, `PLATFORMS_PLANNED = ()`.
- **Vocabulários:** permissões OpenCode `full-access` (omissão para job e segurança) e `read-only`; esforços OpenCode = as chaves de `variants` do modelo no catálogo, nenhum para um modelo sem `variants`; modelos OpenCode = ids `provider/model` do catálogo, `status: active` visíveis.
- **Suites a correr no fim de cada tarefa,** em primeiro plano, com timeout generoso, nunca em background (perdem-se), e **nunca o e2e ao mesmo tempo que o selftest** (partilham `test/sandbox`):

  ```bash
  bash bin/agentloop selftest
  python3.13 -m pytest tests --ignore=tests/security -p no:cacheprovider -q
  TRIVY_SKIP_DB_UPDATE=true TRIVY_SKIP_JAVA_DB_UPDATE=true TRIVY_SKIP_CHECK_UPDATE=true python3.13 -m pytest tests/security -p no:cacheprovider -q --deselect tests/security/test_both_configurations.py::test_the_security_suite_is_green_with_the_engines_on
  bash test/e2e.test.sh
  ```

  A linha de base nesta máquina, antes da entrega: selftest **730/0**, e2e **99/0**, pytest **552**, security **987 passed, 51 skipped, 1 deselected**. Cada tarefa acaba com os quatro números iguais ou maiores, nunca com um vermelho.
- **Worktree e git:** a branch é `feat/opencode-engine`, já criada, num worktree do harness. Nele o guarda do Bash recusa comandos compostos com git: `/usr/bin/git` e **um comando simples por chamada**; nunca `git add -A` nem `git add .` (há `.claude-flow/` untracked no repositório); adicionar sempre por caminho. Commits frequentes, em inglês, com o trailer `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`; empurrar ao fim de cada tarefa (`/usr/bin/git push`). Nunca `--no-verify`, nunca push para `main`.
- **Idioma:** código, comentários, docstrings, mensagens de commit, README e CHANGELOG em **inglês**; a prosa deste plano em português.

---

## Estrutura de ficheiros

| Ficheiro | Responsabilidade neste plano |
|---|---|
| `test/fixtures/opencode/*` (novos, T1) | as medições copiadas para onde os testes as lêem; a pasta das specs fica como registo do dia |
| `test/fake-opencode` (novo, T1) | o stand-in do OpenCode: responde a `--version`, `models [--verbose]`, `auth list`, `run` (os modos medidos) e `export`; grava argv, prompt, `--dir` e `OPENCODE_CONFIG_CONTENT` |
| `tests/test_fake_opencode.py` (novo, T1) | o stand-in emite JSON válido nas formas medidas, em cada modo |
| `bin/platforms/opencode_stream.py` (novo, T2) | o normalizador: OpenCode JSON → stream-json canónico, soma de tokens, custo por base, negações, cópia crua, escoamento por linha |
| `tests/test_opencode_stream.py` (novo, T2) | pytest do normalizador sobre as fixtures; as três bases de custo; o CLI por subprocesso; o `step_start` sozinho já escreve |
| `bin/agentloop`, bloco `# --- the OpenCode catalog ---` (T3) | leitores `opencode_catalog_*`, `resolve_models_opencode`, `opencode_catalog_ensure`, `cmd_resolve_models opencode`, `models_stale` sobre os três blocos |
| `bin/agentloop`, bloco `# --- platforms ---` (T3, T4) | registo, `platform_caps` (+ `prepare_inline`), permissões, esforços, `model_ok`, `catalog_ids`, `models_json`, `check` (opencode), `opencode_config_content`, `platform_argv_opencode`, `platform_normalizer`, `platform_finish` (export) |
| `bin/agentloop`, `run_job` (T5) | as recusas por plataforma, o ramo genérico com normalizador, `OPENCODE_CONFIG_CONTENT` no `run_env`, `platform_finish` com o `run_cwd`, a nota do tecto inerte, `rl_gate opencode` |
| `bin/agentloop`, watchdog (T6, commit próprio) | a regra do stream vazio, `WATCHDOG_POLL` |
| `test/fake-claude` (T6) | `FAKE_MODE=silent` |
| `test/e2e.test.sh` (T5, T6, T9) | cenários 29–38: run OpenCode completo/undeclared/dirty, argv e bloco de permissões, resume, stop, deny, quota, recusas, hook, custo `reported`, a regra do stream vazio, a análise de segurança |
| `bin/agentloop`, `cmd_set_field`, `cmd_create`, `security_derived_jobs`, `job_platform` (T7) | `platform: opencode` como valor; validação e defaults; `tools: false` na derivação |
| `bin/agentloop-server` (T8) | `_opencode_platform()`, `PLATFORM_PERMISSIONS["opencode"]`, `PLATFORMS_PLANNED = ()`, `jobs_using` a validar contra o catálogo OpenCode |
| `tests/test_platforms_api.py`, `tests/test_platform_runs.py` (T7, T8) | a forma de `/api/models.platforms.opencode`; as asserções que pinavam o *planned* |
| `config/pricing.example.json`, `bin/agentloop` (`opencode_unpriced`, `cmd_platforms`, `status_platforms_block`, `cmd_usage`) (T8) | o bloco `opencode` da tabela; `unpriced`; as linhas de `status`, `platforms` e `usage` |
| `bin/agentloop`, `security_prompt`, `cmd_skills` (T9) | os parágrafos OpenCode do prompt da análise; o texto do `skills` |
| `ui/app/editor-domain.js`, `ui/app/jobs-domain.js`, `ui/app/settings.js`, `ui/app/runs.js`, `ui/app/overview.js`, `ui/security/vocabulary.js`, `bin/dashboard.html`, `bin/static/*` (T10) | a terceira plataforma nos editores, cartões, tabelas, modal e Settings; o build |
| `tests/test_page_contract.py` (T10) | o contrato da página para a terceira plataforma; as asserções que pinavam o *planned* |
| `install.sh`, `README.md`, `CHANGELOG.md` (T1, T11) | a entrada do CHANGELOG (aberta em T1, fechada em T11); a linha do `opencode` no install; as secções *Platforms*, *Settings*, *Models*, *Effort*, *Budgets*, *Security block*, *CLI* |
| `docs/superpowers/specs/2026-09-12-opencode-measurements/acceptance-*.txt` (T12) | a aceitação com o CLI real, lida e guardada |

---

### Task 1: As fixtures, o stand-in `test/fake-opencode`, e a entrada do CHANGELOG abre

**Files:**
- Create: `test/fixtures/opencode/` (cópias da evidência, nomes abaixo)
- Create: `test/fake-opencode`
- Create: `tests/test_fake_opencode.py`
- Modify: `CHANGELOG.md` (a entrada *OpenCode engine* sob `## [Unreleased]` → `### Added`)

**Interfaces:**
- Consumes: nada do código; só a evidência em `docs/superpowers/specs/2026-09-12-opencode-measurements/`.
- Produces: `test/fixtures/opencode/<nome>` lidos por T2 (`tests/test_opencode_stream.py`) e T3 (selftest); `test/fake-opencode` lançado por T5/T9 (e2e) e T3 (selftest) através de `AGENTLOOP_OPENCODE_BIN`, com as variáveis `FAKE_SESSION`, `FAKE_MODE` (complete|undeclared|dirty|hang|reject|deny|error|quota), `FAKE_ARGV_OUT` (uma linha por argumento, `<n><TAB><primeira linha>`, mais `ARGC<TAB><n>`), `FAKE_PROMPT_OUT` (o último argumento inteiro), `FAKE_CONFIG_OUT` (o `OPENCODE_CONFIG_CONTENT` que recebeu), `FAKE_DIR_OUT` (o valor de `--dir`), `FAKE_COST` (o `cost` de cada `step_finish`, omissão `0`), `FAKE_RAN_MODEL` (o `provider/model` que o `export` diz ter corrido, omissão `opencode/big-pickle-real`), `FAKE_OPENCODE_NO_MODELS` (`models` responde vazio: uma máquina sem provider), `FAKE_SKIP_PREPARE` (como no `fake-codex`).

- [ ] **Step 1: Copiar as fixtures**

Cada ficheiro é uma cópia verbatim da pasta de evidência (já sem o home do operador e com o scratchpad como `/tmp/probe`). A cópia sintética de 429 é a única coisa escrita à mão, e diz-o no nome.

```bash
mkdir -p test/fixtures/opencode
E=docs/superpowers/specs/2026-09-12-opencode-measurements
cp "$E/01-trivial-turn.jsonl"              test/fixtures/opencode/01-trivial-turn.jsonl
cp "$E/02-tool-use-no-auto.jsonl"          test/fixtures/opencode/02-tool-use-bash-and-read.jsonl
cp "$E/03-tool-use-pure.jsonl"             test/fixtures/opencode/03-tool-use.jsonl
cp "$E/04-permission-ask-no-auto.jsonl"    test/fixtures/opencode/04-auto-rejected-ask.jsonl
cp "$E/06-permission-deny-auto.jsonl"      test/fixtures/opencode/06-tool-denied-invalid.jsonl
cp "$E/09-unknown-model.jsonl"             test/fixtures/opencode/09-unknown-model.jsonl
cp "$E/11-variant-high.jsonl"              test/fixtures/opencode/11-variant-high.jsonl
cp "$E/12-interrupted-turn.jsonl"          test/fixtures/opencode/12-interrupted-turn.jsonl
cp "$E/16-auth-failure-bogus-key.jsonl"    test/fixtures/opencode/16-api-error-401.jsonl
cp "$E/18-write-outside-dir-no-auto.jsonl" test/fixtures/opencode/18-auto-rejected-write.jsonl
cp "$E/22-task-deny-roster.jsonl"          test/fixtures/opencode/22-task-deny-roster.jsonl
cp "$E/23-bash-pattern-deny-echo.jsonl"    test/fixtures/opencode/23-rule-denied-bash.jsonl
cp "$E/24c-configured-cost-reasoning.jsonl" test/fixtures/opencode/24c-priced-reasoning.jsonl
cp "$E/34-paid-provider-cost.jsonl"        test/fixtures/opencode/34-paid-provider-cost.jsonl
cp "$E/14-export-session-03.json"          test/fixtures/opencode/export-session.json
cp "$E/models-verbose-after-provider-change.txt" test/fixtures/opencode/models-verbose.txt
cp "$E/auth-list.txt"                      test/fixtures/opencode/auth-list.txt
```

A sintética, `test/fixtures/opencode/quota-429.synthetic.jsonl` (uma linha, a forma do 16 com `statusCode` 429; a mensagem é inventada e o nome do ficheiro di-lo):

```json
{"type":"error","timestamp":1789224300390,"sessionID":"ses_synthetic429aaaaaaaaaaaaaaaa","error":{"name":"APIError","data":{"message":"Rate limit reached for this model. Please retry after 20 seconds.","statusCode":429,"isRetryable":true,"responseHeaders":{"content-type":"application/json","retry-after":"20"}}}}
```

- [ ] **Step 2: Escrever o teste do stand-in, e vê-lo falhar**

`tests/test_fake_opencode.py`:

```python
"""test/fake-opencode stands in for the OpenCode CLI in the e2e suite and the
selftest. A stand-in that emits a shape the real CLI never emitted would make
those suites green over nothing, so this pins its output to the measured
shapes (test/fixtures/opencode/) in every mode."""
import json
import os
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FAKE = REPO / "test" / "fake-opencode"
FIX = REPO / "test" / "fixtures" / "opencode"


def run(args, env=None, cwd=None):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run([str(FAKE)] + args, env=e, cwd=cwd, capture_output=True,
                          text=True, timeout=30, stdin=subprocess.DEVNULL)


def events(text):
    return [json.loads(ln) for ln in text.splitlines() if ln.strip()]


def test_version_models_and_auth_answer_like_the_cli():
    assert run(["--version"]).stdout.strip() == "1.18.30"
    ids = run(["models"]).stdout.split()
    assert "opencode/big-pickle" in ids and "pdm_ai/glm-5.3-flash" in ids
    assert "pdm_ai/openai/gpt-oss-120b" in ids          # a slash inside the model id
    verbose = run(["models", "--verbose"]).stdout
    assert verbose == (FIX / "models-verbose.txt").read_text()
    assert run(["models"], env={"FAKE_OPENCODE_NO_MODELS": "1"}).stdout.strip() == ""
    auth = run(["auth", "list"]).stdout
    assert "0 credentials" in auth


def test_a_complete_run_has_the_measured_shape(tmp_path):
    p = run(["run", "--format", "json", "--pure", "--auto", "-m", "opencode/big-pickle",
             "--dir", str(tmp_path), "--", "do the thing"],
            env={"FAKE_SESSION": "ses_test0001", "FAKE_ARGV_OUT": str(tmp_path / "argv"),
                 "FAKE_DIR_OUT": str(tmp_path / "dir"), "FAKE_CONFIG_OUT": str(tmp_path / "cfg"),
                 "OPENCODE_CONFIG_CONTENT": '{"share":"disabled"}'})
    assert p.returncode == 0 and p.stderr == ""
    evs = events(p.stdout)
    assert [e["type"] for e in evs] == ["step_start", "tool_use", "step_finish", "step_start", "text", "step_finish"]
    assert all(e["sessionID"] == "ses_test0001" for e in evs)
    assert evs[1]["part"]["tool"] == "bash" and evs[1]["part"]["state"]["status"] == "completed"
    assert evs[2]["part"]["reason"] == "tool-calls" and evs[-1]["part"]["reason"] == "stop"
    assert evs[-1]["part"]["tokens"] == {"total": 13767, "input": 65, "output": 6, "reasoning": 0,
                                         "cache": {"write": 0, "read": 13696}}
    assert evs[-1]["part"]["cost"] == 0
    assert evs[4]["part"]["text"] == "RUN COMPLETE: nothing needed doing."
    assert (tmp_path / "argv").read_text().splitlines()[0] == "ARGC\t11"
    assert (tmp_path / "dir").read_text().strip() == str(tmp_path)
    assert (tmp_path / "cfg").read_text().strip() == '{"share":"disabled"}'


def test_a_cost_per_step_is_reported_when_asked(tmp_path):
    p = run(["run", "--format", "json", "-m", "pdm_ai/glm-5.3-flash", "--dir", str(tmp_path), "--", "x"],
            env={"FAKE_COST": "0.0002"})
    finishes = [e for e in events(p.stdout) if e["type"] == "step_finish"]
    assert [e["part"]["cost"] for e in finishes] == [0.0002, 0.0002]


def test_the_failure_modes_match_the_measured_events(tmp_path):
    base = ["run", "--format", "json", "-m", "opencode/big-pickle", "--dir", str(tmp_path), "--", "x"]
    err = run(base, env={"FAKE_MODE": "error"})
    assert err.returncode == 1
    ev = events(err.stdout)
    assert len(ev) == 1 and ev[0]["type"] == "error" and ev[0]["error"]["name"] == "UnknownError"
    quota = run(base, env={"FAKE_MODE": "quota"})
    assert quota.returncode == 1
    ev = events(quota.stdout)
    assert ev[0]["error"]["name"] == "APIError" and ev[0]["error"]["data"]["statusCode"] == 429
    rej = run(base, env={"FAKE_MODE": "reject"})
    assert rej.returncode == 0
    ev = events(rej.stdout)
    assert [e["type"] for e in ev] == ["step_start", "tool_use", "step_finish"]
    assert ev[1]["part"]["state"]["status"] == "error"
    assert ev[1]["part"]["state"]["error"].startswith("The user rejected permission")
    assert ev[2]["part"]["reason"] == "tool-calls"          # the turn died there
    assert "auto-rejecting" in rej.stderr
    den = run(base, env={"FAKE_MODE": "deny"})
    assert den.returncode == 0
    ev = events(den.stdout)
    assert ev[1]["part"]["state"]["error"].startswith("The user has specified a rule which prevents")
    assert ev[-1]["part"]["reason"] == "stop"               # the turn went on


def test_export_names_the_model_that_ran(tmp_path):
    p = run(["export", "ses_test0002"], env={"FAKE_RAN_MODEL": "pdm_ai/glm-5.3-flash-real"})
    assert p.returncode == 0
    doc = json.loads(p.stdout)
    assert doc["info"]["id"] == "ses_test0002"
    assert doc["info"]["model"] == {"id": "glm-5.3-flash-real", "providerID": "pdm_ai", "variant": "default"}
    assert p.stderr.strip() == "Exporting session: ses_test0002"


def test_the_undeclared_and_dirty_endings(tmp_path):
    base = ["run", "--format", "json", "-m", "opencode/big-pickle", "--dir", str(tmp_path), "--", "x"]
    und = events(run(base, env={"FAKE_MODE": "undeclared"}).stdout)
    assert und[4]["part"]["text"] == "I did some work."
    run(base, env={"FAKE_MODE": "dirty"}, cwd=tmp_path)
    assert (tmp_path / "agent-left-this.txt").exists()
```

Correr: `python3.13 -m pytest tests/test_fake_opencode.py -p no:cacheprovider -q`
Esperado: FAIL (o stand-in não existe: `FileNotFoundError`).

- [ ] **Step 3: Escrever `test/fake-opencode`**

```bash
#!/usr/bin/env bash
# A stand-in for the OpenCode CLI (`opencode`), emitting the JSON shapes
# measured on opencode-ai 1.18.30 -- test/fixtures/opencode/ is the evidence
# -- so an OpenCode run can be driven end to end offline. Same caveat as
# test/fake-claude and test/fake-codex: unless FAKE_ARGV_OUT is set this never
# reads "$@" past the subcommand, so a green run proves nothing about the
# launch line; the e2e scenarios that read one back are the evidence.
#
#   FAKE_SESSION            the sessionID on every event (a resume keeps it)
#   FAKE_MODE               complete | undeclared | dirty | hang | reject | deny | error | quota
#   FAKE_ARGV_OUT           record the argv, one line per argument, "<n><TAB><first line>", plus "ARGC<TAB><n>"
#   FAKE_PROMPT_OUT         record the last argument (the prompt) WHOLE
#   FAKE_CONFIG_OUT         record the OPENCODE_CONFIG_CONTENT the launch carried (the permission block)
#   FAKE_DIR_OUT            record the value of --dir (the run's cwd; a resume MUST carry the session's)
#   FAKE_COST               the `cost` of every step_finish (default 0: the Zen free models, measured)
#   FAKE_RAN_MODEL          what `export` reports as the model that ran (default opencode/big-pickle-real)
#   FAKE_OPENCODE_NO_MODELS set to make `models` print nothing: a machine with no usable provider
#   FAKE_SKIP_PREPARE       set to skip `security prepare` inside a security run (see the hook below)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
FIX="$HERE/fixtures/opencode"

case "${1:-}" in
  --version) echo "1.18.30"; exit 0 ;;
  models)
    [ -z "${FAKE_OPENCODE_NO_MODELS:-}" ] || exit 0
    case " $* " in
      *" --verbose "*) cat "$FIX/models-verbose.txt" ;;
      *) grep -E '^[A-Za-z0-9_-]+/' "$FIX/models-verbose.txt" ;;   # the header lines only: provider/model
    esac
    exit 0 ;;
  auth) cat "$FIX/auth-list.txt"; exit 0 ;;                        # auth list: the box, ANSI colours and all
  export)
    sid="${2:-}"
    ran="${FAKE_RAN_MODEL:-opencode/big-pickle-real}"
    echo "Exporting session: $sid" >&2
    printf '{"info":{"id":"%s","slug":"fake","projectID":"global","directory":"%s","title":"fake","agent":"build","model":{"id":"%s","providerID":"%s","variant":"default"},"version":"1.18.30","cost":0,"tokens":{"input":11974,"output":49,"reasoning":0,"cache":{"read":15488,"write":0}},"permission":[],"time":{"created":1789223554730,"updated":1789223564719}},"messages":[]}\n' \
      "$sid" "$PWD" "${ran#*/}" "${ran%%/*}"
    exit 0 ;;
  run) ;;
  *) echo "fake-opencode: unexpected invocation: $*" >&2; exit 2 ;;
esac

if [ -n "${FAKE_ARGV_OUT:-}" ]; then
  { printf 'ARGC\t%s\n' "$#"
    n=0
    for a in "$@"; do n=$((n + 1)); printf '%s\t%s\n' "$n" "${a%%$'\n'*}"; done
  } > "$FAKE_ARGV_OUT"
fi
if [ -n "${FAKE_PROMPT_OUT:-}" ]; then
  last=""; for a in "$@"; do last="$a"; done
  printf '%s' "$last" > "$FAKE_PROMPT_OUT"
fi
[ -z "${FAKE_CONFIG_OUT:-}" ] || printf '%s\n' "${OPENCODE_CONFIG_CONTENT:-}" > "$FAKE_CONFIG_OUT"
# --dir is the run's cwd (measured 07); the real CLI chdirs there and dies
# when it does not exist (29). The stand-in does the same, so a dirty run's
# file lands where the engine will look for it.
dir=""; prev=""
for a in "$@"; do [ "$prev" = "--dir" ] && dir="$a"; prev="$a"; done
[ -z "${FAKE_DIR_OUT:-}" ] || printf '%s\n' "$dir" > "$FAKE_DIR_OUT"
if [ -n "$dir" ]; then
  cd "$dir" 2>/dev/null || { printf '\033[91m\033[1mError: \033[0mFailed to change directory to %s\n' "$dir" >&2; exit 1; }
fi

sid="${FAKE_SESSION:-ses_fake000000000000000000000}"
mode="${FAKE_MODE:-complete}"
cost="${FAKE_COST:-0}"
# A SECURITY RUN'S FIRST COMMAND, as test/fake-claude does it -- for a launch
# WITHOUT the opencode platform marker only. On opencode the engine runs
# `security prepare` itself before it launches the CLI (prepare_inline is an
# anthropic-only capability), and every launch it makes carries
# AL_PLATFORM=opencode, so the hook is skipped there.
if [ -n "${AL_SECURITY_ANALYSIS_ID:-}" ] && [ -z "${FAKE_SKIP_PREPARE:-}" ] \
   && [ "${AL_PLATFORM:-}" != "opencode" ]; then
  "$HERE/../bin/agentloop" security prepare \
    --analysis "$AL_SECURITY_ANALYSIS_ID" --root "$PWD" --offline >/dev/null 2>&1 || true
fi

ev() { # ev <type> <part-json> -- one event line, the measured envelope
  printf '{"type":"%s","timestamp":1789223561615,"sessionID":"%s","part":%s}\n' "$1" "$sid" "$2"
}
step_start()  { ev step_start '{"id":"prt_fake_start","messageID":"msg_fake","sessionID":"'"$sid"'","type":"step-start"}'; }
step_finish() { # step_finish <reason> <input> <output> <reasoning> <cache-read>
  ev step_finish '{"id":"prt_fake_finish","reason":"'"$1"'","messageID":"msg_fake","sessionID":"'"$sid"'","type":"step-finish","tokens":{"total":'"$(( $2 + $3 + $4 + $5 ))"',"input":'"$2"',"output":'"$3"',"reasoning":'"$4"',"cache":{"write":0,"read":'"$5"'}},"cost":'"$cost"'}'
}
text() { ev text '{"id":"prt_fake_text","messageID":"msg_fake","sessionID":"'"$sid"'","type":"text","text":"'"$1"'","time":{"start":1789223564692,"end":1789223564706}}'; }

case "$mode" in
  error)   # measured 09: an unknown model or provider; the reason is only in the logs
    printf '{"type":"error","timestamp":1789223950570,"sessionID":"%s","error":{"name":"UnknownError","data":{"message":"Unexpected server error. Check server logs for details.","ref":"err_fake0001"}}}\n' "$sid"
    exit 1 ;;
  quota)   # the shape of measurement 16 with the status of a rate limit (synthetic)
    printf '{"type":"error","timestamp":1789224300390,"sessionID":"%s","error":{"name":"APIError","data":{"message":"Rate limit reached for this model. Please retry after 20 seconds.","statusCode":429,"isRetryable":true,"responseHeaders":{"retry-after":"20"}}}}\n' "$sid"
    exit 1 ;;
  reject)  # measured 04/18: an `ask` auto-rejected without --auto ends the turn
    printf '\033[93m\033[1m! \033[0mpermission requested: bash (ls); auto-rejecting\n' >&2
    step_start
    ev tool_use '{"type":"tool","tool":"bash","callID":"call_fake_reject","state":{"status":"error","input":{"command":"ls"},"error":"The user rejected permission to use this specific tool call.","time":{"start":1789223581861,"end":1789223581881}},"id":"prt_fake_tool","sessionID":"'"$sid"'","messageID":"msg_fake"}'
    step_finish tool-calls 5 44 0 13696
    exit 0 ;;
esac

step_start
if [ "$mode" = deny ]; then   # measured 23: a rule denies the call and the turn goes on
  ev tool_use '{"type":"tool","tool":"bash","callID":"call_fake_deny","state":{"status":"error","input":{"command":"echo hello"},"error":"The user has specified a rule which prevents you from using this specific tool call. Here are some of the relevant rules [{\"permission\":\"*\",\"action\":\"allow\",\"pattern\":\"*\"},{\"permission\":\"bash\",\"pattern\":\"echo *\",\"action\":\"deny\"}]","time":{"start":1789224696156,"end":1789224696182}},"id":"prt_fake_tool","sessionID":"'"$sid"'","messageID":"msg_fake"}'
else                          # measured 03: bash ran and answered
  ev tool_use '{"type":"tool","tool":"bash","callID":"call_fake_ls","state":{"status":"completed","input":{"command":"ls"},"output":"README\n","metadata":{"output":"README\n","exit":0,"truncated":false},"title":"ls","time":{"start":1789223562190,"end":1789223562227}},"id":"prt_fake_tool","sessionID":"'"$sid"'","messageID":"msg_fake"}'
fi
step_finish tool-calls 11909 43 0 1792
step_start
case "$mode" in
  dirty)
    echo "the agent was here" > agent-left-this.txt
    result="RUN COMPLETE: made a change and did not push it." ;;
  undeclared) result="I did some work." ;;
  hang)
    # BECOME the sleep, as fake-codex does: the engine's TERM reaches the process
    # that holds the FIFO's write end, so the normalizer sees EOF at once.
    exec sleep 600 ;;
  deny) result="attempted" ;;
  *) result="RUN COMPLETE: nothing needed doing." ;;
esac
text "$result"
step_finish stop 65 6 0 13696
exit 0
```

`chmod +x test/fake-opencode`.

- [ ] **Step 4: Correr o teste do stand-in**

Correr: `python3.13 -m pytest tests/test_fake_opencode.py -p no:cacheprovider -q`
Esperado: `6 passed`.

Se `ARGC\t11` falhar, contar: `run --format json --pure --auto -m opencode/big-pickle --dir <d> -- do the thing` são 11 argumentos depois do nome do binário. O `ARGC` é `$#` visto pelo stand-in, que inclui `run`.

- [ ] **Step 5: Abrir a entrada do CHANGELOG**

Em `CHANGELOG.md`, sob `## [Unreleased]` → `### Added`, **acima** da entrada *Settings › Platforms*, uma entrada nova que as tarefas seguintes alargam com sub-pontos:

```markdown
- **The OpenCode engine: a job, a project and a project's `security` block
  can run on the `opencode` platform.** The third platform arrives the way
  the second one did: measured first (`docs/superpowers/specs/2026-09-12-opencode-measurements/`,
  35 runs of opencode-ai 1.18.30), then translated at the boundary
  (`bin/platforms/opencode_stream.py`) so that no reader in the scheduler
  learns a third dialect. What it cost to not have it: a job that named
  `opencode` was refused at launch, and the models an operator had already
  configured in that CLI (providers with their own keys, the free Zen
  models) were out of reach of every job.
  - The stand-in and the fixtures: `test/fake-opencode` emits the measured
    shapes (a complete run, an undeclared ending, a dirty tree, a hang, an
    auto-rejected permission, a rule denial, an unknown model, a rate
    limit) and answers `--version`, `models`, `auth list` and `export`;
    `test/fixtures/opencode/` holds the measurements the tests read.
```

- [ ] **Step 6: Commit**

```bash
/usr/bin/git add test/fixtures/opencode test/fake-opencode tests/test_fake_opencode.py CHANGELOG.md
/usr/bin/git commit -m "test(opencode): the measured fixtures and the OpenCode stand-in

test/fake-opencode emits the shapes measured on opencode-ai 1.18.30 (a
complete run, an undeclared ending, a dirty tree, a hang, an auto-rejected
permission, a rule denial, an unknown model, a rate limit) and answers
--version, models, auth list and export, recording the argv, the prompt,
the --dir and the OPENCODE_CONFIG_CONTENT it was launched with. The
fixtures under test/fixtures/opencode/ are the measurements themselves,
so nothing the tests read was written from memory.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
/usr/bin/git push
```

O `selftest` continua a 730/0 (nada em `bin/` mudou; o CHANGELOG é mais novo do que o commit de `test/`). Correr as quatro suites na mesma.

---

### Task 2: O normalizador `bin/platforms/opencode_stream.py` e os seus testes

**Files:**
- Create: `bin/platforms/opencode_stream.py`
- Create: `tests/test_opencode_stream.py`
- Modify: `CHANGELOG.md` (um sub-ponto)

**Interfaces:**
- Consumes: `test/fixtures/opencode/*` (T1); `config/models.json` com um bloco `opencode` da forma que T3 escreve (`{"opencode":{"models":[{"id":"provider/model","priced":true|false,…}]}}`); `config/pricing.json` com um bloco `opencode` (`{"opencode":{"<provider/model>":{"input","cached_input","output","cache_write"}}}`, T8).
- Produces: o executável `python3 -u bin/platforms/opencode_stream.py --model M --permission P --cwd D [--catalog config/models.json] [--pricing config/pricing.json] [--raw-out F]`, stdin → stdout; a classe `Normalizer(model, permission, cwd, priced, price)` com `feed(event) -> [events]` e `finish() -> [events]`; as funções `load_price(path, model)`, `catalog_priced(path, model)`, `tokens_of(part)`, `estimate(tokens, price)`, `canonical_name(tool)`, `denial_of(state)`. O `result` canónico com `platform: "opencode"`, `cost_basis`, `tokens`, `usage`, `permission_denials`, `api_error_status`, lido por `run_job` (T5) sem mudança.

- [ ] **Step 1: Escrever os testes, e vê-los falhar**

`tests/test_opencode_stream.py`:

```python
"""The OpenCode -> stream-json normalizer, tested on the measured fixtures.

Every fixture under test/fixtures/opencode/ is a real `opencode run --format
json` run captured on 2026-09-12 (opencode-ai 1.18.30), except the one whose
name says `synthetic`. The normalizer is pure: feed() takes one OpenCode event
and returns the canonical events it becomes, so these tests drive it
in-process; two tests drive the CLI itself, because the FIFO launch in run_job
only ever sees that -- and because the watchdog's empty-stream rule now makes
"the first line is out at once" a matter of life and death for a run.
"""
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
NORM = REPO / "bin" / "platforms" / "opencode_stream.py"
FIX = REPO / "test" / "fixtures" / "opencode"

_spec = importlib.util.spec_from_file_location("opencode_stream", NORM)
ocs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ocs)

PRICE = {"input": 1.0, "cached_input": 0.5, "output": 2.0, "cache_write": 0.25}
SESSION_03 = "ses_f69f73155ffeAHgrtVv1sVFbr7"


def events_of(name):
    out = []
    for line in (FIX / name).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:  # noqa: BLE001
            continue
    return out


def normalize(name=None, events=None, priced=False, price=None, model="opencode/big-pickle",
              permission="full-access"):
    n = ocs.Normalizer(model, permission, "/tmp/x", priced, price)
    out = []
    for ev in (events if events is not None else events_of(name)):
        out.extend(n.feed(ev))
    out.extend(n.finish())
    return out


def as_text(events):
    return "\n".join(json.dumps(e) for e in events) + "\n"


def blocks(out, kind, role):
    return [b for e in out if e["type"] == role for b in e["message"]["content"] if b["type"] == kind]


# ------------------------------------------------------------ the shape

def test_the_first_line_is_the_init_event_carrying_the_session_id():
    out = normalize("03-tool-use.jsonl")
    first = out[0]
    assert first["type"] == "system" and first["subtype"] == "init"
    assert first["session_id"] == SESSION_03
    assert first["model"] == "opencode/big-pickle"      # what was ASKED for
    assert first["platform"] == "opencode"
    assert first["permissionMode"] == "full-access"
    assert first["cwd"] == "/tmp/x" and first["tools"] == []


def test_a_lone_step_start_already_produces_the_init_line():
    # The watchdog kills a run whose stream is still EMPTY after the stall
    # window. step_start is the first thing the CLI writes, and it arrives
    # only when the model starts answering -- so it must reach the file at
    # once, not wait for a completed tool or a closed step.
    n = ocs.Normalizer("m", "full-access", "/", False, None)
    out = n.feed(events_of("03-tool-use.jsonl")[0])
    assert len(out) == 1 and out[0]["subtype"] == "init" and out[0]["session_id"] == SESSION_03


def test_a_finished_turn_ends_in_a_success_result_summing_every_step():
    out = normalize("03-tool-use.jsonl")
    last = out[-1]
    assert last["type"] == "result"
    assert last["subtype"] == "success" and last["is_error"] is False
    assert last["session_id"] == SESSION_03 and last["platform"] == "opencode"
    assert last["result"] == "done"                     # the last text part
    assert last["num_turns"] == sum(1 for e in out if e["type"] == "assistant")
    assert last["permission_denials"] == []
    # two steps: 11909+65 input, 43+6 output, 1792+13696 cached, 0 reasoning
    assert last["tokens"] == {"input": 11974, "cached": 15488, "cache_write": 0, "output": 49, "reasoning": 0}
    assert last["usage"] == {"input_tokens": 11974, "cache_read_input_tokens": 15488,
                             "cache_creation_input_tokens": 0, "output_tokens": 49}
    assert last["api_error_status"] is None


def test_a_tool_call_becomes_a_bash_tool_use_and_its_result_at_once():
    out = normalize("03-tool-use.jsonl")
    uses, results = blocks(out, "tool_use", "assistant"), blocks(out, "tool_result", "user")
    assert uses == [{"type": "tool_use", "id": "call_99041d057e2b48ccb4af895f", "name": "Bash",
                     "input": {"command": "ls"}}]
    assert results == [{"type": "tool_result", "tool_use_id": "call_99041d057e2b48ccb4af895f",
                        "content": "a.txt\nb.txt\n", "is_error": False}]
    # the two come out of ONE event, in order, tool_use first
    kinds = [(e["type"], e["message"]["content"][0]["type"]) for e in out[1:3]]
    assert kinds == [("assistant", "tool_use"), ("user", "tool_result")]


def test_tool_names_are_the_claude_ones_and_unknown_names_pass_through():
    out = normalize("02-tool-use-bash-and-read.jsonl")
    names = [b["name"] for b in blocks(out, "tool_use", "assistant")]
    assert names == ["Bash", "Read"]
    read = [b for b in blocks(out, "tool_use", "assistant") if b["name"] == "Read"][0]
    assert read["input"] == {"filePath": "/tmp/probe/p/a.txt"}
    assert ocs.canonical_name("task") == "Task" and ocs.canonical_name("webfetch") == "WebFetch"
    assert ocs.canonical_name("invalid") == "invalid" and ocs.canonical_name("mcp_thing") == "mcp_thing"


def test_the_server_timeline_draws_the_command(srv):
    turns = srv.parse_turns_text(as_text(normalize("03-tool-use.jsonl")))
    tools = [t for turn in turns for t in turn["tools"]]
    assert tools and tools[0]["tool"] == "Bash" and "ls" in tools[0]["hint"]


def test_a_truncated_copy_still_salvages_session_and_turns(srv):
    text = as_text(normalize("03-tool-use.jsonl"))
    last_text, turns, sess = srv._salvage_from_stream(text[: len(text) // 2])
    assert sess == SESSION_03 and turns >= 1


def test_reasoning_tokens_ride_beside_output_and_inside_usage():
    last = normalize("11-variant-high.jsonl", model="opencode/ling-3.0-flash-fin-free")[-1]
    assert last["tokens"]["output"] == 12 and last["tokens"]["reasoning"] == 15
    assert last["usage"]["output_tokens"] == 27          # output + reasoning: what the model generated
    assert last["tokens"]["input"] == 12225 and last["tokens"]["cached"] == 1920


def test_a_long_tool_output_is_cut_at_eight_kilobytes():
    ev = events_of("03-tool-use.jsonl")[1]
    ev["part"]["state"]["output"] = "x" * 20_000
    out = normalize(events=[events_of("03-tool-use.jsonl")[0], ev])
    content = blocks(out, "tool_result", "user")[0]["content"]
    assert len(content.encode()) < 9_000 and content.endswith("[truncated]")


def test_a_run_cut_off_before_its_final_step_emits_no_result():
    out = normalize("12-interrupted-turn.jsonl")      # step_start only: killed mid-tool
    assert out[-1]["type"] != "result"
    evs = [e for e in events_of("03-tool-use.jsonl") if not (e["type"] == "step_finish" and e["part"]["reason"] == "stop")]
    assert normalize(events=evs)[-1]["type"] != "result"


def test_only_one_result_is_ever_emitted_for_a_run():
    evs = events_of("01-trivial-turn.jsonl")
    out = normalize(events=evs + [evs[-1]])
    assert sum(1 for e in out if e["type"] == "result") == 1


def test_an_unknown_finish_reason_ends_the_run_as_an_error():
    evs = events_of("01-trivial-turn.jsonl")
    evs[-1]["part"]["reason"] = "length"
    last = normalize(events=evs)[-1]
    assert last["type"] == "result" and last["is_error"] is True
    assert last["subtype"] == "error_during_execution" and "length" in last["result"]


# ------------------------------------------------------------ denials

def test_a_rule_denial_is_a_permission_denial_and_the_turn_goes_on():
    out = normalize("23-rule-denied-bash.jsonl")
    last = out[-1]
    assert last["type"] == "result" and last["subtype"] == "success"   # the model answered "attempted"
    assert last["result"] == "attempted"
    assert last["permission_denials"] == [{"tool_name": "Bash", "tool_use_id": "call_2dedd6815de446afb9cc493d",
                                           "tool_input": {"command": "echo hello-from-bash ; whatever"}}]
    res = blocks(out, "tool_result", "user")[0]
    assert res["is_error"] is True and res["content"].startswith("The user has specified a rule")


def test_an_auto_rejected_ask_ends_the_run_as_tools_denied_at_eof():
    for name, tool in (("04-auto-rejected-ask.jsonl", "Bash"), ("18-auto-rejected-write.jsonl", "Write")):
        out = normalize(name)
        last = out[-1]
        assert last["type"] == "result" and last["is_error"] is True
        assert last["subtype"] == "error_during_execution"
        assert "rejected permission" in last["result"] and tool in last["result"]
        assert len(last["permission_denials"]) == 1 and last["permission_denials"][0]["tool_name"] == tool
        assert last["api_error_status"] is None


def test_a_tool_removed_from_the_roster_is_drawn_as_invalid_not_denied():
    out = normalize("06-tool-denied-invalid.jsonl")
    names = [b["name"] for b in blocks(out, "tool_use", "assistant")]
    assert names[0] == "invalid" and "Glob" in names
    assert out[-1]["permission_denials"] == []          # the model adapted; nothing was refused to it


def test_denial_of_reads_the_two_measured_phrases_and_nothing_else():
    assert ocs.denial_of({"status": "error", "error": "The user rejected permission to use this specific tool call."})
    assert ocs.denial_of({"status": "error", "error": "The user has specified a rule which prevents you from using this specific tool call. Here are some of the relevant rules []"})
    assert not ocs.denial_of({"status": "error", "error": "command not found"})
    assert not ocs.denial_of({"status": "completed", "output": "The user rejected permission"})


# ------------------------------------------------------------ failures

def test_an_unknown_model_is_an_error_result_with_no_status():
    out = normalize("09-unknown-model.jsonl")
    assert out[0]["subtype"] == "init"                  # the error event carries the session id
    last = out[-1]
    assert last["type"] == "result" and last["is_error"] is True
    assert last["subtype"] == "error_during_execution"
    assert last["api_error_status"] is None
    assert "Unexpected server error" in last["result"] and "err_001b5330" in last["result"]
    assert last["cost_basis"] == "none" and last["total_cost_usd"] is None
    assert last["usage"] == {"input_tokens": 0, "cache_read_input_tokens": 0,
                             "cache_creation_input_tokens": 0, "output_tokens": 0}


def test_an_api_error_carries_its_status_code():
    last = normalize("16-api-error-401.jsonl")[-1]
    assert last["type"] == "result" and last["is_error"] is True
    assert last["api_error_status"] == 401 and "Incorrect API key" in last["result"]


def test_a_rate_limit_carries_429():
    last = normalize("quota-429.synthetic.jsonl")[-1]
    assert last["api_error_status"] == 429 and last["is_error"] is True


# ------------------------------------------------------------ cost

def test_a_priced_catalog_model_reports_the_cli_cost():
    last = normalize("34-paid-provider-cost.jsonl", priced=True, model="pdm_ai/glm-5.3-flash")[-1]
    assert last["cost_basis"] == "reported"
    assert last["total_cost_usd"] == 0.000426176016
    assert last["tokens"] == {"input": 12800, "cached": 0, "cache_write": 0, "output": 3, "reasoning": 23}


def test_the_reported_cost_is_the_sum_of_every_step():
    evs = events_of("03-tool-use.jsonl")
    for e in evs:
        if e["type"] == "step_finish":
            e["part"]["cost"] = 0.0002
    last = normalize(events=evs, priced=True)[-1]
    assert last["cost_basis"] == "reported" and last["total_cost_usd"] == 0.0004


def test_an_unpriced_model_with_a_table_row_is_estimated_like_the_cli_does():
    last = normalize("24c-priced-reasoning.jsonl", priced=False, price=PRICE)[-1]
    # 11800 in, 32 out + 39 reasoning at the output price, 1856 cached
    expected = round((11800 * 1.0 + (32 + 39) * 2.0 + 1856 * 0.5 + 0 * 0.25) / 1_000_000, 6)
    assert last["cost_basis"] == "estimated" and last["total_cost_usd"] == expected


def test_the_catalog_price_wins_over_the_table():
    last = normalize("34-paid-provider-cost.jsonl", priced=True, price=PRICE, model="pdm_ai/glm-5.3-flash")[-1]
    assert last["cost_basis"] == "reported" and last["total_cost_usd"] == 0.000426176016


def test_zero_in_the_catalog_and_no_table_row_is_unknown_never_free():
    last = normalize("01-trivial-turn.jsonl", priced=False, price=None)[-1]
    assert last["cost_basis"] == "none" and last["total_cost_usd"] is None
    assert last["tokens"]["input"] == 14915             # the tokens are still reported


def test_a_manual_zero_row_is_an_estimated_free_run():
    zero = {"input": 0, "cached_input": 0, "output": 0, "cache_write": 0}
    last = normalize("01-trivial-turn.jsonl", priced=False, price=zero)[-1]
    assert last["cost_basis"] == "estimated" and last["total_cost_usd"] == 0.0


def test_load_price_and_catalog_priced_read_the_two_files(tmp_path):
    table = tmp_path / "pricing.json"
    table.write_text(json.dumps({"opencode": {
        "pdm_ai/x": {"input": 1, "cached_input": 0.1, "output": 2, "cache_write": 0},
        "pdm_ai/half": {"input": None, "cached_input": 0.1, "output": 2}}}))
    assert ocs.load_price(str(table), "pdm_ai/x") == {"input": 1.0, "cached_input": 0.1, "output": 2.0, "cache_write": 0.0}
    assert ocs.load_price(str(table), "pdm_ai/half") is None
    assert ocs.load_price(str(table), "absent") is None
    assert ocs.load_price(str(tmp_path / "nope.json"), "pdm_ai/x") is None
    catalog = tmp_path / "models.json"
    catalog.write_text(json.dumps({"opencode": {"models": [
        {"id": "pdm_ai/glm-5.3-flash", "priced": True}, {"id": "opencode/big-pickle", "priced": False}]}}))
    assert ocs.catalog_priced(str(catalog), "pdm_ai/glm-5.3-flash") is True
    assert ocs.catalog_priced(str(catalog), "opencode/big-pickle") is False
    assert ocs.catalog_priced(str(catalog), "nope/nope") is False
    assert ocs.catalog_priced(str(tmp_path / "missing.json"), "pdm_ai/glm-5.3-flash") is False


# ------------------------------------------------------------ the CLI

def test_the_cli_normalizes_stdin_and_copies_every_raw_line(tmp_path):
    raw_in = (FIX / "03-tool-use.jsonl").read_text() + "this line is not json\n"
    raw_out = tmp_path / "copy.raw"
    p = subprocess.run([sys.executable, "-u", str(NORM), "--model", "opencode/big-pickle",
                        "--permission", "full-access", "--cwd", "/tmp/x",
                        "--raw-out", str(raw_out)],
                       input=raw_in, capture_output=True, text=True, timeout=30)
    assert p.returncode == 0, p.stderr
    lines = [json.loads(ln) for ln in p.stdout.splitlines()]
    assert lines[0]["subtype"] == "init" and lines[-1]["type"] == "result"
    assert lines[-1]["cost_basis"] == "none"
    assert raw_out.read_text() == raw_in            # copied verbatim, bad line included
    assert p.stderr == ""


def test_the_cli_flushes_the_init_line_before_the_stream_ends(tmp_path):
    # Feed step_start alone, keep stdin OPEN, and read the first line back:
    # a normalizer that buffered would leave the file empty for the whole
    # run, and the watchdog would kill a live run at the stall window.
    first = events_of("03-tool-use.jsonl")[0]
    p = subprocess.Popen([sys.executable, "-u", str(NORM), "--model", "m", "--permission", "full-access",
                          "--cwd", "/"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        p.stdin.write(json.dumps(first) + "\n")
        p.stdin.flush()
        line = p.stdout.readline()                  # blocks for ever if nothing was flushed
        assert json.loads(line)["subtype"] == "init"
    finally:
        p.stdin.close()
        p.wait(timeout=10)
```

Correr: `python3.13 -m pytest tests/test_opencode_stream.py -p no:cacheprovider -q`
Esperado: FAIL na importação (`FileNotFoundError: bin/platforms/opencode_stream.py`).

- [ ] **Step 2: Escrever o normalizador**

`bin/platforms/opencode_stream.py`:

```python
#!/usr/bin/env python3
"""OpenCode `run --format json` events -> Claude Code stream-json, one line at
a time.

`opencode run --format json` prints one event per line: step_start, text,
tool_use (already completed), step_finish (tokens and cost per step), error.
Every reader in this scheduler -- the watchdog, turn_is_over, bind_session,
the classifier, the dashboard's Timeline and Terminal -- reads the stream-json
shape Claude Code emits. This filter turns the one into the other at the
boundary, so none of those readers learns a third dialect. It is the sibling
of openai_stream.py and solves the same problems the same way.

Pure and unbuffered: stdin in, stdout out, one canonical line per OpenCode
event that has a translation, flushed at once. Two readers depend on that
flush: the Terminal follows the file live, and the watchdog measures it --
including its new rule that a stream still EMPTY after the stall window is a
dead run. The first OpenCode event (step_start) arrives only when the model
starts answering, so the init line it becomes must reach the file the moment
it arrives, never after a completed tool or a closed step. Every raw line is
copied to --raw-out BEFORE anything is done with it, so a line that is not
JSON, or an event this filter has never seen, is copied and skipped.

The other two things it knows: the catalog (--catalog, config/models.json:
whether the model has a price, in which case the CLI's own per-step `cost`
is reported) and the price table (--pricing, config/pricing.json: the
operator's row, from which an unpriced model is estimated with the CLI's own
formula). Zero in the catalog is UNKNOWN, never free: measured, a provider
with no price configured lists the same zeros as a free model.
"""
import argparse
import json
import sys

OUTPUT_CAP = 8192               # bytes of a tool's output kept in a tool_result

# The tool names Claude Code uses, so the Timeline draws an OpenCode run the
# way it draws the other two (measured roster: 06, 22).
CANONICAL = {"bash": "Bash", "edit": "Edit", "write": "Write", "read": "Read", "glob": "Glob",
             "grep": "Grep", "list": "LS", "webfetch": "WebFetch", "websearch": "WebSearch",
             "task": "Task", "todowrite": "TodoWrite", "skill": "Skill"}

# The two denial phrases the CLI puts in `state.error` (measured 04/18 and 23).
REJECTED = "The user rejected permission"
RULED_OUT = "The user has specified a rule which prevents"


def canonical_name(tool):
    return CANONICAL.get(tool or "", tool or "tool")


def denial_of(state):
    """True when a tool's terminal state is one of the two measured denials."""
    if not isinstance(state, dict) or state.get("status") != "error":
        return False
    err = state.get("error")
    return isinstance(err, str) and (err.startswith(REJECTED) or err.startswith(RULED_OUT))


def load_price(path, model):
    """The per-1M row for `model` in the table's `opencode` block, or None: no
    file, no row, or a null in any of the three billed fields. `cache_write`
    may be absent (0). A row of ZEROS is a price (the operator declaring a
    free model), unlike a zero in the catalog."""
    try:
        with open(path, encoding="utf-8") as fh:
            table = json.load(fh)
    except Exception:  # noqa: BLE001 -- a missing or broken table is "no price"
        return None
    row = (table.get("opencode") or {}).get(model) if isinstance(table, dict) else None
    if not isinstance(row, dict):
        return None
    prices = {}
    for key in ("input", "cached_input", "output"):
        v = row.get(key)
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return None
        prices[key] = float(v)
    cw = row.get("cache_write", 0)
    prices["cache_write"] = float(cw) if isinstance(cw, (int, float)) and not isinstance(cw, bool) else 0.0
    return prices


def catalog_priced(path, model):
    """True when config/models.json's `opencode` catalog prices the model
    (`priced: true`, written by resolve_models_opencode when any of the four
    catalog prices is above zero)."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:  # noqa: BLE001
        return False
    block = data.get("opencode") if isinstance(data, dict) else None
    for m in (block or {}).get("models") or []:
        if isinstance(m, dict) and m.get("id") == model:
            return m.get("priced") is True
    return False


def _n(v):
    return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0


def tokens_of(part):
    """The five counters of a step_finish part, as ints, missing = 0."""
    t = part.get("tokens") if isinstance(part, dict) else None
    t = t if isinstance(t, dict) else {}
    cache = t.get("cache") if isinstance(t.get("cache"), dict) else {}
    return {"input": _n(t.get("input")), "cached": _n(cache.get("read")),
            "cache_write": _n(cache.get("write")), "output": _n(t.get("output")),
            "reasoning": _n(t.get("reasoning"))}


def estimate(tokens, price):
    """USD for the run at `price` (USD per 1,000,000 tokens), with the CLI's
    own formula (measured 24b, 24c, 34): `input` already excludes the cache,
    reasoning is billed at the output price, cached input at the cache price.
    None without a price."""
    if price is None:
        return None
    usd = (tokens["input"] * price["input"] + (tokens["output"] + tokens["reasoning"]) * price["output"]
           + tokens["cached"] * price["cached_input"] + tokens["cache_write"] * price["cache_write"])
    return round(usd / 1_000_000, 6)


class Normalizer:
    """One OpenCode event in, zero or more canonical events out."""

    def __init__(self, model, permission, cwd, priced, price):
        self.model, self.permission, self.cwd = model, permission, cwd
        self.priced, self.price = bool(priced), price
        self.session = ""
        self.inited = False
        self.assistant_events = 0   # what `result.num_turns` reports
        self.last_text = ""         # the last text part: `result.result`
        self.tokens = {"input": 0, "cached": 0, "cache_write": 0, "output": 0, "reasoning": 0}
        self.cost = 0.0             # the CLI's own per-step cost, summed
        self.steps = 0              # step_finish events seen
        self.last_reason = ""       # the last step_finish reason
        self.denials = []           # permission_denials on the final event
        self.done = False           # a result has been emitted

    # -- envelopes ---------------------------------------------------------
    def _msg(self, role, blocks):
        return {"type": "assistant" if role == "assistant" else "user",
                "message": {"role": role, "content": blocks},
                "session_id": self.session}

    def _assistant(self, blocks):
        self.assistant_events += 1
        return self._msg("assistant", blocks)

    def _init(self, ev):
        """The FIRST line, from the first event that names the session,
        whatever its type: session_from_stream reads five lines and stops,
        and the watchdog wants a byte the moment the CLI starts talking."""
        self.session = ev.get("sessionID") or ""
        self.inited = True
        return {"type": "system", "subtype": "init", "session_id": self.session,
                "model": self.model, "platform": "opencode",
                "permissionMode": self.permission, "cwd": self.cwd, "tools": []}

    # -- tools -------------------------------------------------------------
    def _tool(self, part):
        state = part.get("state") if isinstance(part.get("state"), dict) else {}
        name = canonical_name(part.get("tool"))
        call = part.get("callID") or part.get("id") or ""
        inp = state.get("input") if isinstance(state.get("input"), dict) else {}
        is_error = state.get("status") == "error"
        out = state.get("error") if is_error else state.get("output")
        out = out if isinstance(out, str) else ""
        if len(out.encode("utf-8")) > OUTPUT_CAP:
            out = out.encode("utf-8")[:OUTPUT_CAP].decode("utf-8", errors="ignore") + "\n...[truncated]"
        if denial_of(state):
            self.denials.append({"tool_name": name, "tool_use_id": call, "tool_input": inp})
        return [self._assistant([{"type": "tool_use", "id": call, "name": name, "input": inp}]),
                self._msg("user", [{"type": "tool_result", "tool_use_id": call,
                                    "content": out, "is_error": is_error}])]

    # -- the final event ---------------------------------------------------
    def _result(self, error=None):
        self.done = True
        base = {"type": "result", "session_id": self.session, "platform": "opencode",
                "num_turns": self.assistant_events, "permission_denials": list(self.denials),
                "usage": {"input_tokens": self.tokens["input"],
                          "cache_read_input_tokens": self.tokens["cached"],
                          "cache_creation_input_tokens": self.tokens["cache_write"],
                          "output_tokens": self.tokens["output"] + self.tokens["reasoning"]}}
        if error is None:
            cost, basis = self._cost()
            base.update({"subtype": "success", "is_error": False, "result": self.last_text,
                         "total_cost_usd": cost, "cost_basis": basis,
                         "tokens": dict(self.tokens), "api_error_status": None})
        else:
            msg, status = error
            base.update({"subtype": "error_during_execution", "is_error": True, "result": msg,
                         "total_cost_usd": None, "cost_basis": "none",
                         "tokens": dict(self.tokens) if self.steps else None,
                         "api_error_status": status})
        return base

    def _cost(self):
        """(total_cost_usd, cost_basis). The CLI's number when the catalog
        prices the model; the operator's table when it does not; unknown
        otherwise. A run with no step_finish at all has no tokens to price."""
        if not self.steps:
            return None, "none"
        if self.priced:
            return self.cost, "reported"        # the CLI's number, as it came: never rounded
        est = estimate(self.tokens, self.price)
        return (est, "estimated") if est is not None else (None, "none")

    # -- the feed ----------------------------------------------------------
    def feed(self, ev):
        out = []
        if not self.inited and ev.get("sessionID"):
            out.append(self._init(ev))
        kind = ev.get("type")
        part = ev.get("part") if isinstance(ev.get("part"), dict) else {}
        if kind == "text":
            text = part.get("text") or ""
            self.last_text = text
            out.append(self._assistant([{"type": "text", "text": text}]))
        elif kind == "tool_use":
            out.extend(self._tool(part))
        elif kind == "step_finish":
            self.steps += 1
            t = tokens_of(part)
            for k in self.tokens:
                self.tokens[k] += t[k]
            c = part.get("cost")
            if isinstance(c, (int, float)) and not isinstance(c, bool):
                self.cost += float(c)
            reason = part.get("reason") or ""
            self.last_reason = reason
            if reason == "stop" and not self.done:
                out.append(self._result())
            elif reason != "tool-calls" and not self.done:
                # Not measured (length, error, content-filter, ...): the model
                # stopped for a reason that is not "I am done".
                out.append(self._result(error=("the model stopped: " + (reason or "unknown"), None)))
        elif kind == "error" and not self.done:
            err = ev.get("error") if isinstance(ev.get("error"), dict) else {}
            data = err.get("data") if isinstance(err.get("data"), dict) else {}
            msg = data.get("message") if isinstance(data.get("message"), str) else (err.get("name") or "error")
            ref = data.get("ref")
            if isinstance(ref, str) and ref:
                msg += " (ref " + ref + ")"
            status = data.get("statusCode")
            status = status if isinstance(status, int) and not isinstance(status, bool) else None
            out.append(self._result(error=(msg, status)))
        # step_start and anything not seen yet: nothing beyond the init line
        return out

    def finish(self):
        """EOF. A turn that ended on an auto-rejected permission (measured 04,
        18: the last step closed on `tool-calls` and nothing followed) is an
        error that names the tool -- never a silent, result-less run the
        salvage would read as merely killed. Any other EOF without a result
        is left to the salvage path."""
        if self.done or not self.denials or self.last_reason != "tool-calls":
            return []
        d = self.denials[-1]
        msg = "the turn ended on a rejected permission: " + d["tool_name"]
        detail = d.get("tool_input") or {}
        if isinstance(detail, dict) and detail.get("command"):
            msg += " (" + str(detail["command"]) + ")"
        return [self._result(error=(msg, None))]


def main(argv=None):
    ap = argparse.ArgumentParser(description="OpenCode JSON on stdin -> stream-json on stdout")
    ap.add_argument("--model", required=True, help="the provider/model the run asked for")
    ap.add_argument("--permission", required=True, help="the run's permission_mode")
    ap.add_argument("--cwd", required=True, help="the run's working directory")
    ap.add_argument("--catalog", default="", help="config/models.json (whether the model is priced)")
    ap.add_argument("--pricing", default="", help="config/pricing.json (the operator's opencode rows)")
    ap.add_argument("--raw-out", default="", help="where every raw line is copied")
    args = ap.parse_args(argv)
    priced = catalog_priced(args.catalog, args.model) if args.catalog else False
    price = load_price(args.pricing, args.model) if args.pricing else None
    norm = Normalizer(args.model, args.permission, args.cwd, priced, price)
    raw = open(args.raw_out, "ab") if args.raw_out else None
    out = sys.stdout

    def emit(events):
        for e in events:
            out.write(json.dumps(e) + "\n")     # ASCII-safe whatever the locale
        out.flush()                             # the watchdog and the Terminal read the file live

    try:
        # Bytes in, so a locale with no UTF-8 (launchd's default) can neither
        # refuse a curly quote on the way in nor mangle the raw copy.
        for bline in sys.stdin.buffer:
            if raw is not None:
                raw.write(bline if bline.endswith(b"\n") else bline + b"\n")
                raw.flush()
            line = bline.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except Exception:  # noqa: BLE001 -- copied above, skipped here
                continue
            if isinstance(ev, dict):
                emit(norm.feed(ev))
        emit(norm.finish())
    finally:
        if raw is not None:
            raw.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

`chmod +x bin/platforms/opencode_stream.py`.

- [ ] **Step 3: Correr os testes**

Correr: `python3.13 -m pytest tests/test_opencode_stream.py -p no:cacheprovider -q`
Esperado: `28 passed`.

Notas para o implementador, caso um falhe:
- `test_a_finished_turn_ends_in_a_success_result_summing_every_step`: os números vêm do 03 (passo 1: 11909/43/1792, passo 2: 65/6/13696); `usage.output_tokens` é `output + reasoning`.
- `test_a_priced_catalog_model_reports_the_cli_cost`: o custo reportado é a soma dos `cost` **sem arredondar**; o `round(…, 6)` fica só na estimativa, como no irmão.
- `test_an_unknown_model_is_an_error_result_with_no_status`: o `error` traz `sessionID`, por isso o `init` sai primeiro; o `result` de erro leva `tokens: None` porque não houve `step_finish`.

- [ ] **Step 4: O CHANGELOG**

Sub-ponto na entrada *OpenCode engine*:

```markdown
  - The normalizer, `bin/platforms/opencode_stream.py`: the OpenCode events
    become the stream-json every reader here already speaks -- `text` an
    assistant message, a completed `tool_use` a tool_use and its result at
    once (Claude's tool names, so the Timeline draws `Bash` with the
    command), `step_finish` summed into one `result` with the tokens
    (reasoning apart from output, and inside `usage.output_tokens`), the
    two measured denial phrases into `permission_denials`, an `error` into
    an error result with its `statusCode`. The first line is out the
    moment the CLI's first event arrives, flushed, because the watchdog
    now reads an empty file as a dead run.
```

- [ ] **Step 5: Commit**

```bash
/usr/bin/git add bin/platforms/opencode_stream.py tests/test_opencode_stream.py CHANGELOG.md
/usr/bin/git commit -m "feat(opencode): the normalizer, OpenCode events to stream-json at the boundary

bin/platforms/opencode_stream.py is the sibling of openai_stream.py: pure,
unbuffered, one canonical line per OpenCode event, every raw line copied
first. A completed tool_use becomes a tool_use and its tool_result at once
under Claude's tool names; step_finish is summed into one result whose
tokens keep reasoning apart from output; the two measured denial phrases
become permission_denials, and a turn that died on an auto-rejected ask
ends as an error naming the tool instead of a result-less run. The cost
is the CLI's own when the catalog prices the model, the operator's table
when it does not, and unknown otherwise: zero in the catalog is never
read as free. The init line leaves on the first event, because the
watchdog's empty-stream rule turns a buffered first line into a killed
run.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
/usr/bin/git push
```

Correr as quatro suites: o selftest continua verde (o CHANGELOG é mais novo do que `bin/`); o pytest sobe para 552 + 6 + 28.

---

### Task 3: O catálogo OpenCode, a prontidão, e `run_bounded`

**Files:**
- Modify: `bin/agentloop` (novo bloco `# --- the OpenCode catalog ---` junto ao bloco `# --- the OpenAI catalog, read side ---` (~linha 1900); `platform_check` (~1483); `platform_catalog_ids`, `platform_models_json` (~1553); `cmd_resolve_models` (~9469); `models_stale` (~3204); `opencode_catalog_ensure`; a nova `run_bounded` junto a `tree_cpu_seconds` (~2268); selftest)
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `test/fake-opencode` (T1: `models --verbose`, `models`, `auth list`, `--version`, `FAKE_OPENCODE_NO_MODELS`); `test/fixtures/opencode/models-verbose.txt`.
- Produces: o bloco `opencode` de `config/models.json` (`{at, source, version, models:[{id, provider, name, cost{input,output,cache_read,cache_write}, priced, context, output_limit, variants[], tools, reasoning, status}]}` ou `{at, available:false, reason}`, mais `stale_at`/`stale_reason` num refresh falhado); as funções `opencode_catalog_available`, `opencode_catalog_ids`, `opencode_catalog_visible`, `opencode_catalog_efforts <id>`, `opencode_catalog_all_efforts`, `opencode_catalog_priced <id>` (rc), `opencode_catalog_tools <id>` (rc 0 salvo `tools: false`), `resolve_models_opencode`, `opencode_catalog_ensure`, `run_bounded <secs> <cmd…>` (rc 124 no tecto); `platform_check opencode` com `ready`, `account` ("N credentials · providers: a, b") e `reason`; `agentloop resolve-models opencode`; `platform_catalog_ids opencode`; `platform_models_json opencode`. A capacidade `supported` de `platform_check` continua `false` até T4 (o registo só muda lá): esta tarefa deixa o catálogo e a prontidão prontos por baixo de um cartão que ainda diz *planned*.

- [ ] **Step 1: Os casos de selftest, e vê-los falhar**

No `cmd_selftest`, logo a seguir ao bloco `echo "platform_check() — …"` que termina com a linha `[ "$(platform_check martian | "$JQ" -r .reason)" = "unknown platform martian" ] && ok …` (~linha 3736), inserir:

```bash
  echo "the OpenCode catalog — resolve_models_opencode over the stand-in, and the readers"
  local _oc; _oc="$tmp/oc"; mkdir -p "$_oc/config" "$_oc/data"
  ( CONFIG_DIR="$_oc/config"; MODELS_FILE="$_oc/config/models.json"; AGENTLOOP_OPENCODE_BIN="$BASE_DIR/test/fake-opencode"
    resolve_models_opencode >/dev/null 2>&1 ) ; want "resolve-models opencode exits 0 over the stand-in" 0 $?
  "$JQ" -e '.opencode.models | length == 13' "$_oc/config/models.json" >/dev/null 2>&1 \
    && ok "the block carries the 13 models the stand-in lists" || bad "opencode block: $("$JQ" -c '.opencode | {at, source, n: (.models | length)}' "$_oc/config/models.json")"
  "$JQ" -e '.opencode.models[] | select(.id == "pdm_ai/openai/gpt-oss-120b") | .provider == "pdm_ai" and .name == "openai/gpt-oss-120b"' \
    "$_oc/config/models.json" >/dev/null 2>&1 && ok "a slash inside the model id splits at the FIRST slash" || bad "gpt-oss row: $("$JQ" -c '.opencode.models[] | select(.id | test("gpt-oss"))' "$_oc/config/models.json")"
  "$JQ" -e '.opencode.models[] | select(.id == "pdm_ai/glm-5.3-flash") | .priced == true and .cost.input == 0.033011 and .cost.output == 0.139816 and .tools == true and .reasoning == true and (.variants == ["max","high","non-think"]) and .context == 197144' \
    "$_oc/config/models.json" >/dev/null 2>&1 && ok "a priced model carries its price, its variants, its tools and its context" || bad "glm row: $("$JQ" -c '.opencode.models[] | select(.id == "pdm_ai/glm-5.3-flash")' "$_oc/config/models.json")"
  "$JQ" -e '.opencode.models[] | select(.id == "opencode/big-pickle") | .priced == false and .variants == [] and .status == "active"' \
    "$_oc/config/models.json" >/dev/null 2>&1 && ok "a zero-cost model is UNPRICED, not free, and a model without variants offers no effort" || bad "big-pickle row: $("$JQ" -c '.opencode.models[] | select(.id == "opencode/big-pickle")' "$_oc/config/models.json")"
  [ "$("$JQ" -r '.opencode.source, .opencode.version' "$_oc/config/models.json" | tr '\n' '|')" = "opencode models --verbose|1.18.30|" ] \
    && ok "the block says where it came from and which CLI answered" || bad "source/version: $("$JQ" -c '.opencode | {source, version}' "$_oc/config/models.json")"
  ( MODELS_FILE="$_oc/config/models.json"
    [ "$(opencode_catalog_ids | grep -c .)" = "13" ] || exit 1
    [ "$(opencode_catalog_visible | head -1)" = "opencode/big-pickle" ] || exit 2
    [ "$(opencode_catalog_efforts pdm_ai/glm-5.3-flash | tr '\n' ' ')" = "max high non-think " ] || exit 3
    [ -z "$(opencode_catalog_efforts opencode/big-pickle)" ] || exit 4
    opencode_catalog_priced pdm_ai/glm-5.3-flash || exit 5
    opencode_catalog_priced opencode/big-pickle && exit 6
    opencode_catalog_tools pdm_ai/glm-5.3-flash || exit 7
    opencode_catalog_all_efforts | grep -qx 'non-think' || exit 8
    exit 0 ); want "the readers: ids, visible, efforts per model, priced, tools, the union of efforts" 0 $?
  ( CONFIG_DIR="$_oc/config"; MODELS_FILE="$_oc/config/models.json"; AGENTLOOP_OPENCODE_BIN="$BASE_DIR/test/fake-opencode"; FAKE_OPENCODE_NO_MODELS=1; export FAKE_OPENCODE_NO_MODELS
    resolve_models_opencode >/dev/null 2>&1 )
  "$JQ" -e '.opencode.models | length == 13 and (.opencode.stale_reason | length) > 0' "$_oc/config/models.json" >/dev/null 2>&1 \
    && ok "a refresh that lists nothing keeps the catalog it had, stamped stale" || bad "after an empty refresh: $("$JQ" -c '.opencode | {n: (.models | length), stale_reason}' "$_oc/config/models.json")"
  ( CONFIG_DIR="$_oc/config"; MODELS_FILE="$_oc/config/models.json"; AGENTLOOP_OPENCODE_BIN="$BASE_DIR/test/fake-opencode"
    resolve_models_opencode >/dev/null 2>&1 )
  "$JQ" -e '.opencode | has("stale_reason") | not' "$_oc/config/models.json" >/dev/null 2>&1 \
    && ok "and the next good refresh clears the stamp" || bad "stamp survived a good refresh"
  ( CONFIG_DIR="$_oc/config"; MODELS_FILE="$_oc/config/none.json"; AGENTLOOP_OPENCODE_BIN=""; OPENCODE_BIN=/nonexistent
    resolve_models_opencode >/dev/null 2>&1 )
  [ "$("$JQ" -r '.opencode.available, .opencode.reason' "$_oc/config/none.json" | tr '\n' '|')" = "false|opencode not installed|" ] \
    && ok "without the binary the block says so" || bad "no-binary block: $("$JQ" -c .opencode "$_oc/config/none.json")"

  echo "platform_check opencode — ready when the CLI lists a model, and who the account is"
  _pc="$( PLATFORMS_FILE="$pb/none.json"; AGENTLOOP_OPENCODE_BIN="$BASE_DIR/test/fake-opencode"; platform_check opencode )"
  [ "$(printf '%s' "$_pc" | "$JQ" -r '.ready, .version, .account' | tr '\n' '|')" = "true|1.18.30|0 credentials · providers: opencode, pdm_ai|" ] \
    && ok "ready, versioned, and the account names the credentials and the providers" || bad "opencode check: $_pc"
  _pc="$( PLATFORMS_FILE="$pb/none.json"; AGENTLOOP_OPENCODE_BIN="$BASE_DIR/test/fake-opencode"; FAKE_OPENCODE_NO_MODELS=1; export FAKE_OPENCODE_NO_MODELS; platform_check opencode )"
  [ "$(printf '%s' "$_pc" | "$JQ" -r '.ready, .reason' | tr '\n' '|')" = "false|no usable provider: run opencode auth login, or configure one in ~/.config/opencode/opencode.json|" ] \
    && ok "with no model listed it is not ready, and says what to do" || bad "no-provider check: $_pc"

  echo "run_bounded() — a command past its deadline is killed and reads as 124"
  run_bounded 1 sleep 5; want "a 5 s sleep under a 1 s deadline exits 124" 124 $?
  [ "$(run_bounded 5 echo bounded-ok)" = "bounded-ok" ] && ok "a command inside the deadline passes its stdout through" || bad "run_bounded ate the output"
```

O bloco existente a seguir a `printf '#!/bin/sh\necho "1.18.30"\n' > "$pb/bin/opencode"` (~3731–3734) muda: deixa de esperar `ready=false` com "runs on OpenCode arrive with the OpenCode engine" e passa a esperar a razão de um binário que não lista modelos. Substituir essas quatro linhas por:

```bash
  printf '#!/bin/sh\ncase "$1" in --version) echo "1.18.30";; esac\nexit 0\n' > "$pb/bin/opencode"; chmod +x "$pb/bin/opencode"
  _pc="$( PLATFORMS_FILE="$pb/none.json"; AGENTLOOP_OPENCODE_BIN=""; OPENCODE_BIN="$pb/bin/opencode"; platform_check opencode )"
  [ "$(printf '%s' "$_pc" | "$JQ" -r '.ready, .bin_found, .version, .reason' | tr '\n' '|')" = "false|true|1.18.30|no usable provider: run opencode auth login, or configure one in ~/.config/opencode/opencode.json|" ] \
    && ok "platform_check opencode: found and versioned, not ready while no model is listed, with the reason" || bad "opencode found: $_pc"
```

(O `case` está dentro de um `printf` para um ficheiro, não dentro de `$( )`: seguro.)

Correr: `bash bin/agentloop selftest 2>&1 | grep -E 'FAIL|passed'`
Esperado: os casos novos em FAIL (`resolve_models_opencode: command not found`, `run_bounded: command not found`), o resto verde.

- [ ] **Step 2: `run_bounded`**

Logo antes de `tree_cpu_seconds()` (~linha 2268):

```bash
# A command with a deadline. macOS ships no `timeout`, and the two places that
# need one -- `opencode models` behind platform_check, `opencode export` at
# the end of a run -- must never hang the Settings page or a run's close on a
# CLI that has stopped answering (measured 08c/34b: an OpenCode process can
# wait for ever, silently). python3 is a hard dependency; its subprocess
# timeout kills the child and this answers 124, the convention of `timeout`.
run_bounded() { # run_bounded <seconds> <cmd...> -> the command's stdout and rc; 124 past the deadline
  local secs="$1"; shift
  "$PYTHON" - "$secs" "$@" <<'PY'
import subprocess, sys
try:
    sys.exit(subprocess.run(sys.argv[2:], timeout=float(sys.argv[1]), stdin=subprocess.DEVNULL).returncode)
except subprocess.TimeoutExpired:
    sys.exit(124)
except OSError as e:
    print(str(e), file=sys.stderr)
    sys.exit(127)
PY
}
```

- [ ] **Step 3: O catálogo, lado da leitura e da escrita**

Logo antes de `# --- the price table ---` (~linha 2020, depois de `openai_catalog_ensure`):

```bash
# --- the OpenCode catalog ---------------------------------------------------
# config/models.json carries an `opencode` block, written by `resolve-models
# opencode` from `opencode models --verbose`. Every model is `provider/model`,
# the CLI's own name for it, split at the FIRST slash: a model id can carry a
# slash of its own (measured: pdm_ai/openai/gpt-oss-120b). `priced` is true
# when any of the four catalog prices is above zero -- zero in every field is
# UNKNOWN, not free: a custom provider with no `cost` configured lists the
# same zeros as a free Zen model (measured 24b). Without the block every
# reader answers nothing, which is what makes an unresolved catalog REFUSE a
# launch rather than guess an id.
opencode_catalog_available() { # 0 when config/models.json carries an opencode catalog
  [ -f "$MODELS_FILE" ] && "$JQ" -e '.opencode.models | type == "array"' "$MODELS_FILE" >/dev/null 2>&1
}

opencode_catalog_ids() { # every id, active or not, one per line, in the CLI's own order
  opencode_catalog_available || return 0
  "$JQ" -r '.opencode.models[].id' "$MODELS_FILE" 2>/dev/null
}

opencode_catalog_visible() { # the active ids: what the Settings page lists
  opencode_catalog_available || return 0
  "$JQ" -r '.opencode.models[] | select(.status == "active") | .id' "$MODELS_FILE" 2>/dev/null
}

opencode_catalog_efforts() { # opencode_catalog_efforts <id> -> the model's variants, one per line; nothing for a model without any
  opencode_catalog_available || return 0
  [ -n "${1:-}" ] || return 0
  "$JQ" -r --arg m "$1" '.opencode.models[] | select(.id == $m) | .variants[]?' "$MODELS_FILE" 2>/dev/null
}

opencode_catalog_all_efforts() { # the union of every active model's variants, first-seen order
  opencode_catalog_available || return 0
  "$JQ" -r '
    [.opencode.models[] | select(.status == "active") | .variants[]?]
    | reduce .[] as $e ([]; if index($e) then . else . + [$e] end)
    | .[]' "$MODELS_FILE" 2>/dev/null
}

opencode_catalog_priced() { # opencode_catalog_priced <id> -> 0 when the catalog prices the model
  opencode_catalog_available || return 1
  "$JQ" -e --arg m "$1" '.opencode.models[] | select(.id == $m) | .priced == true' "$MODELS_FILE" >/dev/null 2>&1
}

opencode_catalog_tools() { # opencode_catalog_tools <id> -> 0 unless the catalog says the model makes no tool calls
  opencode_catalog_available || return 0
  if "$JQ" -e --arg m "$1" '.opencode.models[] | select(.id == $m) | .tools == false' "$MODELS_FILE" >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

resolve_models_opencode() { # refresh config/models.json's `opencode` block from `opencode models --verbose`
  local raw block tmp kept version
  tmp="$(mktemp "$CONFIG_DIR/.models.XXXXXX")" || return 1
  if [ ! -f "$MODELS_FILE" ]; then
    echo '{"resolved":{}}' > "$MODELS_FILE"
  elif ! "$JQ" -e . "$MODELS_FILE" >/dev/null 2>&1; then
    echo "models.json was not valid JSON — reseeded"
    echo '{"resolved":{}}' > "$MODELS_FILE"
  fi
  if [ ! -x "$(platform_bin opencode)" ]; then
    block="$("$JQ" -nc --argjson at "$(now_epoch)" '{at:$at, available:false, reason:"opencode not installed"}')"
  else
    # --pure: the operator's plugins have no business in a catalog read, and
    # one of them rewrote a command in a run (measured 02). Bounded: a CLI
    # that hangs must not hang the daily pass.
    version="$(run_bounded 30 "$(platform_bin opencode)" --version 2>/dev/null | head -1)"
    raw="$(run_bounded 60 "$(platform_bin opencode)" models --verbose --pure 2>/dev/null)"
    # The format is a header line `provider/model` followed by one pretty
    # JSON document per model; jq cannot read the two interleaved, python can.
    block="$(printf '%s\n' "$raw" | "$PYTHON" - "$(now_epoch)" "$version" <<'PY'
import json, re, sys
at, version = int(sys.argv[1]), sys.argv[2]
text = sys.stdin.read()
models = []
for chunk in re.split(r"^(?=[A-Za-z0-9_.-]+/[^\n{]+\n\{)", text, flags=re.M):
    chunk = chunk.strip()
    if not chunk:
        continue
    head, _, body = chunk.partition("\n")
    try:
        d = json.loads(body)
    except Exception:
        continue
    provider, _, name = head.partition("/")
    def num(v):
        return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0.0
    cost = d.get("cost") if isinstance(d.get("cost"), dict) else {}
    cache = cost.get("cache") if isinstance(cost.get("cache"), dict) else {}
    prices = {"input": num(cost.get("input")), "output": num(cost.get("output")),
              "cache_read": num(cache.get("read")), "cache_write": num(cache.get("write"))}
    caps = d.get("capabilities") if isinstance(d.get("capabilities"), dict) else {}
    limit = d.get("limit") if isinstance(d.get("limit"), dict) else {}
    variants = d.get("variants") if isinstance(d.get("variants"), dict) else {}
    models.append({"id": head, "provider": provider, "name": d.get("name") or name, "cost": prices,
                   "priced": any(v > 0 for v in prices.values()),
                   "context": limit.get("context") or 0, "output_limit": limit.get("output") or 0,
                   "variants": list(variants.keys()), "tools": caps.get("toolcall") is not False,
                   "reasoning": caps.get("reasoning") is True, "status": d.get("status") or "active"})
if models:
    print(json.dumps({"at": at, "source": "opencode models --verbose", "version": version, "models": models}))
else:
    print(json.dumps({"at": at, "available": False,
                      "reason": "opencode models listed no model: no provider is usable"}))
PY
)"
  fi
  # A refresh that failed -- no opencode, an empty list -- must not replace a
  # catalog that still resolves real jobs: keep the block it had, stamped
  # with when and why, exactly as resolve_models_openai does; `platform
  # models` reads the stamp back as `stale`, and models_stale ages the block
  # from it. The {available:false} stub is written only when there is
  # nothing to keep.
  if opencode_catalog_available && printf '%s' "$block" | "$JQ" -e '.available == false' >/dev/null 2>&1; then
    kept="$(printf '%s' "$block" | "$JQ" -r .reason)"
    if ! { "$JQ" --argjson at "$(now_epoch)" --arg r "$kept" '.opencode.stale_at = $at | .opencode.stale_reason = $r' "$MODELS_FILE" > "$tmp" && mv "$tmp" "$MODELS_FILE"; }; then
      rm -f "$tmp"
      echo "opencode -> could not write $MODELS_FILE"
      return 1
    fi
    rm -f "$tmp"
    echo "opencode -> kept the previous catalog ($kept)"
    return 0
  fi
  if ! { "$JQ" --argjson b "$block" '.opencode = $b' "$MODELS_FILE" > "$tmp" && mv "$tmp" "$MODELS_FILE"; }; then
    rm -f "$tmp"
    echo "opencode -> could not write $MODELS_FILE"
    return 1
  fi
  rm -f "$tmp"
  if opencode_catalog_available; then
    echo "opencode -> $(opencode_catalog_visible | tr '\n' ' ')(opencode models --verbose)"
  else
    echo "opencode -> unavailable: $(printf '%s' "$block" | "$JQ" -r .reason)"
  fi
}

opencode_catalog_ensure() { # resolve once, synchronously, when the block is missing and opencode exists
  opencode_catalog_available && return 0
  [ -x "$(platform_bin opencode)" ] || return 1
  resolve_models_opencode >/dev/null 2>&1
  opencode_catalog_available
}
```

Atenção ao heredoc python dentro de `$( )`: nenhuma aspa simples nem `case` lá dentro (o bash 3.2 partiria o ficheiro em runtime). O código acima só usa aspas duplas.

- [ ] **Step 4: `platform_check`, `platform_catalog_ids`, `platform_models_json`, `cmd_resolve_models`, `models_stale`**

Em `platform_check`, o ramo `elif [ "$supported" = false ]; then reason="runs on OpenCode arrive with the OpenCode engine"` fica (o registo só muda em T4), e o `case "$p" in` ganha o ramo `opencode`, depois do `openai)`:

```bash
      opencode)
        # A CLI of providers, not of one account: ready when it lists a model
        # to run (the providers with a key, plus the free Zen models that need
        # none -- measured, 01), and the account line says how many
        # credentials auth.json holds and which providers the catalog shows.
        local list nmod ncred provs esc
        list="$(run_bounded 30 "$bin" models --pure 2>/dev/null | grep -E '^[A-Za-z0-9_.-]+/' || true)"
        nmod="$(num "$(printf '%s\n' "$list" | grep -c . 2>/dev/null)")"
        if [ "$nmod" -gt 0 ]; then
          ready=true
          esc="$(printf '\033')"
          # `auth list` draws a box with ANSI colours even off a TTY (measured); strip them before reading the count
          ncred="$(run_bounded 30 "$bin" auth list 2>/dev/null | sed "s/${esc}\[[0-9;]*m//g" | grep -oE '[0-9]+ credentials' | head -1)"
          provs="$(printf '%s\n' "$list" | cut -d/ -f1 | sort -u | tr '\n' ',' | sed 's/,$//; s/,/, /g')"
          acct="${ncred:-0 credentials} · providers: $provs"
        else
          reason="no usable provider: run opencode auth login, or configure one in ~/.config/opencode/opencode.json"
        fi ;;
```

Mas o `elif [ "$supported" = false ]` corre antes do `case` e nunca chega ao ramo; para esta tarefa (o registo ainda diz *planned*) o `platform_check` tem de correr o ramo `opencode` na mesma. Trocar a estrutura: o `elif [ "$supported" = false ]; then reason=…` **sai**, e o `case` corre para as três; a resposta `supported:false` continua a vir de `platform_planned` no JSON final. O selftest do Step 1 já assume isto (ready `true` com o stand-in, mesmo *planned*).

`platform_catalog_ids`: `case "$1" in anthropic) anthropic_catalog_ids ;; openai) openai_catalog_visible ;; opencode) opencode_catalog_visible ;; *) : ;; esac`.

`platform_models_json`: o ramo `*)` (que hoje responde "the model list arrives with the OpenCode engine") passa a ser o ramo `opencode)`:

```bash
    opencode)
      cat_at="$(num "$("$JQ" -r '.opencode.at // 0' "$MODELS_FILE" 2>/dev/null)")"
      [ -f "$PRICING_FILE" ] && pricing="$("$JQ" -c '.opencode // {}' "$PRICING_FILE" 2>/dev/null || echo '{}')"
      arr=""; opencode_catalog_available && arr="$("$JQ" -c '[.opencode.models[] | select(.status == "active")]' "$MODELS_FILE" 2>/dev/null)"
      [ -n "$arr" ] || arr='[]'
      # `price` is what the page shows per million: the catalog's own when it
      # prices the model, else the operator's row, else null ("no price").
      printf '%s' "$arr" | "$JQ" -c --arg p "$p" --argjson stale "$stale" --arg reason "$reason" --argjson enabled "$enabled" --argjson at "$cat_at" --argjson pricing "$pricing" \
        '{platform:$p, stale:$stale, reason:$reason, catalog_at:$at,
          models: map({v:.id, label:(.name // .id), provider:.provider, desc:"", efforts:(.variants // []), deprecated_by:"",
                       tools:(.tools != false), context:(.context // 0),
                       price: (if .priced == true then {input:.cost.input, output:.cost.output}
                               else (($pricing[.id] // null) | if . != null and (.input | type) == "number" and (.output | type) == "number" then {input:.input, output:.output} else null end) end),
                       enabled: (.id as $x | ($enabled | index($x)) != null)})}' ;;
    *)
      "$JQ" -nc --arg p "$p" '{platform:$p, stale:false, reason:"unknown platform", catalog_at:0, models:[]}' ;;
```

`cmd_platform models`: o `if [ "$p" = "openai" ]` que refresca ganha o irmão:

```bash
      elif [ "$p" = "opencode" ]; then
        out="$(resolve_models_opencode 2>&1)"; rc=$?
        reason="$("$JQ" -r '.opencode.stale_reason // empty' "$MODELS_FILE" 2>/dev/null)"
        if [ -n "$reason" ]; then
          stale=true; reason="refresh failed: $reason"
        elif [ "$rc" -ne 0 ] || ! opencode_catalog_available; then
          stale=true; reason="refresh failed: $(printf '%s' "$out" | tail -1)"
        fi
      fi
```

`cmd_resolve_models`: acrescentar `case "$which" in ""|opencode) resolve_models_opencode || rc=$? ;; esac` a seguir ao do `openai`, e a validação final passa a `""|anthropic|openai|opencode)`. O comentário de cabeçalho da função (`[anthropic|openai]`) passa a `[anthropic|openai|opencode] -- no argument does all three`.

`models_stale`: depois do bloco `oa` do OpenAI, o mesmo para o OpenCode:

```bash
  local oc
  oc="$("$JQ" -r '[.opencode.at // 0, .opencode.stale_at // 0] | max' "$MODELS_FILE" 2>/dev/null)"
  case "$oc" in ''|null|*[!0-9]*) oc=0 ;; esac
  [ "$oc" -lt "$oldest" ] && oldest="$oc"
```

- [ ] **Step 4b: O e2e aponta o OpenCode para o stand-in**

Em `test/e2e.test.sh`, logo a seguir a `export CODEX_HOME="$ROOT/codex-home"`, pela mesma razão que o comentário acima dessa linha dá para o Codex (o primeiro `tick` refresca os catálogos e chegaria ao `opencode` real desta máquina):

```bash
# The same for OpenCode: the daily catalog pass would otherwise run the
# operator's real `opencode models --verbose` against their real config.
export AGENTLOOP_OPENCODE_BIN="$E2E/fake-opencode"
```

- [ ] **Step 5: Correr o selftest**

Correr: `bash bin/agentloop selftest 2>&1 | tail -3`
Esperado: `7NN passed, 0 failed` (os casos novos verdes; o `platform_check opencode … planned` antigo substituído). Se `platform_check` responder `ready: false` com o stand-in, ver se o `elif [ "$supported" = false ]` ainda intercepta antes do `case`.

Nota: o selftest também corre o e2e por dentro; o e2e ainda não conhece o `opencode` e continua 99/0.

- [ ] **Step 6: CHANGELOG e commit**

Sub-ponto:

```markdown
  - The catalog: `agentloop resolve-models opencode` reads `opencode models
    --verbose` into `config/models.json` (id, provider, name, price, whether
    it is priced at all, context, variants, tool calls), refreshed daily
    with the other two and kept, stamped stale, when a refresh lists
    nothing; `platform check opencode` is ready when the CLI lists a model
    and names the credentials and the providers. `run_bounded` puts a
    deadline under the two CLI calls a hung OpenCode could otherwise turn
    into a hung Settings page.
```

```bash
/usr/bin/git add bin/agentloop test/e2e.test.sh CHANGELOG.md
/usr/bin/git commit -m "feat(opencode): the catalog from opencode models --verbose, and readiness from it

resolve_models_opencode parses the CLI's header-plus-JSON listing into a
block the readers, the launch gate and the Settings page share: id split
at the first slash (a model id can carry one), price per million with
priced=false when every field is zero (a custom provider with no cost
configured lists the same zeros as a free model), variants as the effort
vocabulary, whether the model makes tool calls. platform_check opencode is
ready when the CLI lists a model to run, and its account line says how
many credentials auth.json holds and which providers the catalog shows;
run_bounded keeps a hung CLI from hanging the check or the daily pass.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
/usr/bin/git push
```

Correr as quatro suites.

---

### Task 4: A tabela de plataformas: registo, capacidades, permissões, esforço, a linha de lançamento, o bloco de permissões, `platform_normalizer`, `platform_finish`

**Files:**
- Modify: `bin/agentloop` (registo ~1260; `platform_caps` ~1677; `platform_permissions`, `platform_permission_ok`, `platform_default_permission`, `platform_efforts`, `platform_effort_ok`, `platform_model_ok` ~1697–1756; novas `opencode_config_content`, `platform_argv_opencode`, `platform_normalizer`, `opencode_export_model` junto a `platform_argv_openai` ~1815; `platform_finish` ~1871; `platform_install_hint`; selftest)
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: T3 (`opencode_catalog_*`, `run_bounded`), T1 (`test/fake-opencode` para o selftest de `opencode_export_model`).
- Produces: `PLATFORMS="anthropic openai opencode"`, `PLATFORMS_PLANNED=""`, `platform_known opencode` → 0, `platform_planned` → 1 sempre; `platform_caps opencode {tool_lists,denials,cost_reported}` → 0, as outras → 1; `platform_caps anthropic prepare_inline` → 0 (as outras duas → 1); `platform_permissions opencode` → `full-access`, `read-only`; `platform_default_permission opencode {job,security}` → `full-access`; `platform_efforts opencode <model>` → as variantes; `platform_model_ok opencode <id>` → no catálogo; `opencode_config_content <permission> <allowed> <disallowed>` → linha 1 o JSON de `OPENCODE_CONFIG_CONTENT`, linhas seguintes as notas para o `tick.log`; `platform_argv_opencode <resume-sid> <run_cwd> <model> <effort> <prompt> <title>` → `PLATFORM_ARGV`; `platform_normalizer <p>` → o caminho do normalizador ou nada; `opencode_export_model <run_cwd> <sid>` → `provider/model` ou nada; `platform_finish opencode <streamfile> <sid> <job-id> <run_cwd>` → `PF_MODEL_ID`. O `run_job` (T5) consome tudo isto.

- [ ] **Step 1: Os casos de selftest, e vê-los falhar**

No bloco `echo "platforms — the table run_job asks instead of naming a binary"` (~3502), a seguir à linha `platform_known gemini; want "an unknown platform is refused" 1 $?`:

```bash
  platform_known opencode;    want "opencode is a known platform now"   0 $?
  platform_planned opencode;  want "and no longer a planned one"         1 $?
  [ "$PLATFORMS" = "anthropic openai opencode" ] && [ -z "$PLATFORMS_PLANNED" ] && ok "the registry runs three platforms and plans none" || bad "PLATFORMS='$PLATFORMS' PLANNED='$PLATFORMS_PLANNED'"
  local _oc_caps=""
  for _cap in interactive tool_lists denials budget_flag cost_reported stream_rate_limits families prepare_inline; do
    platform_caps opencode "$_cap" && _oc_caps="$_oc_caps $_cap"
  done
  [ "$_oc_caps" = " tool_lists denials cost_reported" ] && ok "opencode has tool_lists, denials and cost_reported, and nothing else" || bad "opencode caps:$_oc_caps"
  platform_caps anthropic prepare_inline; want "anthropic runs security prepare inside the agent" 0 $?
  platform_caps openai prepare_inline;    want "openai does not (the engine runs it first)"  1 $?
  [ "$(platform_permissions opencode | tr '\n' ' ')" = "full-access read-only " ] && ok "the two opencode modes" || bad "opencode modes: $(platform_permissions opencode | tr '\n' ' ')"
  platform_permission_ok opencode read-only;       want "read-only is an opencode mode"        0 $?
  platform_permission_ok opencode workspace-write; want "workspace-write is not (no sandbox)"  1 $?
  [ "$(platform_default_permission opencode job)" = "full-access" ] && [ "$(platform_default_permission opencode security)" = "full-access" ] \
    && ok "full-access is the opencode default for a job and for security" || bad "opencode defaults: $(platform_default_permission opencode job) / $(platform_default_permission opencode security)"
```

Na mesma zona, depois do bloco `echo "the OpenCode catalog — …"` (T3), um bloco novo:

```bash
  echo "opencode effort and model — validated against the catalog, because the CLI validates nothing"
  ( MODELS_FILE="$_oc/config/models.json"
    [ "$(platform_efforts opencode pdm_ai/glm-5.3-flash | tr '\n' ' ')" = "max high non-think " ] || exit 1
    [ -z "$(platform_efforts opencode opencode/big-pickle)" ] || exit 2
    platform_effort_ok opencode pdm_ai/glm-5.3-flash high || exit 3
    platform_effort_ok opencode pdm_ai/glm-5.3-flash "" || exit 4
    platform_effort_ok opencode pdm_ai/glm-5.3-flash ultra && exit 5
    platform_effort_ok opencode opencode/big-pickle low && exit 6
    platform_model_ok opencode pdm_ai/glm-5.3-flash || exit 7
    platform_model_ok opencode pdm_ai/openai/gpt-oss-120b || exit 8
    platform_model_ok opencode opencode/does-not-exist && exit 9
    [ "$(platform_catalog_ids opencode | grep -c .)" = "13" ] || exit 10
    exit 0 ); want "efforts are the model's variants, empty is fine, a model without variants takes none, the id must be in the catalog" 0 $?

  echo "opencode_config_content() — the permission block a run is launched with"
  local _cc
  _cc="$(opencode_config_content full-access "" "" | head -1)"
  [ "$(printf '%s' "$_cc" | "$JQ" -c .)" = '{"share":"disabled","permission":{}}' ] \
    && ok "full-access with no lists: share disabled and an empty block (--auto approves the rest)" || bad "full-access block: $_cc"
  _cc="$(opencode_config_content read-only "" "" | head -1)"
  [ "$(printf '%s' "$_cc" | "$JQ" -c .permission)" = '{"edit":"deny","write":"deny","bash":"deny","task":"deny"}' ] \
    && ok "read-only denies edit, write, bash and task" || bad "read-only block: $_cc"
  _cc="$(opencode_config_content full-access "" "Agent,Bash(git push *),WebFetch" | head -1)"
  [ "$(printf '%s' "$_cc" | "$JQ" -c .permission)" = '{"task":"deny","bash":{"*":"allow","git push *":"deny"},"webfetch":"deny"}' ] \
    && ok "a denylist: Agent closes task, Bash(pattern) is a bash pattern, a plain name closes the tool" || bad "denylist block: $_cc"
  _cc="$(opencode_config_content full-access "Read,Grep,Bash(git *)" "" | head -1)"
  [ "$(printf '%s' "$_cc" | "$JQ" -c .permission)" = '{"*":"deny","read":"allow","grep":"allow","bash":{"*":"deny","git *":"allow"}}' ] \
    && ok "an allowlist: everything else denied, the named tools and the bash pattern allowed" || bad "allowlist block: $_cc"
  _cc="$(opencode_config_content full-access "Read,Edit(*.md)" "Read,Edit(*.py)")"
  [ "$(printf '%s\n' "$_cc" | head -1 | "$JQ" -c .permission)" = '{"*":"deny","read":"deny","edit":"deny"}' ] \
    && ok "deny wins over allow; a pattern on a non-bash tool widens a deny and is dropped from an allow" || bad "both lists: $(printf '%s\n' "$_cc" | head -1)"
  printf '%s\n' "$_cc" | tail -n +2 | grep -q 'Edit(\*.md) ignored' && ok "and the dropped allow pattern is named in a note" || bad "no note for the dropped pattern: $(printf '%s\n' "$_cc" | tail -n +2)"
  _cc="$(opencode_config_content read-only "" "Nonesuch")"
  printf '%s\n' "$_cc" | tail -n +2 | grep -q "Nonesuch" && ok "an unknown tool name is named in a note, not translated" || bad "no note for Nonesuch"
  printf '%s\n' "$_cc" | head -1 | "$JQ" -e '.permission | has("nonesuch") | not' >/dev/null 2>&1 && ok "and never reaches the block" || bad "Nonesuch reached the block"

  echo "platform_argv_opencode() — the measured launch line, for a fresh run and a resume"
  platform_argv_opencode "" /tmp/w pdm_ai/glm-5.3-flash high "PROMPT" "agentloop j1 20260912-120000"
  _av="$(printf '%s\n' "${PLATFORM_ARGV[@]}")"
  [ "${PLATFORM_ARGV[0]}" = "run" ] && [ "${PLATFORM_ARGV[1]}" = "--format" ] && [ "${PLATFORM_ARGV[2]}" = "json" ] && ok "run --format json first" || bad "argv starts ${PLATFORM_ARGV[*]}"
  for _flag in --pure --auto --print-logs; do
    printf '%s\n' "$_av" | grep -qx -- "$_flag" && ok "$_flag on every launch" || bad "no $_flag"
  done
  printf '%s\n' "$_av" | grep -A1 -x -- '--log-level' | grep -qx 'ERROR' && ok "--log-level ERROR: the reason of an UnknownError lands in .err, nothing else does" || bad "log level"
  printf '%s\n' "$_av" | grep -A1 -x -- '-m' | grep -qx 'pdm_ai/glm-5.3-flash' && ok "-m carries the id verbatim" || bad "-m"
  printf '%s\n' "$_av" | grep -A1 -x -- '--variant' | grep -qx 'high' && ok "--variant carries the effort" || bad "--variant"
  printf '%s\n' "$_av" | grep -A1 -x -- '--dir' | grep -qx '/tmp/w' && ok "--dir is the run's cwd" || bad "--dir"
  printf '%s\n' "$_av" | grep -A1 -x -- '--title' | grep -qx 'agentloop j1 20260912-120000' && ok "--title on a fresh run (one model call saved per session)" || bad "--title"
  printf '%s\n' "$_av" | grep -qx -- '-s' && bad "-s on a fresh run" || ok "no -s on a fresh run"
  [ "${PLATFORM_ARGV[$((${#PLATFORM_ARGV[@]} - 2))]}" = "--" ] && [ "${PLATFORM_ARGV[$((${#PLATFORM_ARGV[@]} - 1))]}" = "PROMPT" ] \
    && ok "-- then the prompt, last" || bad "the prompt is not the lone argument after --"
  platform_argv_opencode "" /tmp/w opencode/big-pickle "" "P" "t"
  printf '%s\n' "${PLATFORM_ARGV[@]}" | grep -qx -- '--variant' && bad "an empty effort still emitted --variant" || ok "an empty effort emits no --variant"
  platform_argv_opencode ses_abc /tmp/kept opencode/big-pickle "" "P" "t"
  printf '%s\n' "${PLATFORM_ARGV[@]}" | grep -A1 -x -- '-s' | grep -qx 'ses_abc' && ok "a resume carries -s with the session id" || bad "no -s on the resume"
  printf '%s\n' "${PLATFORM_ARGV[@]}" | grep -A1 -x -- '--dir' | grep -qx '/tmp/kept' && ok "and --dir with the session's own directory (measured: any other directory hangs for ever)" || bad "no --dir on the resume"
  printf '%s\n' "${PLATFORM_ARGV[@]}" | grep -qx -- '--title' && bad "--title on a resume (the session has one)" || ok "no --title on a resume"

  echo "platform_normalizer() — the launch asks for one instead of naming a platform"
  [ "$(platform_normalizer openai)" = "$BIN_DIR/platforms/openai_stream.py" ] && ok "openai has its normalizer" || bad "openai normalizer: $(platform_normalizer openai)"
  [ "$(platform_normalizer opencode)" = "$BIN_DIR/platforms/opencode_stream.py" ] && ok "opencode has its normalizer" || bad "opencode normalizer: $(platform_normalizer opencode)"
  [ -z "$(platform_normalizer anthropic)" ] && ok "anthropic has none: the CLI speaks stream-json itself" || bad "anthropic got a normalizer"

  echo "turn_is_over() — over a normalized OpenCode stream"
  "$PYTHON" -u "$BIN_DIR/platforms/opencode_stream.py" --model opencode/big-pickle --permission full-access --cwd /tmp \
    < "$BASE_DIR/test/fixtures/opencode/03-tool-use.jsonl" > "$tmp/oc-a.ndjson" 2>/dev/null
  turn_is_over "$tmp/oc-a.ndjson"; want "a finished OpenCode turn is over" 0 $?
  grep -v '"reason":"stop"' "$BASE_DIR/test/fixtures/opencode/03-tool-use.jsonl" \
    | "$PYTHON" -u "$BIN_DIR/platforms/opencode_stream.py" --model opencode/big-pickle --permission full-access --cwd /tmp > "$tmp/oc-b.ndjson" 2>/dev/null
  turn_is_over "$tmp/oc-b.ndjson"; want "an OpenCode turn cut before its last step is not" 1 $?
  [ "$(session_from_stream "$tmp/oc-a.ndjson")" = "ses_f69f73155ffeAHgrtVv1sVFbr7" ] \
    && ok "session_from_stream reads the sessionID off the first line" || bad "session $(session_from_stream "$tmp/oc-a.ndjson")"

  echo "opencode_export_model() — the model that ran, read from opencode export"
  mkdir -p "$tmp/ocx"
  [ "$( AGENTLOOP_OPENCODE_BIN="$BASE_DIR/test/fake-opencode"; FAKE_RAN_MODEL=pdm_ai/glm-5.3-flash-real; export FAKE_RAN_MODEL; opencode_export_model "$tmp/ocx" ses_x1 )" = "pdm_ai/glm-5.3-flash-real" ] \
    && ok "provider/model out of info.model" || bad "export model: $( AGENTLOOP_OPENCODE_BIN="$BASE_DIR/test/fake-opencode"; opencode_export_model "$tmp/ocx" ses_x1 )"
  [ -z "$( AGENTLOOP_OPENCODE_BIN="$BASE_DIR/test/fake-opencode"; opencode_export_model "$tmp/does-not-exist" ses_x1 )" ] \
    && ok "no directory, no answer (never a hang: the CLI needs the session's directory)" || bad "export answered without a directory"
  ( AGENTLOOP_OPENCODE_BIN="$BASE_DIR/test/fake-opencode"; FAKE_RAN_MODEL=opencode/big-pickle-real; export FAKE_RAN_MODEL
    platform_finish opencode "$tmp/ocx/none.ndjson" ses_x2 j1 "$tmp/ocx"; [ "$PF_MODEL_ID" = "opencode/big-pickle-real" ] ); want "platform_finish opencode sets PF_MODEL_ID from the export" 0 $?
```

Os casos antigos que pinavam o *planned* mudam de sentido nesta tarefa; substituir:
- `pc_al platform enable opencode >/dev/null 2>&1; want "platform enable refuses a planned platform" 1 $?` (~3776) → o `pc_al` desta zona usa `OPENCODE_BIN=/nonexistent`; fica `want "platform enable refuses a platform whose binary is missing" 1 $?`.
- `pc_al platform models opencode | "$JQ" -e '.models == [] and (.reason | length) > 0'` (~3809) → `pc_al platform models opencode | "$JQ" -e '.models == [] and .stale == true and (.reason | length) > 0' >/dev/null 2>&1; want "platform models opencode without the binary: an empty, stale list with the reason" 0 $?`.
- `.opencode.supported == false` (~3826–3831) → `.opencode.supported == true`.
- a linha de `status` (~4199) `'^opencode  : planned — opencode not found at /nonexistent …'` → `'^opencode  : disabled — opencode not found at /nonexistent — set the path in Settings (or AGENTLOOP_OPENCODE_BIN); install: brew install opencode$'` e a mensagem `ok` passa a "the opencode line says disabled and why the binary is missing".
- `printf 'opencode' | cfg_al set-field cj platform >/dev/null 2>&1; want "set-field platform refuses the planned platform" 1 $?` (~4476) → continua a ser recusado nesta tarefa (a `set-field` só muda em T7), mas pela razão "not enabled in Settings"; renomear para `want "set-field platform refuses a platform not enabled in Settings" 1 $?`.
- `platform_default_model opencode` vazio (~4519): continua a valer.

Correr: `bash bin/agentloop selftest 2>&1 | grep -E 'FAIL|passed'`
Esperado: os casos novos em FAIL, o resto verde.

- [ ] **Step 2: O registo e as capacidades**

```bash
PLATFORMS="anthropic openai opencode"   # the platforms that run
PLATFORMS_PLANNED=""                    # listed and checked for a binary, never run: none today; the mechanism stays for the next one

platform_known() { case "${1:-}" in anthropic|openai|opencode) return 0 ;; *) return 1 ;; esac; }
platform_planned() { case "${1:-}" in "") return 1 ;; *) return 1 ;; esac; }
```

(O `case` de `platform_planned` mantém a forma para o dia em que uma plataforma voltar a ser *planned*; devolve 1 a tudo.)

`platform_caps`:

```bash
platform_caps() { # platform_caps <platform> <capability> -> 0 when the platform HAS it
  #   interactive        a stdin protocol for a human to talk to the live run
  #                      (opencode reads stdin as part of the PROMPT: 13b)
  #   tool_lists         allowed_tools/disallowed_tools reach the CLI (opencode:
  #                      the permission block, per tool and per bash pattern;
  #                      Codex cannot close a tool by flag -- measured)
  #   denials            permission_denials on the final event (opencode: the two
  #                      measured denial phrases; a Codex sandbox refusal produces
  #                      no event at all)
  #   budget_flag        --max-budget-usd (elsewhere the cap is read at the end)
  #   cost_reported      dollars on the final event (opencode: the CLI's own number
  #                      when its catalog prices the model; openai: estimated)
  #   stream_rate_limits rate_limit_event on the stream (openai: the rollout; opencode: none)
  #   families           opus/sonnet aliases resolved to an id (the others: exact ids)
  #   prepare_inline     the security analysis's `prepare` is the AGENT's first
  #                      command (its Bash tool waits for it); elsewhere the engine
  #                      runs it before the launch
  case "$1" in
    anthropic) case "$2" in
      interactive|tool_lists|denials|budget_flag|cost_reported|stream_rate_limits|families|prepare_inline) return 0 ;;
    esac ;;
    openai) : ;;
    opencode) case "$2" in tool_lists|denials|cost_reported) return 0 ;; esac ;;
  esac
  return 1
}
```

- [ ] **Step 3: Permissões, esforço, modelo**

```bash
platform_permissions() { # platform_permissions <platform> -> one mode per line
  case "$1" in
    anthropic) printf '%s\n' acceptEdits auto bypassPermissions manual dontAsk plan ;;
    openai)    printf '%s\n' read-only workspace-write full-access ;;
    # Two modes that say what the CLI enforces. There is no OS sandbox
    # (measured 19, 20: bash writes anywhere and commits from a worktree),
    # so a "workspace" mode would promise what it cannot keep; full-access
    # is the truth of the default, read-only is the file tools, the shell
    # and the subagents denied by rule.
    opencode)  printf '%s\n' full-access read-only ;;
  esac
}
```

`platform_default_permission`: `opencode)  printf 'full-access' ;;` (os dois tipos; o comentário acima da função já explica porquê uma omissão fechada é um job morto).

```bash
platform_efforts() { # platform_efforts <platform> [model] -> one level per line
  case "$1" in
    anthropic) printf '%s\n' low medium high xhigh max ;;
    openai)    openai_catalog_efforts "${2:-}" ;;
    opencode)  opencode_catalog_efforts "${2:-}" ;;   # the model's variants; none for a model without any
  esac
}
```

`platform_effort_ok` fica como está (vazio é sempre ok; senão tem de estar na lista: um modelo sem `variants` não aceita esforço).

```bash
platform_model_ok() { # platform_model_ok <platform> <model>
  case "$1" in
    anthropic) case "$2" in opus|sonnet|haiku|fable|claude-*) return 0 ;; *) return 1 ;; esac ;;
    openai)    openai_catalog_slugs | grep -qxF -- "$2" ;;
    opencode)  opencode_catalog_ids | grep -qxF -- "$2" ;;
    *) return 1 ;;
  esac
}
```

`platform_install_hint`: `opencode)  printf 'brew install opencode (or: npm i -g opencode-ai)' ;;` e a asserção do selftest que compara a razão do binário em falta (~3729) ganha o mesmo sufixo.

- [ ] **Step 4: `opencode_config_content`, `platform_argv_opencode`, `platform_normalizer`, `opencode_export_model`, `platform_finish`**

A seguir a `platform_argv_openai` (~1870):

```bash
# The permission block an OpenCode run is launched with, as the JSON of
# OPENCODE_CONFIG_CONTENT (measured: the CLI reads it, 04-06, 23, 33). Line
# 1 is the JSON; every line after it is a note for tick.log (a tool name the
# table does not know, a pattern that had to be widened or dropped).
#
#   full-access  nothing beyond share:disabled -- --auto approves what the
#                CLI asks by default (external directories, .env reads, doom
#                loops), and there is no sandbox to configure (19, 20).
#   read-only    edit, write, bash and task denied: the agent reads,
#                searches, fetches, and changes nothing.
#
# The job's tool lists ride along, translated by a fixed table. A denylist
# closes tools (`Agent` -> task, the security analysis's own case: 22) and
# bash patterns (`Bash(git push *)` -> a bash rule: 23); an allowlist denies
# everything and opens what it names. A pattern on any tool but bash widens
# to the whole tool in a denylist (closing more than asked is the safe side)
# and is DROPPED from an allowlist (opening more than asked is not). Deny
# wins over allow, as it does on Claude Code.
opencode_config_content() { # opencode_config_content <permission> <allowed_tools> <disallowed_tools>
  "$PYTHON" - "$1" "${2:-}" "${3:-}" <<'PY'
import json, re, sys
mode, allowed, disallowed = sys.argv[1], sys.argv[2], sys.argv[3]
TABLE = {"bash": "bash", "edit": "edit", "multiedit": "edit", "write": "write", "read": "read",
         "glob": "glob", "grep": "grep", "ls": "list", "webfetch": "webfetch", "websearch": "websearch",
         "agent": "task", "task": "task", "todowrite": "todowrite", "skill": "skill"}
notes = []

def items(spec):
    """Comma-separated specifiers, commas inside parentheses kept."""
    out, depth, cur = [], 0, ""
    for ch in spec or "":
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            out.append(cur.strip()); cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return [i for i in out if i and i != "null"]

def parse(item):
    m = re.match(r"^([A-Za-z_]+)(?:\((.*)\))?$", item)
    if not m:
        return None, None
    return m.group(1), (m.group(2) or "")

perm = {}
if mode == "read-only":
    perm.update({"edit": "deny", "write": "deny", "bash": "deny", "task": "deny"})

def bash_rules(default):
    cur = perm.get("bash")
    if not isinstance(cur, dict):
        cur = {"*": cur if isinstance(cur, str) else default}
    perm["bash"] = cur
    return cur

allow_items = items(allowed)
if allow_items:
    perm["*"] = "deny"
    for item in allow_items:
        name, pattern = parse(item)
        tool = TABLE.get((name or "").lower())
        if tool is None:
            notes.append("allowed_tools: " + item + " is not a tool OpenCode has; ignored")
            continue
        if tool == "bash" and pattern:
            bash_rules("deny")[pattern] = "allow"
        elif pattern:
            notes.append("allowed_tools: " + item + " ignored (OpenCode takes patterns on bash only; the tool stays closed)")
        elif perm.get(tool) != "deny":
            perm[tool] = "allow"
for item in items(disallowed):
    name, pattern = parse(item)
    tool = TABLE.get((name or "").lower())
    if tool is None:
        notes.append("disallowed_tools: " + item + " is not a tool OpenCode has; ignored")
        continue
    if tool == "bash" and pattern:
        bash_rules("allow")[pattern] = "deny"
    else:
        if pattern:
            notes.append("disallowed_tools: " + item + " widened to the whole tool (OpenCode takes patterns on bash only)")
        perm[tool] = "deny"
print(json.dumps({"share": "disabled", "permission": perm}))
for n in notes:
    print(n)
PY
}

# The launch line of an OpenCode run, into PLATFORM_ARGV. Every flag was
# measured; the comments say where. The permission block does not travel
# here: it is OPENCODE_CONFIG_CONTENT in the run's environment.
platform_argv_opencode() { # platform_argv_opencode <resume-sid> <run_cwd> <model> <effort> <prompt> <title>
  local resume_sid="$1" run_cwd="$2" model="$3" effort="$4" prompt="$5" title="${6:-}"
  # --format json: the events (01). --pure: the operator's plugins out (one
  # rewrote `ls` to `rtk ls`: 02/03); the skills stay (26, 27). --auto: an
  # `ask` auto-rejected would END the turn (04, 18). --print-logs at ERROR:
  # silent on a healthy run, and the only place the reason of an
  # UnknownError appears (09b, 30).
  PLATFORM_ARGV=(run --format json --pure --auto --print-logs --log-level ERROR -m "$model")
  # The effort is the model's variant (11); validated by the caller, because
  # the CLI accepts anything in silence (11b).
  [ -n "$effort" ] && PLATFORM_ARGV+=(--variant "$effort")
  # --dir on every launch: the run's cwd (07), and on a resume the ONLY
  # directory the session can be resumed from (08b vs 08c).
  PLATFORM_ARGV+=(--dir "$run_cwd")
  if [ -n "$resume_sid" ]; then
    PLATFORM_ARGV+=(-s "$resume_sid")
  else
    # A title of our own saves the CLI a model call per session (30).
    [ -n "$title" ] && PLATFORM_ARGV+=(--title "$title")
  fi
  # `--` before the prompt, as the other two launches do (33).
  PLATFORM_ARGV+=(-- "$prompt")
}

# The normalizer a platform's stream goes through, or nothing: what run_job
# asks to choose the FIFO launch, instead of naming a platform.
platform_normalizer() { # platform_normalizer <platform> -> a script path, or nothing
  case "$1" in
    openai)   printf '%s' "$BIN_DIR/platforms/openai_stream.py" ;;
    opencode) printf '%s' "$BIN_DIR/platforms/opencode_stream.py" ;;
    *) : ;;
  esac
}

# The model an OpenCode session actually ran on, out of `opencode export`
# (measured 14: info.model.providerID + "/" + info.model.id). The export
# needs the session's own directory (the run's cwd, still there at the end
# of the run) and a deadline: a CLI that hangs must not hang the close.
opencode_export_model() { # opencode_export_model <run_cwd> <session-id> -> provider/model, or nothing
  local cwd="$1" sid="$2" doc got
  [ -n "$sid" ] && [ -d "$cwd" ] || return 0
  doc="$(cd "$cwd" && run_bounded 30 "$(platform_bin opencode)" export "$sid" 2>/dev/null)" || return 0
  got="$(printf '%s' "$doc" | "$JQ" -r '.info.model | select(type == "object") | select((.providerID // "") != "" and (.id // "") != "") | .providerID + "/" + .id' 2>/dev/null)"
  [ -n "$got" ] && printf '%s' "$got"
  return 0
}
```

`platform_finish` ganha o quinto argumento e o ramo:

```bash
platform_finish() { # platform_finish <platform> <streamfile> <session-id> [job-id] [run_cwd]
  PF_MODEL_ID=""; PF_ROLLOUT=""
  local tid="${3:-}" id="${4:-run}"
  case "$1" in
    openai) ;;
    opencode)
      [ -n "$tid" ] || return 0
      PF_MODEL_ID="$(opencode_export_model "${5:-}" "$tid")"
      [ -n "$PF_MODEL_ID" ] || log_tick "$id: opencode export gave no model for session $tid — model_id stays the requested id"
      return 0 ;;
    *) return 0 ;;
  esac
  [ -n "$tid" ] || return 0
  … (o corpo OpenAI de hoje, inalterado)
```

- [ ] **Step 5: Correr o selftest**

Correr: `bash bin/agentloop selftest 2>&1 | tail -3`
Esperado: `7NN passed, 0 failed`. Se um `case` novo estiver dentro de `$( )` o selftest morre a meio com um erro de sintaxe estranho: verificar `opencode_config_content` (o `case`… não há; o heredoc só tem python com aspas duplas) e `platform_normalizer` (chamada em `$( )`, definida fora: seguro).

- [ ] **Step 6: CHANGELOG e commit**

Sub-ponto:

```markdown
  - The table: `opencode` is a running platform (`platform_known`), with
    two permission modes that say what the CLI enforces (`full-access`, the
    default, and `read-only`: there is no sandbox, so no "workspace" mode
    that would promise one), the model's own `variants` as its effort
    vocabulary (validated here: the CLI accepts anything in silence), the
    job's `allowed_tools`/`disallowed_tools` translated into the permission
    block the run is launched with (`Agent` closes `task`, `Bash(git push
    *)` is a bash rule, deny wins), the launch line measured flag by flag
    (`--pure --auto --print-logs --log-level ERROR --dir --title`), and
    `platform_finish` reading the model that ran from `opencode export`.
    `platform_normalizer` is what the launch now asks for, and
    `prepare_inline` the capability that says which platform lets the
    security agent run `prepare` itself.
```

```bash
/usr/bin/git add bin/agentloop CHANGELOG.md
/usr/bin/git commit -m "feat(opencode): the platform table learns opencode

The registry runs three platforms; opencode gets a branch in every
function: two honest permission modes (full-access, read-only: no sandbox
to promise more), the model's variants as its effort vocabulary, the
catalog as the model gate, the job's tool lists translated into the
permission block (Agent closes task, Bash patterns become bash rules, deny
wins, share disabled always), the launch line measured flag by flag, and
the model that ran read from opencode export at the close. run_job will ask
platform_normalizer for the FIFO launch instead of naming a platform, and
prepare_inline says which platform lets the security agent run prepare.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
/usr/bin/git push
```

Correr as quatro suites. O e2e continua 99/0 (o `run_job` ainda não lança `opencode`; um job `opencode` é recusado por `platform_enabled` com a fixture que o desliga).

---

### Task 5: O lançamento: `run_job` pergunta pelo normalizador, as recusas, o bloco no ambiente, o fim do run, e os cenários e2e

**Files:**
- Modify: `bin/agentloop` (`run_job`: as recusas ~9690–9716, `run_env` ~9901, o `prepare` pelo motor ~10226, o ramo FIFO ~10244–10262, `platform_finish` ~10500, o tecto ~10620)
- Modify: `test/e2e.test.sh` (cenários 29–40, a fixture de `platforms.json`, `mkjob_opencode`)
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: T4 (`platform_normalizer`, `platform_argv_opencode`, `opencode_config_content`, `platform_finish … <run_cwd>`, `platform_caps … prepare_inline`, `opencode_catalog_tools`), T2 (o normalizador com `--catalog`), T1 (`test/fake-opencode`).
- Produces: um run OpenCode de ponta a ponta pelo `tick`/`run`/`resume`/`stop`; o journal com `platform: opencode`, `cost_basis`, `tokens`, `model_id` do export; a nota "max_budget_usd $X not applied" para as três plataformas; `AL_PLATFORM=opencode` e `OPENCODE_CONFIG_CONTENT` no ambiente do CLI.

- [ ] **Step 1: A fixture e o helper do e2e, e os cenários, para os ver falhar**

Em `test/e2e.test.sh`, a fixture de `platforms.json` no topo passa a ligar o OpenCode com dois modelos:

```bash
cat > "$ROOT/config/platforms.json" <<'JSON'
{"platforms":{"anthropic":{"enabled":true,"bin":"","models":["claude-opus-5"]},
              "openai":{"enabled":true,"bin":"","models":["gpt-5.6-sol"]},
              "opencode":{"enabled":true,"bin":"","models":["opencode/big-pickle","pdm_ai/glm-5.3-flash"]}}}
JSON
```

No fim do ficheiro (antes de qualquer resumo final `echo; echo "  $pass passed, $fail failed"`), os cenários novos. Primeiro o catálogo e o helper:

```bash
# ------------------------------------------------------- the OpenCode platform
# The same lifecycle over the OpenCode stand-in: the run goes down a FIFO
# into opencode_stream.py, the classifier reads the normalized stream, the
# stand-in's `export` supplies the model that ran, and the permission block
# travels in OPENCODE_CONFIG_CONTENT (read back through FAKE_CONFIG_OUT).
"$AL" resolve-models opencode >/dev/null 2>&1
jq -e '.opencode.models | length == 13' "$ROOT/config/models.json" >/dev/null \
  && ok "resolve-models opencode wrote the catalog from the stand-in's models --verbose" \
  || bad "no opencode catalog after resolve-models"
mkjob_opencode() { # mkjob_opencode <id> [permission] [model] [extra-json-fields]
  printf '{"jobs":[{"id":"%s","project":"sandbox","enabled":false,"platform":"opencode","model":"%s","effort":"high","prompt":"do the thing",
    "interval_seconds":3600,"permission_mode":"%s","max_parallel":1%s}]}\n' "$1" "${3:-pdm_ai/glm-5.3-flash}" "${2:-full-access}" "${4:-}" \
    > "$ROOT/config/jobs.json"
  mkdir -p "$ROOT/config/prechecks"
  printf '#!/bin/bash\nexit 0\n' > "$ROOT/config/prechecks/$1.sh"
  chmod +x "$ROOT/config/prechecks/$1.sh"
}

echo
echo "29. an OpenCode run goes through the stand-in and reads as a clean success"
mkjob_opencode j29 full-access opencode/big-pickle
FAKE_MODE=complete FAKE_SESSION=ses_clean "$AL" run j29 >/dev/null 2>&1
sleep 2
[ -z "$(dirs j29)" ] && ok "its run directory is gone (declared ending, nothing undelivered)" || bad "left $(dirs j29)"
[ "$(lastrun | jq -r .status)" = "success" ] && ok "status success: nothing on stderr, a result on the stream" || bad "status $(lastrun | jq -r .status): $(lastrun | jq -r .note)"
[ "$(lastrun | jq -r .session)" = "ses_clean" ] && ok "the session recorded is the sessionID" || bad "session $(lastrun | jq -r .session)"
[ "$(lastrun | jq -r .model_id)" = "opencode/big-pickle-real" ] \
  && ok "model_id is the model the export says ran, not the id asked for" || bad "model_id $(lastrun | jq -r .model_id)"
[ "$(lastrun | jq -r .platform)" = "opencode" ] && ok "the journal names the platform" || bad "platform $(lastrun | jq -r .platform)"
[ "$(lastrun | jq -r .cost_basis)" = "none" ] && [ "$(lastrun | jq -r .cost)" = "0" ] \
  && ok "a model the catalog prices at zero records an UNKNOWN cost, never a free one" || bad "cost $(lastrun | jq -c '{cost,cost_basis}')"
[ "$(lastrun | jq -r '.tokens.input')" = "11974" ] && [ "$(lastrun | jq -r '.tokens.cached')" = "15488" ] \
  && ok "the token counts are the sum of the steps" || bad "tokens $(lastrun | jq -c .tokens)"
s29="$(ls "$ROOT"/data/logs/j29/*.stream.ndjson 2>/dev/null | head -1)"
[ -f "$s29.raw" ] && grep -q '"step_start"' "$s29.raw" && ok "the raw OpenCode stream is kept beside the normalized one" || bad "no .raw copy"
head -1 "$s29" | jq -e '.subtype=="init" and .platform=="opencode"' >/dev/null 2>&1 \
  && ok "the normalized stream opens with the init event" || bad "first line: $(head -1 "$s29")"
[ ! -e "$ROOT"/data/logs/j29/*.raw.fifo ] && ok "the FIFO was removed" || bad "FIFO left behind"
jq -e 'has("opencode") | not' "$ROOT/data/rate-limits.json" >/dev/null 2>&1 \
  && ok "no usage window was invented for opencode" || bad "rate-limits.json grew an opencode block"

echo
echo "30. an OpenCode run that never declares an ending keeps its tree, bound to the session"
mkjob_opencode j30
FAKE_MODE=undeclared FAKE_SESSION=ses_cut "$AL" run j30 >/dev/null 2>&1
sleep 2
d30="$(dirs j30 | head -1)"
[ -n "$d30" ] && [ "$(ended j30 "$d30")" = "open" ] && ok "kept, marked open" || bad "dir '$d30' ended '$(ended j30 "$d30")'"
[ "$(cat "$ROOT/data/worktrees/j30/$d30/.session" 2>/dev/null)" = "ses_cut" ] && ok ".session holds the sessionID" || bad ".session not bound"

echo
echo "31. a resume reattaches, and launches with -s AND --dir on the session's own directory"
argv31="$ROOT/argv-31"; dir31="$ROOT/dir-31"; rm -f "$argv31" "$dir31"
FAKE_ARGV_OUT="$argv31" FAKE_DIR_OUT="$dir31" FAKE_MODE=complete FAKE_SESSION=ses_cut "$AL" resume j30 ses_cut >/dev/null 2>&1
sleep 2
grep -q "resumed ses_cut in its own tree" "$ROOT/data/tick.log" && ok "the tick log says it reattached" || bad "no reattach line"
[ -z "$(dirs j30)" ] && ok "and the finished session took its directory with it" || bad "left $(dirs j30)"
si="$(idx_in "$argv31" -s)"; [ -n "$si" ] && [ "$(at_in "$argv31" $((si + 1)))" = "ses_cut" ] && ok "-s carries the session id" || bad "no -s: $(tr '\n' ' ' < "$argv31")"
case "$(cat "$dir31" 2>/dev/null)" in
  "$ROOT/data/worktrees/j30/$d30/"*) ok "--dir is the kept worktree the session was born in (any other directory hangs for ever: measured)" ;;
  *) bad "--dir on the resume was '$(cat "$dir31" 2>/dev/null)'" ;;
esac
[ -z "$(idx_in "$argv31" --title)" ] && ok "no --title on a resume (the session has one)" || bad "--title passed on a resume"
[ "$(lastrun | jq -r .session)" = "ses_cut" ] && [ "$(lastrun | jq -r .resumed_from)" = "ses_cut" ] && ok "the journal has the same session, resumed" || bad "$(lastrun | jq -c '{session,resumed_from}')"

echo
echo "32. work on no remote is reported for an OpenCode run too"
mkjob_opencode j32
FAKE_MODE=dirty FAKE_SESSION=ses_dirty "$AL" run j32 >/dev/null 2>&1
sleep 2
lastrun | grep -q 'UNDELIVERED' && [ -n "$(dirs j32)" ] && ok "UNDELIVERED, and the tree is kept" || bad "no UNDELIVERED note, or tree gone"

echo
echo "33. the launch line and the permission block of a fresh OpenCode run, read back off the stand-in"
argv33="$ROOT/argv-33"; cfg33="$ROOT/cfg-33"; dir33="$ROOT/dir-33"; rm -f "$argv33" "$cfg33" "$dir33"
mkjob_opencode j33 full-access pdm_ai/glm-5.3-flash ',"disallowed_tools":"Agent,Bash(git push *)"'
FAKE_ARGV_OUT="$argv33" FAKE_CONFIG_OUT="$cfg33" FAKE_DIR_OUT="$dir33" FAKE_MODE=complete FAKE_SESSION=ses_argv "$AL" run j33 >/dev/null 2>&1
sleep 1
argc33="$(awk -F'\t' '$1=="ARGC" {print $2; exit}' "$argv33")"
[ "$(at_in "$argv33" 1)" = "run" ] && [ "$(at_in "$argv33" 2)" = "--format" ] && [ "$(at_in "$argv33" 3)" = "json" ] && ok "run --format json" || bad "argv: $(tr '\n' ' ' < "$argv33")"
for f in --pure --auto --print-logs; do [ -n "$(idx_in "$argv33" "$f")" ] && ok "$f" || bad "no $f"; done
li="$(idx_in "$argv33" --log-level)"; [ "$(at_in "$argv33" $((li + 1)))" = "ERROR" ] && ok "--log-level ERROR" || bad "log level"
mi="$(idx_in "$argv33" -m)"; [ "$(at_in "$argv33" $((mi + 1)))" = "pdm_ai/glm-5.3-flash" ] && ok "-m carries the id verbatim" || bad "-m $(at_in "$argv33" $((mi + 1)))"
vi="$(idx_in "$argv33" --variant)"; [ "$(at_in "$argv33" $((vi + 1)))" = "high" ] && ok "--variant high (a variant the catalog lists for this model)" || bad "--variant"
case "$(cat "$dir33" 2>/dev/null)" in
  "$ROOT/data/worktrees/j33/"*) ok "--dir names the run's working directory" ;;
  *) bad "--dir was '$(cat "$dir33" 2>/dev/null)'" ;;
esac
ti="$(idx_in "$argv33" --title)"; case "$(at_in "$argv33" $((ti + 1)))" in "agentloop j33 "*) ok "--title names the job and the stamp" ;; *) bad "title '$(at_in "$argv33" $((ti + 1)))'" ;; esac
[ -z "$(idx_in "$argv33" -s)" ] && ok "no -s on a fresh run" || bad "-s on a fresh run"
dd="$(idx_in "$argv33" --)"; [ -n "$dd" ] && [ "$((dd + 1))" = "$argc33" ] && ok "the prompt is the one argument after --" || bad "-- at '$dd', argc $argc33"
[ "$(jq -r .share "$cfg33")" = "disabled" ] && ok "OPENCODE_CONFIG_CONTENT disables sharing" || bad "config: $(cat "$cfg33")"
[ "$(jq -c .permission "$cfg33")" = '{"task":"deny","bash":{"*":"allow","git push *":"deny"}}' ] \
  && ok "and carries the job's denylist: Agent closed task, Bash(git push *) became a bash rule" || bad "permission: $(jq -c .permission "$cfg33")"
grep -q "j33: disallowed_tools is ignored" "$ROOT/data/tick.log" && bad "the lists were called ignored on opencode" || ok "nothing calls the tool lists ignored: they are translated"
[ "$(lastrun | jq -r .status)" = "success" ] && ok "and the run went on to finish" || bad "status $(lastrun | jq -r .status)"

echo
echo "33b. read-only launches with the four denies, and a tool the table does not know is named"
cfg33b="$ROOT/cfg-33b"; rm -f "$cfg33b"
mkjob_opencode j33b read-only pdm_ai/glm-5.3-flash ',"allowed_tools":"Read,Nonesuch"'
FAKE_CONFIG_OUT="$cfg33b" FAKE_MODE=complete FAKE_SESSION=ses_ro "$AL" run j33b >/dev/null 2>&1
sleep 1
[ "$(jq -c '.permission | {edit, write, bash, task, "*": .["*"], read}' "$cfg33b")" = '{"edit":"deny","write":"deny","bash":"deny","task":"deny","*":"deny","read":"allow"}' ] \
  && ok "read-only denies edit, write, bash and task; the allowlist closes the rest and opens read" || bad "permission: $(jq -c .permission "$cfg33b")"
grep -q "j33b: allowed_tools: Nonesuch is not a tool OpenCode has; ignored" "$ROOT/data/tick.log" && ok "the unknown tool name is one line in tick.log" || bad "no note for Nonesuch"

echo
echo "34. a tool denied by rule during the run is tools_denied, like a --disallowedTools hit on Claude"
mkjob_opencode j34
FAKE_MODE=deny FAKE_SESSION=ses_deny "$AL" run j34 >/dev/null 2>&1
sleep 2
[ "$(lastrun | jq -r .status)" = "error" ] && [ "$(lastrun | jq -r .cause)" = "tools_denied" ] \
  && ok "error / tools_denied (the stream carried the denial: opencode has that capability, Codex never did)" || bad "$(lastrun | jq -c '{status,cause}')"

echo
echo "35. a rate limit is rate_limited, outside the backoff, with no window to mark"
mkjob_opencode j35
echo '{"j35":{"fail_streak":2}}' > "$ROOT/data/state.json"
FAKE_MODE=quota FAKE_SESSION=ses_quota "$AL" run j35 >/dev/null 2>&1
sleep 2
[ "$(lastrun | jq -r .status)" = "error" ] && [ "$(lastrun | jq -r .cause)" = "rate_limited" ] \
  && ok "error / rate_limited (APIError with statusCode 429)" || bad "$(lastrun | jq -c '{status,cause}')"
[ "$(jq -r '.j35.fail_streak' "$ROOT/data/state.json")" = "2" ] && ok "fail_streak untouched" || bad "streak $(jq -r '.j35.fail_streak' "$ROOT/data/state.json")"
jq -e 'has("opencode") | not' "$ROOT/data/rate-limits.json" >/dev/null 2>&1 && ok "and still no opencode window: the next run comes at the job's own interval" || bad "an opencode window appeared"

echo
echo "35b. an unknown model at run time is an error whose reason is in .err, not on the stream"
mkjob_opencode j35b
FAKE_MODE=error FAKE_SESSION=ses_err "$AL" run j35b >/dev/null 2>&1
sleep 2
[ "$(lastrun | jq -r .status)" = "error" ] && [ "$(lastrun | jq -r .cause)" = "agent_error" ] \
  && ok "error / agent_error: an UnknownError carries no status" || bad "$(lastrun | jq -c '{status,cause}')"

echo
echo "36. a stop ends an OpenCode run that will not end by itself"
mkjob_opencode j36
FAKE_MODE=hang FAKE_SESSION=ses_hang "$AL" run j36 >/dev/null 2>&1 &
w=0; while [ "$w" -lt 20 ] && ! ls "$ROOT"/data/locks/j36/*/child >/dev/null 2>&1; do sleep 1; w=$((w + 1)); done
sleep 1
"$AL" stop j36 >/dev/null 2>&1
wait
[ "$(lastrun | jq -r .status)" = "stopped" ] && ok "status stopped (waited ${w}s for the slot)" || bad "status $(lastrun | jq -r .status)"
[ ! -e "$ROOT"/data/logs/j36/*.raw.fifo ] && ok "the FIFO was removed" || bad "FIFO left behind"

echo
echo "37. a run that cannot start is refused in tick.log before it costs a slot"
mkjob_opencode j37
FAKE_OPENCODE_NO_MODELS=1 "$AL" run j37 >/dev/null 2>&1
grep -q 'j37: opencode is not ready (no usable provider' "$ROOT/data/tick.log" && ok "no provider → refused" || bad "no provider refusal line"
[ ! -d "$ROOT/data/logs/j37" ] && ok "and no log was written" || bad "a run started without a provider"
mkjob_opencode j37 full-access opencode/does-not-exist
"$AL" run j37 >/dev/null 2>&1
grep -q "j37: model 'opencode/does-not-exist' is not in the OpenCode catalog" "$ROOT/data/tick.log" && ok "unknown id → refused" || bad "no catalog refusal"
mkjob_opencode j37 full-access pdm_ai/glm-5.3-flash ',"interactive":true'
"$AL" run j37 >/dev/null 2>&1
grep -q "j37: interactive is not available on opencode" "$ROOT/data/tick.log" && ok "interactive → refused" || bad "no interactive refusal"
mkjob_opencode j37 workspace-write
"$AL" run j37 >/dev/null 2>&1
grep -q "j37: permission_mode 'workspace-write' is not an OpenCode mode" "$ROOT/data/tick.log" && ok "a Codex mode → refused (there is no sandbox to promise)" || bad "no permission refusal"
argv37="$ROOT/argv-37"; rm -f "$argv37"
mkjob_opencode j37
sed -i '' 's/"effort":"high"/"effort":"ultra"/' "$ROOT/config/jobs.json"
FAKE_ARGV_OUT="$argv37" FAKE_MODE=complete FAKE_SESSION=ses_eff "$AL" run j37 >/dev/null 2>&1
sleep 2
grep -q "j37: effort 'ultra' is not a variant of pdm_ai/glm-5.3-flash — launched without an effort" "$ROOT/data/tick.log" \
  && [ -z "$(idx_in "$argv37" --variant)" ] && ok "an effort the model does not list is dropped, said, and the run goes on" || bad "bad effort: $(grep 'j37: effort' "$ROOT/data/tick.log" | tail -1)"
[ "$(lastrun | jq -r .status)" = "success" ] && ok "and finished" || bad "status $(lastrun | jq -r .status)"

echo
echo "38. the run-end hook learns the platform, the cost basis and the tokens"
mkdir -p "$ROOT/config/hooks"
printf '#!/bin/bash\nprintf "%%s %%s %%s\\n" "$AL_PLATFORM" "$AL_COST_BASIS" "$AL_TOKENS" > "%s/hook-38.out"\n' "$ROOT" > "$ROOT/config/hooks/on-run-end.sh"
chmod +x "$ROOT/config/hooks/on-run-end.sh"
mkjob_opencode j38
FAKE_MODE=complete FAKE_SESSION=ses_hook FAKE_COST=0.0002 "$AL" run j38 >/dev/null 2>&1
sleep 3
case "$(cat "$ROOT/hook-38.out" 2>/dev/null)" in
  "opencode reported {"*'"input":11974'*) ok "AL_PLATFORM, AL_COST_BASIS and AL_TOKENS reach the hook" ;;
  *) bad "hook saw: $(cat "$ROOT/hook-38.out" 2>/dev/null)" ;;
esac
rm -f "$ROOT/config/hooks/on-run-end.sh"

echo
echo "39. a model the catalog prices records the CLI's own cost, reported"
mkjob_opencode j39
FAKE_MODE=complete FAKE_SESSION=ses_paid FAKE_COST=0.0002 "$AL" run j39 >/dev/null 2>&1
sleep 2
[ "$(lastrun | jq -r .cost_basis)" = "reported" ] && [ "$(lastrun | jq -r .cost)" = "0.0004" ] \
  && ok "cost 0.0004 reported: two steps at 0.0002, the CLI's number, not an estimate" || bad "cost $(lastrun | jq -c '{cost,cost_basis}')"

echo
echo "40. a per-run cap over an unknown cost says so instead of never firing"
mkjob_opencode j40 full-access opencode/big-pickle ',"max_budget_usd":1'
FAKE_MODE=complete FAKE_SESSION=ses_cap "$AL" run j40 >/dev/null 2>&1
sleep 2
grep -q 'j40: max_budget_usd 1 not applied: the cost of this run is unknown (no price for opencode/big-pickle-real)' "$ROOT/data/tick.log" \
  && ok "tick.log says the cap could not be applied, and why" || bad "no cap note: $(grep 'j40' "$ROOT/data/tick.log" | tail -2)"
lastrun | jq -r .note | grep -q 'max_budget_usd \$1 not applied' && ok "and so does the run's own note" || bad "note: $(lastrun | jq -r .note)"
[ "$(lastrun | jq -r .status)" = "success" ] && ok "without changing the status" || bad "status $(lastrun | jq -r .status)"
```

Correr: `bash test/e2e.test.sh 2>&1 | grep -E 'FAIL|passed'`
Esperado: os cenários 29–40 em FAIL (o `run_job` recusa `opencode` como *planned*… já não: T4 tirou-o do *planned*, por isso a recusa agora é "is not ready" ou o lançamento cai no ramo Anthropic e o stand-in recebe um argv de `claude`; seja qual for, FAIL), 1–28 verdes.

- [ ] **Step 2: As recusas por plataforma no `run_job`**

A seguir ao bloco `if [ "$platform" = "openai" ]; then … fi` das recusas (~9690–9706):

```bash
  if [ "$platform" = "opencode" ]; then
    # The CLI reads stdin as part of the PROMPT (measured 13b): there is no
    # protocol for a human to talk to a live run.
    [ "$interactive" != "true" ] \
      || { log_tick "$id: interactive is not available on opencode (opencode run has no stdin protocol: it reads stdin as part of the prompt), skipped"; return 1; }
    platform_model_ok opencode "$model" \
      || { log_tick "$id: model '$model' is not in the OpenCode catalog (run: agentloop resolve-models opencode), skipped"; return 1; }
    platform_permission_ok opencode "$permission" \
      || { log_tick "$id: permission_mode '$permission' is not an OpenCode mode (full-access, read-only), skipped"; return 1; }
    # The CLI accepts any --variant in silence (measured 11b): an effort the
    # catalog does not list for this model is dropped here, and said to be,
    # rather than passed to change nothing.
    if [ -n "$effort" ] && ! platform_effort_ok opencode "$model" "$effort"; then
      log_tick "$id: effort '$effort' is not a variant of $model — launched without an effort"
      effort=""
    fi
    # A model that makes no tool calls (the catalog says so) still runs -- a
    # prompt that needs no tool is legitimate -- but the operator is told.
    opencode_catalog_tools "$model" \
      || log_tick "$id: model '$model' makes no tool calls (catalog) — the agent can only answer in text"
  fi
```

(Confirmar os nomes das variáveis no `run_job`: `model`, `effort`, `permission`, `interactive` são os que o bloco `openai` acima já usa.)

- [ ] **Step 3: O bloco de permissões no ambiente**

A seguir a `run_env+=("AL_PLATFORM=$platform")` (~9901):

```bash
  # OpenCode takes its permission block from the environment (measured
  # 04-06, 23, 33): the job's mode and its tool lists, translated by
  # opencode_config_content. Every note the translation makes -- a tool
  # name the table does not know, a pattern widened or dropped -- goes to
  # tick.log now, before the launch, so a job that asked for something the
  # CLI cannot do learns it here rather than at its first tool call.
  if [ "$platform" = "opencode" ]; then
    local _occ _ocnote
    _occ="$(opencode_config_content "$permission" "$allowed" "$disallowed")"
    run_env+=("OPENCODE_CONFIG_CONTENT=$(printf '%s\n' "$_occ" | head -1)")
    printf '%s\n' "$_occ" | tail -n +2 | while IFS= read -r _ocnote; do
      [ -n "$_ocnote" ] && log_tick "$id: $_ocnote"
    done
  fi
```

- [ ] **Step 4: O `prepare` pelo motor, por capacidade**

A condição `if [ "$platform" = "openai" ] && [ -n "${AL_SECURITY_ANALYSIS_ID:-}" ] && [ -z "$resume_sid" ]; then` (~10226) passa a:

```bash
  if ! platform_caps "$platform" prepare_inline && [ -n "${AL_SECURITY_ANALYSIS_ID:-}" ] && [ -z "$resume_sid" ]; then
```

e a linha de sucesso `log_tick "$id: deterministic phase ran before the agent (prepare, ${_prep_secs}s) — the Codex shell tool cannot be trusted to wait for it"` passa a `… — $platform does not run it inside the agent (prepare_inline)`. O comentário de cabeçalho desse bloco ("THE DETERMINISTIC PHASE, ENGINE-SIDE, ON CODEX ONLY") ganha uma frase: OpenCode also runs it here: its bash tool waits for a command (measured 19), but that tool's own timeout was not measured and `prepare` can take minutes.

- [ ] **Step 5: O ramo de lançamento pergunta pelo normalizador**

O `if [ "$platform" = "openai" ]; then` do FIFO (~10244) e o seu corpo até `normalizer=$!` passam a:

```bash
  local normalizer_py; normalizer_py="$(platform_normalizer "$platform")"
  if [ -n "$normalizer_py" ]; then
    # A platform with a normalizer: the CLI writes its own dialect; every
    # reader here wants stream-json. The CLI's stdout goes down a FIFO into
    # the normalizer, which writes the canonical stream to $streamfile and a
    # verbatim copy to $streamfile.raw. `exec` makes the subshell BECOME the
    # CLI, so $child below is the CLI's own pid: stop (TERM), the watchdog's
    # tree_cpu_seconds and wait all keep working unchanged. `< /dev/null` is
    # what keeps both CLIs from waiting on stdin for ever (measured on each).
    rawfifo="$logfile.raw.fifo"
    rm -f "$rawfifo"; mkfifo "$rawfifo" 2>/dev/null
    local -a normargs=()
    case "$platform" in
      openai)
        platform_argv_openai "$resume_sid" "$run_cwd" "$model" "$effort" "$permission" "$prompt" \
          "$(openai_writable_roots "$run_cwd" "$run_dir")"
        normargs=(--model "$model" --permission "$permission" --cwd "$run_cwd" \
                  --pricing "$PRICING_FILE" --raw-out "$streamfile.raw") ;;
      opencode)
        platform_argv_opencode "$resume_sid" "$run_cwd" "$model" "$effort" "$prompt" "agentloop $id $stamp"
        normargs=(--model "$model" --permission "$permission" --cwd "$run_cwd" \
                  --catalog "$MODELS_FILE" --pricing "$PRICING_FILE" --raw-out "$streamfile.raw") ;;
    esac
    (
      cd "$run_cwd" || exit 1
      exec env ${run_env[@]+"${run_env[@]}"} "$cli_bin" ${PLATFORM_ARGV[@]+"${PLATFORM_ARGV[@]}"} \
        > "$rawfifo" 2> "$logfile.err" < /dev/null
    ) &
    cli_pid=$!
    "$PYTHON" -u "$normalizer_py" "${normargs[@]}" < "$rawfifo" > "$streamfile" 2>> "$logfile.err" &
    normalizer=$!
  elif [ "$interactive" = "true" ]; then
```

(`stamp` é a variável do `run_job` que nomeia o run dir, `$WORKTREES_DIR/$id/$stamp`.) Confirmar que o comentário original sobre `codex exec` fica reescrito como acima e que nada mais no ramo muda.

- [ ] **Step 6: O fim do run: `platform_finish` com o cwd, e a nota do tecto**

`platform_finish "$platform" "$streamfile" "$session" "$id"` (~10500) → `platform_finish "$platform" "$streamfile" "$session" "$id" "$run_cwd"`.

No bloco do tecto (~10620), antes do `if [ -n "$cap" ] && [ "$status" = "success" ] && awk …`:

```bash
  if [ -n "$cap" ] && [ "$cost_basis" = "none" ]; then
    # Unknown is not zero. The comparison below reads ${cost:-0}, so a run
    # whose cost nobody knows (no price for its model, on any platform)
    # would never reach 90% of anything and the cap would stay silent -- the
    # worst shape a cap can take. Say it, on the run and in tick.log, and
    # leave the status alone: the run itself did nothing wrong.
    log_tick "$id: max_budget_usd $cap not applied: the cost of this run is unknown (no price for ${model_id:-$model})"
    wdreason="${wdreason:+$wdreason; }max_budget_usd \$$cap not applied: the cost of this run is unknown (no price for ${model_id:-$model})"
  elif [ -n "$cap" ] && [ "$status" = "success" ] \
     && awk "BEGIN{exit !(${cost:-0} >= $cap * 0.9)}" 2>/dev/null; then
```

(`model_id` é a variável que o `run_job` já tem para o modelo que correu, preenchida de `PF_MODEL_ID`; confirmar o nome no código à volta de `platform_finish`.)

- [ ] **Step 7: Correr o e2e, depois o selftest**

Correr: `bash test/e2e.test.sh 2>&1 | tail -3`
Esperado: `1NN passed, 0 failed`, com os cenários 29–40 verdes. Depois `bash bin/agentloop selftest 2>&1 | tail -2` verde, e as duas suites pytest.

Se o 29 der `status error` com `cause killed` e a nota "normalizer exited 2": o normalizador não aceitou um argumento (`--catalog` é novo: conferir T2). Se o 31 pendurar: o `--dir` do resume não é a worktree retida; conferir `run_cwd` no ramo do resume.

- [ ] **Step 8: CHANGELOG e commit**

Sub-pontos:

```markdown
  - The launch: `run_job` asks `platform_normalizer` whether a platform's
    stream is translated and goes down the FIFO for either, refuses an
    OpenCode run that cannot start (no usable provider, an id outside the
    catalog, a Codex mode, `interactive`) before a slot is spent, drops an
    effort the model's catalog entry does not list (the CLI would accept it
    in silence), hands the permission block to the CLI in its environment,
    and reads the model that ran from `opencode export` at the close.
  - A per-run cap over an unknown cost now says so. `max_budget_usd`
    compared `${cost:-0}` with 90% of the cap, so a run whose cost nobody
    knows (an unpriced model, on any platform) never fired the BUDGET
    LIMITED warning and never said why; the run's note and `tick.log` now
    carry "max_budget_usd $X not applied: the cost of this run is unknown".
```

```bash
/usr/bin/git add bin/agentloop test/e2e.test.sh CHANGELOG.md
/usr/bin/git commit -m "feat(opencode): launch, refuse, translate and close an OpenCode run

run_job goes down the FIFO for any platform with a normalizer, chosen by
platform_normalizer instead of a platform name; an OpenCode run that
cannot start is refused before a slot is spent, an effort the catalog does
not list is dropped and said, the permission block travels in the CLI's
environment, the security analysis's prepare runs engine-side wherever
prepare_inline is off, and the model that ran comes from opencode export.
A per-run cap over an unknown cost, on any platform, now says it could not
be applied instead of never firing.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
/usr/bin/git push
```

---

### Task 6: O watchdog: um stream ainda vazio ao fim do stall é um run morto (commit próprio)

**Files:**
- Modify: `bin/agentloop` (`WATCHDOG_POLL` junto a `STALL_HOURS` ~2966; o loop do watchdog ~10353–10380)
- Modify: `test/fake-claude` (`FAKE_MODE=silent`)
- Modify: `test/e2e.test.sh` (cenários 41 e 41b)
- Modify: `CHANGELOG.md` (entrada própria, em `### Fixed`)

**Interfaces:**
- Consumes: nada do OpenCode. Esta tarefa toca as três plataformas e vive num commit que se reverte sozinho.
- Produces: `WATCHDOG_POLL` (`AGENTLOOP_WATCHDOG_POLL`, omissão 30); a nota `stalled: no output at all for Ns (the CLI never started answering; killed by watchdog)`; `FAKE_MODE=silent` no `fake-claude`.

- [ ] **Step 1: Os cenários e2e, e vê-los falhar**

No fim de `test/e2e.test.sh`:

```bash
echo
echo "41. a run that never writes a byte is killed at the stall timeout, whatever its CPU does"
# Measured on OpenCode (evidence 35): a hung CLI process burns ~1 CPU second
# every 75 s of idling, which the watchdog's "CPU changed" test reads as
# life for ever. A stream still EMPTY after stall_timeout_seconds is the one
# shape both measured hangs share, and no healthy run of any platform has:
# the first event is written in seconds.
mkjob j41
sed -i '' 's/"max_parallel":1/"max_parallel":1,"stall_timeout_seconds":4/' "$ROOT/config/jobs.json"
AGENTLOOP_WATCHDOG_POLL=2 FAKE_MODE=silent FAKE_SESSION=sess-silent "$AL" run j41 >/dev/null 2>&1
sleep 1
[ "$(lastrun | jq -r .status)" = "error" ] && [ "$(lastrun | jq -r .cause)" = "killed" ] \
  && ok "error / killed" || bad "$(lastrun | jq -c '{status,cause}')"
lastrun | jq -r .note | grep -q 'no output at all for 4s' && ok "the note names the rule: no output at all" || bad "note: $(lastrun | jq -r .note)"

echo
echo "41b. a run that wrote its first event and then went quiet is still judged by the old rule"
mkjob j41b
sed -i '' 's/"max_parallel":1/"max_parallel":1,"stall_timeout_seconds":4/' "$ROOT/config/jobs.json"
AGENTLOOP_WATCHDOG_POLL=2 FAKE_MODE=hang FAKE_SESSION=sess-quiet "$AL" run j41b >/dev/null 2>&1
sleep 1
lastrun | jq -r .note | grep -q 'no output and no CPU for 4s' && ok "killed by the CPU-and-output rule, not the empty-stream one" || bad "note: $(lastrun | jq -r .note)"
lastrun | jq -r .note | grep -q 'no output at all' && bad "the empty-stream rule fired on a run that had written" || ok "the empty-stream rule never touches a run that wrote a byte"
```

`mkjob` (o helper Anthropic do topo do ficheiro) escreve `"max_parallel":1}` como último campo; o `sed` acrescenta o stall a seguir.

E o caso que motivou a regra, na plataforma em que foi medido (08c, 34b): o `test/fake-opencode` ganha o modo `silent` (nunca escreve um byte, `exec sleep 600`, como o `hang` mas antes do primeiro evento), e um cenário a seguir ao 41b:

```bash
echo
echo "41c. the case that motivated the rule: an OpenCode run whose provider never answers"
mkjob_opencode j41c
sed -i '' 's/"max_parallel":1/"max_parallel":1,"stall_timeout_seconds":4/' "$ROOT/config/jobs.json"
AGENTLOOP_WATCHDOG_POLL=2 FAKE_MODE=silent FAKE_SESSION=ses_silent "$AL" run j41c >/dev/null 2>&1
sleep 1
[ "$(lastrun | jq -r .status)" = "error" ] && [ "$(lastrun | jq -r .cause)" = "killed" ] && ok "error / killed" || bad "$(lastrun | jq -c '{status,cause}')"
lastrun | jq -r .note | grep -q 'no output at all for 4s' && ok "the empty-stream rule ended it (measured 34b: the CLI itself never would)" || bad "note: $(lastrun | jq -r .note)"
[ ! -e "$ROOT"/data/logs/j41c/*.raw.fifo ] && ok "and the FIFO was removed" || bad "FIFO left behind"
```

(`mkjob_opencode` existe desde T5, que corre antes desta tarefa. No `test/fake-opencode`, o modo entra no `case "$mode" in` que trata `error`/`quota`/`reject`, antes do primeiro `step_start`: `silent) exec sleep 600 ;;`, e a lista de modos do cabeçalho e o teste `tests/test_fake_opencode.py` não mudam: um modo que nunca escreve não tem forma a fixar.)

No `test/fake-claude`, antes do bloco do `init` (o `{ printf '{"type":"system","subtype":"init"…`), o modo `silent`:

```bash
# `silent`: never write a byte, then sleep -- the shape of a CLI whose
# provider never answered, or of a resume that a CLI took to another
# directory (both measured on OpenCode). `exec` so the engine's TERM ends it.
[ "$mode" != "silent" ] || exec sleep 600
```

E a lista de modos no cabeçalho do stand-in ganha `silent`.

Correr: `bash test/e2e.test.sh 2>&1 | grep -E '^41|FAIL|passed'`
Esperado: o 41 em FAIL (hoje o `silent` é morto pela regra antiga ao fim de 4 s: a nota diz "no output and no CPU", não "no output at all"; o `sleep` do stand-in não queima CPU, por isso a regra antiga apanha-o aqui, ao contrário do processo real do OpenCode); o 41b verde já hoje.

- [ ] **Step 2: A regra no watchdog**

Junto a `STALL_HOURS` (~2966):

```bash
# How often the run watchdog looks at a run (seconds). Overridable for the
# tests only: the e2e drives a 4-second stall with a 2-second poll.
WATCHDOG_POLL="${AGENTLOOP_WATCHDOG_POLL:-30}"
case "$WATCHDOG_POLL" in ''|*[!0-9]*|0) WATCHDOG_POLL=30 ;; esac
```

No loop do watchdog: `local last_size=-1 last_cpu=-1 last_change now size cpu began poll=30` → `… began poll="$WATCHDOG_POLL"`. E, **antes** do `if [ "$stall" -gt 0 ] && [ "$((now - last_change))" -ge "$stall" ]; then` existente:

```bash
      # A stream still EMPTY this long after the launch is a dead run,
      # whatever the CPU says. Measured on OpenCode (evidence 35): a CLI
      # whose provider never answers, or a resume the CLI took to another
      # directory, hangs with no output for ever and still gains a CPU
      # second every minute or so of idling -- which the test below reads as
      # life, so the stall never fired and timeout_seconds has no default.
      # Every healthy run of every platform writes its first event within
      # seconds (Claude's init, Codex's thread.started, OpenCode's
      # step_start when the model starts answering), so this rule changes
      # the fate of no run that ever wrote a byte. A CPU floor was weighed
      # and rejected: the slowest legitimate work here (docker builds, trivy
      # pulling its policies, a clone on a bad link) burns its CPU outside
      # the run's process tree and survives today by the same tick.
      if [ "$stall" -gt 0 ] && [ "${size:-0}" -eq 0 ] && [ "$((now - began))" -ge "$stall" ]; then
        printf 'stalled: no output at all for %ss (the CLI never started answering; killed by watchdog)\n' "$stall" > "$wdfile"
        kill -TERM "$child" 2>/dev/null; break
      fi
```

- [ ] **Step 3: Correr o e2e e o selftest**

Correr: `bash test/e2e.test.sh 2>&1 | tail -3` → 41 e 41b verdes. `bash bin/agentloop selftest 2>&1 | tail -2` verde (o selftest corre o e2e por dentro).

- [ ] **Step 4: CHANGELOG, commit próprio**

Sob `## [Unreleased]`, numa secção `### Fixed` (criar a seguir a `### Added` se não existir):

```markdown
- **A run that never wrote a byte is killed at the stall timeout, whatever
  its CPU does.** The watchdog read any change of the run's CPU seconds as
  life, and a hung CLI is not still: measured on OpenCode, a process whose
  provider never answered gains about one CPU second every 75 seconds of
  idling, so the stall never fired and, with no default `timeout_seconds`,
  the run held its slot for ever. A stream still empty after
  `stall_timeout_seconds` is now a dead run, with its own note ("no output
  at all"); every healthy run of every platform writes its first event
  within seconds, so no run that ever wrote a byte is judged differently.
  A hang AFTER the first byte still rides on the CPU signal, and
  `timeout_seconds` remains the tool for it; `AGENTLOOP_WATCHDOG_POLL`
  lets the tests drive the rule in seconds.
```

```bash
/usr/bin/git add bin/agentloop test/fake-claude test/fake-opencode test/e2e.test.sh CHANGELOG.md
/usr/bin/git commit -m "fix(watchdog): a run that never wrote a byte dies at the stall timeout

The watchdog read any change of the run's tree CPU as life, and a hung CLI
is not still: measured on OpenCode, a process whose provider never
answered gains a CPU second every 75 s of idling, so the stall never fired
and, with no default timeout_seconds, the run held its slot for ever. A
stream still empty after stall_timeout_seconds is now a dead run, killed
with its own note. Every healthy run of every platform writes its first
event within seconds, so no run that ever wrote a byte is judged
differently; a CPU floor was weighed and rejected because the slowest
legitimate work here burns its CPU outside the run's tree. Its own commit,
so it can be reverted alone.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
/usr/bin/git push
```

---

### Task 7: O esquema de configuração: `set-field`, `create`, `project-set`, o job derivado, a semente

**Files:**
- Modify: `bin/agentloop` (`cmd_set_field` platform/model ~11480–11530; `cmd_create` ~11700–11730; `security_derived_jobs` ~330–380; `PLATFORMS_JQ`, `platforms_jq`, `platforms_seed` ~1303–1360; `cmd_platforms` (as duas chamadas a `platforms_jq`); selftest)
- Modify: `tests/test_platforms_api.py` (as asserções sobre o *planned*: linhas ~77–124, ~349)
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: T3 (`opencode_catalog_ensure`, `opencode_catalog_visible`, `opencode_catalog_tools`), T4 (`platform_known`, defaults).
- Produces: `set-field <id> platform opencode` aceite quando `usable`, com a reescrita dos três campos; `set-field model` validado contra o catálogo OpenCode; `create` com `platform: opencode`; `security_derived_jobs` com `platform: opencode` (e `tools: false` a cair no default com aviso); `platforms_jq <adef> <odef> <ocdef> <filter>`; a semente com `opencode` como as outras.

- [ ] **Step 1: Os casos de selftest, e vê-los falhar**

No bloco `echo "configuration — platform is a field, and model, effort and permission_mode are validated on it"` (~4407), a seguir aos casos OpenAI existentes. A fixture desse bloco escreve `models.json` com `openai:{…}`; acrescentar-lhe um bloco `opencode` (na mesma chamada `"$JQ" -n '{resolved:{}, openai:{…}, opencode:{at:1, source:"fixture", version:"1.18.30", models:[{id:"opencode/big-pickle", provider:"opencode", name:"Big Pickle", cost:{input:0,output:0,cache_read:0,cache_write:0}, priced:false, context:200000, output_limit:32000, variants:[], tools:true, reasoning:true, status:"active"}, {id:"pdm_ai/glm-5.3-flash", provider:"pdm_ai", name:"glm-5.3-flash", cost:{input:0.033011,output:0.139816,cache_read:0,cache_write:0}, priced:true, context:197144, output_limit:65000, variants:["max","high","non-think"], tools:true, reasoning:true, status:"active"}, {id:"pdm_ai/vision", provider:"pdm_ai", name:"vision", cost:{input:0,output:0,cache_read:0,cache_write:0}, priced:false, context:262000, output_limit:65000, variants:[], tools:false, reasoning:false, status:"active"}]}}'`) e o `platforms.json` dessa fixture (~4419) liga o opencode com `models:["pdm_ai/glm-5.3-flash","opencode/big-pickle"]`.

```bash
  echo "configuration — opencode is a value of platform, validated like the other two"
  printf 'opencode' | cfg_al set-field cj platform >/dev/null 2>&1; want "set-field platform opencode is accepted when Settings switched it on" 0 $?
  [ "$(cfg_al get cj | "$JQ" -r '.platform, .model, .permission_mode' | tr '\n' '|')" = "opencode|pdm_ai/glm-5.3-flash|full-access|" ] \
    && ok "and the model and the mode were rewritten to the platform's defaults (the first enabled model, full-access)" || bad "after the move: $(cfg_al get cj | "$JQ" -c '{platform,model,effort,permission_mode}')"
  printf 'opencode/big-pickle' | cfg_al set-field cj model >/dev/null 2>&1; want "set-field model takes an enabled catalog id" 0 $?
  printf 'opencode/nope' | cfg_al set-field cj model 2>&1 | grep -q "unknown OpenCode model 'opencode/nope' — the catalog lists: opencode/big-pickle pdm_ai/glm-5.3-flash pdm_ai/vision" \
    && ok "an id outside the catalog is refused, naming the catalog" || bad "no catalog refusal"
  printf 'high' | cfg_al set-field cj effort >/dev/null 2>&1; want "an effort a model without variants does not offer is refused" 1 $?
  printf 'pdm_ai/glm-5.3-flash' | cfg_al set-field cj model >/dev/null 2>&1
  printf 'high' | cfg_al set-field cj effort >/dev/null 2>&1; want "and accepted on a model that lists it" 0 $?
  printf 'read-only' | cfg_al set-field cj permission_mode >/dev/null 2>&1; want "read-only is an opencode mode" 0 $?
  printf 'workspace-write' | cfg_al set-field cj permission_mode >/dev/null 2>&1; want "workspace-write is not" 1 $?
  printf 'anthropic' | cfg_al set-field cj platform >/dev/null 2>&1
  [ "$(cfg_al get cj | "$JQ" -r '.permission_mode')" = "bypassPermissions" ] && ok "moving back rewrites read-only to the anthropic default" || bad "mode after the move back: $(cfg_al get cj | "$JQ" -r .permission_mode)"
  printf '{"id":"oc-new","platform":"opencode","prompt":"x","interval_seconds":60}' | cfg_al create >/dev/null 2>&1; want "create with platform opencode" 0 $?
  [ "$(cfg_al get oc-new | "$JQ" -r '.model, .permission_mode' | tr '\n' '|')" = "pdm_ai/glm-5.3-flash|full-access|" ] \
    && ok "a created opencode job takes the platform's defaults" || bad "created: $(cfg_al get oc-new | "$JQ" -c '{model,permission_mode}')"
```

(`cfg_al` e `cj` são o helper e o job que o bloco OpenAI já usa; `get` é o subcomando que imprime um job. Se o nome for outro, usar o que o bloco vizinho usa.)

No bloco `echo "security_derived_jobs() — the block's platform, with the same fallback-and-warn as its permission mode"` (~4575): a fixture `projects.json` ganha dois projectos, o `platforms.json` liga o opencode, e o `MODELS_FILE` desse bloco (`$tmp/cfg/config/models.json`) já traz o catálogo OpenCode acrescentado acima.

Na fixture `projects.json` (o heredoc `JSON`), duas linhas a mais antes do `]}`:

```json
 {"name":"Of","cwd":"/tmp/of","security":{"enabled":true,"platform":"opencode","model":"pdm_ai/glm-5.3-flash","effort":"high"}},
 {"name":"Og","cwd":"/tmp/og","security":{"enabled":true,"platform":"opencode","model":"pdm_ai/vision"}},
```

No `platforms.json` dessa fixture: `opencode:{enabled:true,bin:"",models:["pdm_ai/glm-5.3-flash","opencode/big-pickle"]}`.

Depois da asserção `grep -q "not enabled in Settings ('claude-sonnet-5' on anthropic) -- using opus" …`:

```bash
  [ "$(dplat security-of .platform)" = "opencode" ] && [ "$(dplat security-of .model)" = "pdm_ai/glm-5.3-flash" ] && [ "$(dplat security-of .effort)" = "high" ] \
    && [ "$(dplat security-of .permission_mode)" = "full-access" ] && [ "$(dplat security-of .disallowed_tools)" = "Agent" ] \
    && ok "an opencode block: platform, model, a variant the model lists, full-access, and Agent closed (task: deny)" || bad "Of: $(dplat security-of '{platform,model,effort,permission_mode,disallowed_tools}')"
  dplat security-of .prompt | grep -qF 'The `task` tool is closed for this run' \
    && ok "the derived job on opencode carries the by-rule subagent paragraph" || bad "Of prompt lacks the task paragraph: $(dplat security-of .prompt | grep -n task | head -2)"
  [ "$(dplat security-og .model)" = "pdm_ai/glm-5.3-flash" ] \
    && ok "a model that makes no tool calls falls back to the first enabled model that does" || bad "Og model $(dplat security-og .model)"
  grep -q "names a model that makes no tool calls ('pdm_ai/vision') -- an analysis needs tools; using pdm_ai/glm-5.3-flash" "$tmp/dplat/data/security/derivation-warnings.txt" 2>/dev/null \
    && ok "and the derivation warning says why" || bad "no tools warning: $(cat "$tmp/dplat/data/security/derivation-warnings.txt" 2>/dev/null | tail -2)"
```

(O parágrafo do prompt "The `task` tool is closed for this run" só existe depois de T9; nesta tarefa essa asserção fica em FAIL e passa em T9. Alternativa mais limpa: acrescentar a asserção do prompt em T9, não aqui.)

Correr: `bash bin/agentloop selftest 2>&1 | grep -E 'FAIL|passed'` → os casos novos em FAIL.

- [ ] **Step 2: `set-field`**

Em `platform)`: `anthropic|openai)` → `anthropic|openai|opencode)`; a linha `opencode) die "opencode is not supported yet — it arrives with the OpenCode engine" ;;` **sai**; `*) die "platform must be anthropic or openai (or empty…)"` → `"platform must be anthropic, openai or opencode (or empty, to inherit the project's)"`. A seguir ao `if [ "$eff" = "openai" ] && ! openai_catalog_ensure; then die …; fi`:

```bash
      if [ "$eff" = "opencode" ] && ! opencode_catalog_ensure; then
        die "no OpenCode catalog yet: install opencode, configure a provider, and run: agentloop resolve-models opencode"
      fi
```

Em `model)`: o `if [ "$p" = "openai" ]; then … else die "model must be a family …"` ganha o ramo:

```bash
        elif [ "$p" = "opencode" ]; then
          opencode_catalog_ensure >/dev/null 2>&1 || true
          platform_model_ok opencode "$value" \
            || die "unknown OpenCode model '$value' — the catalog lists: $(opencode_catalog_visible | tr '\n' ' ')(refresh with: agentloop resolve-models opencode)"
```

`effort)` e `permission_mode)` já validam por `platform_effort_ok`/`platform_permission_ok` da plataforma do job: confirmar lendo os ramos; nada a mudar se for assim.

- [ ] **Step 3: `create`**

`anthropic|openai) : ;;` → `anthropic|openai|opencode) : ;;`; a linha `opencode) die "create: …"` sai; `*) die "create: platform must be anthropic or openai"` → `"create: platform must be anthropic, openai or opencode"`. Depois do `if [ "$cplat" = "openai" ] && ! openai_catalog_ensure`:

```bash
  if [ "$cplat" = "opencode" ] && ! opencode_catalog_ensure; then
    die "create: no OpenCode catalog yet: install opencode, configure a provider, and run: agentloop resolve-models opencode"
  fi
```

- [ ] **Step 4: `security_derived_jobs`**

`anthropic|openai) : ;;` → `anthropic|openai|opencode) : ;;`. No ramo `if [ -z "$sdefault" ]; then`:

```bash
        if [ "$splat" = openai ] && ! openai_catalog_available; then
          security_warn "…"
        elif [ "$splat" = opencode ] && ! opencode_catalog_available; then
          security_warn "security: project '$project' runs on opencode but no OpenCode catalog is resolved yet (run: agentloop resolve-models opencode) -- the analysis will be refused at launch"
        else
```

E a seguir ao bloco "The operator's own choice, on top of the CLI's" (o `platform_model_enabled`), antes de `seffort=`:

```bash
    # An analysis needs tools: prepare's output is read with `checklist`,
    # findings are re-reported with the CLI. A model the OpenCode catalog
    # marks `tools: false` cannot do any of that; fall back to the first
    # enabled one, with the warning the other fallbacks give.
    if [ "$splat" = opencode ] && [ -n "$smodel" ] && ! opencode_catalog_tools "$smodel"; then
      local stools; stools="$(platform_models_enabled opencode | while IFS= read -r mid; do opencode_catalog_tools "$mid" && printf '%s\n' "$mid"; done | head -1)"
      security_warn "security: project '$project' names a model that makes no tool calls ('$smodel') -- an analysis needs tools; using ${stools:-nothing, the analysis will be refused at launch}"
      smodel="$stools"
    fi
```

- [ ] **Step 5: A semente e `PLATFORMS_JQ`**

`PLATFORMS_JQ`:
- `def known: if . == "openai" then "openai" else "anthropic" end;` → `def known: if . == "openai" then "openai" elif . == "opencode" then "opencode" else "anthropic" end;`
- `def valid($p; $m): if $p == "openai" then … else (…) end;` → `if $p == "openai" then ((($ocat | length) == 0) or (($ocat | index($m)) != null)) elif $p == "opencode" then ((($occat | length) == 0) or (($occat | index($m)) != null)) else (…) end;`
- `def effective($p; $m): … (if $p == "openai" then $odef else $adef end)` → `(if $p == "openai" then $odef elif $p == "opencode" then $ocdef else $adef end)`.

`platforms_jq` passa a `platforms_jq <anthropic-default> <openai-default> <opencode-default> <jq-filter> [jq options…]`: `local adef="$1" odef="$2" ocdef="$3" filter="$4"; shift 4`, `occat='[]'`, `occat="$("$JQ" -ec '[.opencode.models[]?.id]' "$MODELS_FILE" 2>/dev/null)" || occat='[]'`, e `--arg ocdef "$ocdef" --argjson occat "$occat"` na chamada ao jq. Os três callers: `platforms_seed` → `platforms_jq opus "$(openai_catalog_visible | head -1)" "$(opencode_catalog_visible | head -1)" '…'` com `{platforms: {anthropic: entry("anthropic"), openai: entry("openai"), opencode: entry("opencode")}}`; as duas chamadas em `cmd_platforms` ganham `"$(platform_default_model opencode)"` como terceiro argumento. O comentário de cabeçalho de `platforms_jq` actualizado.

**O invariante do registo contra o jq** (a forma como o contador de jobs se enganou na entrega 1: uma plataforma que o registo conhece e o `PLATFORMS_JQ` não). No mesmo bloco, antes dos casos de `set-field`:

```bash
  echo "PLATFORMS_JQ — every platform the registry runs is known to the jq, with its own model"
  local _pj _pjm
  for _pj in $PLATFORMS; do
    case "$_pj" in anthropic) _pjm="claude-opus-5" ;; openai) _pjm="gpt-a" ;; opencode) _pjm="pdm_ai/glm-5.3-flash" ;; *) _pjm="" ;; esac
    [ "$( JOBS_FILE="$tmp/cfg/config/jobs.json"; PROJECTS_FILE="$tmp/cfg/config/projects.json"; MODELS_FILE="$tmp/cfg/config/models.json"
          platforms_jq opus gpt-a pdm_ai/glm-5.3-flash '($p | known), (valid($p; $m) | tostring), effective($p; $m)' -r --arg p "$_pj" --arg m "$_pjm" | tr '\n' '|' )" = "$_pj|true|$_pjm|" ] \
      && ok "$_pj: known keeps it, valid accepts its model, effective keeps its model" \
      || bad "$_pj through PLATFORMS_JQ: $( JOBS_FILE="$tmp/cfg/config/jobs.json"; PROJECTS_FILE="$tmp/cfg/config/projects.json"; MODELS_FILE="$tmp/cfg/config/models.json"; platforms_jq opus gpt-a pdm_ai/glm-5.3-flash '($p | known), (valid($p; $m) | tostring), effective($p; $m)' -r --arg p "$_pj" --arg m "$_pjm" | tr '\n' '|' )"
  done
```

(O `case` está fora de qualquer `$( )`. A fixture `$tmp/cfg/config/models.json` desse bloco traz os catálogos OpenAI e OpenCode; o ciclo percorre `$PLATFORMS` para que uma quarta plataforma sem ramo no jq falhe aqui, com o seu nome.) E, depois de a T7 fechar, confirmar à mão o sintoma que este invariante guarda: `agentloop platforms` sobre uma config de rascunho com um job em `opencode` credita-o a `jobs_on_platform` **do opencode**, com o **seu** modelo em `jobs_using`, não a `anthropic` com `opus`.

**O caminho de actualização, com o ficheiro que uma instalação real tem hoje** (duas chaves, sem `opencode`). No mesmo bloco de selftest, depois dos casos de `create`:

```bash
  echo "upgrade path — a platforms.json without the opencode key, the file every install has today"
  mkdir -p "$tmp/up/config" "$tmp/up/data"
  printf '{"platforms":{"anthropic":{"enabled":true,"bin":"","models":["claude-opus-5"]},"openai":{"enabled":false,"bin":"","models":[]}}}\n' > "$tmp/up/config/platforms.json"
  up_al() { AGENTLOOP_CONFIG="$tmp/up/config" AGENTLOOP_DATA="$tmp/up/data" AGENTLOOP_OPENCODE_BIN="$BASE_DIR/test/fake-opencode" "$BASE_DIR/bin/agentloop" "$@"; }
  ( PLATFORMS_FILE="$tmp/up/config/platforms.json"; platforms_valid ); want "the two-key file is still a valid platforms file" 0 $?
  ( PLATFORMS_FILE="$tmp/up/config/platforms.json"; platform_enabled opencode ); want "opencode reads as DISABLED, not as an error and not as enabled by default" 1 $?
  ( PLATFORMS_FILE="$tmp/up/config/platforms.json"; platform_enabled anthropic ); want "and anthropic keeps its state" 0 $?
  [ "$(up_al platforms | "$JQ" -r '.opencode.supported, .opencode.enabled, .opencode.usable' | tr '\n' '|')" = "true|false|false|" ] \
    && ok "platforms lists the card from the registry, disabled, with no key in the file" || bad "platforms over the two-key file: $(up_al platforms | "$JQ" -c .opencode)"
  up_al platform enable opencode >/dev/null 2>&1; want "platform enable opencode writes the key that was not there (the stand-in is ready)" 0 $?
  "$JQ" -e '.platforms.opencode.enabled == true and .platforms.opencode.models == [] and .platforms.anthropic.enabled == true' "$tmp/up/config/platforms.json" >/dev/null 2>&1 \
    && ok "the file now carries the key, enabled, and the other two are untouched" || bad "after enable: $(cat "$tmp/up/config/platforms.json")"
  printf '["opencode/big-pickle"]' | up_al platform set-models opencode >/dev/null 2>&1; want "set-models writes into the new key" 0 $?
  [ "$("$JQ" -r '.platforms.opencode.models[0]' "$tmp/up/config/platforms.json")" = "opencode/big-pickle" ] && ok "and the model is on the list" || bad "models: $("$JQ" -c .platforms.opencode "$tmp/up/config/platforms.json")"
```

(`up_al` corre o engine como processo, com o catálogo a vir do stand-in: `platform enable` chama `platform_check`, e `set-models` valida contra `platform_catalog_ids`, que resolve o catálogo se faltar; se `set-models` recusar por catálogo vazio, correr `up_al resolve-models opencode >/dev/null 2>&1` antes dele.)

O caso de selftest `( pf_env; platform_enabled opencode ); want "opencode is never enabled by the seed" 1 $?` (~3554) passa a semear um job em opencode e a esperar `enabled: true`: ler o bloco `pf_env` para a fixture; escrever `{"jobs":[{"id":"oc","platform":"opencode","model":"opencode/big-pickle","enabled":true,…}]}` e `want "opencode is seeded enabled when an enabled job runs on it" 0 $?`.

- [ ] **Step 6: O pytest do servidor que pinava o *planned***

Em `tests/test_platforms_api.py` (~77–124): a asserção `assert c["reason"] == "runs on OpenCode arrive with the OpenCode engine"` passa a `assert c["supported"] is True` e `assert c["available"] is False and "opencode not installed" in c["reason"]` (o `monkeypatch.setenv("AGENTLOOP_OPENCODE_BIN", "/nonexistent/opencode")` dessa fixture continua). Ler o teste inteiro antes: a forma da entrada muda em T8 (`_opencode_platform`), por isso aqui só a razão e o `supported`; se o teste ler `available`, deixá-lo para T8.

- [ ] **Step 7: Correr o selftest e o pytest; CHANGELOG; commit**

Sub-ponto:

```markdown
  - Configuration: `platform: opencode` on a job, a project or a `security`
    block, validated like the other two (`set-field`, `create`,
    `project-set`); moving a job onto it rewrites a model, an effort or a
    mode the platform does not know to its defaults and says so; the
    derived security job refuses a model the catalog marks as making no
    tool calls; the seed treats OpenCode as it treats the others.
```

```bash
/usr/bin/git add bin/agentloop tests/test_platforms_api.py CHANGELOG.md
/usr/bin/git commit -m "feat(opencode): opencode is a value of platform in every editor path

set-field, create and the derived security job accept opencode, validate
the model against its catalog and the effort against the model's variants,
rewrite what the platform does not know to its defaults, and refuse an
analysis on a model that makes no tool calls. The seed of
config/platforms.json enables opencode when an enabled job runs on it, as
it does for the other two.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
/usr/bin/git push
```

---

### Task 8: O servidor (`/api/models.platforms.opencode`), a tabela de preços, `unpriced`, `platforms`, `status`, `usage`

**Files:**
- Modify: `bin/agentloop-server` (`PLATFORM_REGISTRY`/`PLATFORMS_PLANNED` ~70; `PLATFORM_PERMISSIONS` ~2472; nova `_opencode_platform()` a seguir a `_openai_platform()` ~2497; `jobs_using.valid` ~2681; `list_models` ~2755–2845)
- Modify: `bin/agentloop` (`opencode_unpriced` junto a `pricing_unpriced` ~2045; `cmd_platforms` ~9492; `status_platforms_block` ~11149; `cmd_usage` ~3047; `platform_models_json opencode` já feito em T3)
- Modify: `config/pricing.example.json`
- Modify: `tests/test_platforms_api.py`, `tests/test_platform_runs.py`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: T3 (o bloco `opencode` de `models.json`), T4 (`platform_permissions opencode`).
- Produces: `/api/models.platforms.opencode = {available, reason, catalog_at, models:[{v, label, provider, desc, efforts, default_effort, deprecated_by, retires_at, priced, price, tools, context}], efforts, permissions, default_model, unpriced, supported, enabled, usable, bin, bin_source, bin_found, models_enabled, jobs_on_platform, …}`; `PLATFORM_PERMISSIONS["opencode"]`; `config/pricing.example.json` com um bloco `opencode` vazio; `agentloop platforms` com `catalog_at`, `catalog_available`, `unpriced` para o opencode; a linha do `status`; a linha do `usage`.

- [ ] **Step 1: Os testes do servidor, e vê-los falhar**

Em `tests/test_platforms_api.py`, junto aos testes da forma de `/api/models` (ler `test_…_platforms_shape` ou o nome que lá estiver, ~99–130, que escreve `platforms.json` e chama `srv.list_models()`), acrescentar:

```python
def test_the_opencode_entry_reads_the_catalog_and_prices_from_it(srv, monkeypatch, tmp_path):
    cfg = Path(srv.CONFIG_DIR)
    (cfg / "models.json").write_text(json.dumps({"resolved": {}, "opencode": {
        "at": 1789226000, "source": "opencode models --verbose", "version": "1.18.30", "models": [
            {"id": "opencode/big-pickle", "provider": "opencode", "name": "Big Pickle",
             "cost": {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}, "priced": False,
             "context": 200000, "output_limit": 32000, "variants": [], "tools": True, "reasoning": True, "status": "active"},
            {"id": "pdm_ai/glm-5.3-flash", "provider": "pdm_ai", "name": "glm-5.3-flash",
             "cost": {"input": 0.033011, "output": 0.139816, "cache_read": 0, "cache_write": 0}, "priced": True,
             "context": 197144, "output_limit": 65000, "variants": ["max", "high", "non-think"], "tools": True,
             "reasoning": True, "status": "active"},
            {"id": "pdm_ai/old", "provider": "pdm_ai", "name": "old", "cost": {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0},
             "priced": False, "context": 1, "output_limit": 1, "variants": [], "tools": False, "reasoning": False, "status": "retired"}]}}))
    (cfg / "pricing.json").write_text(json.dumps({"opencode": {
        "opencode/big-pickle": {"input": 0, "cached_input": 0, "output": 0, "cache_write": 0, "source": "manual"}}}))
    (cfg / "platforms.json").write_text(json.dumps({"platforms": {
        "anthropic": {"enabled": True, "bin": "", "models": ["claude-opus-5"]},
        "openai": {"enabled": False, "bin": "", "models": []},
        "opencode": {"enabled": True, "bin": "", "models": ["pdm_ai/glm-5.3-flash"]}}}))
    monkeypatch.setenv("AGENTLOOP_OPENCODE_BIN", "/nonexistent/opencode")
    c = srv.list_models()["platforms"]["opencode"]
    assert c["supported"] is True and c["available"] is True and c["reason"] == ""
    assert c["catalog_at"] == 1789226000
    assert [m["v"] for m in c["models"]] == ["opencode/big-pickle", "pdm_ai/glm-5.3-flash"]   # retired: out
    glm = c["models"][1]
    assert glm["label"] == "glm-5.3-flash" and glm["provider"] == "pdm_ai"
    assert glm["efforts"] == ["max", "high", "non-think"] and glm["default_effort"] == ""
    assert glm["priced"] is True and glm["price"] == {"input": 0.033011, "cached_input": 0, "output": 0.139816, "cache_write": 0}
    assert glm["tools"] is True and glm["context"] == 197144
    pickle = c["models"][0]
    assert pickle["priced"] is True and pickle["price"]["input"] == 0          # the operator's manual zero row IS a price
    assert pickle["efforts"] == []
    assert c["efforts"] == ["max", "high", "non-think"]
    assert [p["v"] for p in c["permissions"]] == ["full-access", "read-only"]
    assert c["default_model"] == "pdm_ai/glm-5.3-flash" and c["usable"] is True
    assert c["unpriced"] == []


def test_an_unpriced_opencode_model_is_named(srv, monkeypatch):
    cfg = Path(srv.CONFIG_DIR)
    (cfg / "models.json").write_text(json.dumps({"resolved": {}, "opencode": {"at": 1, "source": "x", "version": "1.18.30", "models": [
        {"id": "opencode/big-pickle", "provider": "opencode", "name": "Big Pickle", "cost": {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0},
         "priced": False, "context": 1, "output_limit": 1, "variants": [], "tools": True, "reasoning": True, "status": "active"}]}}))
    (cfg / "pricing.json").write_text(json.dumps({"opencode": {}}))
    c = srv.list_models()["platforms"]["opencode"]
    assert c["models"][0]["priced"] is False and c["models"][0]["price"] is None
    assert c["unpriced"] == ["opencode/big-pickle"]


def test_without_a_catalog_and_without_the_binary_the_entry_says_so(srv, monkeypatch):
    cfg = Path(srv.CONFIG_DIR)
    (cfg / "models.json").write_text(json.dumps({"resolved": {}}))
    monkeypatch.setenv("AGENTLOOP_OPENCODE_BIN", "/nonexistent/opencode")
    c = srv.list_models()["platforms"]["opencode"]
    assert c["supported"] is True and c["available"] is False
    assert "opencode not installed" in c["reason"]
    assert c["models"] == [] and c["permissions"] and c["permissions"][0]["v"] == "full-access"


def test_a_two_key_platforms_file_still_lists_the_opencode_card_disabled(srv, monkeypatch):
    # The file every install has today has no opencode key; the card comes
    # from the registry and reads disabled, never as an error.
    cfg = Path(srv.CONFIG_DIR)
    (cfg / "platforms.json").write_text(json.dumps({"platforms": {
        "anthropic": {"enabled": True, "bin": "", "models": ["claude-opus-5"]},
        "openai": {"enabled": False, "bin": "", "models": []}}}))
    (cfg / "models.json").write_text(json.dumps({"resolved": {}}))
    monkeypatch.setenv("AGENTLOOP_OPENCODE_BIN", "/nonexistent/opencode")
    out = srv.list_models()
    c = out["platforms"]["opencode"]
    assert c["supported"] is True and c["enabled"] is False and c["usable"] is False
    assert c["models_enabled"] == [] and out["error"] in ("", None)
    assert out["platforms"]["anthropic"]["enabled"] is True


def test_the_server_permission_lists_match_the_engine_for_opencode(srv):
    # The engine is the authority on the vocabulary; the server mirrors it.
    # tests/test_platforms_api.py already pins anthropic and openai this way
    # (read that test and call the engine exactly as it does; the shape below
    # is the plain `agentloop platforms` call).
    env = {**os.environ, "AGENTLOOP_CONFIG": str(srv.CONFIG_DIR), "AGENTLOOP_DATA": str(srv.DATA_DIR),
           "AGENTLOOP_OPENCODE_BIN": "/nonexistent/opencode"}
    out = subprocess.run([str(REPO / "bin" / "agentloop"), "platforms"], capture_output=True, text=True, env=env, timeout=60)
    engine = json.loads(out.stdout)
    assert [p["v"] for p in srv.PLATFORM_PERMISSIONS["opencode"]] == engine["opencode"]["permissions"]
```

(`REPO`, `os`, `subprocess`, `json` e `Path` importados como o ficheiro já faz.)

As asserções antigas sobre o *planned* nesse ficheiro (`c["reason"] == "runs on OpenCode arrive with the OpenCode engine"`, `supported` falso) mudam para o que T7 já descreveu: `supported is True`, `available is False`, "opencode not installed" na razão.

Em `tests/test_platform_runs.py` (~200 linhas): ler; se pinar `platform in ("anthropic","openai")` em algum sítio, alargar a `opencode`. Se não, nada.

Correr: `python3.13 -m pytest tests/test_platforms_api.py -p no:cacheprovider -q` → os novos em FAIL (`KeyError: 'available'`… ou `supported False`).

- [ ] **Step 2: O servidor**

`PLATFORMS_PLANNED = ()` (com o comentário "none today; the tuple stays for the next planned platform").

`PLATFORM_PERMISSIONS` ganha:

```python
    "opencode": [
        {"v": "full-access", "label": "full-access — every tool, no approvals (the worktree is the isolation)"},
        {"v": "read-only", "label": "read-only — no edit, write, bash or subagents"},
    ],
```

(as etiquetas seguem a forma das vizinhas, travessão incluído, porque é a convenção dessa lista).

`_opencode_platform()`, a seguir a `_openai_platform()`:

```python
def _opencode_platform():
    """The opencode entry of /api/models, from config/models.json's `opencode`
    block (written by `resolve-models opencode`). Missing altogether, it is
    resolved ONCE, synchronously, when the CLI exists (about a second:
    `opencode models --verbose` reads the CLI's own cache); without the CLI
    the answer is `available: false` and the reason. A model is `priced`
    when the CLI's catalog prices it OR the operator's table carries a row
    for it -- a manual row of zeros is a price (a declared free model); a
    catalog of zeros is not (measured: a provider with no cost configured
    lists the same zeros as a free one)."""
    path = CONFIG_DIR / "models.json"

    def block():
        try:
            return (json.loads(path.read_text()) or {}).get("opencode")
        except Exception:  # noqa: BLE001
            return None

    b = block()
    if b is None:
        exe = _env("OPENCODE_BIN") or shutil.which("opencode") or \
            ("/opt/homebrew/bin/opencode" if os.path.exists("/opt/homebrew/bin/opencode") else None)
        if exe:
            al(["resolve-models", "opencode"])
            b = block()
    empty = {"models": [], "efforts": [], "permissions": PLATFORM_PERMISSIONS["opencode"],
             "default_model": "", "unpriced": []}
    if not isinstance(b, dict) or not isinstance(b.get("models"), list):
        reason = (b or {}).get("reason") if isinstance(b, dict) else None
        return {"available": False, "reason": reason or "opencode not installed: install it, configure a provider, then agentloop resolve-models opencode",
                "catalog_at": (b or {}).get("at", 0) if isinstance(b, dict) else 0, **empty}
    try:
        table = json.loads((CONFIG_DIR / "pricing.json").read_text()) or {}
    except Exception:  # noqa: BLE001
        table = {}
    rows = table.get("opencode") if isinstance(table, dict) else None
    rows = rows if isinstance(rows, dict) else {}

    def _num(v):
        return isinstance(v, (int, float)) and not isinstance(v, bool)

    def price_of(m):
        cost = m.get("cost") if isinstance(m.get("cost"), dict) else {}
        if m.get("priced") is True:
            return {"input": cost.get("input", 0), "cached_input": cost.get("cache_read", 0),
                    "output": cost.get("output", 0), "cache_write": cost.get("cache_write", 0)}
        row = rows.get(m.get("id"))
        if not isinstance(row, dict) or not all(_num(row.get(k)) for k in ("input", "cached_input", "output")):
            return None
        return {"input": row["input"], "cached_input": row["cached_input"], "output": row["output"],
                "cache_write": row.get("cache_write") if _num(row.get("cache_write")) else 0}

    def _model(m):
        price = price_of(m)
        return {"v": m["id"], "label": m.get("name") or m["id"], "provider": m.get("provider") or "",
                "desc": "", "efforts": list(m.get("variants") or []), "default_effort": "",
                "deprecated_by": "", "retires_at": "", "priced": price is not None, "price": price,
                "tools": m.get("tools") is not False, "context": m.get("context") or 0}

    models = [_model(m) for m in b["models"] if isinstance(m, dict) and m.get("id") and m.get("status", "active") == "active"]
    efforts, seen = [], set()
    for m in models:
        for e in m["efforts"]:
            if e not in seen:
                seen.add(e); efforts.append(e)
    return {"available": True, "reason": "", "catalog_at": b.get("at", 0),
            "models": models, "efforts": efforts, "permissions": PLATFORM_PERMISSIONS["opencode"],
            "default_model": models[0]["v"] if models else "",
            "unpriced": [m["v"] for m in models if not m["priced"]]}
```

Em `list_models`: `catalog_slugs` é o conjunto dos slugs OpenAI; acrescentar `opencode_ids = {m["id"] for m in (odata_oc.get("models") or []) if isinstance(m, dict) and m.get("id")}` lido do mesmo `data` (o bloco `opencode`), e passar aos `platform_entry`/`jobs_using` para o opencode. A assinatura de `jobs_using(p, jobs, projects, resolved, default, catalog_slugs)` mantém-se: o caller passa `catalog_slugs` para `openai` e `opencode_ids` para `opencode`; `valid(m)` ganha `if p == "opencode": return not catalog_slugs or m in catalog_slugs` antes do ramo anthropic. A entrada:

```python
    opencode = _opencode_platform()
    opencode.update(platform_entry("opencode", cfg, jobs, projects, resolved, opencode_ids))
    opencode["default_model"] = (opencode["models_enabled"] or [""])[0]
```

(o `default_model` como as outras: o primeiro activado). `_job_platform` já aceita qualquer chave de `PLATFORM_PERMISSIONS`.

- [ ] **Step 3: A tabela de preços, `unpriced`, `platforms`, `status`, `usage`**

`config/pricing.example.json` ganha, depois do bloco `openai`:

```json
  "_opencode_note": "OpenCode prices a run itself from its own catalog (models.dev) when the model has a price there. Rows here price the models it does not: a custom provider's, keyed by provider/model. A row of zeros declares a model free; a model with no row and no catalog price records cost_basis none and the dollar caps do not see its spend.",
  "opencode": {}
```

(o `_note` do topo continua a falar do refresh OpenAI; o `resolve-pricing` não toca no bloco `opencode`).

Em `bin/agentloop`, a seguir a `pricing_unpriced`:

```bash
opencode_unpriced() { # the enabled opencode ids with no price in the catalog nor in the table, one per line
  local m
  for m in $(platform_models_enabled opencode); do
    opencode_catalog_priced "$m" && continue
    [ -s "$PRICING_FILE" ] && "$JQ" -e --arg m "$m" '.opencode[$m] | (.input|type) == "number" and (.cached_input|type) == "number" and (.output|type) == "number"' \
      "$PRICING_FILE" >/dev/null 2>&1 && continue
    printf '%s\n' "$m"
  done
}
```

`cmd_platforms`: o `if [ "$p" = "openai" ]; then efforts=…` ganha `elif [ "$p" = "opencode" ]; then efforts="$(opencode_catalog_all_efforts | "$JQ" -R . | "$JQ" -sc .)"`; e o bloco `if [ "$p" = "openai" ]; then cat_at=…` ganha:

```bash
    elif [ "$p" = "opencode" ]; then
      cat_at="$(num "$("$JQ" -r '.opencode.at // 0' "$MODELS_FILE" 2>/dev/null)")"
      opencode_catalog_available && cat_ok=true
      unpriced="$(opencode_unpriced | "$JQ" -R . | "$JQ" -sc .)"
    fi
```

e o jq final `+ (if $p == "openai" then {…} else {} end)` passa a `+ (if $p == "openai" then {…} elif $p == "opencode" then {catalog_at:$cat_at, catalog_available:$cat_ok, unpriced:$unpriced} else {} end)`. As duas chamadas a `platforms_jq` já levam o terceiro default (T7).

`status_platforms_block`: a seguir ao `if [ "$p" = "openai" ]; then … fi` do fim da linha:

```bash
    if [ "$p" = "opencode" ]; then
      local nu
      nu="$(opencode_unpriced | tr '\n' ' ' | sed 's/ *$//')"
      printf '; catalog %s (%s models); unpriced: %s' \
        "$(age_label "$("$JQ" -r '.opencode.at // 0' "$MODELS_FILE" 2>/dev/null)")" \
        "$(opencode_catalog_visible 2>/dev/null | grep -c . || true)" "${nu:-none}"
    fi
```

`cmd_usage`: no `for p in $PLATFORMS; do`, primeira linha do corpo:

```bash
      if [ "$p" = "opencode" ]; then
        echo "opencode: no usage windows — each provider has its own API, and nothing on the stream or in the export reports one"
        continue
      fi
```

- [ ] **Step 4: Os casos de selftest de `platforms`, `status` e `usage`**

Junto aos casos de `rl_gate` (procurar `echo "rl_gate() —`), um caso: `rl_gate opencode >/dev/null 2>&1; want "rl_gate opencode never holds a run back: there are no windows" 1 $?` (o jq de `rl_gate` sai com 4 sem bloco; qualquer código diferente de 0 é "deixa passar", e o `want` compara com o código real: usar `[ $? -ne 0 ]` se o código não for 1: `if rl_gate opencode >/dev/null 2>&1; then bad "rl_gate held an opencode run back"; else ok "rl_gate opencode never holds a run back: there are no windows"; fi`).

No bloco onde `_pl="$(pc_al platforms)"` é lido (~3826), acrescentar à asserção existente `.opencode.supported == true and (.opencode | has("unpriced"))`. No bloco do `status` (~4187–4201), com o `platforms.json` a ligar o opencode e `AGENTLOOP_OPENCODE_BIN` no stand-in, a linha esperada passa a começar por `opencode  : enabled — 1.18.30, 0 credentials · providers: opencode, pdm_ai; ` (conferir o resto no output e fixar).

- [ ] **Step 5: Correr tudo; CHANGELOG; commit**

`python3.13 -m pytest tests -p no:cacheprovider -q --ignore=tests/security` e o selftest verdes.

Sub-ponto:

```markdown
  - `/api/models` carries the OpenCode catalog per model: the provider, the
    price per million (the CLI's own, or the operator's row in
    `config/pricing.json`'s new `opencode` block, or none), the variants as
    the effort ladder, whether the model makes tool calls. `agentloop
    platforms`, `status` and `usage` say what they say for the other two,
    OpenCode's way: the catalog's age, the enabled models still unpriced,
    and that there are no usage windows to wait for.
```

```bash
/usr/bin/git add bin/agentloop bin/agentloop-server config/pricing.example.json tests/test_platforms_api.py tests/test_platform_runs.py CHANGELOG.md
/usr/bin/git commit -m "feat(opencode): the server and the terminal see the third platform

/api/models carries the OpenCode catalog per model (provider, the CLI's
price or the operator's row, the variants as efforts, tool calls), the two
modes, the enabled models still unpriced; platforms, status and usage
answer for opencode the way they do for the other two.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
/usr/bin/git push
```

---

### Task 9: A análise de segurança em OpenCode

**Files:**
- Modify: `bin/agentloop` (`security_prompt` ~629–700; `cmd_skills` status text)
- Modify: `test/e2e.test.sh` (cenário 42)
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: T5 (o `prepare` pelo motor via `prepare_inline`; o lançamento), T7 (`security_derived_jobs` com `platform: opencode` e `disallowed_tools: Agent` → `task: deny` pelo bloco).
- Produces: o ramo `opencode` de `security_prompt`; o cenário e2e da análise completa.

- [ ] **Step 1: O cenário e2e, e vê-lo falhar**

```bash
echo
echo "42. a security analysis on OpenCode goes through the stand-in, closes task by rule, and closes done"
jq --arg cwd "$ROOT/work/app" '.projects += [{"name":"sandbox-oc","cwd":$cwd,"base":"main","worktree":{"enabled":true},
   "security":{"enabled":true,"platform":"opencode","model":"pdm_ai/glm-5.3-flash","max_budget_usd":5}}]' \
   "$ROOT/config/projects.json" > "$ROOT/projects.next" && mv "$ROOT/projects.next" "$ROOT/config/projects.json"
argv42="$ROOT/argv-42"; prompt42="$ROOT/prompt-42"; cfg42="$ROOT/cfg-42"; rm -f "$argv42" "$prompt42" "$cfg42"
out42="$(AL_SECURITY_ENGINES=off FAKE_SKIP_PREPARE=1 FAKE_ARGV_OUT="$argv42" FAKE_PROMPT_OUT="$prompt42" FAKE_CONFIG_OUT="$cfg42" \
  FAKE_MODE=complete FAKE_SESSION=ses_sec FAKE_COST=0.0002 \
  "$AL" security analyze sandbox-oc anything main quick 2>&1)"
aid42="$(secid "$out42")"
[ -n "$aid42" ] && ok "the analysis opened: $aid42" || bad "no analysis id in: $out42"
[ "$(secstate sandbox-oc "$aid42")" = "done" ] \
  && ok "and closed done: the engine ran security prepare before the agent, and the close found nothing untriaged" \
  || bad "state '$(secstate sandbox-oc "$aid42")'"
grep -q 'deterministic phase ran before the agent (prepare' "$ROOT/data/tick.log" \
  && ok "the engine ran prepare before launching opencode (prepare_inline is off)" || bad "no engine-side prepare line"
[ "$(at_in "$argv42" 1)" = "run" ] && ok "it went down the OpenCode launch line" || bad "argv: $(tr '\n' ' ' < "$argv42" 2>/dev/null)"
mi="$(idx_in "$argv42" -m)"; [ -n "${mi:-}" ] && [ "$(at_in "$argv42" $((mi + 1)))" = "pdm_ai/glm-5.3-flash" ] \
  && ok "-m carries the block's model" || bad "-m '$(at_in "$argv42" $((${mi:-0} + 1)))'"
[ "$(jq -r '.permission.task' "$cfg42")" = "deny" ] && ok "task is closed BY RULE in the permission block (Agent -> task: deny)" || bad "permission: $(jq -c .permission "$cfg42")"
[ -n "$(idx_in "$argv42" --auto)" ] && ok "--auto: full-access, the security default on opencode" || bad "no --auto"
grep -q 'The `task` tool is closed for this run' "$prompt42" && ok "the prompt says the task tool is closed, by rule" || bad "no task paragraph in the prompt"
grep -q 'security-analysis/SKILL.md' "$prompt42" && grep -q 'Invoke the `security-analysis` skill' "$prompt42" \
  && ok "and names the skill by name AND by path (the CLI reads ~/.claude/skills: measured)" || bad "the prompt lacks the skill by name or by path"
grep -q 'ALREADY RAN for this analysis' "$prompt42" && ! grep -q 'YOUR FIRST COMMAND' "$prompt42" \
  && ok "the prompt says the deterministic phase already ran" || bad "the prompt still asks the agent to run prepare"
grep -q 'Do not spawn subagents' "$prompt42" && bad "the Codex-only wording leaked into the opencode prompt" || ok "no Codex wording"
[ "$(lastrun | jq -r .id)" = "security-sandbox-oc" ] && [ "$(lastrun | jq -r .platform)" = "opencode" ] && [ "$(lastrun | jq -r .cost_basis)" = "reported" ] \
  && ok "the journal has the derived job's run on opencode, with the CLI's own cost" || bad "$(lastrun | jq -c '{id,platform,cost_basis}')"
sleep 1
```

Correr: `bash test/e2e.test.sh 2>&1 | grep -E '^42|FAIL'` → FAIL nos parágrafos do prompt (o `security_prompt` ainda trata `opencode` como anthropic ou como openai).

- [ ] **Step 2: `security_prompt`**

O `if [ "${7:-anthropic}" = "openai" ]; then … else … fi` ganha um ramo `elif [ "${7:-anthropic}" = "opencode" ]; then` entre os dois:

```bash
  elif [ "${7:-anthropic}" = "opencode" ]; then
    # The skill by NAME (the CLI lists ~/.claude/skills to the model and
    # loads one by name through its `skill` tool: measured 26, 27) AND by
    # path, so a machine where the link is missing still finds it. The
    # deterministic phase already ran engine-side (prepare_inline is off);
    # the `task` tool is closed by the permission block the derived job's
    # `disallowed_tools: Agent` translates to (measured 22), so the prompt
    # states a fact rather than pleading.
    skill_para="The deterministic phases -- secrets, dependency CVEs, SBOM, hygiene and
infrastructure-as-code misconfigurations -- ALREADY RAN for this analysis,
before you started: the engine ran \`agentloop security prepare\` in this
worktree. Do not run it again; the skill file's first step is done.
Invoke the \`security-analysis\` skill (your \`skill\` tool lists it; the file
is \`$SKILLS_DIR/security-analysis/SKILL.md\`) and follow the rest of it exactly.
It is mandatory."
    prepare_para="The coverage note of that deterministic phase is on the analysis
(\`agentloop security checklist --analysis $5\` prints it as coverage_note); if
it is not empty you must repeat it in your final message."
    agents_para="The \`task\` tool is closed for this run, by rule: there are no subagents.
Two earlier analyses spent their whole budget fanning the SAST pass out to six
subagents and triaged none of the deterministic findings -- which is the part
that matters most. Do the work yourself, in this one session, and spend the
budget on triage first."
```

O comentário de cabeçalho da função ganha uma frase sobre o OpenCode. Confirmar que o selftest de `security_derived_jobs` (T7) que procura `The \`task\` tool is closed for this run` passa agora.

`cmd_skills` (status): onde diz para onde as skills estão linkadas, acrescentar a frase "OpenCode reads ~/.claude/skills too (measured), so the same link serves both CLIs". Ler a função e pôr a frase no `echo` do estado, sem mudar os destinos.

- [ ] **Step 3: Correr o e2e e o selftest; CHANGELOG; commit**

Sub-ponto:

```markdown
  - Security analyses run on OpenCode: the derived job's `Agent` in
    `disallowed_tools` closes the `task` tool by rule, `prepare` runs
    engine-side before the agent (the tool's own timeout was not measured
    and `prepare` can take minutes), and the prompt names the skill by name
    and by path. Nothing new to link: OpenCode reads `~/.claude/skills`.
```

```bash
/usr/bin/git add bin/agentloop test/e2e.test.sh CHANGELOG.md
/usr/bin/git commit -m "feat(opencode): a security analysis runs on OpenCode with its subagents closed by rule

The derived job's disallowed_tools: Agent becomes task: deny in the
permission block, so the prompt states that the task tool is closed
instead of pleading; prepare runs engine-side before the agent; the skill
is named by name (the CLI lists ~/.claude/skills) and by path.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
/usr/bin/git push
```

---

### Task 10: A UI: a terceira plataforma nos editores, cartões, tabelas, modal e Settings

**Files:**
- Modify: `ui/app/editor-domain.js`, `ui/app/jobs-domain.js`, `ui/app/settings.js`, `ui/app/runs.js`, `ui/app/overview.js`, `ui/security/vocabulary.js`, `bin/dashboard.html`
- Modify: `tests/test_page_contract.py` (as asserções que pinavam o *planned*: ~3196–3211, ~3325, ~3468–3500, ~3539; e as novas)
- Modify: `bin/static/app.js`, `bin/static/app.css`, `bin/static/security.js` (pelo `bash build/build-ui.sh`, no mesmo commit)
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: T8 (`/api/models.platforms.opencode` com `models[].provider`, `models[].tools`, `price`, `efforts`, `permissions`, `supported`, `available`).
- Produces: `PLATFORM_LABELS`, `KNOWN_PLATFORMS`, `platformKey(p)`, `platformOf`, `platformLabel`, `platformOptions`, `effortsFor`, `permissionsFor`, `defaultPermissionFor`, `defaultModelFor`, `modelEnabled`, `modelOptionsFor`, `hiddenModelCount` a tratarem as três plataformas; `platformState` sem o `planned` fixo; o cartão OpenCode das Settings sem *Coming soon*; o editor com `Interactive` desligado e a nota de custo por plataforma.

- [ ] **Step 1: Os testes do contrato da página, e vê-los falhar**

Em `tests/test_page_contract.py`, os testes que fixam o mundo de duas plataformas mudam:
- ~3204–3211 (`platformOptions(p, "opencode")` → `planned` com a etiqueta "OpenCode (not supported yet)"): passa a esperar `{"v": "opencode", "label": "OpenCode", ...}` quando `opencode.usable` é `true` na carga, e `{"v":"opencode","label":"OpenCode (disabled in Settings)","flagged":True}` quando é `false` (o mesmo sufixo `DISABLED_SUFFIX` das outras; ler a constante).
- ~3325 (`platformState({platform: "opencode"}, null, P)` → `"planned"`): passa a esperar `"platform_disabled"` quando a carga traz `opencode.usable: false`, e `"ok"` quando `true`.
- ~3468–3500 (o `REGISTRY` e `P` das Settings): `opencode` entra na contagem "N of 3 platforms enabled" quando `enabled: true`.
- ~3539 (`platformJobsLine` → "runs on OpenCode are not supported yet"): passa a esperar a frase genérica ("jobs may pick this platform" / "unlocks when the session test passes"), porque `supported` é `true`.

E novos, no mesmo estilo dos vizinhos (cada um corre a função real sobre um stub, via `node`):

```python
def test_effortsFor_reads_the_opencode_models_variants():
    out = run_js("""
      const P = {opencode: {efforts: ["max","high","non-think","low"], models: [
        {v: "pdm_ai/glm-5.3-flash", efforts: ["max","high","non-think"]}, {v: "opencode/big-pickle", efforts: []}]}};
      return {glm: effortsFor("opencode", "pdm_ai/glm-5.3-flash", P),
              pickle: effortsFor("opencode", "opencode/big-pickle", P),
              none: effortsFor("opencode", "", P)};
    """)
    assert out["glm"] == ["", "max", "high", "non-think"]
    assert out["pickle"] == [""]                       # a model without variants offers only unset
    assert out["none"] == ["", "max", "high", "non-think", "low"]


def test_the_opencode_permission_and_model_defaults_mirror_the_engine():
    out = run_js("""
      const P = {opencode: {permissions: [{v: "full-access", label: "fa"}, {v: "read-only", label: "ro"}],
                            default_model: "pdm_ai/glm-5.3-flash", models_enabled: ["pdm_ai/glm-5.3-flash"],
                            models: [{v: "pdm_ai/glm-5.3-flash", label: "glm-5.3-flash", provider: "pdm_ai", priced: true},
                                     {v: "opencode/big-pickle", label: "Big Pickle", provider: "opencode", priced: false}]}};
      return {perms: permissionsFor("opencode", P).map(o => o.v),
              job: defaultPermissionFor("opencode", "job"), sec: defaultPermissionFor("opencode", "security"),
              model: defaultModelFor("opencode", P), fallback: defaultModelFor("opencode", {}),
              opts: modelOptionsFor("opencode", P, null, "").map(o => o.label),
              hidden: hiddenModelCount("opencode", P), label: platformLabel("opencode")};
    """)
    assert out["perms"] == ["full-access", "read-only"]
    assert out["job"] == "full-access" and out["sec"] == "full-access"
    assert out["model"] == "pdm_ai/glm-5.3-flash" and out["fallback"] == ""
    assert out["opts"] == ["glm-5.3-flash (pdm_ai)"]            # flat, provider named, the switched-off one hidden
    assert out["hidden"] == 1 and out["label"] == "OpenCode"


def test_platformOf_and_platformOptions_know_three_platforms():
    out = run_js("""
      const P = {anthropic: {enabled: true, usable: true}, openai: {enabled: true, usable: false}, opencode: {enabled: true, usable: true}};
      return {own: platformOf({platform: "opencode"}, null), inherited: platformOf({}, {platform: "opencode"}),
              options: platformOptions(P, "").map(o => o.v)};
    """)
    assert out["own"] == "opencode" and out["inherited"] == "opencode"
    assert out["options"] == ["anthropic", "opencode"]
```

(`run_js` é o helper que o ficheiro já usa para correr `editor-domain.js` num `node` com stub; ler o nome exacto e o modo de importação nos testes vizinhos de `effortsFor`.)

Correr: `python3.13 -m pytest tests/test_page_contract.py -p no:cacheprovider -q -k "opencode or effortsFor or platformOf"` → os novos em FAIL, os antigos alterados em FAIL.

- [ ] **Step 2: `ui/app/editor-domain.js`**

Uma constante e um helper novos no topo da zona das plataformas, e cada `platform === "openai" ? "openai" : "anthropic"` passa por eles:

```js
export const KNOWN_PLATFORMS = ["anthropic", "openai", "opencode"];
export const PLATFORM_LABELS = {anthropic: "Anthropic", openai: "OpenAI", opencode: "OpenCode"};
// The key a platform value reads /api/models under: the value itself when
// the page knows it, anthropic for anything else (a hand-edited unknown).
export function platformKey(p){ return KNOWN_PLATFORMS.includes(p) ? p : "anthropic"; }
```

- `effortsFor`: `if((platform || "anthropic") === "openai" && model){` → `if(platformKey(platform) !== "anthropic" && model){` (o OpenCode também tem esforços por modelo).
- `FALLBACK_PERMISSIONS` ganha `opencode: [{v: "full-access", label: "full-access — every tool, no approvals (the worktree is the isolation)"}, {v: "read-only", label: "read-only — no edit, write, bash or subagents"}]`.
- `permissionsFor`, `defaultModelFor`, `modelEnabled`, `modelOptionsFor`, `hiddenModelCount`: `const key = platform === "openai" ? "openai" : "anthropic";` → `const key = platformKey(platform);`. Em `defaultModelFor`: `return key === "anthropic" ? "opus" : "";` fica.
- `defaultPermissionFor`: `if(platform === "openai") return …;` mantém-se e ganha antes `if(platform === "opencode") return "full-access";`.
- `modelOptionsFor`, no ramo não-Anthropic: a etiqueta de um modelo OpenCode é `m.label + " (" + m.provider + ")"` quando `m.provider` existe, mais `" · no price"` quando `m.priced === false` (o mesmo sufixo que o OpenAI já usa), mais `" · no tools"` quando `m.tools === false`. Ler o ramo OpenAI e escrever o OpenCode ao lado dele, não em cima.
- `platformOf`: `if(own) return own === "openai" ? "openai" : "anthropic";` → `if(own) return platformKey(own);` e `if(pp === "anthropic" || pp === "openai") return pp;` → `if(KNOWN_PLATFORMS.includes(pp)) return pp;`.
- `platformLabel`: `return PLATFORM_LABELS[p] || "Anthropic";`.
- `platformOptions`: `const known = ["anthropic", "openai"];` → `const known = KNOWN_PLATFORMS;` e o caso especial `current === "opencode" ? … "(not supported yet)"` **sai**: um `opencode` desligado leva o `DISABLED_SUFFIX` como qualquer outro.

- [ ] **Step 3: `jobs-domain.js`, `settings.js`, `runs.js`, `overview.js`, `vocabulary.js`**

- `jobs-domain.js` `platformState`: a linha `if(j && j.platform === "opencode") return "planned";` sai; o `planned` só volta a existir se `entry.supported === false` (manter esse ramo se já lá estiver, senão acrescentar `if(entry && entry.supported === false) return "planned";` a seguir a `if(!entry …) return "ok";`).
- `settings.js` `REGISTRY`: `{id: "opencode", name: "OpenCode", cli: "opencode", sub: "OpenCode — opencode run --format json", mark: "OC"}`. Na zona de sessão, `(r.id === "anthropic" ? "claude auth status" : "codex login status")` → uma tabela: `{anthropic: "claude auth status", openai: "codex login status", opencode: "opencode models"}[r.id]`. Em `modelRow`: `else if(r.id === "openai" && !gone)` → `else if(r.id !== "anthropic" && !gone)`; e uma marca `no tools` quando `m.tools === false`: `if(m.tools === false) meta.appendChild(el("span", null, "no tools"));`; e o provider antes do preço quando `m.provider`: `if(m.provider) meta.appendChild(el("span", null, m.provider));`. Em `modelsSection`: `const from = r.id === "openai" ? "from codex debug models" : "from the installed CLI";` → `{anthropic: "from the installed CLI", openai: "from codex debug models", opencode: "from opencode models --verbose"}[r.id]`. Os textos "arrives with the next release", "runs on OpenCode are not supported yet", "Nothing to switch on yet — OpenCode jobs…" continuam guardados atrás de `entry.supported === false`, que agora nunca é verdade; ficam para a próxima plataforma *planned*.
- `runs.js` (~443): `el("span", "platbadge" + (plat === "openai" ? "" : " alt"), platformLabel(plat))` → `el("span", "platbadge plat-" + plat, platformLabel(plat))`, e em `ui/css/` a classe `.platbadge.plat-anthropic`, `.plat-openai`, `.plat-opencode` com as cores que hoje `.platbadge` e `.platbadge.alt` têm (a terceira: a mesma tinta do `alt`, para não inventar cor). O tooltip `(plat === "openai" ? "the Codex CLI" : "Claude Code")` → `{anthropic: "Claude Code", openai: "the Codex CLI", opencode: "the OpenCode CLI"}[plat] || plat`.
- `overview.js` (~653): `bit(plat === "openai" ? "OpenAI · " + model : model, …)` → `bit(plat === "anthropic" ? model : platformLabel(plat) + " · " + model, …)` (importar `platformLabel` de `editor-domain.js` se não estiver).
- `ui/security/vocabulary.js` (~170): `secPlatformLabel = (p) => p === "openai" ? "OpenAI" : "Anthropic"` → `({anthropic: "Anthropic", openai: "OpenAI", opencode: "OpenCode"})[p] || "Anthropic"`.

- [ ] **Step 4: `bin/dashboard.html`**

Cada `p==="openai"` / `plat==="openai"` do editor lê-se agora como "não é Anthropic" ou "é este":
- ~2555 `const pjp=(p&&p.platform==="openai")?"openai":"anthropic";` → `const pjp=ALApp.platformKey(p&&p.platform);` e ~2557 `const sp=(sec.platform==="openai"||sec.platform==="anthropic")?sec.platform:"";` → `const sp=ALApp.KNOWN_PLATFORMS.includes(sec.platform)?sec.platform:"";` (exportar `platformKey` e `KNOWN_PLATFORMS` em `ALApp`, onde as outras funções de `editor-domain.js` já são expostas).
- ~2564, ~3620–3622, ~3673–3675, ~3824: `if(splat==="openai") secEfforts=ALApp.effortsFor("openai", …)` e afins → `if(splat!=="anthropic") secEfforts=ALApp.effortsFor(splat, …)` (idem para `$("ed-platform").value`).
- ~3589 `edModelCfg.def=…||(p==="openai"?"":"opus");` → `…||(p==="anthropic"?"opus":"");`.
- ~3603–3608: `const oa=(p==="openai")` → `const noStdin=(p!=="anthropic")`, e a ajuda: `{openai: "Codex exec has no stdin protocol; runs on OpenAI end by themselves", opencode: "opencode run has no stdin protocol (it reads stdin as part of the prompt); runs on OpenCode end by themselves"}[p] || "You can interact with the agent while the job is running."`.
- ~3629–3633 `paintLimitsNote`: `if(p!=="openai"){…return;}` → `if(p==="anthropic"){…return;}`; `const m=((PLATFORMS.openai||{}).models||[])` → `((PLATFORMS[p]||{}).models||[])`; o texto por plataforma: `openai` o de hoje; `opencode`: `"Cost is what the OpenCode CLI reports from its catalog; a model without a price shows — and does not count towards dollar caps unless priced in config/pricing.json; the per-run cap is advisory on OpenCode (checked when the run ends)."`, e com `m.priced===false`: `" No price for "+model+" — dollar caps will not see this job's spend, and a max_budget_usd is not applied."`.
- ~3663–3667 (`sec-model-help`, `sec-perm-help`): `p==="openai" ? … : …` → uma tabela por plataforma com a frase OpenCode: modelo "one of the models switched on in Settings for OpenCode (provider/model)"; permissão "full-access is the default: the analysis writes the ledger through the CLI and needs bash; there is no sandbox on OpenCode".
- ~4148 (a dica de resume no modal): `((rec&&rec.platform)==="openai" ? "codex exec resume " : "claude --resume ") + sid` → `({openai: "codex exec resume ", opencode: "opencode run --dir <run dir> -s "}[(rec&&rec.platform)] || "claude --resume ") + sid`.
- ~1041 e ~1132 (ajuda estática): "Anthropic is Claude Code, OpenAI is the Codex CLI, OpenCode is the OpenCode CLI (providers you configured there)."

Depois: `bash build/build-ui.sh`. Verificar `/usr/bin/git status --short bin/static` mostra os três bundles alterados.

- [ ] **Step 5: Correr o contrato da página, o build e o selftest**

`python3.13 -m pytest tests/test_page_contract.py -p no:cacheprovider -q` → verde (o ficheiro tem ~10 000 linhas; correr inteiro). `bash bin/agentloop selftest 2>&1 | tail -2` → verde, incluindo "bin/static/app.js matches the sources it was built from".

- [ ] **Step 6: Ver com os olhos**

Um servidor de rascunho, nunca na 8787, contra uma config de rascunho com o stand-in (para não precisar do CLI real): `AGENTLOOP_CONFIG=$TMP/cfg AGENTLOOP_DATA=$TMP/data AGENTLOOP_OPENCODE_BIN=$PWD/test/fake-opencode AGENTLOOP_PORT=8799 bash bin/agentloop serve`, com `platforms.json`, `jobs.json` e `models.json` copiados da sandbox do e2e. Com a skill `dev-browser`: Settings › Platforms (o cartão OpenCode com Test, a lista de modelos com provider, preço e variantes, o interruptor), o editor de um job em OpenCode (modelo plano, esforço do modelo, os dois modos, Interactive desligado, a nota de custo), a tabela de runs com o badge, o modal de um run OpenCode. Uma captura de cada, para o PR.

- [ ] **Step 7: CHANGELOG e commit**

Sub-ponto:

```markdown
  - The dashboard: OpenCode in the Platform combo of the three editors
    (flat model list naming the provider, the model's variants as the
    effort ladder, the two modes, Interactive off, the cost note per
    platform), the badge on cards, tables and the run modal, and the
    Settings card doing what the other two do (Test, the catalog with
    provider, price, variants and "no tools", the switch) instead of
    "Coming soon".
```

```bash
/usr/bin/git add ui/app/editor-domain.js ui/app/jobs-domain.js ui/app/settings.js ui/app/runs.js ui/app/overview.js ui/security/vocabulary.js ui/css bin/dashboard.html bin/static/app.js bin/static/app.css bin/static/security.js tests/test_page_contract.py CHANGELOG.md
/usr/bin/git commit -m "feat(ui): the third platform in the editors, the tables, the modal and Settings

The page stops knowing two platforms by name: a platform key decides which
/api/models entry an editor reads, so OpenCode gets the flat model list
with its provider, the model's own effort ladder, its two modes and the
cost note, and the Settings card does what the other two do instead of
saying coming soon. Bundles rebuilt in the same commit.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
/usr/bin/git push
```

---

### Task 11: `install.sh`, o README e o CHANGELOG fechado

**Files:**
- Modify: `install.sh` (~48–51)
- Modify: `README.md` (secções *Platforms* ~823–934, *Settings* ~1615–1713, *Jobs* (a linha de `platform`, `model`, `effort`, `permission_mode` ~240–256), *Models* ~796, *Effort* ~812, *Budgets* ~560, *Security block* ~1331, *CLI* ~1779, *Tests* ~721)
- Modify: `CHANGELOG.md`

- [ ] **Step 1: `install.sh`**

A seguir ao bloco do `codex`:

```bash
if command -v opencode >/dev/null 2>&1; then
  say "✓ opencode ($(opencode --version 2>/dev/null | head -1)) — optional, for jobs on the OpenCode platform"
else
  say "· opencode — not on your PATH. Optional: only jobs with \"platform\": \"opencode\" need it (brew install opencode, or npm i -g opencode-ai; then configure a provider or use the free models)."
fi
```

- [ ] **Step 2: O README**

A tabela de *Platforms* ganha a terceira coluna, linha a linha, com as frases da spec:

| | `opencode` |
|---|---|
| CLI | OpenCode, `opencode run --format json` |
| `model` | `provider/model`, the CLI's own id, verbatim; the first slash separates the provider |
| `effort` | the model's `variants` (`high`, `max`, `non-think`, … per model); a model without variants takes none |
| `permission_mode` | `full-access`, `read-only` |
| the network | open in both modes |
| writing git history | anywhere the account can: there is no sandbox (measured: bash writes outside the directory and commits from a worktree) |
| `interactive` | no: `opencode run` reads stdin as part of the prompt |
| `allowed_tools`, `disallowed_tools` | yes, translated into the permission block the run is launched with (`Agent` closes `task`; `Bash(git push *)` is a bash rule; deny wins) |
| `max_budget_usd` | no flag: read at the end, BUDGET LIMITED; over an unknown cost the run says the cap was not applied |
| cost | **reported** by the CLI when its catalog prices the model; estimated from `config/pricing.json`'s `opencode` rows otherwise; unknown (never zero) when neither |
| usage windows | none: each provider has its own API |

E, a seguir à tabela, os parágrafos **Choosing** (`platform: opencode`; `resolve-models opencode`; a catalog refresh that fails keeps the catalog), **What a run needs** (the CLI installed and a provider usable: `opencode models` lists at least one model; the free `opencode/*-free` models need no account; `AGENTLOOP_OPENCODE_BIN`), **How an OpenCode run is read** (`bin/platforms/opencode_stream.py`; `.raw`; the session id; `--dir` on a resume, and why; the model that ran from `opencode export`; the permission block from `OPENCODE_CONFIG_CONTENT`; `--pure` and what it drops and keeps; `--title`; `--print-logs --log-level ERROR` and what lands in `.err`), **Cost** (the three bases, zero is unknown, a manual zero row declares a free model, `unpriced` in `status`), **Security analyses** (task closed by rule; prepare engine-side; skills read from `~/.claude/skills`). A secção *Settings*: o parágrafo "OpenCode, in this version, is listed and found … arrives with the OpenCode engine" **sai**, e o exemplo de `platforms.json` mostra `"opencode": {"enabled": true, "bin": "", "models": ["pdm_ai/glm-5.3-flash"]}`; o parágrafo dos modelos ganha "on OpenCode it is `opencode models --verbose`, with the provider, the price and the variants beside each id, and *no tools* on a model that makes no tool calls". *Jobs*: as quatro linhas da tabela ganham o vocabulário OpenCode. *Tests*: uma frase sobre `tests/test_opencode_stream.py` e `test/fake-opencode`. *When a run is killed*: a frase da regra nova ("a run whose stream is still empty after `stall_timeout_seconds` is killed whatever its CPU does: a CLI whose provider never answered").

Regra do repositório: nenhum `/Users/<nome>` real; `/Users/me` nos exemplos.

- [ ] **Step 3: O CHANGELOG fechado**

Reler a entrada *OpenCode engine* inteira: uma frase de abertura que diga o que mudou e o que custava não ter, os sub-pontos das tarefas por ordem, sem repetições. Acrescentar o sub-ponto final:

```markdown
  - `install.sh` names the CLI when it finds it; the README's *Platforms*
    table has its third column, and *Settings*, *Jobs*, *Models*, *Effort*,
    *Budgets*, the *Security block* and *Tests* say what OpenCode does
    differently.
```

- [ ] **Step 4: Correr tudo; commit**

As quatro suites. O selftest tem uma verificação de que o README não fala do nome antigo e de que nenhum ficheiro traz um home real.

```bash
/usr/bin/git add install.sh README.md CHANGELOG.md
/usr/bin/git commit -m "docs(opencode): the README, install.sh and the changelog entry for the third platform

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
/usr/bin/git push
```

---

### Task 12: A aceitação com o CLI real

**Files:**
- Create: `docs/superpowers/specs/2026-09-12-opencode-measurements/acceptance-job.md` e `acceptance-security.md`
- Modify: `CHANGELOG.md` (uma linha, se algo tiver de mudar por causa do que se leu)

- [ ] **Step 1: Um job de rascunho, de ponta a ponta**

Nunca contra `config/` ou `data/` reais. Um directório de rascunho `$TMP/acc` com `config/` (`platforms.json` a ligar `opencode` com `pdm_ai/glm-5.3-flash`; `jobs.json` com um job `acc-oc` em `opencode`, `pdm_ai/glm-5.3-flash`, `effort: high`, `full-access`, `worktree` desligado, `cwd` num repositório git descartável em `$TMP/acc/repo` com um ficheiro, prompt "Read README.md, then create NOTES.md with one line summarising it, commit it with the message 'acceptance', and finish with RUN COMPLETE: <what you did>") e `data/`. O `AGENTLOOP_OPENCODE_BIN` **não** é definido: o CLI real de `/opt/homebrew/bin/opencode`.

```bash
AGENTLOOP_CONFIG=$TMP/acc/config AGENTLOOP_DATA=$TMP/acc/data bash bin/agentloop resolve-models opencode
AGENTLOOP_CONFIG=$TMP/acc/config AGENTLOOP_DATA=$TMP/acc/data bash bin/agentloop run acc-oc
```

Ler, não só ver verde: `tail -1 $TMP/acc/data/runs.ndjson` (status `success`, `platform: opencode`, `cost_basis: reported`, um custo na ordem de `0.000N`, `model_id: pdm_ai/glm-5.3-flash`, `session` a começar por `ses_`); o stream normalizado (`init` primeiro, `Bash`/`Write`/`Edit` na Timeline, `result` com `tokens`); o `.raw` ao lado; `tick.log` sem nada inesperado; `NOTES.md` e o commit `acceptance` no repositório de rascunho. Depois um resume: cortar o prompt para um que peça "reply with NOTHING TO DO: nothing left" **não** serve (o resume só existe para um run aberto); em vez disso um segundo job `acc-oc-open` com um prompt que acabe sem declarar o fim ("Reply with exactly: I did some work."), `run`, confirmar o directório retido e `.session`, e `resume acc-oc-open <ses_…>` com o CLI real: o mesmo `session`, o `--dir` da worktree retida no `tick.log`, o run a acabar. Guardar em `acceptance-job.md`: os comandos, a linha do journal, as primeiras cinco e as últimas duas linhas do stream normalizado, a linha do `tick.log` do resume, com o scratchpad substituído por `/tmp/acc` e nenhum home real.

- [ ] **Step 2: Uma análise de segurança real**

No mesmo `$TMP/acc/config`, `projects.json` com um projecto `acc-sec` sobre um repositório pequeno de rascunho (um `package.json` com uma dependência antiga e um ficheiro com um segredo de exemplo `AKIAIOSFODNN7EXAMPLE`, que os scanners reconhecem como exemplo), `security: {enabled: true, platform: opencode, model: pdm_ai/glm-5.3-flash, max_budget_usd: 2}`. `agentloop security analyze acc-sec acc-sec main quick`, e ler o ledger: `security list --project acc-sec` com o estado `done` ou `capped` com razão; `prepare` correu pelo motor (a linha no `tick.log`); `checklist` consultado (as chamadas `agentloop security checklist` no stream); findings re-reportados com fingerprints; `finish` chamado. Guardar em `acceptance-security.md` o estado, a nota de cobertura, o número de findings e a linha do journal.

- [ ] **Step 3: Commit**

```bash
/usr/bin/git add docs/superpowers/specs/2026-09-12-opencode-measurements/acceptance-job.md docs/superpowers/specs/2026-09-12-opencode-measurements/acceptance-security.md
/usr/bin/git commit -m "docs(opencode): acceptance with the real CLI, read end to end

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
/usr/bin/git push
```

Se a aceitação encontrar um defeito, é uma tarefa de correcção com o seu teste (selftest, e2e ou pytest) antes do PR, não um remendo.

---

## Auto-revisão do plano

- **Cobertura da spec:** tabela de plataformas (T3, T4), normalizador (T2), lançamento e fim do run (T5), resume com `--dir` (T4, T5), watchdog (T6), configuração e validação (T7), catálogo (T3, T8), custos e `unpriced` (T2, T8), janelas (T8 `usage`), journal/hooks (T5, já genéricos), UI (T10), segurança (T5, T7, T9), skills/instalação/estado (T8, T9, T11), erros (cada linha da tabela da spec tem um cenário: recusas T5 §37, `UnknownError` T5 §35b, 401/429 T2/T5 §35, negações T5 §34, provider mudo T6 §41, resume fora do directório T4 (argv) e a recusa existente, `export` falhado T4 (selftest), stderr T5 §29 (vazio) e T2, preço em falta T5 §29/§40, stop T5 §36), testes (todos), fora de âmbito (nenhuma tarefa toca em XDG, `--agent`, `--file`, MCP, `doom_loop`).
- **Marcadores por preencher:** nenhum; os pontos que dependem de ler o código vizinho dizem exactamente o que ler e o que copiar.
- **Nomes:** `platform_normalizer`, `opencode_config_content`, `platform_argv_opencode`, `opencode_export_model`, `run_bounded`, `opencode_catalog_*`, `opencode_unpriced`, `WATCHDOG_POLL`, `KNOWN_PLATFORMS`, `platformKey`, `_opencode_platform`, `FAKE_*` usados com os mesmos nomes em todas as tarefas.

## Entrega

No fim de T12, `superpowers:finishing-a-development-branch`: as quatro suites verdes uma última vez, a branch `feat/opencode-engine` empurrada, um PR para `main` com a descrição em inglês (o que a entrega faz, o que ficou medido e onde, as decisões e o que fica de fora, os números das suites nesta máquina, as capturas de ecrã de T10, a nota de que o merge é do operador), e o trailer `🤖 Generated with [Claude Code](https://claude.com/claude-code)`. O merge é do operador.

