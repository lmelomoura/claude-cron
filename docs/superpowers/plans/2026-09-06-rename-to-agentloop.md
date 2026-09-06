# Renomear claude-cron para agentloop — plano de implementação

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** o produto passa a chamar-se `agentloop` em tudo o que é entregue — binários, symlinks, labels launchd, variáveis de ambiente, contrato de ambiente dos runs, header da dashboard, identificadores internos e documentação — com uma instalação existente a migrar sozinha e os nomes antigos a funcionar durante uma versão de transição.

**Architecture:** um teste guarda (`tests/test_no_old_name_survives.py`) define o que "renomeado" quer dizer e é escrito primeiro; cada tarefa faz uma camada da renomeação com `git mv` e substituições mecânicas, acrescenta os atalhos de transição (um shim de ambiente no engine, `_env()` no servidor, exportação dupla `AL_*`/`CC_*`, header duplo) e os testes que os pinam, e acaba com as suites existentes verdes. A migração de uma instalação antiga vive numa função só (`install_migrate_legacy`), testada com um `HOME` e um `launchctl` falsos.

**Tech Stack:** bash 3.2 (macOS), Python 3.13 stdlib, pytest, esbuild 0.25.0 via `npx` (só para reconstruir `bin/static/`), `perl -pi` para as substituições.

**Spec:** [`docs/superpowers/specs/2026-09-06-rename-to-agentloop-design.md`](../specs/2026-09-06-rename-to-agentloop-design.md).

## Global Constraints

- **Bash 3.2:** sem arrays associativos, sem `mapfile`; `case` dentro de `$( )` parte em runtime e o `bash -n` não apanha — validar a correr.
- **CHANGELOG na mesma commit:** `agentloop selftest` falha quando a última commit que tocou `bin/`, `skills/` ou `test/` é mais recente do que a última que tocou `CHANGELOG.md`. Toda a commit que toque `bin/` ou `test/` leva a sua linha no CHANGELOG.
- **`bin/static/*` é gerado e commitado:** qualquer alteração em `ui/` exige `bash build/build-ui.sh` na mesma commit; o selftest verifica os dois digests.
- **Nomes novos, verbatim:** `bin/agentloop`, `bin/agentloop-server`, `com.agentloop.tick`, `com.agentloop.server`, `AGENTLOOP_*`, `AL_*`, `X-AL-Token`, `ALApp`, `ALSecurity`, `AL` (o objecto de estado da página, antes `CC`), `al()` (servidor), `al_server` (testes), `al_port`/`al_env_set`/`al_env_ports`/`al_copy_ignored` (provision-lib), `al-ports.*`.
- **Não muda:** `AGENTLOOP_CLAUDE_BIN`, `AGENTLOOP_CLAUDE_CONFIG_DIR`, `CLAUDE_CONFIG_DIR`, `claude_config_dir`, `test/fake-claude`, `bin/statusline-rate-limits.sh`, o histórico do `CHANGELOG.md`, `docs/superpowers/*` anteriores, `.superpowers/`, `tests/security/fixtures/` (capturas reais de scanners), `data/`, nomes de ficheiros em `config/`.
- **Transição de uma versão:** os atalhos ficam nesta release; a seguinte apaga-os. Cada linha de atalho ou emparelha o nome antigo com o novo na mesma linha, ou está na lista `ALLOWED` do teste guarda.
- **Suites a correr no fim de cada tarefa** (todas offline):

  ```bash
  bin/agentloop selftest
  python3 -m pytest tests/ -q --ignore=tests/security
  python3 -m pytest tests/security -q
  bash test/e2e.test.sh
  ```

- **Código, comentários e mensagens de commit em inglês.** Nunca escrever o nome antigo num comentário novo: o guarda apanha-o. Diz-se "the pre-rename name" ou usa-se a constante `LEGACY_*`.
- **Branch:** `feat/rename-to-agentloop`, cortado de `main` depois de o PR das specs (`docs/agentloop-and-openai-design`) estar fundido; se ainda não estiver, cortado desse branch.

---

## Estrutura de ficheiros

| Ficheiro | Responsabilidade nesta renomeação |
|---|---|
| `tests/test_no_old_name_survives.py` (novo) | o guarda: percorre a árvore entregue e falha em qualquer nome antigo fora das linhas de transição |
| `tests/test_rename_transition.py` (novo) | pytest do servidor: `_env()` lê o nome antigo; o header antigo autentica |
| `tests/security/test_rename_transition.py` (novo) | pytest do pacote `security`: `adapters._engines_setting()` e a porta do `cli.py` lêem `CC_*` |
| `bin/agentloop` (era `bin/claude-cron`) | o shim `CLAUDE_CRON_*` → `AGENTLOOP_*`; exportação dupla `AL_*`/`CC_*`; `LEGACY_*`; `install_migrate_legacy`; avisos em `install` e `status`; casos novos no selftest |
| `bin/agentloop-server` (era `bin/claude-cron-server`) | `_env()`; `al()`; header duplo em `_authed` |
| `bin/worktree-lib.sh` | exportação dupla no hook de provisioning |
| `bin/provision-lib.sh` | `al_port` e irmãos, com aliases `cc_*` e leituras com fallback |
| `bin/round-cap.sh` | leituras com fallback |
| `bin/statusline-rate-limits.sh` | as três leituras de ambiente com fallback |
| `bin/security/adapters.py`, `bin/security/cli.py` | leituras com fallback; `prog="agentloop security"` |
| `bin/dashboard.html`, `ui/**`, `bin/static/*` | `X-AL-Token`, `ALApp`, `ALSecurity`, `AL`, ids `al-logo`; rebuild |
| `install.sh`, `uninstall.sh` | nomes novos; `uninstall.sh` remove também os symlinks antigos |
| `README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `.github/*`, `skills/*/SKILL.md`, `package.json`, `config/*.example*` | nomes novos; secção *Upgrading from claude-cron*; entrada no CHANGELOG |

---

### Task 1: O teste guarda, e os binários mudam de nome

**Files:**
- Create: `tests/test_no_old_name_survives.py`
- Rename: `bin/claude-cron` → `bin/agentloop`; `bin/claude-cron-server` → `bin/agentloop-server`
- Modify (substituição mecânica): `bin/agentloop`, `bin/agentloop-server`, `bin/worktree-lib.sh`, `bin/provision-lib.sh`, `bin/statusline-rate-limits.sh`, `bin/dashboard.html`, `bin/security/cli.py`, `bin/security/deps.py`, `bin/security/adapters.py`, `bin/security/engines.py`, `ui/app/*.js`, `ui/security/*.js`, `ui/css/*.css`, `test/e2e.test.sh`, `test/fake-claude`, `test/round-cap.test.sh`, `tests/*.py`, `tests/security/*.py`, `build/*.sh`, `install.sh`, `uninstall.sh`, `CONTRIBUTING.md`, `.github/workflows/ci.yml`, `.github/pull_request_template.md`, `package.json`, `config/jobs.example.json`, `config/prechecks/example-hello.sh`, `.gitignore`, `skills/*/SKILL.md`, `README.md`, `CHANGELOG.md`

**Interfaces:**
- Produces: `tests/test_no_old_name_survives.py::test_nothing_shipped_spells_the_old_name`, a lista `ALLOWED` que as tarefas 2 a 5 alimentam; os nomes `bin/agentloop`, `bin/agentloop-server`, `com.agentloop.tick`, `com.agentloop.server` que tudo o resto usa.

- [ ] **Step 1: Escrever o teste guarda, que vai falhar**

Cria `tests/test_no_old_name_survives.py` com este conteúdo:

```python
"""The rename to agentloop is complete only when nothing in the shipped tree
spells the old name. This test is the definition of "complete".

Three names are checked: the product (`claude-cron`, `CLAUDE_CRON_*`), the
run-environment prefix (`CC_*`, and the `cc_port` family of helpers) and the
identifiers that were derived from it (`CCApp`, `CCSecurity`, the page's `CC`
state object, `cc_server`, `X-CC-Token`). A one-release transition keeps the
old names working, and every line that exists for that purpose is either
PAIRED with its new name on the same line (a fallback read, a dual export, the
dual header, an alias) or listed in ALLOWED below. Removing the transition
later means emptying ALLOWED and deleting the paired halves — this test then
keeps them from coming back.
"""
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# What is scanned: everything shipped. Not scanned: CHANGELOG.md (history is
# written in the name of its day), docs/ (dated specs and plans), the raw
# scanner captures under tests/security/fixtures/ and the stream samples under
# test/fixtures/ (real samples of a tree that had the old name when they were
# taken), and this file.
SCANNED = [
    "bin", "ui", "skills", "build", "test", "tests", ".github",
    "install.sh", "uninstall.sh", "README.md", "CONTRIBUTING.md",
    "package.json", ".gitignore",
    "config/jobs.example.json", "config/prechecks/example-hello.sh",
    "config/provision/example-hello.up.sh",
]
SKIP_DIRS = {"__pycache__", ".pytest_cache", "node_modules", "fixtures"}
SKIP_FILES = {Path(__file__).name}

OLD = re.compile(
    r"claude-cron"
    r"|CLAUDE_CRON_[A-Z_]+"
    r"|\bCC_[A-Z_]+"
    r"|\bcc_(?:port|env_set|env_ports|copy_ignored)\b"
    r"|CCApp|CCSecurity|cc_server|X-CC-Token"
    r"|\bCC\.[A-Za-z_]|\bCC\s*=[^=]"
)

# Lines allowed to carry the old name, by (path, substring). Each one exists
# for the transition or for the migration, and each says why.
ALLOWED = [
    # the migration constants: the only place the old labels and names are spelled
    ("bin/agentloop", 'LEGACY_PLIST_LABEL="com.claude-cron.tick"'),
    ("bin/agentloop", 'LEGACY_SERVER_LABEL="com.claude-cron.server"'),
    ("bin/agentloop", 'LEGACY_CLI_NAME="claude-cron"'),
    ("bin/agentloop", 'LEGACY_ENV_PREFIX="CLAUDE_CRON_"'),
    ("bin/agentloop", 'LEGACY_RUN_PREFIX="CC_"'),
    ("uninstall.sh", 'LEGACY_CLI_NAME="claude-cron"'),
    # the server binds its config dirs at import time, before any shim could run
    ("bin/agentloop-server", 'LEGACY_ENV_PREFIX = "CLAUDE_CRON_"'),
    # the security package reads its switch and its marker straight from the environment
    ("bin/security/adapters.py", 'LEGACY_ENGINES_ENV = "CC_SECURITY_ENGINES"'),
    # comments and assertions that name a path INSIDE a scanner capture taken before the rename
    ("bin/security/adapters.py", "taken before the rename"),
    ("bin/security/engines.py", "taken before the rename"),
    ("tests/security/test_adapters.py", "taken before the rename"),
    ("tests/security/test_engines.py", "taken before the rename"),
]


def _files():
    for entry in SCANNED:
        p = REPO / entry
        if p.is_file():
            yield p
            continue
        for f in sorted(p.rglob("*")):
            if not f.is_file():
                continue
            if SKIP_DIRS & set(f.relative_to(REPO).parts):
                continue
            if f.name in SKIP_FILES:
                continue
            yield f


def _paired(line, token):
    """A transition line carries BOTH spellings: the old one is tolerated only
    next to the new one it falls back from."""
    if token.startswith("CLAUDE_CRON_"):
        return "AGENTLOOP_" + token[len("CLAUDE_CRON_"):] in line
    if token.startswith("CC_"):
        return "AL_" + token[len("CC_"):] in line
    if token.startswith("cc_"):
        return "al_" + token[len("cc_"):] in line
    if token == "X-CC-Token":
        return "X-AL-Token" in line
    return False


def _readme_upgrade_section(text):
    """The README's own upgrade notes have to say what the old names were.
    They live under one heading, and only there."""
    lines = text.splitlines()
    start = next((i for i, l in enumerate(lines)
                  if l.startswith("### Upgrading from claude-cron")), None)
    if start is None:
        return set()
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].startswith("## ") or lines[i].startswith("### ")), len(lines))
    return set(range(start, end))


def test_nothing_shipped_spells_the_old_name():
    offenders = []
    for path in _files():
        rel = path.relative_to(REPO).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        exempt = _readme_upgrade_section(text) if rel == "README.md" else set()
        for n, line in enumerate(text.splitlines()):
            if n in exempt:
                continue
            for m in OLD.finditer(line):
                if _paired(line, m.group(0)):
                    continue
                if any(rel == p and s in line for p, s in ALLOWED):
                    continue
                offenders.append(f"{rel}:{n + 1}: {m.group(0)}  |  {line.strip()[:110]}")
    assert not offenders, (f"{len(offenders)} old-name spellings survive:\n"
                           + "\n".join(offenders[:200]))
```

- [ ] **Step 2: Correr o guarda e ver que falha por centenas de linhas**

```bash
python3 -m pytest tests/test_no_old_name_survives.py -q 2>&1 | tail -5
```

Esperado: `FAILED … old-name spellings survive` com um número na ordem das centenas. Anota o número: cada tarefa fá-lo descer.

- [ ] **Step 3: Mudar o nome dos binários com `git mv`**

```bash
git mv bin/claude-cron bin/agentloop
git mv bin/claude-cron-server bin/agentloop-server
ls -la bin/agentloop bin/agentloop-server   # both still executable (-rwxr-xr-x)
```

- [ ] **Step 4: A substituição mecânica do nome do produto**

Uma só passagem, sobre tudo o que é mecânico. `perl -pi` porque o `sed -i` do macOS exige o argumento vazio e não tem `\b`.

```bash
perl -pi -e 's/claude-cron/agentloop/g' \
  bin/agentloop bin/agentloop-server bin/worktree-lib.sh bin/provision-lib.sh bin/round-cap.sh \
  bin/statusline-rate-limits.sh bin/dashboard.html \
  bin/security/cli.py bin/security/deps.py bin/security/adapters.py bin/security/engines.py \
  ui/app/*.js ui/security/*.js ui/css/*.css \
  test/e2e.test.sh test/fake-claude test/round-cap.test.sh \
  tests/*.py tests/security/*.py \
  build/build-ui.sh build/ui-digest.sh build/ui-bundle-digest.sh \
  install.sh uninstall.sh CONTRIBUTING.md .github/workflows/ci.yml .github/pull_request_template.md \
  package.json config/jobs.example.json config/prechecks/example-hello.sh .gitignore \
  skills/*/SKILL.md README.md
```

Isto trata de uma vez `bin/claude-cron` → `bin/agentloop`, `claude-cron-server` → `agentloop-server`, `com.claude-cron.tick` → `com.agentloop.tick`, `/tmp/claude-cron-hello` → `/tmp/agentloop-hello`, `.before-claude-cron.` → `.before-agentloop.`, `lmelomoura/claude-cron` → `lmelomoura/agentloop`, `"name": "claude-cron-ui"` → `"agentloop-ui"`, `prog="claude-cron security"` → `prog="agentloop security"`, `vendor: "claude-cron"` → `"agentloop"`, o título e o rodapé da página, e todos os comentários.

Depois, os identificadores internos que só existiam por causa do nome, e a variável do e2e:

```bash
perl -pi -e 's/\bCLAUDE_CRON\b/AGENTLOOP/g' bin/agentloop-server
perl -pi -e 's/ccselftest\.XXXXXX/alselftest.XXXXXX/; s/\bcc_account_probe\b/al_account_probe/g; s#/tmp/cc-#/tmp/al-#g' bin/agentloop
perl -pi -e 's/mktemp\("cc"\)/mktemp("al")/' tests/conftest.py
before="$(grep -cE '\$CC\b' test/e2e.test.sh)"      # the harness variable, 15 lines today
perl -pi -e 's/\bCC=/AL=/; s/\$CC\b/\$AL/g' test/e2e.test.sh
grep -n 'AGENTLOOP = str' bin/agentloop-server     # expected: AGENTLOOP = str(BIN_DIR / "agentloop")
[ "$(grep -cE '\$AL\b' test/e2e.test.sh)" = "$before" ] && echo "e2e variable renamed on every line"
grep -c '\$CC\b' test/e2e.test.sh                   # expected: 0
```

- [ ] **Step 5: Repor as linhas que descrevem capturas feitas antes da renomeação**

Cinco ficheiros têm linhas que nomeiam um caminho **dentro de uma captura real** de um scanner (`tests/security/fixtures/engines/*.json`, que não é tocada). A substituição do passo 4 tornou-as mentirosas. Cada uma volta ao nome antigo e ganha a frase `taken before the rename`, que é o que o guarda aceita. Localiza cada linha com o `grep` indicado e substitui o texto exacto.

`bin/security/adapters.py` (quatro linhas):

```bash
grep -n 'code/agentloop/tests/security/fixtures/composer.lock' bin/security/adapters.py
```
Substituir
```
# else touched: `<home>/code/agentloop/tests/security/fixtures/composer.lock`,
```
por
```
# else touched: `<home>/code/claude-cron/tests/security/fixtures/composer.lock` (a path taken before the rename),
```

```bash
grep -n '`bin/agentloop-server`, one finding, three occurrences' bin/security/adapters.py
```
Substituir
```
    `bin/agentloop-server`, one finding, three occurrences.
```
por
```
    `bin/claude-cron-server` (its name in this capture, taken before the rename), one finding, three occurrences.
```

```bash
grep -n "this tree's own shell lives in \`bin/agentloop\`" bin/security/adapters.py
```
Substituir
```
    than it closes: this tree's own shell lives in `bin/agentloop`, which has
```
por
```
    than it closes: this tree's own shell lived in `bin/claude-cron` (taken before the rename), which has
```

```bash
grep -n 'PartialParsing", \[{"path": "bin/agentloop"' bin/security/adapters.py
```
Substituir
```
        "type": ["PartialParsing", [{"path": "bin/agentloop", …}]]
```
por
```
        "type": ["PartialParsing", [{"path": "bin/claude-cron", …}]]   # taken before the rename
```

`bin/security/engines.py` (uma linha):

```bash
grep -n '`bin/agentloop` in this repository' bin/security/engines.py
```
Substituir
```
    # `bin/agentloop` in this repository's own capture -- which is the hazard
```
por
```
    # `bin/claude-cron` (its name in the capture, taken before the rename) -- which is the hazard
```

`tests/security/test_adapters.py` (sete linhas; a linha `bin/agentloop selftest` perto de `stops dropping these entries` fica como o passo 4 a deixou, porque essa nomeia o produto):

```bash
grep -nE 'bin/agentloop-server"|bin/agentloop` in this capture|md5 calls in `bin/agentloop-server`|shell lives in `bin/agentloop`|"path": "bin/agentloop"|"bin/agentloop" not in reason|"/etc/passwd", "bin/agentloop"' tests/security/test_adapters.py
```
Sete substituições, na ordem em que aparecem no ficheiro:

```
    assert f["occurrences"][0]["file"] == "bin/agentloop-server"
```
→
```
    assert f["occurrences"][0]["file"] == "bin/claude-cron-server"   # the capture's own path, taken before the rename
```

```
    message of a parse error -- ~2kB of `bin/agentloop` in this capture --
```
→
```
    message of a parse error -- ~2kB of `bin/claude-cron` in this capture (taken before the rename) --
```

```
    exactly that case: three md5 calls in `bin/agentloop-server`."""
```
→
```
    exactly that case: three md5 calls in `bin/claude-cron-server` (taken before the rename)."""
```

```
    tree's own shell lives in `bin/agentloop`, which has NO EXTENSION --
```
→
```
    tree's own shell lived in `bin/claude-cron` (taken before the rename), which has NO EXTENSION --
```

```
        "type": ["PartialParsing", [{"path": "bin/agentloop",
```
→
```
        "type": ["PartialParsing", [{"path": "bin/claude-cron",   # taken before the rename
```

```
    assert "bin/agentloop" not in reason, reason
```
→
```
    assert "bin/claude-cron" not in reason, reason   # taken before the rename
```

```
    "/etc/passwd", "bin/agentloop", "a.py", {"path": "x"}, 7, None, "",
```
→
```
    "/etc/passwd", "bin/claude-cron", "a.py", {"path": "x"}, 7, None, "",   # taken before the rename
```

`tests/security/test_engines.py` (uma linha):

```bash
grep -n '~2kB of `bin/agentloop`' tests/security/test_engines.py
```
Substituir
```
    # FILE -- ~2kB of `bin/agentloop` in the capture this project's fixture
```
por
```
    # FILE -- ~2kB of `bin/claude-cron` (taken before the rename) in the capture this project's fixture
```

Confirma que não sobrou nenhuma outra linha nesses ficheiros a apontar para a captura com o nome novo:

```bash
grep -nE 'bin/agentloop' tests/security/test_adapters.py tests/security/test_engines.py bin/security/adapters.py bin/security/engines.py
```
Esperado: só a linha `bin/agentloop selftest` de `test_adapters.py` e, em `adapters.py`, nenhuma que nomeie a captura.

- [ ] **Step 6: A entrada no CHANGELOG**

Em `CHANGELOG.md`, logo a seguir a `## [Unreleased]` e antes de `### Fixed`, insere:

```markdown
### Changed

- **claude-cron is now agentloop.** The scheduler runs more than one agent from
  here on (see `docs/superpowers/specs/2026-09-06-platforms-anthropic-openai-design.md`),
  and a product named after one of them misnames the other. Everything that
  spelled the old name moves with it: the two binaries (`bin/agentloop`,
  `bin/agentloop-server`), the `~/.local/bin` symlinks, the launchd labels
  (`com.agentloop.tick`, `com.agentloop.server`) and the documentation. What it
  cost to not have it: a tool called claude-cron that launches the Codex is a
  name that lies to whoever reads a job card.
  - `tests/test_no_old_name_survives.py` is the definition of "renamed": it
    fails on any old spelling that is not one of the transition lines it
    lists, and emptying that list is how the transition ends.
```

Nas tarefas 2 a 5 acrescentam-se sub-pontos a esta entrada.

- [ ] **Step 7: Correr tudo**

```bash
bin/agentloop selftest 2>&1 | tail -3
python3 -m pytest tests/ -q --ignore=tests/security 2>&1 | tail -3
python3 -m pytest tests/security -q 2>&1 | tail -3
bash test/e2e.test.sh 2>&1 | tail -3
python3 -m pytest tests/test_no_old_name_survives.py -q 2>&1 | tail -3
```

Esperado: as quatro suites verdes (`N passed, 0 failed` no selftest e no e2e; `passed` no pytest). O guarda ainda falha, mas só com `CLAUDE_CRON_*`, `CC_*`, `cc_port`, `CCApp`, `CCSecurity`, `CC.`, `cc_server` e `X-CC-Token` — nenhum `claude-cron`. Confirma:

```bash
python3 -m pytest tests/test_no_old_name_survives.py -q 2>&1 | grep -c ': claude-cron '
```
Esperado: `0`.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "rename: claude-cron becomes agentloop — the binaries, the labels and every mention of the product

The guard test tests/test_no_old_name_survives.py is written first and still
fails: the environment names, the run prefix, the header and the page's own
identifiers follow in the next commits, each with its transition shim.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: `CLAUDE_CRON_*` passa a `AGENTLOOP_*`, com o shim de transição

**Files:**
- Modify: `bin/agentloop` (topo, ~linhas 24–26; `cmd_status`; `cmd_install`; `cmd_selftest`), `bin/agentloop-server` (linhas 44–47, 97, 107, ~2301), `bin/statusline-rate-limits.sh` (linhas 34, 36, 41), `bin/worktree-lib.sh:615`, `test/e2e.test.sh`, `tests/conftest.py`, `tests/test_security_api.py`, `README.md`, `CHANGELOG.md`
- Create: `tests/test_rename_transition.py`

**Interfaces:**
- Produces: no engine, `LEGACY_ENV_PREFIX` (string `CLAUDE_CRON_`), `LEGACY_ENV_SEEN` (lista separada por espaços dos nomes antigos vistos) e `legacy_env_warnings()`; no servidor, `LEGACY_ENV_PREFIX` e `_env(name, default=None)`.
- Consumes: os nomes `bin/agentloop`, `bin/agentloop-server` da Task 1.

- [ ] **Step 1: O caso de selftest que vai falhar**

Em `bin/agentloop`, dentro de `cmd_selftest`, imediatamente antes da linha `echo "the committed UI artifacts — built from the sources sitting next to them"`, acrescenta:

```bash
  echo "the rename — the pre-rename environment names still work for one release"
  mkdir -p "$tmp/legacy/config" "$tmp/legacy/data"
  got="$( env -i HOME="$HOME" PATH="$PATH" "${LEGACY_ENV_PREFIX}PORT=9876" \
            AGENTLOOP_CONFIG="$tmp/legacy/config" AGENTLOOP_DATA="$tmp/legacy/data" \
            bash "$SELF" status 2>/dev/null )"
  case "$got" in *"http://127.0.0.1:9876/"*) ok "a port set only under the old name is honoured" ;;
                 *) bad "status said: $got" ;; esac
  case "$got" in *"${LEGACY_ENV_PREFIX}PORT is set"*) ok "and status says which old name it found" ;;
                 *) bad "no warning about the old name in: $got" ;; esac
  got="$( env -i HOME="$HOME" PATH="$PATH" "${LEGACY_ENV_PREFIX}PORT=9876" AGENTLOOP_PORT=1111 \
            AGENTLOOP_CONFIG="$tmp/legacy/config" AGENTLOOP_DATA="$tmp/legacy/data" \
            bash "$SELF" status 2>/dev/null )"
  case "$got" in *"http://127.0.0.1:1111/"*) ok "the new name wins when both are set" ;;
                 *) bad "status said: $got" ;; esac

```

- [ ] **Step 2: O pytest do servidor que vai falhar**

Cria `tests/test_rename_transition.py`:

```python
"""The rename kept the old spellings alive for one release. These pin the two
the server itself honours: its environment names, and the dashboard's token
header. Both fallbacks are deleted in the release after the rename, and so
are these tests."""


def test_the_server_reads_the_pre_rename_environment_names_for_one_release(srv, monkeypatch):
    legacy = srv.LEGACY_ENV_PREFIX + "SESSION_TTL"
    monkeypatch.delenv("AGENTLOOP_SESSION_TTL", raising=False)
    monkeypatch.setenv(legacy, "42")
    assert srv._env("SESSION_TTL") == "42"
    monkeypatch.setenv("AGENTLOOP_SESSION_TTL", "7")
    assert srv._env("SESSION_TTL") == "7", "the new name wins when both are set"
    monkeypatch.delenv("AGENTLOOP_SESSION_TTL")
    monkeypatch.delenv(legacy)
    assert srv._env("SESSION_TTL", "fallback") == "fallback"
    assert srv._env("SESSION_TTL") is None
```

- [ ] **Step 3: Correr os dois e vê-los falhar**

```bash
bin/agentloop selftest 2>&1 | grep -A3 'pre-rename environment'
python3 -m pytest tests/test_rename_transition.py -q 2>&1 | tail -3
```
Esperado: no selftest, `FAIL  status said: …` (o `PORT` ambiente é ignorado hoje) e `FAIL  no warning…`; no pytest, `AttributeError: … has no attribute 'LEGACY_ENV_PREFIX'`.

- [ ] **Step 4: A substituição mecânica**

```bash
perl -pi -e 's/CLAUDE_CRON_/AGENTLOOP_/g' \
  bin/agentloop bin/agentloop-server bin/worktree-lib.sh \
  test/e2e.test.sh tests/conftest.py tests/test_security_api.py README.md
grep -c 'AGENTLOOP_' bin/agentloop      # expected: 35 (the lines that carried the old prefix)
grep -n 'CLAUDE_CRON_' bin/agentloop bin/agentloop-server bin/worktree-lib.sh test/e2e.test.sh tests/*.py README.md
```
Esperado no último: nenhuma linha.

- [ ] **Step 5: O shim no engine**

Em `bin/agentloop`, logo a seguir à linha `BASE_DIR="$(cd "$BIN_DIR/.." && pwd)"` e antes de `CONFIG_DIR=…`, insere:

```bash
# --- transition: the pre-rename environment names still work for one release --
# Every AGENTLOOP_X read below had another prefix until 2026-09-06, and an
# existing install carries that prefix in its launchd plists and shell
# profiles. Map each old name onto the new one when the new one is unset,
# remember what was mapped so `status` and `install` can say so, and delete
# this whole block in the release after the rename.
LEGACY_ENV_PREFIX="CLAUDE_CRON_"
LEGACY_ENV_SEEN=""
for _legacy in $(env | sed -n "s/^${LEGACY_ENV_PREFIX}\([A-Z_]*\)=.*/\1/p"); do
  if eval "[ -z \"\${AGENTLOOP_${_legacy}+x}\" ]"; then
    eval "export AGENTLOOP_${_legacy}=\"\$${LEGACY_ENV_PREFIX}${_legacy}\""
  fi
  LEGACY_ENV_SEEN="$LEGACY_ENV_SEEN ${LEGACY_ENV_PREFIX}${_legacy}"
done
unset _legacy

legacy_env_warnings() { # one line per pre-rename variable still in the environment
  local v
  for v in $LEGACY_ENV_SEEN; do
    printf 'WARNING: %s is set — it is read as AGENTLOOP_%s for now; the old name stops working in the next release.\n' \
      "$v" "${v#"$LEGACY_ENV_PREFIX"}"
  done
}
```

Em `cmd_status`, depois da última linha `echo "Dashboard : http://127.0.0.1:$PORT/   (agentloop dashboard)"`, acrescenta:

```bash
  legacy_env_warnings
```

Em `cmd_install`, depois da última linha `echo "Open the dashboard with: agentloop dashboard"`, acrescenta:

```bash
  legacy_env_warnings
```

- [ ] **Step 6: `_env()` no servidor**

Em `bin/agentloop-server`, substitui o bloco

```python
CONFIG_DIR = Path(os.environ.get("AGENTLOOP_CONFIG", BASE_DIR / "config"))
DATA_DIR = Path(os.environ.get("AGENTLOOP_DATA", BASE_DIR / "data"))
```
por
```python
# The pre-rename prefix, read for one release: config, data and port still
# arrive under it from a plist written before 2026-09-06. Delete
# LEGACY_ENV_PREFIX and the fallback in _env in the release after the rename.
LEGACY_ENV_PREFIX = "CLAUDE_CRON_"


def _env(name, default=None):
    """AGENTLOOP_<name>, else its pre-rename spelling, else default."""
    v = os.environ.get("AGENTLOOP_" + name)
    if v is None:
        v = os.environ.get(LEGACY_ENV_PREFIX + name)
    return default if v is None else v


CONFIG_DIR = Path(_env("CONFIG", BASE_DIR / "config"))
DATA_DIR = Path(_env("DATA", BASE_DIR / "data"))
```

e as outras três leituras:

```python
PORT = int(os.environ.get("AGENTLOOP_PORT", "8787"))
```
→
```python
PORT = int(_env("PORT", "8787"))
```

```python
WORKTREE_SESSION_TTL = int(os.environ.get("AGENTLOOP_SESSION_TTL") or 86400)
```
→
```python
WORKTREE_SESSION_TTL = int(_env("SESSION_TTL") or 86400)
```

```python
    claude = os.environ.get("AGENTLOOP_CLAUDE_BIN") or str(Path.home() / ".local/bin/claude")
```
→
```python
    claude = _env("CLAUDE_BIN") or str(Path.home() / ".local/bin/claude")
```

```bash
grep -n 'os.environ.get("AGENTLOOP' bin/agentloop-server
```
Esperado: nenhuma linha.

- [ ] **Step 7: O statusline lê os dois nomes**

`bin/statusline-rate-limits.sh` é invocado pelo Claude Code, não pelo engine, por isso o shim não o cobre. Substitui as três leituras:

```sh
DATA_DIR="${AGENTLOOP_DATA:-${CLAUDE_CRON_DATA:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/data}}"
JQ="${AGENTLOOP_JQ:-${CLAUDE_CRON_JQ:-$(command -v jq 2>/dev/null || echo /usr/bin/jq)}}"
MIN_WRITE_SECONDS="${AGENTLOOP_STATUSLINE_MIN_SECONDS:-${CLAUDE_CRON_STATUSLINE_MIN_SECONDS:-15}}"
```

- [ ] **Step 8: Correr tudo**

```bash
bin/agentloop selftest 2>&1 | tail -3
python3 -m pytest tests/ -q --ignore=tests/security 2>&1 | tail -3
python3 -m pytest tests/security -q 2>&1 | tail -3
bash test/e2e.test.sh 2>&1 | tail -3
python3 -m pytest tests/test_no_old_name_survives.py -q 2>&1 | grep -c 'CLAUDE_CRON_'
```
Esperado: suites verdes; o último número é `0`.

- [ ] **Step 9: CHANGELOG e commit**

No CHANGELOG, dentro da entrada da Task 1, acrescenta o sub-ponto:

```markdown
  - The engine's environment is `AGENTLOOP_*` (it was `CLAUDE_CRON_*`). **For
    this release only** the old names are still read, and `install` and
    `status` list every one they find so it can be renamed before the next
    release drops the fallback.
```

```bash
git add -A
git commit -m "rename: CLAUDE_CRON_* becomes AGENTLOOP_*, read under the old name for one release

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: `CC_*` passa a `AL_*`, exportado nos dois nomes e lido com fallback

**Files:**
- Modify: `bin/agentloop` (`security_run_analysis`, os três `export CC_PRECHECK_DRY_RUN=1`, `run_env+=`, `run_end_hook`, `fleet_stall_check`, `cmd_status`, `cmd_install`, `cmd_selftest`), `bin/worktree-lib.sh` (`wt_provision`), `bin/provision-lib.sh`, `bin/round-cap.sh`, `bin/security/adapters.py`, `bin/security/cli.py`, `test/fake-claude`, `test/e2e.test.sh`, `test/round-cap.test.sh`, `tests/*.py`, `tests/security/*.py`, `.github/workflows/ci.yml`, `config/provision/example-hello.up.sh`, `README.md`, `CHANGELOG.md`
- Create: `tests/security/test_rename_transition.py`

**Interfaces:**
- Produces: `LEGACY_RUN_PREFIX` (`CC_`) e `legacy_scripts_warnings()` no engine; `adapters.LEGACY_ENGINES_ENV` e `adapters._engines_setting()`; `cli._agent_env(name)`; `al_port`, `al_env_set`, `al_env_ports`, `al_copy_ignored` em `provision-lib.sh`, com `cc_*` como aliases.
- Consumes: `LEGACY_ENV_PREFIX` da Task 2 (padrão para os nomes).

- [ ] **Step 1: A substituição mecânica, primeiro**

O rename puro não muda comportamento nenhum, e tem de vir ANTES dos testes desta tarefa: os testes escrevem `CC_*` de propósito, ao lado de `AL_*`, e uma substituição corrida depois deles desfazia-os.

```bash
perl -pi -e 's/\bCC_/AL_/g' \
  bin/agentloop bin/worktree-lib.sh bin/provision-lib.sh bin/round-cap.sh \
  bin/security/adapters.py bin/security/cli.py \
  test/fake-claude test/e2e.test.sh test/round-cap.test.sh \
  tests/*.py tests/security/*.py .github/workflows/ci.yml \
  config/provision/example-hello.up.sh README.md
perl -pi -e 's/\bcc_(port|env_set|env_ports|copy_ignored)\b/al_$1/g; s/cc-ports\./al-ports./g' \
  bin/provision-lib.sh bin/worktree-lib.sh bin/agentloop config/provision/example-hello.up.sh README.md
grep -rnE '\bCC_|\bcc_(port|env)' bin ui test tests .github config/provision/example-hello.up.sh README.md \
  --exclude-dir=__pycache__ --exclude-dir=fixtures --exclude-dir=static | grep -v test_no_old_name_survives
bin/agentloop selftest 2>&1 | tail -1
```
Esperado: o `grep` não devolve nada; o selftest continua verde (só nomes mudaram).

- [ ] **Step 2: Os testes que vão falhar — selftest**

Em `bin/agentloop`, dentro de `cmd_selftest`, imediatamente antes de `echo "the rename — the pre-rename environment names still work for one release"` (o caso da Task 2), acrescenta quatro casos:

```bash
  echo "the rename — a run, its hooks and its prechecks see AL_* and CC_* alike for one release"
  mkdir -p "$tmp/hookcfg/hooks"
  printf '%s\n' '#!/usr/bin/env bash' \
    'printf "%s|%s|%s|%s\n" "$AL_JOB_ID" "$CC_JOB_ID" "$AL_STATUS" "$CC_STATUS" > "$AL_HOOK_OUT"' \
    > "$tmp/hookcfg/hooks/on-run-end.sh"
  export AL_HOOK_OUT="$tmp/hook-twins.seen"; rm -f "$AL_HOOK_OUT"
  ( CONFIG_DIR="$tmp/hookcfg"; run_end_hook j7 warning 0.2 "n" P sess /tmp/l.json 1 2 ) >/dev/null 2>&1
  waited=0
  while [ ! -f "$AL_HOOK_OUT" ] && [ "$waited" -lt 50 ]; do sleep 0.1; waited=$((waited+1)); done
  got="$(cat "$AL_HOOK_OUT" 2>/dev/null)"
  [ "$got" = "j7|j7|warning|warning" ] && ok "on-run-end sees AL_JOB_ID and CC_JOB_ID with one value" \
    || bad "the hook saw '$got'"
  unset AL_HOOK_OUT
  rm -f "$tmp/hookcfg/hooks/on-run-end.sh"

  mkdir -p "$tmp/twins/cfg/provision" "$tmp/twins/run/repoA"
  printf '%s\n' '#!/usr/bin/env bash' 'printf "%s|%s\n" "$AL_REPO_NAME" "$CC_REPO_NAME" > "$AL_WORKTREE/twins"' \
    > "$tmp/twins/cfg/provision/twins.up.sh"
  ( CONFIG_DIR="$tmp/twins/cfg"; PROJECTS_FILE="$tmp/proj/projects.json"
    wt_provision up twins j1 "$tmp/twins/run" repoA /x/a "$tmp/twins/run/repoA" develop ) >/dev/null 2>&1
  got="$(cat "$tmp/twins/run/repoA/twins" 2>/dev/null)"
  [ "$got" = "repoA|repoA" ] && ok "a provisioning hook sees AL_REPO_NAME and CC_REPO_NAME with one value" \
    || bad "the provisioning hook saw '$got'"

  # Structural, like the bind_session call-site count above: the three places
  # a precheck is run dry all export the marker under both names, and a
  # fourth caller added later has to as well.
  got="$(grep -c 'export AL_PRECHECK_DRY_RUN=1 CC_PRECHECK_DRY_RUN=1' "$SELF")"
  [ "$got" = "3" ] && ok "every dry precheck exports the marker under both names ($got sites)" \
    || bad "$got sites export both spellings of the dry-run marker, expected 3"

  echo "the rename — install and status name the personal scripts still reading CC_*"
  mkdir -p "$tmp/legacy/prechecks" "$tmp/legacy/provision" "$tmp/legacy/hooks"
  printf '%s\n' '#!/bin/bash' "echo \"\$${LEGACY_RUN_PREFIX}JOB_ID\"" > "$tmp/legacy/prechecks/old.sh"
  printf '%s\n' '#!/bin/bash' 'echo "$AL_JOB_ID"' > "$tmp/legacy/provision/new.up.sh"
  got="$( CONFIG_DIR="$tmp/legacy" legacy_scripts_warnings )"
  case "$got" in *"prechecks/old.sh reads ${LEGACY_RUN_PREFIX}"*) ok "a script still on the old prefix is named" ;;
                 *) bad "the warning was: '$got'" ;; esac
  case "$got" in *"new.up.sh"*) bad "a script already on AL_ was named" ;; *) ok "a script already on AL_ is not" ;; esac

```

O terceiro caso é estrutural, como a contagem de sítios de `bind_session` que o selftest já faz: pina que os três `export` do marcador de dry-run levam as duas grafias, para que o dia em que alguém apagar uma das metades tenha um teste que diz o que se perdeu.

- [ ] **Step 3: Os testes que vão falhar — round-cap e pacote security**

Em `test/round-cap.test.sh`, depois do bloco `== the cap is configurable ==` e antes de `== dry run must not write ==`, acrescenta:

```bash
echo
echo "== the cap still reads its pre-rename name for one release =="
( export CC_ROUND_CAP=4    # the spelling before AL_ROUND_CAP, honoured for one release
  AUTH="x:y"; JIRA="http://127.0.0.1:$PORT"; JQ=/usr/bin/jq
  . "${AL_LIB:-$(cd "$(dirname "$0")/../bin" && pwd)}/round-cap.sh"
  [ "$RC_CAP" = "4" ] ) \
  && ok "CC_ROUND_CAP alone still raises the cap (read as AL_ROUND_CAP)" \
  || bad "CC_ROUND_CAP alone still raises the cap (read as AL_ROUND_CAP)" "cap not honoured"
```

Cria `tests/security/test_rename_transition.py`:

```python
"""The security package reads two things straight from the environment: the
engines switch and the marker that says "this process is the agent under
review". Both had another prefix until 2026-09-06 and both are still read
under it for one release. Delete the fallbacks, and this file, after."""
import os
import subprocess
import sys
from pathlib import Path

from security import adapters
from test_cli import open_analysis   # the same fixture test_cli's own refusal test opens

REPO = Path(__file__).resolve().parent.parent.parent
CLI = REPO / "bin" / "security" / "cli.py"


def test_the_engines_switch_reads_its_pre_rename_name_for_one_release(monkeypatch):
    monkeypatch.delenv(adapters.ENGINES_ENV, raising=False)
    monkeypatch.setenv(adapters.LEGACY_ENGINES_ENV, "off")
    assert adapters._engines_setting() == "off"
    monkeypatch.setenv(adapters.ENGINES_ENV, "on")
    assert adapters._engines_setting() == "on", "the new name wins when both are set"
    monkeypatch.delenv(adapters.ENGINES_ENV)
    monkeypatch.delenv(adapters.LEGACY_ENGINES_ENV)
    assert adapters._engines_setting() == ""


def test_the_door_refuses_the_agent_under_its_pre_rename_marker(tmp_path):
    """`decide` is refused inside an analysis run. The marker arrives as
    AL_SECURITY_AGENT now; a precheck or hook written before the rename may
    still spell it the old way, and the refusal must hold either way."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("AL_SECURITY_AGENT", "CC_SECURITY_AGENT")}
    env["CC_SECURITY_AGENT"] = "1"   # the spelling before AL_SECURITY_AGENT
    open_analysis(tmp_path / "security.db")
    out = subprocess.run(
        [sys.executable, str(CLI), "decide", "--project", "web", "--fingerprint", "a" * 64,
         "--state", "false_positive", "--reason", "r", "--by", "me",
         "--db", str(tmp_path / "security.db")],
        capture_output=True, text=True, check=False, env=env)
    assert out.returncode != 0
    assert "AL_SECURITY_AGENT" in out.stderr
```

- [ ] **Step 4: Correr e ver falhar**

```bash
bin/agentloop selftest 2>&1 | grep -E 'FAIL' | head
bash test/round-cap.test.sh 2>&1 | grep -E 'FAIL|pre-rename' | head -3
python3 -m pytest tests/security/test_rename_transition.py -q 2>&1 | tail -3
```
Esperado: os quatro casos novos do selftest em `FAIL`; o caso do round-cap em `FAIL`; no pytest `AttributeError: … no attribute 'LEGACY_ENGINES_ENV'` e a refusal a passar sem refusal nenhuma (o marcador antigo já não é lido), logo `returncode != 0` falha.

- [ ] **Step 5: As exportações duplas no engine**

Oito sítios em `bin/agentloop`. Cada linha leva as duas grafias, e a nova primeiro.

Em `security_run_analysis`:
```bash
  AL_BASE_OVERRIDE="$branch" AL_SKIP_PROVISION=1 \
  AL_SECURITY_AGENT=1 AL_SECURITY_ANALYSIS_ID="$aid" \
    run_job "$jid" --force || rc=$?
```
→
```bash
  AL_BASE_OVERRIDE="$branch" AL_SKIP_PROVISION=1 \
  AL_SECURITY_AGENT=1 CC_SECURITY_AGENT=1 \
  AL_SECURITY_ANALYSIS_ID="$aid" CC_SECURITY_ANALYSIS_ID="$aid" \
    run_job "$jid" --force || rc=$?
```

As três linhas com `export AL_PRECHECK_DRY_RUN=1` (em `cmd_check`'s precheck, no precheck de um resume dentro de `run_job`, e em `cmd_precheck`) — localiza-as com `grep -n 'export AL_PRECHECK_DRY_RUN=1' bin/agentloop` e em cada uma substitui `export AL_PRECHECK_DRY_RUN=1` por `export AL_PRECHECK_DRY_RUN=1 CC_PRECHECK_DRY_RUN=1`.

Em `run_job`, o bloco `run_env+=(…)`:
```bash
    run_env+=("AL_RUN_DIR=$run_dir" "AL_RUN_MANIFEST=$run_dir/.run.json" \
              "AL_PROJECT=$project" "AL_JOB_ID=$id" \
              "AL_PRIMARY_REPO=$(basename "$run_cwd")" \
              "AL_PORT_BASE=$port_base" "AL_PORT_SPAN=$AL_PORT_SPAN" \
              "AL_PROVISION_LIB=$BIN_DIR/provision-lib.sh")
```
→
```bash
    # Both spellings of every run variable, for one release: the prompts,
    # prechecks and hooks of an existing install still read the old one.
    local primary_repo; primary_repo="$(basename "$run_cwd")"
    run_env+=("AL_RUN_DIR=$run_dir" "CC_RUN_DIR=$run_dir" \
              "AL_RUN_MANIFEST=$run_dir/.run.json" "CC_RUN_MANIFEST=$run_dir/.run.json" \
              "AL_PROJECT=$project" "CC_PROJECT=$project" "AL_JOB_ID=$id" "CC_JOB_ID=$id" \
              "AL_PRIMARY_REPO=$primary_repo" "CC_PRIMARY_REPO=$primary_repo" \
              "AL_PORT_BASE=$port_base" "CC_PORT_BASE=$port_base" \
              "AL_PORT_SPAN=$AL_PORT_SPAN" "CC_PORT_SPAN=$AL_PORT_SPAN" \
              "AL_PROVISION_LIB=$BIN_DIR/provision-lib.sh" "CC_PROVISION_LIB=$BIN_DIR/provision-lib.sh")
```

Em `run_end_hook`, o corpo de `_hook`:
```bash
      AL_JOB_ID="$1" AL_STATUS="$2" AL_COST="$3" AL_NOTE="$4" AL_PROJECT="$5" \
      AL_SESSION="$6" AL_LOG="$7" AL_START="$8" AL_END="$9" \
      AL_DURATION="$(( ${9:-0} - ${8:-0} ))" AL_DASHBOARD="http://127.0.0.1:$PORT/" \
        bash "$script" >>"$DATA_DIR/exec.log" 2>&1
```
→
```bash
      AL_JOB_ID="$1" CC_JOB_ID="$1" AL_STATUS="$2" CC_STATUS="$2" AL_COST="$3" CC_COST="$3" \
      AL_NOTE="$4" CC_NOTE="$4" AL_PROJECT="$5" CC_PROJECT="$5" \
      AL_SESSION="$6" CC_SESSION="$6" AL_LOG="$7" CC_LOG="$7" \
      AL_START="$8" CC_START="$8" AL_END="$9" CC_END="$9" \
      AL_DURATION="$(( ${9:-0} - ${8:-0} ))" CC_DURATION="$(( ${9:-0} - ${8:-0} ))" \
      AL_DASHBOARD="http://127.0.0.1:$PORT/" CC_DASHBOARD="http://127.0.0.1:$PORT/" \
        bash "$script" >>"$DATA_DIR/exec.log" 2>&1
```

Em `fleet_stall_check`, o corpo de `_stall_hook`:
```bash
      AL_REASON="$1" AL_STALL_HOURS="$STALL_HOURS" AL_DASHBOARD="http://127.0.0.1:$PORT/" \
        bash "$script" >>"$DATA_DIR/exec.log" 2>&1
```
→
```bash
      AL_REASON="$1" CC_REASON="$1" AL_STALL_HOURS="$STALL_HOURS" CC_STALL_HOURS="$STALL_HOURS" \
      AL_DASHBOARD="http://127.0.0.1:$PORT/" CC_DASHBOARD="http://127.0.0.1:$PORT/" \
        bash "$script" >>"$DATA_DIR/exec.log" 2>&1
```

Os dois `export AL_PORT_BASE="$port_base" AL_PORT_SPAN AL_PROVISION_LIB=…` dentro de `run_job` ficam como estão: são o ambiente interno que `wt_setup` lê, e o hook recebe o seu ambiente explícito em `wt_provision` (passo seguinte).

- [ ] **Step 6: A exportação dupla no hook de provisioning**

Em `bin/worktree-lib.sh`, dentro de `wt_provision`, o corpo de `_wt_hook`:
```bash
    AL_REPO_NAME="$name" AL_REPO_PATH="$repo" AL_WORKTREE="$wt" AL_BASE="$base" \
    AL_RUN_DIR="$run_dir" AL_RUN_MANIFEST="$run_dir/.run.json" \
    AL_PROJECT="$project" AL_JOB_ID="$id" \
    AL_PORT_BASE="$pb" AL_PORT_SPAN="${AL_PORT_SPAN:-100}" \
    AL_PROVISION_LIB="${AL_PROVISION_LIB:-}" \
      bash "$script" >>"$DATA_DIR/exec.log" 2>&1
```
→
```bash
    AL_REPO_NAME="$name" CC_REPO_NAME="$name" AL_REPO_PATH="$repo" CC_REPO_PATH="$repo" \
    AL_WORKTREE="$wt" CC_WORKTREE="$wt" AL_BASE="$base" CC_BASE="$base" \
    AL_RUN_DIR="$run_dir" CC_RUN_DIR="$run_dir" \
    AL_RUN_MANIFEST="$run_dir/.run.json" CC_RUN_MANIFEST="$run_dir/.run.json" \
    AL_PROJECT="$project" CC_PROJECT="$project" AL_JOB_ID="$id" CC_JOB_ID="$id" \
    AL_PORT_BASE="$pb" CC_PORT_BASE="$pb" \
    AL_PORT_SPAN="${AL_PORT_SPAN:-100}" CC_PORT_SPAN="${AL_PORT_SPAN:-100}" \
    AL_PROVISION_LIB="${AL_PROVISION_LIB:-}" CC_PROVISION_LIB="${AL_PROVISION_LIB:-}" \
      bash "$script" >>"$DATA_DIR/exec.log" 2>&1
```

- [ ] **Step 7: As leituras com fallback em `provision-lib.sh` e `round-cap.sh`**

Em `bin/provision-lib.sh`, depois do passo 1 as funções chamam-se `al_port`, `al_env_set`, `al_env_ports`, `al_copy_ignored`. Substitui `al_port` inteira por:

```bash
al_port() { # <NAME> [fallback]
  local name="${1:?al_port needs a name}" fallback="${2:-}"
  # AL_PORT_BASE, or its pre-rename spelling, for one release.
  local base="${AL_PORT_BASE:-${CC_PORT_BASE:-}}"
  if [ -z "$base" ]; then printf '%s\n' "$fallback"; return 0; fi
  local span="${AL_PORT_SPAN:-${CC_PORT_SPAN:-100}}" file="${TMPDIR:-/tmp}/al-ports.$$.$base"
  local seen n
  seen="$(grep -m1 "^$name " "$file" 2>/dev/null | cut -d' ' -f2 || true)"
  if [ -n "$seen" ]; then printf '%s\n' "$seen"; return 0; fi
  # `wc -l < missing` is a REDIRECTION error, raised by the shell before wc ever
  # runs — so a 2>/dev/null inside the substitution does not silence it, and the
  # first al_port of every run would print a spurious "No such file" into
  # exec.log. Ask whether the file is there instead.
  n=0
  [ -f "$file" ] && n="$(wc -l < "$file" | tr -d ' ')"
  if [ "$n" -ge "$span" ]; then
    echo "al_port: this run has used all $span ports of its block" >&2
    printf '%s\n' "$fallback"; return 1
  fi
  local port=$(( base + n ))
  printf '%s %s\n' "$name" "$port" >> "$file"
  printf '%s\n' "$port"
}
```

Em `al_copy_ignored`, substitui as duas leituras de `$AL_REPO_PATH`:
```bash
al_copy_ignored() { # <path relative to the repo root> [...]
  local f repo="${AL_REPO_PATH:-${CC_REPO_PATH:-}}"
  for f in "$@"; do
    [ -f "$repo/$f" ] || continue
    mkdir -p "$(dirname "$f")"
    # -c asks APFS for a clone: same bytes, no copy, no extra disk.
    cp -c "$repo/$f" "$f" 2>/dev/null || cp "$repo/$f" "$f"
  done
}
```

No fim do ficheiro, os aliases:
```bash
# The pre-rename names of the four helpers above, kept for one release so a
# hook written before 2026-09-06 keeps working. Delete after.
cc_port()         { al_port "$@"; }
cc_env_set()      { al_env_set "$@"; }
cc_env_ports()    { al_env_ports "$@"; }
cc_copy_ignored() { al_copy_ignored "$@"; }
```

No cabeçalho do ficheiro, a linha `#     source "$AL_PROVISION_LIB"` e os exemplos `al_port POSTGRES_PORT`, `al_env_ports .env` já vêm do passo 4.

Em `bin/round-cap.sh`:
```bash
RC_CAP="${AL_ROUND_CAP:-2}"
```
→
```bash
RC_CAP="${AL_ROUND_CAP:-${CC_ROUND_CAP:-2}}"
```
```bash
RC_ROUND_STATUS="${AL_ROUND_STATUS:-Change Requested}"
```
→
```bash
RC_ROUND_STATUS="${AL_ROUND_STATUS:-${CC_ROUND_STATUS:-Change Requested}}"
```
```bash
  if [ -n "${AL_PRECHECK_DRY_RUN:-}" ]; then
```
→
```bash
  if [ -n "${AL_PRECHECK_DRY_RUN:-${CC_PRECHECK_DRY_RUN:-}}" ]; then
```

- [ ] **Step 8: As leituras com fallback no pacote `security`**

Em `bin/security/adapters.py`:
```python
ENGINES_ENV = "AL_SECURITY_ENGINES"
_OFF = {"off", "0", "no", "false", "none"}


def engine_path(name: str):
    """The engine's binary, or None when it is absent OR switched off."""
    if os.environ.get(ENGINES_ENV, "").strip().lower() in _OFF:
        return None
    return engines.find(name)
```
→
```python
ENGINES_ENV = "AL_SECURITY_ENGINES"
# The switch's spelling before 2026-09-06, read for one release. Delete after.
LEGACY_ENGINES_ENV = "CC_SECURITY_ENGINES"
_OFF = {"off", "0", "no", "false", "none"}


def _engines_setting() -> str:
    """The switch, lower-cased and stripped: ENGINES_ENV, else its pre-rename
    spelling, else empty (which reads as ON, see engine_path)."""
    v = os.environ.get(ENGINES_ENV)
    if v is None:
        v = os.environ.get(LEGACY_ENGINES_ENV, "")
    return v.strip().lower()


def engine_path(name: str):
    """The engine's binary, or None when it is absent OR switched off."""
    if _engines_setting() in _OFF:
        return None
    return engines.find(name)
```

Em `bin/security/cli.py`, antes da função que contém `if os.environ.get("AL_SECURITY_AGENT", "").strip():` (localiza com `grep -n 'AL_SECURITY_AGENT", ""' bin/security/cli.py`), acrescenta ao nível do módulo:

```python
def _agent_env(name: str) -> str:
    """The run-environment variable AL_<name>, or its pre-rename spelling —
    the engine exports both for one release, a hook written before the rename
    may still set only the old one. Stripped; empty when neither is set."""
    return (os.environ.get("AL_" + name) or os.environ.get("CC_" + name) or "").strip()
```

e substitui as três leituras:
```python
    if os.environ.get("AL_SECURITY_AGENT", "").strip():
```
→
```python
    if _agent_env("SECURITY_AGENT"):
```
```python
    manifest = os.environ.get("AL_RUN_MANIFEST", "").strip()
    if not (os.environ.get("AL_SECURITY_AGENT", "").strip() and manifest):
```
→
```python
    manifest = _agent_env("RUN_MANIFEST")
    if not (_agent_env("SECURITY_AGENT") and manifest):
```

```bash
grep -n 'os.environ.get("AL_' bin/security/cli.py
```
Esperado: nenhuma linha.

- [ ] **Step 9: O aviso dos scripts pessoais**

Em `bin/agentloop`, logo a seguir à função `legacy_env_warnings` da Task 2, acrescenta:

```bash
# The run-environment prefix before 2026-09-06. The engine exports every run
# variable under both prefixes for one release; this names the operator's own
# scripts that still read the old one, so they can be moved before the export
# stops. Delete with the dual exports.
LEGACY_RUN_PREFIX="CC_"

legacy_scripts_warnings() { # one line per personal script under config/ still reading the old prefix
  local f n
  for f in "$CONFIG_DIR"/prechecks/*.sh "$CONFIG_DIR"/provision/*.sh "$CONFIG_DIR"/hooks/*; do
    [ -f "$f" ] || continue
    n="$(num "$(grep -cE "${LEGACY_RUN_PREFIX}[A-Z_]+" "$f" 2>/dev/null)")"
    [ "$n" -gt 0 ] || continue
    printf 'WARNING: %s reads %s* on %s line(s) — those names are exported alongside AL_* for now, and stop in the next release.\n' \
      "$f" "$LEGACY_RUN_PREFIX" "$n"
  done
}
```

E chama-a nos dois sítios onde a Task 2 pôs `legacy_env_warnings`, logo a seguir:
```bash
  legacy_env_warnings
  legacy_scripts_warnings
```

- [ ] **Step 10: Correr tudo**

```bash
bin/agentloop selftest 2>&1 | tail -3
bash test/round-cap.test.sh 2>&1 | tail -3
python3 -m pytest tests/ -q --ignore=tests/security 2>&1 | tail -3
python3 -m pytest tests/security -q 2>&1 | tail -3
bash test/e2e.test.sh 2>&1 | tail -3
python3 -m pytest tests/test_no_old_name_survives.py -q 2>&1 | grep -cE ': (CC_|cc_)'
```
Esperado: suites verdes; o último número é `0`. (O selftest já corre `test/round-cap.test.sh`; correr à parte dá o output inteiro.)

- [ ] **Step 11: CHANGELOG e commit**

Sub-ponto na entrada:

```markdown
  - The run environment is `AL_*` (it was `CC_*`), and the provisioning helpers
    are `al_port`, `al_env_set`, `al_env_ports` and `al_copy_ignored`. **For
    this release only** every run variable is exported under both prefixes
    and the old helper names still answer, and `install` and `status` name
    each script under `config/` that still reads the old prefix.
```

```bash
git add -A
git commit -m "rename: CC_* becomes AL_*, exported under both names for one release

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: O header, os globais da página, `al()` e `al_server`, e o rebuild

**Files:**
- Modify: `bin/agentloop-server` (`_authed`, `al()`), `bin/dashboard.html`, `ui/app/*.js`, `ui/security/*.js`, `ui/css/pages.css`, `tests/conftest.py`, `tests/test_page_contract.py`, `tests/test_rename_transition.py`, `bin/static/security.js`, `bin/static/app.js`, `bin/static/app.css` (rebuild), `CHANGELOG.md`

**Interfaces:**
- Produces: header `X-AL-Token`; `Handler._authed` aceita os dois; `al(args, stdin=None, background=False)` no servidor; globais `ALApp`, `ALSecurity` e o objecto `AL` na página; módulo de teste `al_server`.

- [ ] **Step 1: O pytest do header duplo, que vai falhar**

Acrescenta a `tests/test_rename_transition.py`:

```python
def test_the_api_accepts_the_pre_rename_token_header_for_one_release(srv):
    """A dashboard tab open across the upgrade keeps sending the old header
    until it reloads; refusing it would log the operator out mid-click."""
    class Req:
        def __init__(self, headers):
            self.headers = headers

    authed = srv.Handler._authed
    assert authed(Req({"X-AL-Token": srv.TOKEN}))
    assert authed(Req({"X-CC-Token": srv.TOKEN}))   # the spelling before X-AL-Token
    assert not authed(Req({"X-AL-Token": "nope"}))
    assert not authed(Req({}))
    assert not authed(Req({"X-AL-Token": srv.TOKEN, "Origin": "http://evil.example"}))
```

```bash
python3 -m pytest tests/test_rename_transition.py -q 2>&1 | tail -3
```
Esperado: `FAILED … test_the_api_accepts_the_pre_rename_token_header…` (o header novo ainda não autentica).

- [ ] **Step 2: As substituições**

```bash
perl -pi -e 's/X-CC-Token/X-AL-Token/g' \
  bin/agentloop-server bin/dashboard.html ui/app/*.js ui/security/*.js tests/test_page_contract.py
perl -pi -e 's/CCApp/ALApp/g; s/CCSecurity/ALSecurity/g' \
  bin/dashboard.html ui/app/*.js ui/security/*.js ui/css/pages.css tests/test_page_contract.py
perl -pi -e 's/\bCC\b/AL/g' \
  bin/dashboard.html ui/app/*.js ui/security/*.js tests/test_page_contract.py
perl -pi -e 's/\bcc\(/al(/g' bin/agentloop-server
perl -pi -e 's/cc_server/al_server/g' tests/conftest.py
perl -pi -e 's/\bcc-(logo|g1|g2)\b/al-$1/g' bin/dashboard.html
grep -c 'ALApp' bin/dashboard.html          # expected: 179
grep -c 'X-AL-Token' bin/dashboard.html     # expected: 23
grep -n 'const AL = {' bin/dashboard.html   # expected: one line
grep -n 'def al(' bin/agentloop-server      # expected: one line
grep -rnE 'CCApp|CCSecurity|X-CC-Token|\bCC\b|\bcc\(|cc_server|cc-logo' bin/agentloop-server bin/dashboard.html ui tests/*.py \
  | grep -v test_rename_transition | grep -v test_no_old_name_survives
```
Esperado no último: nenhuma linha (os dois testes excluídos nomeiam o header antigo de propósito, emparelhado com o novo).

- [ ] **Step 3: O header duplo no servidor**

Em `bin/agentloop-server`, em `Handler._authed`:
```python
        return secrets.compare_digest(self.headers.get("X-AL-Token", ""), TOKEN)
```
→
```python
        # The header, and its spelling before 2026-09-06: a dashboard tab open
        # across the upgrade keeps sending the old one until it reloads. The
        # second read goes in the release after the rename.
        sent = self.headers.get("X-AL-Token") or self.headers.get("X-CC-Token") or ""
        return secrets.compare_digest(sent, TOKEN)
```

E na docstring do módulo (linha ~16), a frase `the shared token in the X-AL-Token header;` já vem do passo 2.

- [ ] **Step 4: Reconstruir os artefactos da UI**

Precisa de rede na primeira vez: `npx` descarrega o esbuild 0.25.0 que o script fixa.

```bash
bash build/build-ui.sh
git status --short bin/static/
grep -c 'ALApp' bin/static/app.js        # expected: > 0
grep -c 'X-AL-Token' bin/static/app.js   # expected: > 0
```
Esperado: os três ficheiros em `bin/static/` modificados.

- [ ] **Step 5: Correr tudo**

```bash
bin/agentloop selftest 2>&1 | tail -3
python3 -m pytest tests/ -q --ignore=tests/security 2>&1 | tail -3
bash test/e2e.test.sh 2>&1 | tail -3
python3 -m pytest tests/test_no_old_name_survives.py -q 2>&1 | tail -3
```
Esperado: suites verdes, incluindo `check_ui_artifacts` no fim do selftest. O guarda deve estar a **passar** a partir daqui, ou a falhar só em `uninstall.sh` (a Task 5 trata dela). Se falhar noutro sítio, o que ele lista é o que falta.

- [ ] **Step 6: CHANGELOG e commit**

Sub-ponto na entrada:

```markdown
  - The dashboard's token header is `X-AL-Token` (it was `X-CC-Token`), and
    the page's own globals are `ALApp`, `ALSecurity` and `AL`. **For this
    release only** the server also accepts the old header, so a tab left open
    across the upgrade keeps working until it reloads.
```

```bash
git add -A
git commit -m "rename: X-AL-Token, ALApp, ALSecurity and al() — the old header is accepted for one release

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: A migração de uma instalação antiga, e os avisos

**Files:**
- Modify: `bin/agentloop` (constantes `LEGACY_*` junto de `PLIST_LABEL`; `install_migrate_legacy`; `statusline_path_warning`; `cmd_install`; `cmd_uninstall`; `cmd_status`; `cmd_selftest`), `uninstall.sh`, `CHANGELOG.md`

**Interfaces:**
- Produces: `LEGACY_PLIST_LABEL`, `LEGACY_SERVER_LABEL`, `LEGACY_CLI_NAME`; `install_migrate_legacy` (imprime no stdout o `CLAUDE_CONFIG_DIR` fixado no plist antigo, se houver; mensagens no stderr); `statusline_path_warning`.
- Consumes: `legacy_env_warnings`, `legacy_scripts_warnings` (Tasks 2 e 3).

- [ ] **Step 1: O caso de selftest que vai falhar**

Em `bin/agentloop`, dentro de `cmd_selftest`, imediatamente antes de `echo "the rename — a run, its hooks and its prechecks see AL_* and CC_* alike for one release"`, acrescenta:

```bash
  echo "the rename — install retires the pre-rename agents and symlinks, and keeps the pinned account"
  mkdir -p "$tmp/mig/home/Library/LaunchAgents" "$tmp/mig/home/.local/bin" "$tmp/mig/fakebin"
  printf '%s\n' '#!/bin/sh' 'echo "launchctl $*" >> "$MIG_LOG"' > "$tmp/mig/fakebin/launchctl"
  chmod +x "$tmp/mig/fakebin/launchctl"
  cat > "$tmp/mig/home/Library/LaunchAgents/$LEGACY_PLIST_LABEL.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>x</string>
  <key>EnvironmentVariables</key><dict><key>CLAUDE_CONFIG_DIR</key><string>/tmp/pinned-account</string></dict>
</dict></plist>
PLIST
  : > "$tmp/mig/home/Library/LaunchAgents/$LEGACY_SERVER_LABEL.plist"
  ln -s "$BASE_DIR/bin/$LEGACY_CLI_NAME" "$tmp/mig/home/.local/bin/$LEGACY_CLI_NAME"
  ln -s "/somewhere/else/$LEGACY_CLI_NAME-server" "$tmp/mig/home/.local/bin/$LEGACY_CLI_NAME-server"
  got="$( HOME="$tmp/mig/home" MIG_LOG="$tmp/mig/log" PATH="$tmp/mig/fakebin:$PATH" install_migrate_legacy 2>/dev/null )"
  [ "$got" = "/tmp/pinned-account" ] && ok "the account pinned in the old agent is handed on" || bad "install_migrate_legacy printed '$got'"
  [ ! -e "$tmp/mig/home/Library/LaunchAgents/$LEGACY_PLIST_LABEL.plist" ] \
    && [ ! -e "$tmp/mig/home/Library/LaunchAgents/$LEGACY_SERVER_LABEL.plist" ] \
    && ok "both old plists are gone" || bad "an old plist survived"
  grep -q "launchctl unload .*$LEGACY_PLIST_LABEL" "$tmp/mig/log" 2>/dev/null \
    && grep -q "launchctl unload .*$LEGACY_SERVER_LABEL" "$tmp/mig/log" 2>/dev/null \
    && ok "and both were unloaded before being removed" || bad "unload was not called: $(cat "$tmp/mig/log" 2>/dev/null)"
  [ ! -L "$tmp/mig/home/.local/bin/$LEGACY_CLI_NAME" ] && ok "the old symlink into this folder is removed" || bad "the old symlink was kept"
  [ -L "$tmp/mig/home/.local/bin/$LEGACY_CLI_NAME-server" ] && ok "a symlink pointing elsewhere is left alone" || bad "somebody else's symlink was removed"
  got="$( HOME="$tmp/mig/home" MIG_LOG="$tmp/mig/log" PATH="$tmp/mig/fakebin:$PATH" install_migrate_legacy 2>/dev/null )"
  [ -z "$got" ] && ok "a second run finds nothing to migrate" || bad "second run printed '$got'"

  echo "the rename — the statusline that still points at the old folder is named"
  mkdir -p "$tmp/mig/home2/.claude"
  printf '{"statusLine":{"type":"command","command":"/Users/me/%s/bin/statusline-rate-limits.sh"}}\n' "$LEGACY_CLI_NAME" \
    > "$tmp/mig/home2/.claude/settings.json"
  got="$( HOME="$tmp/mig/home2" statusline_path_warning )"
  case "$got" in *"statusline-rate-limits.sh"*"$BIN_DIR/statusline-rate-limits.sh"*) ok "the warning names the old path and the new one" ;;
                 *) bad "the warning was: '$got'" ;; esac
  printf '{"statusLine":{"type":"command","command":"%s/statusline-rate-limits.sh"}}\n' "$BIN_DIR" \
    > "$tmp/mig/home2/.claude/settings.json"
  got="$( HOME="$tmp/mig/home2" statusline_path_warning )"
  [ -z "$got" ] && ok "a statusline already on the new path gets no warning" || bad "warned anyway: '$got'"

```

```bash
bin/agentloop selftest 2>&1 | grep -E 'FAIL' | head -5
```
Esperado: os casos novos em `FAIL` (`install_migrate_legacy: command not found` no stderr suprimido; `$LEGACY_PLIST_LABEL` vazio).

- [ ] **Step 2: As constantes e as duas funções**

Em `bin/agentloop`, logo a seguir a `SERVER_PLIST="$HOME/Library/LaunchAgents/$SERVER_LABEL.plist"`, insere:

```bash
# The names this install had until 2026-09-06. A machine installed under them
# still carries two launchd agents and two symlinks so named; `install`
# retires them (install_migrate_legacy). These three lines are the only place
# the old names are spelled — everything else reaches them through here.
LEGACY_PLIST_LABEL="com.claude-cron.tick"
LEGACY_SERVER_LABEL="com.claude-cron.server"
LEGACY_CLI_NAME="claude-cron"
```

Logo antes de `cmd_install()`, insere:

```bash
install_migrate_legacy() { # retire the pre-rename agents and symlinks; prints the account they had pinned, if any
  local old_tick="$HOME/Library/LaunchAgents/$LEGACY_PLIST_LABEL.plist"
  local old_server="$HOME/Library/LaunchAgents/$LEGACY_SERVER_LABEL.plist"
  local link
  if [ -f "$old_tick" ]; then
    # The account pinned into the old agent has to reach the new one: dropping
    # it would sign every run in as the CLI default from the next tick on.
    "$PYTHON" - "$old_tick" <<'PY'
import plistlib, sys
try:
    v = plistlib.load(open(sys.argv[1], "rb")).get("EnvironmentVariables", {}).get("CLAUDE_CONFIG_DIR")
except Exception:
    v = None
if v:
    print(v)
PY
    launchctl unload "$old_tick" 2>/dev/null
    rm -f "$old_tick"
    echo "retired $LEGACY_PLIST_LABEL" >&2
  fi
  if [ -f "$old_server" ]; then
    launchctl unload "$old_server" 2>/dev/null
    rm -f "$old_server"
    echo "retired $LEGACY_SERVER_LABEL" >&2
  fi
  for link in "$HOME/.local/bin/$LEGACY_CLI_NAME" "$HOME/.local/bin/$LEGACY_CLI_NAME-server"; do
    # Only a link into THIS folder is ours to remove.
    [ -L "$link" ] || continue
    case "$(readlink "$link")" in
      "$BASE_DIR"/*) rm -f "$link"; echo "removed $link" >&2 ;;
    esac
  done
}

statusline_path_warning() { # ~/.claude/settings.json may still run the statusline from the folder's old name
  local settings="$HOME/.claude/settings.json" cmd
  [ -f "$settings" ] || return 0
  cmd="$("$JQ" -r '.statusLine.command // ""' "$settings" 2>/dev/null)"
  case "$cmd" in
    *"/$LEGACY_CLI_NAME/"*)
      echo "WARNING: the statusLine in $settings runs $cmd — that folder was renamed; point it at $BIN_DIR/statusline-rate-limits.sh" ;;
  esac
}
```

- [ ] **Step 3: `cmd_install`, `cmd_uninstall`, `cmd_status`**

Em `cmd_install`, o início:
```bash
  local plist_cfgdir=""
  if [ -n "${AGENTLOOP_CLAUDE_CONFIG_DIR:-}" ]; then
```
→
```bash
  # An install that predates the rename is retired first, and the account it
  # had pinned is read out of it before it goes.
  local legacy_cfgdir
  legacy_cfgdir="$(install_migrate_legacy)"
  local plist_cfgdir=""
  if [ -n "${AGENTLOOP_CLAUDE_CONFIG_DIR:-}" ]; then
```

e o fim desse `if` (a seguir ao heredoc `PY` que lê o plist novo):
```bash
)"
  fi

  # 1) the tick agent — fires the scheduler once a minute
```
→
```bash
)"
  elif [ -n "$legacy_cfgdir" ]; then
    plist_cfgdir="
    <key>CLAUDE_CONFIG_DIR</key><string>$legacy_cfgdir</string>"
  fi

  # 1) the tick agent — fires the scheduler once a minute
```

No fim de `cmd_install`, onde a Task 3 deixou:
```bash
  legacy_env_warnings
  legacy_scripts_warnings
```
→
```bash
  legacy_env_warnings
  legacy_scripts_warnings
  statusline_path_warning
```

`cmd_uninstall`:
```bash
cmd_uninstall() {
  launchctl unload "$PLIST_PATH" 2>/dev/null
  launchctl unload "$SERVER_PLIST" 2>/dev/null
  rm -f "$PLIST_PATH" "$SERVER_PLIST"
  echo "Unloaded and removed both agents. Jobs, state and logs were kept."
}
```
→
```bash
cmd_uninstall() {
  install_migrate_legacy >/dev/null     # an install that was never re-run since the rename still has the old agents
  launchctl unload "$PLIST_PATH" 2>/dev/null
  launchctl unload "$SERVER_PLIST" 2>/dev/null
  rm -f "$PLIST_PATH" "$SERVER_PLIST"
  echo "Unloaded and removed both agents. Jobs, state and logs were kept."
}
```

No fim de `cmd_status`, a seguir a `legacy_scripts_warnings`, acrescenta `statusline_path_warning`.

- [ ] **Step 4: `uninstall.sh`**

```bash
#!/bin/bash
# agentloop uninstaller. Removes the launchd agents and the ~/.local/bin
# symlinks. Your jobs, prechecks and run history under this folder are KEPT.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# The symlinks an install made under the pre-rename name; removed too.
LEGACY_CLI_NAME="claude-cron"

echo "agentloop · uninstaller"
"$HERE/bin/agentloop" uninstall || true
rm -f "$HOME/.local/bin/agentloop" "$HOME/.local/bin/agentloop-server" \
      "$HOME/.local/bin/$LEGACY_CLI_NAME" "$HOME/.local/bin/$LEGACY_CLI_NAME-server"
echo "Removed the agents and the PATH symlinks."
echo "Kept: config/ (jobs, prechecks) and data/ (history, index.db) under $HERE."
echo "Delete the whole folder to remove everything."
```

- [ ] **Step 5: Correr tudo**

```bash
bash -n bin/agentloop && bash -n uninstall.sh
bin/agentloop selftest 2>&1 | tail -3
python3 -m pytest tests/ -q --ignore=tests/security 2>&1 | tail -3
bash test/e2e.test.sh 2>&1 | tail -3
python3 -m pytest tests/test_no_old_name_survives.py -q 2>&1 | tail -3
```
Esperado: tudo verde, guarda incluído.

- [ ] **Step 6: CHANGELOG e commit**

Sub-ponto na entrada:

```markdown
  - `agentloop install` retires the two pre-rename launchd agents and the old
    `~/.local/bin` symlinks on an existing machine, carrying the pinned Claude
    account over to the new agents, and says so when `~/.claude/settings.json`
    still runs the statusline from the folder's old name. Re-running
    `install.sh` is the whole upgrade.
```

```bash
git add -A
git commit -m "rename: install retires the pre-rename agents and symlinks and keeps the pinned account

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: A documentação, e o guarda a passar de vez

**Files:**
- Modify: `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md` (verificar), `.github/pull_request_template.md` (verificar)

- [ ] **Step 1: A secção de upgrade no README**

Em `README.md`, imediatamente antes da linha `### Verify it is running`, insere (a fence exterior de quatro acentos é só deste plano; o bloco `bash` interior vai para o README tal como está):

````markdown
### Upgrading from claude-cron

This scheduler was called **claude-cron** until 2026-09-06. An install made
under that name upgrades by pulling and running the installer again:

```bash
bash install.sh
```

`agentloop install` retires the two old agents (`com.claude-cron.tick` and
`com.claude-cron.server`), carrying the Claude account pinned in them over to
the new ones, and replaces the `claude-cron` and `claude-cron-server` symlinks
in `~/.local/bin`. Your jobs, projects, run history and prechecks are untouched.

Three things still answer to their old names **for this release only**, and the
installer and `agentloop status` list every one they find on your machine:

- the environment: every `CLAUDE_CRON_*` is read as `AGENTLOOP_*`;
- the run environment: every `CC_*` your prechecks, provisioning hooks and
  `on-run-end.sh` read is exported alongside its `AL_*` twin, and `cc_port`,
  `cc_env_set`, `cc_env_ports` and `cc_copy_ignored` still answer for
  `al_port` and its siblings;
- the dashboard's `X-CC-Token` header, now `X-AL-Token`.

Rename them at your leisure before the next release, where the old spellings
stop working. If the folder itself was renamed, point the `statusLine` in
`~/.claude/settings.json` at the new path — the installer says so when it
notices. The repository moved to `lmelomoura/agentloop`; GitHub redirects the
old address.

````

- [ ] **Step 2: O cabeçalho do CHANGELOG**

Em `CHANGELOG.md`:
```markdown
All notable changes to claude-cron.
```
→
```markdown
All notable changes to agentloop — called claude-cron until 2026-09-06; entries
older than that use the old name, as they did on their day.
```
e, no mesmo parágrafo de introdução:
```markdown
cannot trust or adopt. `claude-cron selftest` fails when `main` has moved and this
```
→
```markdown
cannot trust or adopt. `agentloop selftest` fails when `main` has moved and this
```

- [ ] **Step 3: Verificar o que a Task 1 já mudou nos outros documentos**

```bash
grep -n 'agentloop' CONTRIBUTING.md | head -5           # fork line: gh repo fork lmelomoura/agentloop --clone
grep -n 'selftest' .github/pull_request_template.md     # - [ ] `agentloop selftest` passes
grep -n '"name"' package.json                            # "agentloop-ui"
grep -n 'agentloop-hello' config/jobs.example.json config/prechecks/example-hello.sh
```
Esperado: as quatro linhas com o nome novo.

- [ ] **Step 4: O guarda passa, e tudo o resto também**

```bash
python3 -m pytest tests/test_no_old_name_survives.py -q 2>&1 | tail -3
bin/agentloop selftest 2>&1 | tail -3
python3 -m pytest tests/ -q --ignore=tests/security 2>&1 | tail -3
python3 -m pytest tests/security -q 2>&1 | tail -3
bash test/e2e.test.sh 2>&1 | tail -3
```
Esperado: `1 passed` no guarda e o resto verde.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "docs: how an install called claude-cron upgrades to agentloop

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: Verificação final, PR, e o que fica para o operador

**Files:** nenhum novo.

- [ ] **Step 1: A árvore está limpa e os artefactos são reprodutíveis**

```bash
git status --short                 # expected: empty
bash build/build-ui.sh && git status --short bin/static/   # expected: empty (the build is reproducible)
bin/agentloop selftest 2>&1 | tail -1
python3 -m pytest tests/ -q 2>&1 | tail -1
bash test/e2e.test.sh 2>&1 | tail -1
```

- [ ] **Step 2: Uma instalação real, nesta máquina**

Só depois de tudo o resto: o `install` toca no launchd do operador. Antes, confirma que a instalação actual está viva; depois, que só a nova existe. A regra desta máquina é UMA instância do servidor de cada vez.

```bash
launchctl list | grep -E 'claude-cron|agentloop'          # before: the two com.claude-cron.* agents
bash install.sh
launchctl list | grep -E 'claude-cron|agentloop'          # after: only com.agentloop.tick and com.agentloop.server
ls -la ~/.local/bin | grep -E 'claude-cron|agentloop'     # after: only agentloop and agentloop-server
agentloop status | tail -12                               # the WARNING lines name what is still on the old names
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8787/health   # 200
```

O `status` deve nomear os oito scripts pessoais em `config/prechecks` e `config/provision` que lêem `CC_*`. Passá-los a `AL_*` é opcional e é do operador: se ele disser que sim na altura, `perl -pi -e 's/\bCC_/AL_/g; s/\bcc_(port|env_set|env_ports|copy_ignored)\b/al_$1/g' config/prechecks/*.sh config/provision/*.sh` e um `agentloop check <job>` por job para ver o precheck a correr.

- [ ] **Step 3: O PR**

```bash
git push -u origin feat/rename-to-agentloop
gh pr create --base main --title "claude-cron is now agentloop" --body "$(cat <<'EOF'
## What

The product is renamed to **agentloop**, down to the run-environment prefix and the dashboard header, per `docs/superpowers/specs/2026-09-06-rename-to-agentloop-design.md`.

- binaries `bin/agentloop`, `bin/agentloop-server` (`git mv`, history kept); symlinks and launchd labels follow
- `CLAUDE_CRON_*` → `AGENTLOOP_*`; `CC_*` → `AL_*`; `cc_port` family → `al_*`; `X-CC-Token` → `X-AL-Token`; `CCApp`/`CCSecurity`/`CC` → `ALApp`/`ALSecurity`/`AL`
- `agentloop install` retires the old agents and symlinks on an existing machine and keeps the pinned account
- **one-release transition**: every old spelling still works and `install`/`status` list what they find; `tests/test_no_old_name_survives.py` is the definition of "renamed" and the list to empty when the transition ends

## How to verify

- [ ] `bin/agentloop selftest` passes
- [ ] `python3 -m pytest tests/ -q` passes (both `tests/security` configurations run in CI)
- [ ] `bash test/e2e.test.sh` passes
- [ ] `bash install.sh` on a machine that had claude-cron: only `com.agentloop.*` remain loaded, the dashboard answers, `agentloop status` names what is still on the old names

## After merge (operator)

1. `gh repo rename agentloop`
2. `mv ~/Projects/claude-cron ~/Projects/agentloop && cd ~/Projects/agentloop && bash install.sh`
3. point `statusLine.command` in `~/.claude/settings.json` at the new path

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 4: Depois do merge — as três acções do operador, na ordem**

Não são passos deste plano; ficam aqui para não se perderem. 1) `gh repo rename agentloop`. 2) mover a pasta e correr `bash install.sh` de dentro dela. 3) apontar o `statusLine` para o caminho novo. O assistente move então a pasta de memória do projecto e actualiza a nota `claude-cron-post-merge` (label do launchd e nome do comando).
