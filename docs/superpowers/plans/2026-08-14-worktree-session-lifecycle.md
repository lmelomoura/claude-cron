# Worktree Session Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Passar a posse do worktree do *processo* do run para a *sessão* do agente, de modo a que a limpeza deixe de depender de uma heurística sobre trabalho não entregue e passe a ser incondicional.

**Architecture:** Hoje o worktree pertence ao processo: nasce com o `stamp` do run e é apagado quando o processo acaba, a menos que `wt_unsafe_to_remove()` detecte trabalho que não existe em mais lado nenhum — e nesse caso fica para sempre. Como um `claude-cron resume` corta um worktree **novo** a partir da base, esse directório preservado nunca é devolvido a ninguém. O plano liga o run dir ao `session_id` do agente, faz o resume reencontrá-lo, e reduz o teardown a uma pergunta com resposta certa: *a sessão acabou?* Se sim, `down` e apagar, sem condições. Se não, guardar sem `down` e deixar expirar por TTL. O detector de trabalho não entregue não desaparece: deixa de decidir o que fica em disco e passa a classificar o run como `error`.

**Tech Stack:** bash 3.2 (macOS system bash, `set -u`, sem `mapfile` nem arrays associativos), `jq`, `git worktree`, Python 3 stdlib (servidor de controlo), pytest, launchd.

## Global Constraints

- **Idioma:** todo o código, identificadores, comentários de código, docstrings, mensagens de commit e texto do `README.md`/`CHANGELOG.md` em **inglês**. Apenas este plano está em português.
- **Alvo bash:** bash 3.2 sob `set -u`. Sem `mapfile`, sem arrays associativos, arrays vazios expandidos como `${a[@]+"${a[@]}"}`.
- **`CHANGELOG.md` na mesma commit que o código.** `claude-cron selftest` falha quando `bin/`, `skills/` ou `test/` mudaram depois da última entrada. Cada tarefa abaixo tem o passo de changelog explícito, e a entrada diz **o que mudou de comportamento e o que custava não o ter** — nunca "corrigido X".
- **Duas suites, ambas offline:** `claude-cron selftest` (motor, bash) e `python3 -m pytest tests/` (servidor, Python). Correr **as duas** depois de tocar em qualquer lado.
- **`config/` é git-ignored.** Nenhuma regra de que o motor dependa pode viver só lá: ou é código versionado, ou é um contrato injectado no prompt, ou é uma asserção do `selftest`.
- **Nada em `worktree-lib.sh` nomeia um repositório ou uma linguagem.** Tudo o que é específico de um projecto declara-se em `projects.json`.
- **Branch:** todo o trabalho vai para `feat/worktree-session-lifecycle`, cortado de **`feat/reload-notice`** — **não** de `main`. As duas divergiram: `feat/reload-notice` está 7 commits à frente e por fundir, e traz `562c270 feat: per-run port blocks`, que é `alloc_port_base()`, `bin/provision-lib.sh` e todo o `CC_PORT_BASE`. As Tarefas 1, 2 e 7 dependem dessa commit; sobre `main` não há nada para editar.

---

## Ponto de partida — o que já se confirmou no código

Estes factos foram verificados antes de escrever o plano e são a razão de cada tarefa existir. O executor não precisa de os reconfirmar, mas precisa de os conhecer:

1. `LOCK_DIR="$DATA_DIR/locks"` (`bin/claude-cron:38`) — os slots vivem em `data/` e **sobrevivem a um reboot**. `slots_active()`, `wt_is_claimed()` e `alloc_port_base()` decidem "vivo" com `kill -0 <pid>`. Depois de um reboot, um pid reciclado faz um slot morto parecer vivo: o job bate no `max_parallel` e deixa de correr, o worktree órfão nunca é ceifado, e o bloco de portas fica retido.
2. `wt_provision()` (`bin/worktree-lib.sh:216`) lê `CC_PORT_BASE` do **ambiente do shell chamador**. `wt_prune_orphans()` (`bin/worktree-lib.sh:427`) corre a partir do tick, que por definição não tem slot — logo o `down` de um run crashado corre com `CC_PORT_BASE` vazio.
3. `git worktree prune` no checkout canónico só corre dentro de `wt_remove_all()` (`bin/worktree-lib.sh:408`). Um `rm -rf` manual num run dir deixa registos obsoletos em `.git/worktrees/` e o branch preso.
4. **Um resume não reencontra o worktree do run anterior.** `run_job()` calcula `stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"` (`bin/claude-cron:2057`) sem qualquer caso especial para `resume_sid`, e chama `wt_setup` com esse stamp novo. O agente retoma a *conversa* numa árvore *vazia*, cortada de fresco da base. O directório preservado do run crashado fica órfão até um humano carregar em **Discard**.

O ponto 4 é o que torna a heurística de preservação inútil na prática: ela guarda trabalho que ninguém vai buscar.

---

## File Structure

| Ficheiro | Responsabilidade depois deste plano |
|---|---|
| `bin/claude-cron` | Motor e CLI. Ganha `boot_id()`/`slot_alive()` (leases), a ligação run dir ↔ sessão, o marcador de fim de run, o ramo de resume que reencontra o worktree, e as asserções novas do `selftest`. |
| `bin/worktree-lib.sh` | Ciclo de vida do worktree. `wt_teardown` passa a decidir pela sessão; `wt_unsafe_to_remove` torna-se `wt_undelivered_work` (relata, não decide); ganha `wt_find_by_session`, `wt_prune_canonicals` e o TTL das sessões abertas. |
| `bin/claude-cron-server` | Servidor de controlo. Ganha `boot_id()`/`slot_alive()` em Python e passa a listar sessões abertas com o tempo que lhes resta. |
| `bin/dashboard.html` | A tabela "Worktrees" ganha a coluna **Expires** e a cópia deixa de prometer que cada linha é trabalho insubstituível. |
| `tests/test_slot_lease.py` | **Novo.** O lease do servidor: um slot de outro boot está morto. |
| `tests/test_retained_worktrees.py` | Passa a cobrir o TTL e o campo `expires_in`. |
| `CHANGELOG.md` | Uma entrada por tarefa, na mesma commit. |
| `README.md` | Secções *Isolation* e *When a run is killed* reescritas na Tarefa 8. |

---

## Task 1: A lease outlives its pid

Um slot é um **lease**, e um pid sozinho não consegue exprimir um. Esta tarefa dá-lhe a identidade do boot em que foi tomado. É a primeira porque as tarefas 6, 7 e 8 exprimem posse através de slots — construí-las sobre uma claim que mente é construí-las em falso.

**Files:**
- Modify: `bin/claude-cron` (helpers junto de `lock_take`, `bin/claude-cron:200`; `acquire_lock` em `:489`; `lock_active` em `:668`; `slots_active` em `:522`; `acquire_slot` em `:534`; `alloc_port_base` em `:571`; `cmd_runs`; `selftest`)

**Fechar todas as rotas, não só as nomeadas.** `slot_alive` é uma regra, e uma
regra que só recusa a rota que o plano nomeou reabre-se sozinha. Antes de dar a
tarefa por feita, correr `grep -n 'kill -0' bin/claude-cron bin/worktree-lib.sh`
e `grep -n 'os.kill' bin/claude-cron-server`: **todo** o sítio que decide se um
slot está vivo passa por `slot_alive`. Os que o plano nomeia são os que já se
conhecem; `cmd_runs` é um deles e não estava nesta lista até a Tarefa 1 o
encontrar. O `kill -0` que sobrar tem de ser um que não fale de slots — e nesse
caso, dizê-lo no relatório.
- Modify: `bin/worktree-lib.sh` (cabeçalho de dependências, `:30`; `wt_is_claimed`, `:448`)
- Modify: `bin/claude-cron-server` (`retained_worktrees`, `:1297`; `active_runs_for`, junto de `:1255`)
- Create: `tests/test_slot_lease.py`
- Modify: `CHANGELOG.md`

**Interfaces:**
- Produces (bash): `boot_id()` → imprime a **boot session UUID** desta máquina (`kern.bootsessionuuid`, opaca — nunca comparada por ordem, só por igualdade), vazia se não conseguir apurar. `slot_alive <slot-dir>` → 0 se o processo que o slot nomeia ainda é o processo que o tomou.
- Produces (Python): `boot_id()` → `str`. `slot_alive(slot: Path)` → `bool`.
- Consumes: nada de tarefas anteriores.

- [ ] **Step 1: Write the failing selftest assertions**

Em `bin/claude-cron`, dentro da função de selftest, imediatamente **antes** da linha `echo "wt_prune_orphans() — an unclaimed run dir is reaped, a claimed one is not"` (`bin/claude-cron:1309`), inserir:

```bash
  echo "boot_id() — an opaque per-boot identity, stable within one boot"
  got="$(boot_id)"
  case "$got" in
    *-*-*-*-*) ok "it is a boot session uuid, not a timestamp that a clock step moves" ;;
    *) bad "boot_id printed '$got', which is not a uuid" ;;
  esac
  [ "$got" = "$(CC_BOOT_ID=""; boot_id)" ] \
    && ok "and two reads inside one boot agree" || bad "boot_id is not stable"

  echo "slot_alive() — a lease is pinned to the boot it was taken in"
  mkdir -p "$tmp/locks/j8/$$"
  echo $$ > "$tmp/locks/j8/$$/pid"
  boot_id > "$tmp/locks/j8/$$/boot"
  ( LOCK_DIR="$tmp/locks"; slot_alive "$tmp/locks/j8/$$" )
  want "this process's own slot, stamped with this boot, is alive" 0 $?
  echo "0" > "$tmp/locks/j8/$$/boot"
  ( LOCK_DIR="$tmp/locks"; slot_alive "$tmp/locks/j8/$$" )
  want "the same live pid from an earlier boot is dead" 1 $?
  rm -f "$tmp/locks/j8/$$/boot"
  ( LOCK_DIR="$tmp/locks"; slot_alive "$tmp/locks/j8/$$" )
  want "a slot with no boot file predates this and falls back to the pid" 0 $?
  rm -rf "$tmp/locks/j8"

  echo "wt_is_claimed() — a claim from an earlier boot holds nothing"
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"; WORKTREES_DIR="$tmp/wtroot"
    wt_setup j8 two "$tmp/g/repo" stampBoot ) >/dev/null 2>&1
  mkdir -p "$tmp/locks/j8/$$"
  echo $$ > "$tmp/locks/j8/$$/pid"
  echo "0" > "$tmp/locks/j8/$$/boot"
  echo "$tmp/wtroot/j8/stampBoot" > "$tmp/locks/j8/$$/worktree"
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"
    WORKTREES_DIR="$tmp/wtroot"; LOCK_DIR="$tmp/locks"
    wt_prune_orphans ) >/dev/null 2>&1
  [ ! -d "$tmp/wtroot/j8/stampBoot" ] \
    && ok "a run dir claimed only by a pre-reboot slot is reaped" \
    || bad "a stale pre-reboot claim kept an orphan alive"
  rm -rf "$tmp/locks/j8"
```

- [ ] **Step 2: Run the selftest to verify it fails**

Run: `bin/claude-cron selftest`
Expected: FAIL, com `slot_alive: command not found` na primeira asserção nova.

- [ ] **Step 3: Add the helpers**

Em `bin/claude-cron`, imediatamente **a seguir** a `lock_drop() { rm -rf "${1:-}"; }` (`bin/claude-cron:219`), inserir:

```bash
# A slot is a LEASE, and a pid alone cannot express one. $LOCK_DIR lives under
# data/, so every slot survives a reboot — and the kernel reissues pids from 1
# on the way up, so a recycled pid makes a dead slot answer `kill -0`. That one
# false positive leaked three ways at once: it counted a phantom against
# max_parallel (the job simply stopped running, with nothing saying why), it kept
# an orphaned worktree unreapable, and it held a port block for good. Pinning the
# lease to the boot it was taken in is what makes "this process" mean the same
# process. Managed Agents has no equivalent bug because its claims are
# server-side leases with an expiry; ours are directories, so they carry the
# boot themselves.
# `kern.bootsessionuuid`, NOT `kern.boottime`. The obvious identifier is the
# boot time, and it is wrong: XNU shifts `kern.boottime` whenever the calendar
# clock is stepped — NTP resync, wake from sleep — so that uptime stays
# monotonic. Comparing it exactly would then declare every slot taken before
# the step to be from another boot, and every consequence of that runs the
# WRONG WAY: a live run's slot deleted and its worktree swept out from under
# it, its port block handed to somebody else. Widening the compare to a
# tolerance would paper over it; the boot session UUID has no such behaviour to
# tolerate. It is opaque, so there is also no field to parse and no greedy
# pattern to get wrong.
CC_BOOT_ID=""
boot_id() {
  if [ -z "$CC_BOOT_ID" ]; then
    CC_BOOT_ID="$(sysctl -n kern.bootsessionuuid 2>/dev/null | tr -d '[:space:]')"
  fi
  printf '%s\n' "$CC_BOOT_ID"
}

# 0 = the process this slot names is still the process that took it.
slot_alive() { # slot_alive <slot-dir>
  local slot="${1:-}" pid boot now
  [ -d "$slot" ] || return 1
  pid="$(cat "$slot/pid" 2>/dev/null || true)"
  [ -n "$pid" ] || return 1
  boot="$(cat "$slot/boot" 2>/dev/null || true)"
  now="$(boot_id)"
  # A slot from an earlier boot is dead however healthy its pid looks. One with
  # no boot file at all predates this change: fall back to the pid alone, so an
  # upgrade does not reap the runs it finds in flight.
  if [ -n "$boot" ] && [ -n "$now" ] && [ "$boot" != "$now" ]; then
    return 1
  fi
  kill -0 "$pid" 2>/dev/null
}
```

- [ ] **Step 4: Stamp the boot onto every claim, and read it back everywhere**

Em `bin/claude-cron`, `acquire_lock()` (`bin/claude-cron:489`) — substituir o corpo a partir de `if mkdir "$lock"`:

```bash
  if mkdir "$lock" 2>/dev/null; then
    echo $$ > "$lock/pid"; boot_id > "$lock/boot"; return 0
  fi
  if slot_alive "$lock"; then
    return 1                      # a previous run is still going
  fi
  rm -rf "$lock"                  # stale lock from a killed run, or an old boot
  mkdir "$lock" 2>/dev/null && { echo $$ > "$lock/pid"; boot_id > "$lock/boot"; return 0; }
  return 1
```

`lock_active()` (`bin/claude-cron:668`) — substituir inteira:

```bash
lock_active() { # 0 = a run is currently holding the lock for <id> (single mutex)
  slot_alive "$LOCK_DIR/$1"
}
```

`slots_active()` (`bin/claude-cron:522`) — substituir o corpo do ciclo:

```bash
slots_active() { # <id> -> prints count of live slots; prunes dead ones
  local id="$1"                           # separate stmt: $id must exist before...
  local base="$LOCK_DIR/$id" d n=0        # ...it is expanded here (set -u)
  [ -d "$base" ] || { echo 0; return 0; }
  for d in "$base"/*/; do                # glob skips the dotfile mutex (.acq)
    [ -d "$d" ] || continue
    if slot_alive "${d%/}"; then n=$((n + 1)); else rm -rf "$d"; fi
  done
  echo "$n"
}
```

`acquire_slot()` (`bin/claude-cron:534`) — na linha `mkdir -p "$slot"; echo $$ > "$slot/pid"`, passar a:

```bash
  mkdir -p "$slot"; echo $$ > "$slot/pid"; boot_id > "$slot/boot"
```

`alloc_port_base()` (`bin/claude-cron:571`) — substituir a linha do `kill -0`:

```bash
    slot_alive "${d%/}" || continue
```

Em `bin/worktree-lib.sh`, `wt_is_claimed()` (`:448`) — substituir inteira:

```bash
# Is this run dir the working directory of a run that is alive right now?
wt_is_claimed() { # <id> <run dir>
  local id="$1" wt="$2"
  local base="$LOCK_DIR/$id" slot owner
  [ -d "$base" ] || return 1
  for slot in "$base"/*/; do
    [ -d "$slot" ] || continue
    slot_alive "${slot%/}" || continue
    owner="$(cat "$slot/worktree" 2>/dev/null || true)"
    [ "$owner" = "$wt" ] && return 0
  done
  return 1
}
```

E no cabeçalho de `bin/worktree-lib.sh` (`:30`), acrescentar `slot_alive` à lista de dependências. A linha passa de:

```
# Depends on the sourcing script for: JQ, CONFIG_DIR, DATA_DIR, WORKTREES_DIR, LOCK_DIR,
# projects_json, project_get, job_get, resolve, lock_active, state_get, log_tick.
```

para:

```
# Depends on the sourcing script for: JQ, CONFIG_DIR, DATA_DIR, WORKTREES_DIR, LOCK_DIR,
# projects_json, project_get, job_get, resolve, lock_active, slot_alive, state_get,
# log_tick, num, now_epoch.
```

(`num` já era usado sem estar declarado; `now_epoch` passa a sê-lo na Tarefa 8. Declarar ambos agora evita uma segunda edição do mesmo cabeçalho.)

- [ ] **Step 5: Run the selftest to verify it passes**

Run: `bin/claude-cron selftest`
Expected: PASS, incluindo as quatro asserções novas.

- [ ] **Step 6: Write the failing server test**

Criar `tests/test_slot_lease.py`:

```python
"""A lock slot is a lease, not a pid.

data/locks survives a reboot and the kernel reissues pids from 1 on the way up,
so a recycled pid used to make a dead slot answer os.kill(pid, 0). The server
believed it too: a phantom slot hid a retained run dir from the only screen that
lists them.
"""

import os


def _slot(srv, job, pid, boot=None, worktree=None):
    slot = srv.DATA_DIR / "locks" / job / str(pid)
    slot.mkdir(parents=True)
    (slot / "pid").write_text(str(pid))
    if boot is not None:
        (slot / "boot").write_text(boot)
    if worktree is not None:
        (slot / "worktree").write_text(str(worktree))
    return slot


def test_this_process_in_this_boot_is_alive(clean_data):
    srv = clean_data
    slot = _slot(srv, "alpha", os.getpid(), boot=srv.boot_id())
    assert srv.slot_alive(slot) is True


def test_the_same_live_pid_from_an_earlier_boot_is_dead(clean_data):
    srv = clean_data
    slot = _slot(srv, "beta", os.getpid(), boot="0")
    assert srv.slot_alive(slot) is False


def test_a_slot_with_no_boot_file_falls_back_to_the_pid(clean_data):
    """Slots that predate the boot id must not all be reaped by an upgrade."""
    srv = clean_data
    slot = _slot(srv, "gamma", os.getpid())
    assert srv.slot_alive(slot) is True


def test_a_pre_reboot_claim_does_not_hide_a_retained_run_dir(clean_data):
    srv = clean_data
    d = srv.DATA_DIR / "worktrees" / "delta" / "stamp-old"
    (d / "repo").mkdir(parents=True)
    _slot(srv, "delta", os.getpid(), boot="0", worktree=d)
    assert [g["stamp"] for g in srv.retained_worktrees()] == ["stamp-old"]
```

- [ ] **Step 7: Run the server test to verify it fails**

Run: `python3 -m pytest tests/test_slot_lease.py -v`
Expected: FAIL com `AttributeError: module 'cc_server' has no attribute 'boot_id'`.

- [ ] **Step 8: Add the server-side lease**

Em `bin/claude-cron-server`, imediatamente **antes** de `def retained_worktrees():` (`:1297`), inserir:

```python
_BOOT_ID = None


def boot_id():
    """The boot this machine is in, as the engine stamps it onto every slot.

    Slots live under data/ and survive a reboot; pids are reissued from 1 on the
    way up. Without the boot, a recycled pid makes a dead slot look live — and
    the dashboard then hides a run dir nobody owns from the only list that
    offers to discard it.
    """
    global _BOOT_ID
    if _BOOT_ID is None:
        try:
            out = subprocess.run(["sysctl", "-n", "kern.bootsessionuuid"],
                                 capture_output=True, text=True,
                                 timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            out = ""
        _BOOT_ID = out.strip()
    return _BOOT_ID


def slot_alive(slot):
    """Is the process this slot names still the process that took it?"""
    try:
        pid = int((slot / "pid").read_text().strip())
    except (OSError, ValueError):
        return False
    try:
        boot = (slot / "boot").read_text().strip()
    except OSError:
        boot = ""       # predates the boot id: fall back to the pid alone
    now = boot_id()
    if boot and now and boot != now:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True
```

Confirmar que o topo do ficheiro importa `os`, `re` e `subprocess`; acrescentar os que faltarem à lista de imports existente.

Em `retained_worktrees()` (`:1297`), substituir o bloco que lê o pid:

```python
                try:
                    pid = int((slot / "pid").read_text().strip())
                    os.kill(pid, 0)
                except (OSError, ValueError):
                    continue           # dead slot: whatever it named is nobody's
```

por:

```python
                if not slot_alive(slot):
                    continue           # dead slot: whatever it named is nobody's
```

Em `active_runs_for()` (o bloco perto de `:1255` que monta a lista de runs vivos), aplicar a mesma substituição: onde decide se um slot conta, chamar `slot_alive(d)` em vez de ler o pid e fazer `os.kill`.

- [ ] **Step 9: Run both suites to verify they pass**

Run: `python3 -m pytest tests/ -v && bin/claude-cron selftest`
Expected: PASS em ambas.

- [ ] **Step 10: Write the changelog entry and commit**

Em `CHANGELOG.md`, sob `## [Unreleased]` → `### Fixed` (criar a secção se não existir, a seguir a `### Added`):

```markdown
- **A run slot is a lease pinned to a boot, not a bare pid.** `data/locks` lives
  under `data/`, so slots survive a reboot — and the kernel reissues pids from 1
  on the way up, so a recycled pid made a dead slot answer `kill -0`. One false
  positive leaked three ways at once: the phantom counted against `max_parallel`
  and the job silently stopped running with nothing on the card saying why; the
  sweep read the orphaned worktree as claimed and never reaped it; and the port
  block it named was never handed back. Every slot now records the boot it was
  taken in, and a slot from an earlier boot is dead however healthy its pid
  looks. Slots written before this change carry no boot and still fall back to
  the pid, so an upgrade does not reap the runs it finds in flight.
```

```bash
git add bin/claude-cron bin/worktree-lib.sh bin/claude-cron-server tests/test_slot_lease.py CHANGELOG.md
git commit -m "fix: a run slot is a lease pinned to its boot, not a bare pid"
```

---

## Task 2: Teardown is reconstructible from disk

O `down` de um run crashado corre a partir do tick, que não tem `CC_PORT_BASE`. O manifesto já guarda `fork_sha` e `dirt_sha`; falta-lhe o bloco de portas. Depois desta tarefa o teardown não precisa de nada do ambiente — é reconstruível só a partir do disco, que é exactamente o que significa "a plataforma consegue sempre reclamar".

**Files:**
- Modify: `bin/worktree-lib.sh` (`wt_setup`, `:268`; `wt_provision`, `:204`)
- Modify: `bin/claude-cron` (`run_job`, `:2083`; `selftest`)
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `slot_alive` da Tarefa 1 (indirectamente, via `wt_prune_orphans`).
- Produces: `.run.json` ganha a chave de topo `port_base` (string de dígitos, `""` quando o run não é isolado). `wt_setup` passa a aceitar um 5º argumento `<port_base>`.

- [ ] **Step 1: Write the failing selftest assertion**

Em `bin/claude-cron`, dentro do selftest, imediatamente **antes** de `echo "wt_prune_orphans() — an unclaimed run dir is reaped, a claimed one is not"`, inserir:

```bash
  # No backticks in this string: inside double quotes the shell would run it.
  echo "wt_provision() — a down hook from the orphan sweep still knows its ports"
  printf '%s\n' '#!/usr/bin/env bash' 'echo "down saw ${CC_PORT_BASE:-none}" >> "$CC_RUN_DIR/../down.log"' \
    > "$tmp/cfg/provision/two.down.sh"
  chmod +x "$tmp/cfg/provision/two.down.sh"
  rm -f "$tmp/wtroot/j6/down.log"
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"; WORKTREES_DIR="$tmp/wtroot"
    wt_setup j6 two "$tmp/g/repo" stampP 27100 ) >/dev/null 2>&1
  got="$("$JQ" -r '.port_base' "$tmp/wtroot/j6/stampP/.run.json" 2>/dev/null)"
  [ "$got" = "27100" ] && ok "the manifest records the run's port block" \
    || bad "port_base was '$got'"
  # No slot, no ambient CC_PORT_BASE: exactly the orphan sweep's situation.
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"
    WORKTREES_DIR="$tmp/wtroot"; LOCK_DIR="$tmp/locks"
    unset CC_PORT_BASE
    wt_prune_orphans ) >/dev/null 2>&1
  grep -q "down saw 27100" "$tmp/wtroot/j6/down.log" 2>/dev/null \
    && ok "a crashed run's down hook reads its ports from the manifest" \
    || bad "down ran without the run's port block"
  rm -f "$tmp/cfg/provision/two.down.sh" "$tmp/wtroot/j6/down.log"
```

- [ ] **Step 2: Run the selftest to verify it fails**

Run: `bin/claude-cron selftest`
Expected: FAIL com `port_base was 'null'`.

- [ ] **Step 3: Record the port block in the manifest**

Em `bin/worktree-lib.sh`, `wt_setup()` (`:268`) — a assinatura e a primeira linha passam a:

```bash
wt_setup() { # <id> <project> <canonical_cwd> <stamp> [port_base]
  local id="${1:-}" project="${2:-}" cwd="${3:-}" stamp="${4:-}" port_base="${5:-}"
```

E a escrita do manifesto (o bloco `"$JQ" -Rn ...` em `:303-309`) passa a:

```bash
  "$JQ" -Rn --arg job "$id" --arg project "$project" --arg run_dir "$run_dir" \
        --arg primary "$(basename "$primary")" --arg port_base "$port_base" '
    {job:$job, project:$project, run_dir:$run_dir, primary:$primary,
     # NOTE: no apostrophes in this comment — it sits inside a single-quoted
     # bash string, so one would terminate the jq program mid-word.
     # The port block for this run. Recorded here and not left to the environment
     # because `down` also runs from the orphan sweep, which has no slot and
     # therefore no CC_PORT_BASE: a hook computing what to release from
     # cc_port would have released numbers it never bound. Everything teardown
     # needs must be reconstructible from disk alone.
     port_base:$port_base,
     repos: [inputs | split("\t")
             | {name:.[0], canonical:.[1], worktree:.[2],
                base:.[3], base_ref:.[4], fork_sha:.[5]}]}' "$tsv" > "$run_dir/.run.json"
```

- [ ] **Step 4: Read it back in the hook**

Em `bin/worktree-lib.sh`, `wt_provision()` (`:204`) — substituir a função inteira:

```bash
wt_provision() { # <up|down> <project> <id> <run_dir> <name> <canonical> <worktree> <base>
  local phase="${1:-}" project="${2:-}" id="${3:-}" run_dir="${4:-}"
  local name="${5:-}" repo="${6:-}" wt="${7:-}" base="${8:-}"
  local script t rc pb
  script="$CONFIG_DIR/provision/$project.$phase.sh"
  [ -f "$script" ] || return 0
  t="$(project_get "$project" '.worktree.provision_timeout_seconds' '900')"
  case "$t" in ''|null|*[!0-9]*) t=900 ;; esac
  # The manifest is the source of truth for the port block, not the environment.
  # `down` also runs from the orphan sweep, which has no slot and so no ambient
  # CC_PORT_BASE — a hook that asked cc_port there got different numbers from
  # the ones `up` bound, and released nothing.
  pb="$("$JQ" -r '.port_base // ""' "$run_dir/.run.json" 2>/dev/null)"
  case "$pb" in null) pb="" ;; esac
  [ -z "$pb" ] && pb="${CC_PORT_BASE:-}"
  _wt_hook() {
    cd "$wt" 2>/dev/null || return 1
    CC_REPO_NAME="$name" CC_REPO_PATH="$repo" CC_WORKTREE="$wt" CC_BASE="$base" \
    CC_RUN_DIR="$run_dir" CC_RUN_MANIFEST="$run_dir/.run.json" \
    CC_PROJECT="$project" CC_JOB_ID="$id" \
    CC_PORT_BASE="$pb" CC_PORT_SPAN="${CC_PORT_SPAN:-100}" \
    CC_PROVISION_LIB="${CC_PROVISION_LIB:-}" \
      bash "$script" >>"$DATA_DIR/exec.log" 2>&1
  }
  wt_run_limited "$t" _wt_hook; rc=$?
  unset -f _wt_hook
  [ "$rc" -eq 0 ] || log_tick "$id: provision $phase failed for $name (rc=$rc) — see exec.log"
  return "$rc"
}
```

`CC_PROVISION_LIB` continua a vir do ambiente: é o caminho de uma biblioteca do próprio repositório, não estado do run. Quando o sweep corre sem ele, o hook que o precisar falha alto em `exec.log`, que é o comportamento correcto.

- [ ] **Step 5: Pass the block in from the engine**

Em `bin/claude-cron`, `run_job()` (`:2087`) — a chamada passa a levar o bloco:

```bash
    if ! worktree="$(wt_setup "$id" "$project" "$cwd" "$stamp" "$port_base")"; then
```

- [ ] **Step 6: Run the selftest to verify it passes**

Run: `bin/claude-cron selftest`
Expected: PASS, incluindo as duas asserções novas.

- [ ] **Step 7: Write the changelog entry and commit**

Em `CHANGELOG.md`, sob `### Fixed`:

```markdown
- **A crashed run's `down` hook knows which ports it bound.** `wt_provision`
  read `CC_PORT_BASE` from the environment, but `down` also runs from the orphan
  sweep — which fires from the tick, and a run dir is an orphan precisely because
  its slot is gone. So the one path that exists to clean up after a crash ran the
  hook with no port block at all, and a hook computing what to release with
  `cc_port` released numbers it had never bound: the compose stack from the
  crashed run stayed up, holding the ports the next run wanted. The block is now
  recorded in `.run.json` next to `fork_sha`, and the hook reads it from there.
  Teardown is reconstructible from the disk alone, which is the whole point of
  having a sweep.
```

```bash
git add bin/worktree-lib.sh bin/claude-cron CHANGELOG.md
git commit -m "fix: record the run's port block in the manifest so a crashed down still has it"
```

---

## Task 3: Stale worktree registrations are pruned

O dashboard mostra o tamanho de cada run dir retido, portanto mais cedo ou mais tarde alguém faz `rm -rf` a um. Fica um registo obsoleto em `.git/worktrees/` do checkout canónico e — pior — o branch continua "checked out" na vista do git, por isso o canónico não o consegue voltar a ter.

**Files:**
- Modify: `bin/worktree-lib.sh` (nova `wt_prune_canonicals`, a seguir a `wt_prune_orphans`, `:445`)
- Modify: `bin/claude-cron` (o tick, junto da chamada existente a `wt_prune_orphans`; `selftest`)
- Modify: `CHANGELOG.md`

**Interfaces:**
- Produces: `wt_prune_canonicals()` — sem argumentos; corre `git worktree prune` em cada checkout canónico que `projects.json` declara.

- [ ] **Step 1: Write the failing selftest assertion**

Em `bin/claude-cron`, no selftest, imediatamente a seguir ao bloco `wt_prune_orphans()`, inserir:

```bash
  echo "wt_prune_canonicals() — a run dir removed by hand leaves no registration behind"
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"; WORKTREES_DIR="$tmp/wtroot"
    wt_setup j5 two "$tmp/g/repo" stampR ) >/dev/null 2>&1
  rm -rf "$tmp/wtroot/j5/stampR"          # behind git's back, the way a human does it
  git -C "$tmp/g/repo" worktree list --porcelain 2>/dev/null | grep -q 'stampR' \
    && ok "git still lists the registration before the prune" \
    || bad "the fixture did not leave a stale registration to clear"
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"; WORKTREES_DIR="$tmp/wtroot"
    wt_prune_canonicals ) >/dev/null 2>&1
  git -C "$tmp/g/repo" worktree list --porcelain 2>/dev/null | grep -q 'stampR' \
    && bad "the stale registration survived the prune" \
    || ok "the canonical checkout is clean again"
```

- [ ] **Step 2: Run the selftest to verify it fails**

Run: `bin/claude-cron selftest`
Expected: FAIL com `wt_prune_canonicals: command not found`.

- [ ] **Step 3: Add the function**

Em `bin/worktree-lib.sh`, imediatamente **antes** de `wt_is_claimed()` (`:448`), inserir:

```bash
# Clear stale worktree registrations from every canonical checkout a project
# names. wt_remove_all prunes the one repo it just removed from, which covers
# every path this engine controls — but not the one a human takes: the dashboard
# lists each retained run dir with its size, so sooner or later somebody reaches
# for `rm -rf`. Git then keeps the registration in .git/worktrees/ and, worse,
# still believes the branch is checked out, so the canonical cannot have it back.
# Pruning is idempotent and costs a fork per repo per tick.
wt_prune_canonicals() {
  local path seen=""
  while IFS= read -r path; do
    [ -n "$path" ] && [ -d "$path" ] || continue
    case " $seen " in *" $path "*) continue ;; esac   # a repo shared by two projects
    seen="$seen $path"
    git -C "$path" worktree prune >/dev/null 2>&1 || true
  done < <(projects_json | "$JQ" -r '
    .projects[]? | (.repos // [] | .[].path), .cwd | select(. != null and . != "")' 2>/dev/null)
}
```

- [ ] **Step 4: Call it from the tick**

Em `bin/claude-cron`, localizar a chamada existente a `wt_prune_orphans` no tick (`grep -n 'wt_prune_orphans' bin/claude-cron` — é a que **não** está dentro do selftest) e acrescentar imediatamente a seguir:

```bash
  wt_prune_canonicals
```

- [ ] **Step 5: Run the selftest to verify it passes**

Run: `bin/claude-cron selftest`
Expected: PASS, incluindo as duas asserções novas.

- [ ] **Step 6: Write the changelog entry and commit**

```markdown
- **A run directory removed by hand no longer wedges its canonical checkout.**
  `git worktree remove` was only ever reached through the engine's own teardown,
  so a run dir deleted with `rm -rf` — which the dashboard invites, by listing
  each one with its size — left the registration in `.git/worktrees/`. Git went
  on believing the branch was checked out somewhere, and the canonical checkout
  could not have it back: `git checkout <branch>` failed with "already checked
  out" against a directory that no longer existed. The tick now prunes every
  canonical checkout the projects declare.
```

```bash
git add bin/worktree-lib.sh bin/claude-cron CHANGELOG.md
git commit -m "fix: prune stale worktree registrations from every canonical checkout"
```

---

## Task 4: A run directory knows its session

A ligação que falta para tudo o resto. O `session_id` só existe depois de o agente arrancar — vem no primeiro evento do transcript — por isso o run dir nasce com o `stamp` e ganha a sessão a seguir.

**Files:**
- Modify: `bin/claude-cron` (novo `session_from_stream`, junto de `turn_is_over`; o ciclo do watchdog em `run_job`; `selftest`)
- Modify: `CHANGELOG.md`

**Interfaces:**
- Produces: `session_from_stream <streamfile>` → imprime o `session_id` do primeiro evento que o traz, ou nada. `$run_dir/.session` — ficheiro de uma linha com o id da sessão, escrito uma só vez.

- [ ] **Step 1: Write the failing selftest assertion**

Em `bin/claude-cron`, no selftest, junto das outras asserções sobre transcripts (a seguir ao bloco `turn_is_over`), inserir:

```bash
  echo "session_from_stream() — the session id is read from the transcript's first event"
  printf '%s\n' \
    '{"type":"system","subtype":"init","session_id":"sess-abc123"}' \
    '{"type":"assistant","message":{}}' > "$tmp/s1.ndjson"
  got="$(session_from_stream "$tmp/s1.ndjson")"
  [ "$got" = "sess-abc123" ] && ok "the init event's session is found" \
    || bad "read '$got'"
  printf '%s\n' '{"type":"assistant","message":{}}' > "$tmp/s2.ndjson"
  got="$(session_from_stream "$tmp/s2.ndjson")"
  [ -z "$got" ] && ok "a transcript with no session yet reports nothing" \
    || bad "invented a session '$got'"
  : > "$tmp/s3.ndjson"
  got="$(session_from_stream "$tmp/s3.ndjson")"
  [ -z "$got" ] && ok "an empty transcript reports nothing" || bad "read '$got' from nothing"
```

- [ ] **Step 2: Run the selftest to verify it fails**

Run: `bin/claude-cron selftest`
Expected: FAIL com `session_from_stream: command not found`.

- [ ] **Step 3: Add the reader**

Em `bin/claude-cron`, imediatamente **antes** de `turn_is_over()`, inserir:

```bash
# The session a run reported in its transcript. The id is what binds a run dir
# to the conversation that owns it: a resume looks the directory up by this, so
# the agent continues in the tree it was working in rather than in a fresh
# checkout of the base. Only the head of the file is read — the id arrives in
# the first event and never changes.
session_from_stream() { # session_from_stream <streamfile>
  local f="${1:-}"
  [ -s "$f" ] || return 0
  head -c 8192 "$f" 2>/dev/null \
    | "$JQ" -r 'select(type=="object") | .session_id // empty' 2>/dev/null \
    | head -1
}
```

- [ ] **Step 4: Bind the run dir to the session as soon as it is known**

Em `bin/claude-cron`, no ciclo do watchdog dentro de `run_job` (o `while kill -0 "$child"` que vigia `$streamfile`), inserir no topo do corpo do ciclo:

```bash
      # Bind this run dir to its session the moment the transcript names one.
      # It has to happen while the run is alive: a run that crashes is exactly
      # the one whose directory a resume will need to find again.
      if [ -n "$run_dir" ] && [ ! -f "$run_dir/.session" ]; then
        sid_seen="$(session_from_stream "$streamfile")"
        [ -n "$sid_seen" ] && printf '%s\n' "$sid_seen" > "$run_dir/.session" 2>/dev/null || true
      fi
```

Declarar `sid_seen` na lista de `local` no topo de `run_job` (a linha que já declara `start end stamp logfile streamfile …`), acrescentando ` sid_seen` ao fim.

**Nota para o executor:** `run_job` tem mais do que um ciclo de vigilância — o interactivo e o não-interactivo. O bloco acima vai **no ciclo do watchdog que ambos atravessam** (o que faz `kill -0 "$child"` e mede o crescimento de `$streamfile`). Se existirem dois, inserir em ambos: a escrita é idempotente e guardada por `[ ! -f ]`.

- [ ] **Step 5: Run the selftest to verify it passes**

Run: `bin/claude-cron selftest`
Expected: PASS, incluindo as três asserções novas.

- [ ] **Step 6: Write the changelog entry and commit**

```markdown
- **A run directory now records the session working in it** (`.session`). The id
  arrives in the transcript's first event and is written as soon as it is seen —
  while the run is alive, because a run that crashes is exactly the one whose
  directory has to be findable afterwards. Nothing reads it yet; it is what the
  resume and the teardown below are built on.
```

```bash
git add bin/claude-cron CHANGELOG.md
git commit -m "feat: bind a run directory to the session working in it"
```

---

## Task 5: Undelivered work is reported, not preserved

`wt_unsafe_to_remove` não desaparece — muda de papel. A pergunta que faz ("há aqui trabalho que não existe em mais lado nenhum?") continua a ser a pergunta certa; o que estava errado era a resposta ser *guardar o directório*. Passa a ser *classificar o run como falhado*, que é o que Managed Agents faz na prática: se não foi para o remote, o run não entregou.

**Files:**
- Modify: `bin/worktree-lib.sh` (`wt_unsafe_to_remove` → `wt_undelivered_work`, `:341`)
- Modify: `bin/claude-cron` (o classificador, `:2380`; `selftest` `:1293`)
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: o manifesto com `fork_sha`/`dirt_sha` (inalterados).
- Produces: `wt_undelivered_work <run dir>` → 0 quando há trabalho que nenhum remote conhece, e **imprime uma descrição de uma linha** (`"2 commits in api, uncommitted changes in web"`); 1 quando não há nada por entregar.

- [ ] **Step 1: Write the failing selftest assertion**

Em `bin/claude-cron`, substituir o bloco `echo "wt_unsafe_to_remove() — …"` (`:1293-1307`) inteiro por:

```bash
  echo "wt_undelivered_work() — what provisioning left behind is not the agent's work"
  printf '%s\n' '#!/usr/bin/env bash' 'echo residue > provisioned.txt' \
    > "$tmp/cfg/provision/two.up.sh"
  local rd3="$tmp/wtroot/j4/stampE"
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"; WORKTREES_DIR="$tmp/wtroot"
    wt_setup j4 two "$tmp/g/repo" stampE ) >/dev/null 2>&1
  [ -f "$rd3/one/provisioned.txt" ] && ok "the hook's untracked file is there" || bad "hook wrote nothing"
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"; WORKTREES_DIR="$tmp/wtroot"
    wt_undelivered_work "$rd3" ) >/dev/null 2>&1
  want "provisioning residue alone is NOT undelivered work" 1 $?
  echo "the agent was here" > "$rd3/two/agent.txt"
  got="$( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"; WORKTREES_DIR="$tmp/wtroot"
          wt_undelivered_work "$rd3" )"
  want "a file the agent added after provisioning IS undelivered work" 0 $?
  case "$got" in *"uncommitted changes in two"*)
      ok "and it names the repo it is in" ;;
    *) bad "the description was '$got'" ;;
  esac
  rm -f "$tmp/cfg/provision/two.up.sh"
```

- [ ] **Step 2: Run the selftest to verify it fails**

Run: `bin/claude-cron selftest`
Expected: FAIL com `wt_undelivered_work: command not found`.

- [ ] **Step 3: Rewrite the function to report instead of decide**

Em `bin/worktree-lib.sh`, substituir `wt_unsafe_to_remove()` (`:341-370`, incluindo o comentário que a precede) por:

```bash
# 0 = this run produced work that exists on no remote, and prints a one-line
# description of what and where. 1 = everything the agent made was delivered.
#
# This used to decide whether the run dir survived, and that was the wrong job
# for it. A directory kept because it holds unpushed commits is a directory
# nothing can ever release: the sweep re-reaches the same verdict every tick, and
# only a human clicking Discard ends it. Worse, a resume never got it back — it
# cut a fresh worktree from the base — so the work was preserved for nobody.
#
# The question is still the right question. Its answer belongs in the run's
# STATUS: a run that ended with commits no remote knows about did not deliver,
# and that is a failure the operator should see on the card, not a folder they
# have to find. Push is the delivery channel; not pushing is a failed run.
wt_undelivered_work() { # <run dir> -> 0 and a description, or 1
  local run_dir="${1:-}" mf="${1:-}/.run.json" wt head fork snap name found=""
  [ -d "$run_dir" ] || return 1
  while IFS= read -r wt; do
    [ -n "$wt" ] || continue
    name="$(basename "$wt")"
    # Dirty compared to the END OF PROVISIONING, not to a pristine checkout:
    # the hook just copied a .env and a vendor/ in, and calling that the agent's
    # work marks every single run as undelivered. With no snapshot (setup died
    # before provisioning) fall back to the strict reading.
    snap=""
    [ -f "$mf" ] && snap="$("$JQ" -r --arg w "$wt" \
        '.repos[] | select(.worktree==$w) | .dirt_sha // ""' "$mf" 2>/dev/null)"
    if [ -n "$snap" ]; then
      [ "$(wt_dirt_sha "$wt")" != "$snap" ] && found="$found, uncommitted changes in $name"
    else
      [ -n "$(git -C "$wt" status --porcelain 2>/dev/null)" ] \
        && found="$found, uncommitted changes in $name"
    fi
    head="$(git -C "$wt" rev-parse --verify --quiet HEAD 2>/dev/null || true)"
    [ -n "$head" ] || continue
    fork=""
    [ -f "$mf" ] && fork="$("$JQ" -r --arg w "$wt" \
        '.repos[] | select(.worktree==$w) | .fork_sha' "$mf" 2>/dev/null)"
    # No new commits since the fork point → nothing was made here.
    [ -n "$fork" ] && [ "$fork" = "$head" ] && continue
    # New commits exist: delivered only if they already live on some remote.
    [ -n "$(git -C "$wt" branch -r --contains "$head" 2>/dev/null)" ] && continue
    found="$found, unpushed commits in $name"
  done < <(wt_run_worktrees "$run_dir")
  [ -n "$found" ] || return 1
  printf '%s\n' "${found#, }"
}
```

- [ ] **Step 4: Keep the caller compiling**

`wt_teardown()` (`:381`) ainda chama `wt_unsafe_to_remove`. A Tarefa 6 reescreve-o por inteiro; até lá, para manter o comportamento **exactamente** como está e a suite verde, substituir a linha:

```bash
  if wt_unsafe_to_remove "$run_dir"; then
```

por:

```bash
  if wt_undelivered_work "$run_dir" >/dev/null; then
```

- [ ] **Step 5: Run the selftest to verify it passes**

Run: `bin/claude-cron selftest`
Expected: PASS, incluindo as três asserções novas.

- [ ] **Step 6: Write the failing classifier assertion**

Em `bin/claude-cron`, no selftest, junto das outras asserções do classificador (perto do bloco `declared()`, `:1070`), inserir:

```bash
  echo "undelivered_note() — the note names what was left behind and how to continue"
  got="$(undelivered_note "unpushed commits in api")"
  case "$got" in
    "UNDELIVERED: unpushed commits in api."*)
      ok "it leads with the marker the dashboard matches on, then the finding" ;;
    *) bad "the note read '$got'" ;;
  esac
  case "$got" in
    *"resume this run"*) ok "and points at the one action that continues the work" ;;
    *) bad "the note never says how to continue: '$got'" ;;
  esac
```

- [ ] **Step 7: Run the selftest to verify it fails**

Run: `bin/claude-cron selftest`
Expected: FAIL com `undelivered_note: command not found`.

- [ ] **Step 8: Add the note builder and the classifier rule**

Em `bin/claude-cron`, imediatamente **antes** da função que contém o classificador (junto das outras funções auxiliares de run, a seguir a `session_from_stream`), inserir:

```bash
# What a run that delivered nothing tells the operator. Split out of the
# classifier so the selftest can assert its shape rather than a whole run's:
# a marker the dashboard can match on, the finding, and the one action that
# continues the work.
undelivered_note() { # undelivered_note <description>
  printf 'UNDELIVERED: %s. The run made changes that exist on no remote, so nothing was handed over — push the branch, or resume this run to finish it, before treating the ticket as done.' "$1"
}
```

E imediatamente **a seguir** ao bloco `UNDECLARED ENDING` (`:2386-2392`) e **antes** do bloco `BUDGET LIMITED`, inserir:

```bash
  # A run that produced commits or changes no remote knows about handed nothing
  # over. It used to be answered by keeping the run directory on disk for ever,
  # which preserved the work for nobody: a resume cuts a fresh worktree, so the
  # only thing that folder ever did was fill the disk and wait for a human. Push
  # is the delivery channel; failing to use it is a failed run, and it belongs on
  # the card. A warning, not an error: the agent may have been cut off mid-task,
  # and a resume is the right next move rather than a backoff.
  if [ -n "$run_dir" ] && [ "$status" != "error" ]; then
    local undelivered
    if undelivered="$(wt_undelivered_work "$run_dir")"; then
      wdreason="$(undelivered_note "$undelivered")"
      status="warning"
    fi
  fi
```

- [ ] **Step 9: Run both suites to verify they pass**

Run: `bin/claude-cron selftest && python3 -m pytest tests/ -v`
Expected: PASS em ambas.

- [ ] **Step 10: Write the changelog entry and commit**

```markdown
### Changed

- **A run that ends with work on no remote is reported, not filed away.**
  `wt_unsafe_to_remove` is now `wt_undelivered_work`: it asks the same question —
  are there commits or changes here that exist nowhere else? — but its answer no
  longer decides what stays on disk. It decides the run's status. Keeping the
  directory preserved the work for nobody: a resume cuts a fresh worktree from
  the base, so the folder was never handed back to anyone, and only a human
  clicking Discard ever ended it. The run now finishes `warning` with
  `UNDELIVERED: unpushed commits in api` on the card. Push is the delivery
  channel, and not pushing is a run that did not deliver.
```

```bash
git add bin/worktree-lib.sh bin/claude-cron CHANGELOG.md
git commit -m "feat: report undelivered work as a run outcome instead of preserving its directory"
```

---

## Task 6: Teardown asks whether the session is done

**Files:**
- Modify: `bin/claude-cron` (`run_cleanup`, `:653`; `run_job` no ponto onde o run é classificado; `selftest`)
- Modify: `bin/worktree-lib.sh` (`wt_teardown`, `:381`)
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `.session` da Tarefa 4; `wt_undelivered_work` da Tarefa 5.
- Produces: `$run_dir/.ended` — uma linha, `done` ou `open`. `done` = a sessão acabou e o directório pode ir; `open` = a sessão pode ser retomada, guardar sem `down`.

- [ ] **Step 1: Write the failing selftest assertion**

Em `bin/claude-cron`, no selftest, substituir tudo desde a linha
`echo "wt_teardown() — down runs, and unpushed work in ANY repo preserves the run"`
até (exclusive) à linha
`echo "wt_undelivered_work() — what provisioning left behind is not the agent's work"`
— que a Tarefa 5 acabou de renomear, e é o marcador que delimita o fim do bloco — por:

```bash
  echo "wt_teardown() — a finished session's dir goes, whatever is in it"
  printf '%s\n' '#!/usr/bin/env bash' 'echo down >> "$CC_RUN_DIR/../down.count"' \
    > "$tmp/cfg/provision/two.down.sh"
  chmod +x "$tmp/cfg/provision/two.down.sh"
  rm -f "$tmp/wtroot/j2/down.count"
  local rd2="$tmp/wtroot/j2/stampC"
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"; WORKTREES_DIR="$tmp/wtroot"
    wt_setup j2 two "$tmp/g/repo" stampC ) >/dev/null 2>&1
  echo "work nobody else has" > "$rd2/one/agent.txt"
  echo done > "$rd2/.ended"
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"; WORKTREES_DIR="$tmp/wtroot"
    wt_teardown j2 two "$rd2" ) >/dev/null 2>&1
  [ ! -d "$rd2" ] \
    && ok "a done session is removed even holding work on no remote" \
    || bad "a done session's dir survived"
  got="$(wc -l < "$tmp/wtroot/j2/down.count" 2>/dev/null | tr -d ' ')"
  [ "${got:-0}" -eq 2 ] && ok "down ran once per repo" || bad "down ran $got times for 2 repos"

  echo "wt_teardown() — an open session is kept, and its down is NOT run"
  rm -f "$tmp/wtroot/j2/down.count"
  local rd5="$tmp/wtroot/j2/stampO"
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"; WORKTREES_DIR="$tmp/wtroot"
    wt_setup j2 two "$tmp/g/repo" stampO ) >/dev/null 2>&1
  echo open > "$rd5/.ended"
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"; WORKTREES_DIR="$tmp/wtroot"
    wt_teardown j2 two "$rd5" ) >/dev/null 2>&1
  [ -d "$rd5" ] && ok "an open session keeps its tree" || bad "an open session was removed"
  [ ! -f "$tmp/wtroot/j2/down.count" ] \
    && ok "and its services are left up for the resume" \
    || bad "down tore down a session that is still open"

  echo "wt_teardown() — a dir with no marker is treated as done"
  local rd6="$tmp/wtroot/j2/stampN"
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"; WORKTREES_DIR="$tmp/wtroot"
    wt_setup j2 two "$tmp/g/repo" stampN ) >/dev/null 2>&1
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"; WORKTREES_DIR="$tmp/wtroot"
    wt_teardown j2 two "$rd6" ) >/dev/null 2>&1
  [ ! -d "$rd6" ] && ok "a run that died before marking anything is reclaimed" \
    || bad "an unmarked dir was kept, which is the old leak"
  rm -f "$tmp/cfg/provision/two.down.sh" "$tmp/wtroot/j2/down.count"
```

- [ ] **Step 2: Run the selftest to verify it fails**

Run: `bin/claude-cron selftest`
Expected: FAIL em `a done session is removed even holding work on no remote` — o teardown actual preserva.

- [ ] **Step 3: Rewrite wt_teardown**

Em `bin/worktree-lib.sh`, substituir `wt_teardown()` (`:381-406`, com o comentário que a precede) por:

```bash
# Finish a run's directory. The question is whether the SESSION is done, and it
# has exactly one right answer per state:
#
#   done    -> `down` for every repo (reverse declaration order, while the trees
#              still exist), then remove. UNCONDITIONALLY: a session that is over
#              is not coming back for its files, and anything it failed to
#              deliver was already reported on the run (wt_undelivered_work).
#   open    -> keep the tree AND leave the services up. The run was cut short and
#              a resume will continue in this very directory, so tearing the
#              stack down here would hand the resumed agent a provisioned tree
#              with nothing running behind it.
#
# No marker means the run died before it could write one — that is `done`. The
# old default was the opposite, and it is what made this leak: every crash left a
# directory nothing could ever release.
#
# `.down` still guards `down` from running twice, because an open session is
# swept again on every tick.
wt_teardown() { # <id> <project> <run dir>
  local id="${1:-}" project="${2:-}" run_dir="${3:-}" mf="${3:-}/.run.json"
  local name repo wt base ended
  [ -n "$run_dir" ] && [ -d "$run_dir" ] || return 0
  ended="$(cat "$run_dir/.ended" 2>/dev/null || true)"
  if [ "$ended" = "open" ]; then
    return 0
  fi
  if [ -f "$mf" ] && [ ! -f "$run_dir/.down" ]; then
    : > "$run_dir/.down"
    while IFS="$(printf '\t')" read -r name repo wt base; do
      [ -n "$wt" ] && [ -d "$wt" ] || continue
      wt_provision down "$project" "$id" "$run_dir" "$name" "$repo" "$wt" "$base" || true
    done < <("$JQ" -r '.repos | reverse | .[] | [.name,.canonical,.worktree,.base] | @tsv' \
                "$mf" 2>/dev/null)
  fi
  wt_remove_all "$run_dir"
}
```

- [ ] **Step 4: Mark how the run ended**

Em `bin/claude-cron`, dentro de `run_job`, imediatamente **a seguir** ao bloco que insere a regra `UNDELIVERED` (Tarefa 5, passo 8) e **antes** de `local cap`, inserir:

```bash
  # The session's fate, written where teardown can read it. A run that reached a
  # declared ending is over and its tree can go; anything else may be picked up
  # by a resume, and the resume needs this exact directory.
  if [ -n "$run_dir" ] && [ -d "$run_dir" ]; then
    case "$status" in
      success) printf 'done\n' > "$run_dir/.ended" 2>/dev/null || true ;;
      *)       printf 'open\n' > "$run_dir/.ended" 2>/dev/null || true ;;
    esac
  fi
```

E em `run_cleanup()` (`bin/claude-cron:653`), imediatamente **antes** da chamada a `wt_teardown`, inserir:

```bash
    # A run that never reached its own classifier — killed, crashed, the machine
    # went down — left no marker. Default it to `open`: its session may still be
    # resumable, and Task 8's TTL is what ends it if nobody comes back. Only a
    # run the operator stopped on purpose is closed here.
    if [ ! -f "$wt/.ended" ]; then
      if [ -f "$slot/stopped" ]; then
        printf 'done\n' > "$wt/.ended" 2>/dev/null || true
      else
        printf 'open\n' > "$wt/.ended" 2>/dev/null || true
      fi
    fi
```

**Atenção:** em `run_cleanup` a variável do run dir chama-se `wt` (lida de `$slot/worktree`), não `run_dir`. O bloco acima usa `wt` de propósito.

- [ ] **Step 5: Run the selftest to verify it passes**

Run: `bin/claude-cron selftest`
Expected: PASS, incluindo as cinco asserções novas.

- [ ] **Step 6: Write the changelog entry and commit**

```markdown
- **Teardown asks whether the session is done, not whether the tree looks
  precious.** A run directory was kept when git said it held work that existed
  nowhere else — a verdict the sweep re-reached every tick, so nothing ever
  released it, and one only a human could end. Directories are now marked with
  how their run ended: a finished session is torn down and removed
  unconditionally, and a run cut short is kept **with its services still up**,
  because the resume continues in that same directory and would otherwise get a
  provisioned tree with nothing running behind it. A run that died before
  marking anything counts as finished, which is the case the old default got
  backwards: every crash used to leave a folder nothing could reclaim.
```

```bash
git add bin/worktree-lib.sh bin/claude-cron CHANGELOG.md
git commit -m "feat: tear a run directory down by session state, not by what git finds in it"
```

---

## Task 7: A resume reattaches to its session's worktree

**Files:**
- Modify: `bin/worktree-lib.sh` (nova `wt_find_by_session`, a seguir a `wt_run_worktrees`, `:255`)
- Modify: `bin/claude-cron` (`run_job`, o ramo de isolamento em `:2076-2100`; `selftest`)
- Modify: `CHANGELOG.md`

**Interfaces:**
- Consumes: `.session` (Tarefa 4), `.ended` (Tarefa 6), `port_base` no manifesto (Tarefa 2), `slot_alive` (Tarefa 1).
- Produces: `wt_find_by_session <id> <session-id>` → imprime o run dir ligado a essa sessão, ou nada.

- [ ] **Step 1: Write the failing selftest assertion**

Em `bin/claude-cron`, no selftest, a seguir ao bloco `wt_teardown()`, inserir:

```bash
  echo "wt_find_by_session() — a session's directory is found again by its id"
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"; WORKTREES_DIR="$tmp/wtroot"
    wt_setup jR two "$tmp/g/repo" stampS1 ) >/dev/null 2>&1
  echo "sess-xyz" > "$tmp/wtroot/jR/stampS1/.session"
  echo open       > "$tmp/wtroot/jR/stampS1/.ended"
  got="$( WORKTREES_DIR="$tmp/wtroot"; wt_find_by_session jR sess-xyz )"
  [ "$got" = "$tmp/wtroot/jR/stampS1" ] && ok "the open session's dir is found" \
    || bad "found '$got'"
  got="$( WORKTREES_DIR="$tmp/wtroot"; wt_find_by_session jR sess-nope )"
  [ -z "$got" ] && ok "an unknown session finds nothing" || bad "found '$got'"
  echo done > "$tmp/wtroot/jR/stampS1/.ended"
  got="$( WORKTREES_DIR="$tmp/wtroot"; wt_find_by_session jR sess-xyz )"
  [ -z "$got" ] && ok "a session already closed is not offered back" || bad "found '$got'"
  got="$( WORKTREES_DIR="$tmp/wtroot"; wt_find_by_session jOther sess-xyz )"
  [ -z "$got" ] && ok "another job's session is never returned" || bad "found '$got'"
  rm -rf "$tmp/wtroot/jR"
```

- [ ] **Step 2: Run the selftest to verify it fails**

Run: `bin/claude-cron selftest`
Expected: FAIL com `wt_find_by_session: command not found`.

- [ ] **Step 3: Add the lookup**

Em `bin/worktree-lib.sh`, imediatamente **antes** de `wt_setup()` (`:268`), inserir:

```bash
# The run dir an open session is working in, or nothing. Scoped to one job on
# purpose: session ids are unique, but a job's directories are the only ones it
# has any business reattaching to, and a lookup that crossed jobs would let a
# mistyped id hand one agent another's tree.
wt_find_by_session() { # <id> <session-id> -> prints a run dir, or nothing
  local id="${1:-}" sid="${2:-}" d
  [ -n "$sid" ] || return 0
  [ -d "$WORKTREES_DIR/$id" ] || return 0
  for d in "$WORKTREES_DIR/$id"/*; do
    [ -d "$d" ] || continue
    [ "$(cat "$d/.session" 2>/dev/null || true)" = "$sid" ] || continue
    # Only an OPEN session is offered back. A closed one is on its way out, and
    # handing it to a resume would race the sweep for the same directory.
    [ "$(cat "$d/.ended" 2>/dev/null || true)" = "open" ] || continue
    printf '%s\n' "$d"
    return 0
  done
}
```

- [ ] **Step 4: Reattach on resume**

Em `bin/claude-cron`, `run_job`, substituir o corpo do `if wt_isolation_enabled …` (`:2076` até ao `fi` que fecha o ramo, imediatamente antes de `run_cwd="$worktree"`) por:

```bash
  if wt_isolation_enabled "$project" "$cwd"; then
    local reattached=""
    [ -n "$resume_sid" ] && reattached="$(wt_find_by_session "$id" "$resume_sid")"
    if [ -n "$reattached" ]; then
      # THE RESUME CONTINUES IN THE TREE THE SESSION WAS WORKING IN. Cutting a
      # fresh worktree here — which is what used to happen, with no special case
      # for a resume at all — handed the agent a conversation that remembered
      # editing files and a checkout of the base that had none of them.
      #
      # Everything below is read from the manifest, never re-derived from
      # projects.json. That is deliberate and it is the freeze: the repo set is
      # fixed for the session's life, so editing a project's `repos` while a
      # session is open cannot change what that session is working on. Changing
      # the mount set means a new session, exactly as it does upstream.
      run_dir="$reattached"
      echo "$run_dir" > "$slot/worktree"
      port_base="$("$JQ" -r '.port_base // ""' "$run_dir/.run.json" 2>/dev/null)"
      case "$port_base" in null) port_base="" ;; esac
      if [ -z "$port_base" ]; then
        port_base="$(alloc_port_base "$slot")"
      elif ! port_base_free "$slot" "$port_base"; then
        # Its services are still bound to that block and somebody else holds it.
        # Refusing is the honest answer: a fresh block would silently point the
        # resumed agent's config at ports nothing is listening on.
        log_tick "$id: cannot resume $resume_sid — its port block $port_base is held by a live run"
        state_set "$id" last_status '"error"'
        run_cleanup "$id" "$slot"; trap - EXIT
        return 1
      else
        { echo "$port_base" > "$slot/portbase"; } 2>/dev/null || true
      fi
      export CC_PORT_BASE="$port_base" CC_PORT_SPAN CC_PROVISION_LIB="$BIN_DIR/provision-lib.sh"
      worktree="$run_dir/$("$JQ" -r '.primary // ""' "$run_dir/.run.json" 2>/dev/null)"
      if [ ! -d "$worktree" ]; then
        log_tick "$id: cannot resume $resume_sid — its primary worktree is gone"
        state_set "$id" last_status '"error"'
        run_cleanup "$id" "$slot"; trap - EXIT
        return 1
      fi
      # `up` runs again, with the SAME port block. The hooks are written to be
      # re-runnable (cc_copy_ignored, cc_env_ports, `herd link`, `compose up -d`
      # all are), and this is what puts a stack back that a reboot took down
      # while the session sat open.
      while IFS="$(printf '\t')" read -r rname rrepo rwt rbase; do
        [ -n "$rname" ] || continue
        wt_provision up "$project" "$id" "$run_dir" "$rname" "$rrepo" "$rwt" "$rbase" || true
      done < <("$JQ" -r '.repos[] | [.name,.canonical,.worktree,.base] | @tsv' \
                  "$run_dir/.run.json" 2>/dev/null)
      log_tick "$id: resumed $resume_sid in its own tree $run_dir (cwd $worktree)"
    else
      # Claim the path BEFORE anything exists there. The sweep removes any run dir
      # no live slot claims, so creating first and claiming after leaves a window
      # in which it can delete the very directory this agent is about to work in.
      # The path is ours to predict, so stake it first.
      run_dir="$WORKTREES_DIR/$id/$stamp"
      echo "$run_dir" > "$slot/worktree"
      # Before wt_setup, because the provisioning hooks it calls are what need the
      # block: they are what write the run's ports into its config.
      port_base="$(alloc_port_base "$slot")"
      export CC_PORT_BASE="$port_base" CC_PORT_SPAN CC_PROVISION_LIB="$BIN_DIR/provision-lib.sh"
      if ! worktree="$(wt_setup "$id" "$project" "$cwd" "$stamp" "$port_base")"; then
        state_set "$id" last_start "$start"
        state_set "$id" last_status '"error"'
        log_tick "$id: worktree isolation failed — run aborted (no shared-checkout fallback)"
        run_cleanup "$id" "$slot"; trap - EXIT
        return 1
      fi
      log_tick "$id: isolated in $run_dir (cwd $worktree)"
    fi
```

Declarar `rname rrepo rwt rbase` na lista de `local` no topo de `run_job`.

Remover a linha `log_tick "$id: isolated in $run_dir (cwd $run_cwd)"` que existia depois deste bloco — os dois ramos já registam o seu próprio.

- [ ] **Step 5: Add the port-block guard**

Em `bin/claude-cron`, imediatamente **a seguir** a `alloc_port_base()`, inserir:

```bash
# Is this port block free for <slot> to take? Used by a resume, which must have
# the block its services were bound to or none at all.
port_base_free() { # port_base_free <slot-dir> <base>
  local slot="$1" want="$2" d b
  for d in "$LOCK_DIR"/*/*/; do
    [ -d "$d" ] || continue
    [ "$d" = "$slot/" ] && continue
    slot_alive "${d%/}" || continue
    b="$(cat "$d/portbase" 2>/dev/null || true)"
    [ "$b" = "$want" ] && return 1
  done
  return 0
}
```

- [ ] **Step 6: Run the selftest to verify it passes**

Run: `bin/claude-cron selftest`
Expected: PASS, incluindo as quatro asserções novas.

- [ ] **Step 7: Write the changelog entry and commit**

```markdown
- **A resume continues in the tree its session was working in.** `run_job`
  computed a fresh timestamp and cut new worktrees from the base with no special
  case for a resume at all — so `claude-cron resume` handed the agent a
  conversation that remembered editing files and a checkout that had none of
  them, while the crashed run's directory sat preserved on disk for nobody. The
  resume now finds the directory by the session id recorded in it, takes back the
  same port block (and refuses outright if a live run holds it, rather than
  pointing the agent's config at ports nothing is listening on), and re-runs the
  provisioning hooks so a stack a reboot took down comes back.

  It reads the run's manifest and never re-derives the repo set from
  `projects.json`, which fixes that set for the session's life: editing a
  project's `repos` no longer changes what an already-open session is working on.
  Provisioning hooks must therefore tolerate being run twice on the same tree —
  `cc_copy_ignored`, `cc_env_ports`, `herd link` and `compose up -d` all do.
```

```bash
git add bin/worktree-lib.sh bin/claude-cron CHANGELOG.md
git commit -m "feat: a resume reattaches to the worktree its session was working in"
```

---

## Task 8: Open sessions expire

O último fio solto: uma sessão aberta que ninguém retoma. Sem TTL, a Tarefa 6 troca uma fuga por outra.

**Files:**
- Modify: `bin/worktree-lib.sh` (`wt_prune_orphans`, `:427`)
- Modify: `bin/claude-cron` (`selftest`)
- Modify: `bin/claude-cron-server` (`retained_worktrees`, `:1297`)
- Modify: `bin/dashboard.html` (`renderRetained`, `:3286`)
- Modify: `tests/test_retained_worktrees.py`
- Modify: `README.md`, `CHANGELOG.md`

**Interfaces:**
- Consumes: `.ended` (Tarefa 6), `slot_alive` (Tarefa 1).
- Produces: `CLAUDE_CRON_SESSION_TTL` (segundos, default `86400`). Cada linha de `retained_worktrees()` ganha `expires_in` (segundos até à expiração; `0` quando já expirou; `null` quando a sessão está fechada e vai na próxima varredura).

- [ ] **Step 1: Write the failing selftest assertion**

Em `bin/claude-cron`, no selftest, imediatamente **a seguir** ao bloco que a Tarefa 3
acrescentou — o que começa em
`echo "wt_prune_canonicals() — a run dir removed by hand leaves no registration behind"`
e acaba na sua última asserção — inserir:

```bash
  echo "wt_prune_orphans() — an open session outlives one sweep and dies of old age"
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"; WORKTREES_DIR="$tmp/wtroot"
    wt_setup jT two "$tmp/g/repo" stampT ) >/dev/null 2>&1
  echo open > "$tmp/wtroot/jT/stampT/.ended"
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"
    WORKTREES_DIR="$tmp/wtroot"; LOCK_DIR="$tmp/locks"
    wt_prune_orphans ) >/dev/null 2>&1
  [ -d "$tmp/wtroot/jT/stampT" ] && ok "an open session survives the sweep" \
    || bad "the sweep reaped a session that is still open"
  ( PROJECTS_FILE="$tmp/proj/two.json"; CONFIG_DIR="$tmp/cfg"
    WORKTREES_DIR="$tmp/wtroot"; LOCK_DIR="$tmp/locks"
    CLAUDE_CRON_SESSION_TTL=0
    wt_prune_orphans ) >/dev/null 2>&1
  [ ! -d "$tmp/wtroot/jT/stampT" ] && ok "and is reclaimed once its ttl is up" \
    || bad "an expired session was kept"
```

- [ ] **Step 2: Run the selftest to verify it fails**

Run: `bin/claude-cron selftest`
Expected: FAIL em `and is reclaimed once its ttl is up`.

- [ ] **Step 3: Expire open sessions in the sweep**

Em `bin/worktree-lib.sh`, substituir `wt_prune_orphans()` (`:427-446`) por:

```bash
# Sweep the run dirs whose owning run is no longer active (a killed or crashed
# run, or a tick that died between setup and launch), tearing each down safely.
# Called at the top of every tick.
#
# A dir whose session is still `open` is left alone — a resume needs it — but
# only until its TTL is up. Without that, Task 6 would have swapped one leak for
# another: a session nobody ever resumes is exactly as permanent as the unpushed
# work it replaced. The expiry closes the session first, so the normal path runs
# `down` and removes it like any other finished run.
wt_prune_orphans() {
  [ -d "$WORKTREES_DIR" ] || return 0
  local iddir id d project ttl age now
  ttl="$(num "${CLAUDE_CRON_SESSION_TTL:-}" 86400)"
  now="$(now_epoch)"
  for iddir in "$WORKTREES_DIR"/*; do
    [ -d "$iddir" ] || continue
    id="$(basename "$iddir")"
    for d in "$iddir"/*; do
      [ -d "$d" ] || continue                 # skips the .<stamp>.tsv scratch files
      # Claimed by a LIVE run? Ask the run slots, which is where that fact
      # lives: every running job holds a slot naming its run dir. Asking the
      # old single mutex (or the state's one cur_worktree, which cannot describe
      # several concurrent runs) said "nobody owns this" for worktrees that were
      # very much in use — and the sweep deleted them out from under the agents.
      wt_is_claimed "$id" "$d" && continue
      if [ "$(cat "$d/.ended" 2>/dev/null || true)" = "open" ]; then
        age="$(( now - $(num "$(wt_mtime "$d")" "$now") ))"
        [ "$age" -lt "$ttl" ] && continue
        # Out of time. Close it, so the teardown below treats it as any other
        # finished run: `down` for every repo, then gone.
        printf 'done\n' > "$d/.ended" 2>/dev/null || true
        log_tick "$id: session in $d expired after ${age}s with nobody resuming it"
      fi
      project="$(job_get "$id" '.project' '')"
      wt_teardown "$id" "$project" "$d"
    done
  done
}

# When a run dir was last touched, in epoch seconds. BSD stat; falls back to
# nothing so the caller's own default applies.
wt_mtime() { # <dir>
  stat -f %m "${1:-}" 2>/dev/null || true
}
```

- [ ] **Step 4: Run the selftest to verify it passes**

Run: `bin/claude-cron selftest`
Expected: PASS, incluindo as duas asserções novas.

- [ ] **Step 5: Write the failing server test**

Acrescentar a `tests/test_retained_worktrees.py`:

```python
def test_an_open_session_reports_the_time_it_has_left(clean_data):
    """A kept directory that says nothing about when it goes is the old leak
    wearing a new label."""
    srv = clean_data
    d = _mk_run_dir(srv, "epsilon", "s-open")
    (d / ".ended").write_text("open\n")
    got = srv.retained_worktrees()[0]
    assert got["expires_in"] > 0


def test_a_closed_session_has_no_expiry_because_it_goes_next_sweep(clean_data):
    srv = clean_data
    d = _mk_run_dir(srv, "zeta", "s-done")
    (d / ".ended").write_text("done\n")
    got = srv.retained_worktrees()[0]
    assert got["expires_in"] is None
```

- [ ] **Step 6: Run the server test to verify it fails**

Run: `python3 -m pytest tests/test_retained_worktrees.py -v`
Expected: FAIL com `KeyError: 'expires_in'`.

- [ ] **Step 7: Report the expiry**

Em `bin/claude-cron-server`, `retained_worktrees()`, substituir o bloco que monta cada linha:

```python
            out.append({"job": jobdir.name, "stamp": d.name, "path": str(d),
                        "age": age, "repos": repos, "bytes": bytes_})
```

por:

```python
            # An open session is kept for a resume, and the sweep reclaims it
            # once its TTL is up. Saying when turns a folder that looks abandoned
            # into a queue with an end.
            try:
                ended = (d / ".ended").read_text().strip()
            except OSError:
                ended = ""
            expires_in = max(0, SESSION_TTL - age) if ended == "open" else None
            out.append({"job": jobdir.name, "stamp": d.name, "path": str(d),
                        "age": age, "repos": repos, "bytes": bytes_,
                        "ended": ended, "expires_in": expires_in})
```

E junto das outras constantes no topo do módulo (onde `DATA_DIR` e `CONFIG_DIR` são resolvidos), acrescentar:

```python
# Kept in step with the engine's own default (bin/worktree-lib.sh,
# wt_prune_orphans): the dashboard must never promise a directory more time than
# the sweep will give it.
SESSION_TTL = int(os.environ.get("CLAUDE_CRON_SESSION_TTL") or 86400)
```

- [ ] **Step 8: Run both suites to verify they pass**

Run: `python3 -m pytest tests/ -v && bin/claude-cron selftest`
Expected: PASS em ambas.

- [ ] **Step 9: Show it on the dashboard**

Em `bin/dashboard.html`, substituir `const WT_COLS=["Job","Run","Repos","Size","Kept since",""];` (`:3285`) por:

```javascript
const WT_COLS=["Job","Run","Repos","Size","Kept since","Expires",""];
```

Substituir as duas cópias do `$("wt-blurb").textContent` (`:3289-3294`) por:

```javascript
  $("wt-blurb").textContent = items.length
    ? "Directories from runs that are over, still on disk. One whose session was cut short is "
      + "kept so a resume can continue in it — with its services still up — and is reclaimed on "
      + "its own once the session expires. Discard ends one early."
    : "Nothing on disk. A run cut short keeps its tree here until it is resumed or expires.";
```

E na linha da tabela, imediatamente **antes** de `+'<td class="rowacts">`, inserir a célula nova:

```javascript
      +'<td class="muted nowrap">'+(w.expires_in==null
          ? '<span class="muted">—</span>'
          : (w.expires_in<=0 ? "due now"
             : (w.expires_in>=3600 ? "in "+Math.floor(w.expires_in/3600)+"h"
                                   : "in "+Math.max(1,Math.floor(w.expires_in/60))+"m")))+'</td>'
```

`fmtAgo` **não** serve aqui: formata um instante passado ("3h ago"), e aplicá-lo a uma expiração futura imprimiria "23h ago" para algo que ainda falta. Daí a formatação inline.

O `colspan` da linha vazia já usa `WT_COLS.length`, portanto acompanha sozinho — confirmar que sim e não o tocar.

- [ ] **Step 10: Verify the page still parses and every element it reaches for exists**

Run: `python3 -m pytest tests/test_page_contract.py -v`
Expected: PASS.

- [ ] **Step 11: Update the README**

Em `README.md`, substituir a subsecção `#### Worktrees that are kept back` inteira por:

```markdown
#### Sessions that are still open

A run that ends cleanly has its worktrees removed. A run that was **cut short** —
killed, crashed, stopped by a watchdog — keeps its run dir, and keeps its
provisioned services **up**, because `claude-cron resume <job> <session>`
continues in that same directory: the agent's conversation remembers the files it
edited, and a fresh checkout of the base would not have them.

Nothing else keeps a directory. A run that ends holding commits or changes that
exist on no remote is reported as a `warning` on the card
(`UNDELIVERED: unpushed commits in api`) and its tree is still removed — pushing
is how work is delivered, and a folder nobody is coming back for was only ever
filling the disk.

An open session that nobody resumes expires after **24 hours**
(`CLAUDE_CRON_SESSION_TTL`, in seconds), at which point the sweep runs its `down`
hooks and removes it like any other finished run. The dashboard lists every open
session with its size, its age and the time it has left, and **Discard** ends one
early (`claude-cron worktree-drop <job-id> <stamp>` from the CLI). A run dir a
live run is using is never offered, and never dropped.
```

Substituir também, na secção *Isolation*, a frase:

```
A run dir is removed when the run ends — unless a worktree still holds work that
exists nowhere else (uncommitted changes, or commits on no remote), in which case
the whole run dir is kept and the tick log says so.
```

por:

```
A run dir is removed when the run ends. A run that was cut short keeps its dir
until it is resumed or expires — see [Sessions that are still open](#sessions-that-are-still-open).
```

Acrescentar `CLAUDE_CRON_SESSION_TTL` à lista de *Environment overrides* na secção **CLI**.

- [ ] **Step 12: Write the changelog entry and commit**

```markdown
- **An open session expires instead of waiting for a human.** Keeping a cut-short
  run's tree so a resume can use it would have swapped one permanent directory
  for another: a session nobody ever resumes is exactly as immortal as the
  unpushed work it replaced. Open sessions now expire after 24 hours
  (`CLAUDE_CRON_SESSION_TTL`), and expiring closes the session so the ordinary
  path runs its `down` hooks and removes the tree like any other finished run.
  The dashboard shows how long each has left, so the list reads as a queue with
  an end rather than a pile.
```

```bash
git add bin/worktree-lib.sh bin/claude-cron bin/claude-cron-server bin/dashboard.html tests/test_retained_worktrees.py README.md CHANGELOG.md
git commit -m "feat: open sessions expire on their own instead of waiting for a human"
```

---

## Verificação final

- [ ] **Both suites, clean:**

```bash
bin/claude-cron selftest && python3 -m pytest tests/ -v
```

- [ ] **Um ciclo real, ponta a ponta.** Com um job de teste isolado num repositório descartável:

1. `claude-cron run <id>` e deixar acabar limpo → o run dir desaparece, `down` correu uma vez por repo (ver `data/exec.log`).
2. `claude-cron run <id>` e `claude-cron stop <id>` a meio → o run dir fica, `.ended` diz `open`, os serviços continuam de pé, e o dashboard mostra a linha com tempo restante.
3. `claude-cron resume <id> <session>` → o log do tick diz `resumed <sid> in its own tree <dir>`, e o `cwd` do agente é o mesmo directório de (2).
4. Deixar esse resume acabar limpo → o directório desaparece.
5. `CLAUDE_CRON_SESSION_TTL=0` e esperar um tick → uma sessão aberta é reclamada, com a linha de expiração em `data/tick.log`.

- [ ] **Reboot.** Reiniciar a máquina com um run a meio, e confirmar que no primeiro tick a seguir o slot antigo é considerado morto: o job volta a correr (não fica preso no `max_parallel`) e o run dir órfão é tratado pelo sweep.
