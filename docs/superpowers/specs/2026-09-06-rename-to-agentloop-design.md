# Renomear claude-cron para agentloop — desenho

> Sub-projecto **A** de dois. O B é
> [`2026-09-06-platforms-anthropic-openai-design.md`](2026-09-06-platforms-anthropic-openai-design.md),
> e depende deste: os nomes novos que o B introduz nascem já com o prefixo
> certo, e nada é renomeado duas vezes.
>
> Estado: desenho aprovado em brainstorming a 2026-09-06; por implementar.

---

## Porquê

O scheduler passa a correr agentes de duas plataformas, Anthropic e OpenAI. Um
produto chamado *claude-cron* que lança o Codex tem um nome que mente. O nome
novo vem do subtítulo que o README já usa desde o início, *Agent Loop Manager*,
e do vocabulário dos próprios prompts: **agentloop**.

## Objectivo

Nenhum vestígio do nome antigo no produto, nas suas variáveis, no contrato de
ambiente dos runs, no header da dashboard nem na documentação entregue. Uma
instalação existente migra sozinha ao correr `install.sh`. Os scripts pessoais
do operador continuam a funcionar durante **uma versão de transição**, com aviso
do que ainda lê o nome antigo.

## O que muda de nome

| Camada | Antes | Depois |
|---|---|---|
| comando e servidor | `bin/claude-cron`, `bin/claude-cron-server` | `bin/agentloop`, `bin/agentloop-server` — via `git mv`, história preservada |
| symlinks em `~/.local/bin` | `claude-cron`, `claude-cron-server` | `agentloop`, `agentloop-server` |
| launchd | `com.claude-cron.tick`, `com.claude-cron.server` | `com.agentloop.tick`, `com.agentloop.server` |
| ambiente do engine (20 nomes) | `CLAUDE_CRON_*` | `AGENTLOOP_*` |
| contrato de ambiente dos runs (38 nomes) | `CC_*` | `AL_*` |
| header da dashboard | `X-CC-Token` | `X-AL-Token` |
| identificadores internos que soletram o nome | `CCApp`, `CCSecurity` (globais JS), `cc()` (servidor), `cc_server` (testes), `cc-ports.*` (provision-lib) | `ALApp`, `ALSecurity`, `al()`, `al_server`, `al-ports.*` |
| `package.json` | `claude-cron-ui` | `agentloop-ui` |
| `bin/security/cli.py` | `prog="claude-cron security"` | `prog="agentloop security"` |
| SBOM (`bin/security/deps.py`) | vendor `claude-cron` | vendor `agentloop` |
| docs entregues | README, CONTRIBUTING, template de PR, cabeçalho do CHANGELOG, `skills/*/SKILL.md`, comentários de código | agentloop |
| repositório GitHub | `lmelomoura/claude-cron` | `lmelomoura/agentloop` (acção do operador, ver abaixo) |

Os 20 nomes `CLAUDE_CRON_*`, para o plano os apanhar todos: `DATA`, `CONFIG`,
`PORT`, `CLAUDE_BIN`, `CLAUDE_CONFIG_DIR`, `PYTHON`, `JQ`, `LOG_MAX`,
`HOOK_TIMEOUT`, `LOCK_GRACE`, `SESSION_TTL`, `SECURITY_DB`,
`SECURITY_STALE_GRACE`, `STATUSLINE_MIN_SECONDS`, `STALL_HOURS`, `PORT_SPAN`,
`PORT_RANGE_START`, `PORT_BLOCKS`, `SPEND_SCAN`, `RATE_LIMIT_STOP_AT`.

Os 38 nomes `CC_*`: `SECURITY_AGENT`, `SECURITY_ENGINES`, `SECURITY_ANALYSIS_ID`,
`BASE_OVERRIDE`, `BASE`, `PORT_BASE`, `PORT_SPAN`, `PORT_BLOCKS`,
`PORT_RANGE_START`, `RUN_MANIFEST`, `RUN_DIR`, `SKIP_PROVISION`, `REPO_PATH`,
`REPO_NAME`, `PRIMARY_REPO`, `WORKTREE`, `PRECHECK_DRY_RUN`, `JOB_ID`,
`PROJECT`, `PROVISION_LIB`, `LIB`, `HOOK_OUT`, `ROUND_CAP`, `ROUND_STATUS`,
`DASHBOARD`, `BOOT_ID`, `STATUS`, `REASON`, `NOTE`, `COST`, `START`, `END`,
`DURATION`, `SESSION`, `LOG`, `STALL_HOURS`, `JOBS_FILE`, `ARGV_OUT`.

## O que não muda

- `AGENTLOOP_CLAUDE_BIN` e `AGENTLOOP_CLAUDE_CONFIG_DIR` mantêm *claude* no
  nome porque nomeiam o CLI da Anthropic, não o produto. O mesmo vale para
  `claude_config_dir` em `projects.json` e para a variável `CLAUDE_CONFIG_DIR`
  que o engine exporta para o CLI.
- `test/fake-claude` mantém o nome: finge o CLI da Anthropic.
- `bin/statusline-rate-limits.sh` mantém o nome; só a pasta em que vive muda.
- O `CHANGELOG.md` mantém todas as entradas antigas como foram escritas. Uma
  nota no topo diz que o projecto foi renomeado a 2026-09-06 e que as entradas
  anteriores usam o nome antigo.
- `docs/superpowers/specs/` e `docs/superpowers/plans/` anteriores, e
  `.superpowers/sdd/`: documentos datados, não são tocados.
- Nomes de ficheiros em `config/` e `data/`, e a forma de `state.json`,
  `runs.ndjson`, `rate-limits.json`, `index.db`, `app.db`, `security.db`,
  `control.token`. O ficheiro órfão `data/claude-cron.db` não é referido por
  código nenhum e fica onde está.

## Migração, feita por `agentloop install`

Numa instalação que era claude-cron, por esta ordem:

1. **Plists.** Se `~/Library/LaunchAgents/com.claude-cron.tick.plist` existir,
   lê dele o `CLAUDE_CONFIG_DIR` fixado (o mesmo `plistlib` que hoje lê o plist
   novo), descarrega e apaga os dois plists antigos, e só então escreve e carrega
   `com.agentloop.tick` e `com.agentloop.server`. O plist do servidor passa a
   levar `AGENTLOOP_PORT`.
2. **Symlinks.** Remove `~/.local/bin/claude-cron` e `claude-cron-server`
   **apenas se apontarem para esta pasta**; cria `agentloop` e
   `agentloop-server`.
3. **Skills.** `cmd_skills install` já é idempotente e compara o alvo do link:
   depois de a pasta mudar de nome, relinka `~/.claude/skills/*` sem mais nada.
4. **Statusline.** Se `~/.claude/settings.json` tiver um `statusLine.command`
   cujo caminho contenha `claude-cron`, imprime o caminho novo a colocar lá.
   Não edita o ficheiro: é do utilizador.
5. **Avisos de transição** (ver secção seguinte), impressos no fim.

`install.sh` e `uninstall.sh` mudam de texto e chamam `bin/agentloop`.
`uninstall.sh` remove também os symlinks antigos, se ainda existirem.

## Compatibilidade durante uma versão de transição

A versão que entrega a renomeação mantém estes atalhos. A versão seguinte
remove-os, e a entrada do CHANGELOG diz isso com estas palavras.

- **Variáveis do engine.** Cada leitura é
  `AGENTLOOP_X="${AGENTLOOP_X:-${CLAUDE_CRON_X:-default}}"`. `install` e
  `status` listam qualquer `CLAUDE_CRON_*` presente no ambiente, com o nome novo
  ao lado.
- **Contrato dos runs.** O engine exporta **`AL_*` e `CC_*`** com o mesmo valor
  para: o processo do agente, o precheck, os hooks de provisioning `up` e
  `down`, `on-run-end.sh` e `on-fleet-stalled.sh`. `bin/provision-lib.sh` e
  `bin/round-cap.sh` lêem `AL_*` com fallback para `CC_*`. `install` e `status`
  percorrem `config/prechecks/*.sh`, `config/provision/*.sh` e `config/hooks/*`
  e listam cada ficheiro que ainda leia `CC_[A-Z_]+`, com a contagem e o aviso
  de que a exportação dupla acaba na versão seguinte.
- **Header.** O servidor aceita `X-AL-Token` e `X-CC-Token`; a página envia só
  `X-AL-Token`. Um separador aberto durante o deploy continua a poder falar com
  o servidor até recarregar.
- **Scripts pessoais do operador.** Os oito scripts em `config/prechecks/` e
  `config/provision/` desta instalação lêem `CC_*`. São pessoais e não
  versionados. O plano inclui um passo **opcional**, feito na mesma sessão e com
  OK explícito na altura, para os passar a `AL_*`.

## Fora do repositório, acções do operador depois do merge

1. `gh repo rename agentloop` — o GitHub mantém redirecções do nome antigo para
   clones e links existentes.
2. `mv ~/Projects/claude-cron ~/Projects/agentloop` e, dentro da pasta nova,
   `bash install.sh`. Os scripts resolvem o próprio caminho, por isso a
   migração acima trata do resto.
3. Actualizar `statusLine.command` em `~/.claude/settings.json` para o caminho
   novo, como o `install` indica.
4. A memória do Claude Code deste projecto está indexada pelo caminho da pasta;
   é movida pelo assistente quando a pasta mudar.

## Testes que fecham a renomeação

- **Teste guarda** (pytest): falha se `claude-cron`, `CLAUDE_CRON`, `CC_`
  como prefixo de variável, `CCApp`, `CCSecurity`, `cc_server` ou `X-CC-Token`
  sobreviverem em `bin/`, `ui/`, `skills/`, `build/`, `install.sh`,
  `uninstall.sh`, `README.md`, `CONTRIBUTING.md`, `.github/` e `package.json`,
  **fora de uma lista explícita de linhas de compatibilidade** (as leituras com
  fallback, a exportação dupla, a aceitação do header antigo e o código de
  migração, que têm de nomear o nome antigo para o apagar). A lista é curta e
  vive no próprio teste, para que remover os atalhos na versão seguinte seja
  apagar entradas dessa lista até ela ficar vazia.
- **Selftest**: uma variável só no nome antigo é lida com o valor certo e
  reportada por `status`; um run vê `AL_JOB_ID` e `CC_JOB_ID` iguais; um
  precheck e um hook de fim de run vêem os dois prefixos; `install` com um
  `HOME` de teste que tem os plists antigos acaba só com os novos e com o
  `CLAUDE_CONFIG_DIR` preservado; o aviso dos scripts pessoais nomeia o ficheiro
  certo.
- **pytest** do servidor: os dois headers autenticam; o antigo sozinho também.
- Tudo o que já existe continua verde: `agentloop selftest`,
  `pytest tests/`, `test/e2e.test.sh`, e o CI, que passa a chamar
  `bin/agentloop selftest`.

## Ordem de implementação, para o plano

1. `git mv` dos dois binários; caminhos internos, `SELF`, `SERVER_BIN`, labels,
   `PLIST_*`, e as variáveis `AGENTLOOP_*` com fallback.
2. `CC_*` → `AL_*` com exportação dupla; `provision-lib.sh` e `round-cap.sh`.
3. Header, globais JS, `cc()`, `cc_server`; rebuild de `bin/static/`.
4. Migração em `cmd_install`, `install.sh`, `uninstall.sh`, avisos em `status`.
5. Docs, skills, `cli.py`, `deps.py`, `package.json`, CI, template de PR.
6. Teste guarda, casos de selftest, casos pytest; CHANGELOG.
7. PR contra `main`; depois do merge, as acções do operador.
