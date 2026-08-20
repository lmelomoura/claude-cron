# Correr outro engine além do Claude — o que foi medido, e o que falta

> **Fase 0** do trabalho de suportar o Codex (ideia 6 da lista tirada de
> `stablyai/orca`). Este documento existe para que a próxima sessão **não repita
> a investigação** e não desenhe o adaptador em cima de suposições.
>
> **Estado: bloqueado, com data.** A conta Codex esgotou a quota a 2026-08-20 e
> só reabre a **2026-08-21 06:32**. Sem um turno bem-sucedido não se conhece o
> formato dos eventos que interessam, e desenhar o adaptador sem isso é adivinhar.

---

## Porque é que a Fase 0 existe

O Orca vende *"works with any CLI agent"* e paga por isso 1.252 linhas em
`agent-completion-coordinator.ts` mais 165 KB de `agent-hook-listener.ts`, só
para responder a "o agente acabou?" através de três canais frágeis (hook /
título da janela / morte do processo). O claude-cron responde à mesma pergunta
em cinco linhas (`turn_is_over`) porque escolheu um agente **com protocolo**.

A conclusão para nós: acrescentar engines **traduzindo JSON na fronteira**, nunca
inferindo por terminal. Isso exige conhecer o JSON — daí esta fase.

---

## Medido em 2026-08-20 (factos, não memória)

Instalado: `npm install -g @openai/codex` → `codex-cli 0.148.0` em
`/opt/homebrew/bin/codex`. Autenticação: `codex login status` →
`Logged in using ChatGPT`.

### A interface headless existe e é próxima da nossa

| o que o claude-cron precisa | flag do `codex exec` | notas |
|---|---|---|
| modo não interactivo | `codex exec [PROMPT]` | `-p` do Claude |
| eventos em JSONL | `--json` | confirmado |
| escolher o modelo | `-m, --model` | |
| directório de trabalho | `-C, --cd <DIR>` | hoje fazemos `cd` antes de lançar |
| ignorar aprovações | `--dangerously-bypass-approvals-and-sandbox` | análogo a `bypassPermissions`, que é o que **todos os 8 jobs** usam |
| política de sandbox | `-s, --sandbox` | `read-only` / `workspace-write` / `danger-full-access` |
| continuar sessão | `codex exec resume <id>` ou `--last` | subcomando, não flag |
| última mensagem | `-o, --output-last-message <FILE>` | dá o "resultado" sem escavar o stream |
| correr fora de um repo git | `--skip-git-repo-check` | as nossas worktrees são repos, provavelmente irrelevante |

**Sem equivalente encontrado:** `--max-budget-usd` e `--effort`. Pode haver via
`-c key=value` (override do `config.toml`) — **por confirmar**.

### Dois factos práticos que custam caro se forem descobertos em produção

1. **`codex exec` bloqueia à espera de stdin.** Com o stdin herdado escreve
   `Reading additional input from stdin...` e fica ali para sempre — o primeiro
   lançamento ficou pendurado até ao timeout de 300s. Exige `< /dev/null`. O
   claude-cron lança o CLI com o stdin herdado no caminho não interactivo, por
   isso isto seria um deadlock silencioso no primeiro run.
2. **A quota é por conta e reinicia a uma hora fixa.** O erro chega como evento,
   não como código HTTP (ver abaixo) — o que significa que a taxonomia de causas
   (`api_error` / `rate_limited`, ver PR #16) precisa de um ramo próprio por
   engine, não de uma leitura de `api_error_status`.

### O formato dos eventos, tanto quanto se viu

Capturado em `test/fixtures/codex-exec-quota-exhausted.jsonl`:

```json
{"type":"thread.started","thread_id":"01a01e80-4d86-7a42-b4c0-a162076308b0"}
{"type":"turn.started"}
{"type":"error","message":"You've hit your usage limit…try again at Aug 21st, 2026 6:32 AM."}
{"type":"turn.failed","error":{"message":"…"}}
```

Mapeamento provável — **o `thread_id` é o análogo do `session_id`**, e é a chave
de que todo o ciclo de vida das worktrees depende (`bind_session`,
`wt_find_by_session`). O exit code foi `1`.

---

## Por medir (a lista para 2026-08-21, depois das 06:32)

Correr **exactamente** isto e guardar o resultado como fixture:

```bash
codex exec --json --skip-git-repo-check -s read-only -C <dir> 'Reply with exactly: ok' < /dev/null
```

E depois uma tarefa que **use ferramentas** (ler um ficheiro, correr um comando),
porque é aí que estão os eventos que o dashboard desenha. Perguntas a responder,
por ordem de importância para o desenho:

- [ ] Qual é o evento **final** de um turno com sucesso, e o que carrega? É o
      análogo do `{"type":"result"}` de que `turn_is_over` depende — **sem ele o
      watchdog não sabe quando um run está quieto e pode ser morto.**
- [ ] Há **custo e contagem de turnos**? Se não houver, `cost` e `turns` ficam
      vazios para este engine e a UI tem de o dizer, não mostrar `$0.00` (a mesma
      regra que se aplicou ao `api_error_status`).
- [ ] Que forma têm os eventos de **tool call** e de **mensagem do agente**? É o
      que `parse_turns_text` e `parse_conversation` desenham.
- [ ] Um **`resume` devolve o mesmo `thread_id`?** Este é o contrato não
      verificado de que todo o ciclo de vida das worktrees depende — está escrito
      em `bin/claude-cron` na nota do `--resume`. Para o Claude nunca foi
      confirmado; para o Codex tem de ser, **antes** e não depois.
- [ ] Há um análogo de `permission_denials`? Se não houver, o gate "ferramentas
      negadas = erro" não se aplica e a capability tem de dizer isso.
- [ ] O `-c` chega para exprimir um tecto de gasto ou um nível de esforço?

---

## O desenho, quando os factos existirem

Uma **tabela**, uma entrada por engine (é o padrão que o próprio Orca usa em
`agent-headless-command.ts`: *"a table (not an if-chain) so adding an agent is
one entry"*), com três responsabilidades:

1. `agent_argv` — monta a linha de comandos.
2. `agent_normalize` — filtro que traduz o JSONL do CLI para os eventos
   canónicos que os ~47 sítios existentes já lêem. **Traduzir à entrada, não
   reescrever a jusante.**
3. `agent_caps` — declara o que suporta: `resume`, `interactive`, `cost`,
   `budget`, `denials`. Uma capability em falta tem de aparecer na UI como
   "este engine não reporta isto", nunca como um zero.

O job ganha `engine` (default `claude`), para nenhum job existente mudar.

**Não fazer sem os factos:** qualquer coisa que assuma a forma de um evento que
ainda não foi visto. O erro que esta fase existe para evitar já aconteceu uma vez
nesta série de trabalho — o plano do gate de rate-limit afirmava que o statusline
podia ser alimentado pelos runs, e a medição mostrou que **não corre em modo
headless**. Medir primeiro custou uma hora; ter construído em cima da suposição
teria custado a funcionalidade toda.
