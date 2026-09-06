# Plataformas Anthropic e OpenAI — desenho

> Sub-projecto **B** de dois. Depende do A,
> [`2026-09-06-rename-to-agentloop-design.md`](2026-09-06-rename-to-agentloop-design.md):
> este documento já usa os nomes novos (`agentloop`, `AGENTLOOP_*`, `AL_*`).
>
> Estado: desenho aprovado em brainstorming a 2026-09-06; por implementar.
> Evidência: [`2026-09-06-codex-measurements/`](2026-09-06-codex-measurements/README.md).

---

## Contexto

O agentloop lança um agente headless por job, lê o stream de eventos que o CLI
emite e decide tudo a partir dele: quando o run acabou, que sessão é, quanto
custou, porque falhou, o que mostrar na dashboard. Hoje o único agente é o
Claude Code. Este desenho acrescenta o Codex CLI da OpenAI, e fá-lo do único
modo que a Fase 0 (`plans/2026-08-20-codex-engine-probe.md`) admitiu: traduzir
o JSON na fronteira, nunca inferir por terminal, e nunca desenhar sobre um
evento que não foi visto.

### O que ficou medido a 2026-09-05 (Codex CLI 0.148.0)

| Facto | Consequência para o desenho |
|---|---|
| headless: `codex exec --json [-m slug] [-s sandbox] [-C dir] [-c k=v] --skip-git-repo-check PROMPT`, **sempre com `</dev/null`** | sem stdin fechado o processo fica pendurado à espera de input |
| eventos: `thread.started{thread_id}`, `turn.started`, `item.started/completed{item}`, `turn.completed{usage}`, `turn.failed{error}`, `error{message}`; exit 0 / 1 | o evento final que o `turn_is_over` e o classificador precisam é `turn.completed` ou `turn.failed` |
| tipos de item vistos: `agent_message{text}`, `command_execution{command, aggregated_output, exit_code, status}`, `error{message}` | mapeáveis para `text`, `tool_use`/`tool_result` e texto de erro |
| `usage`: `input_tokens`, `cached_input_tokens`, `cache_write_input_tokens`, `output_tokens`, `reasoning_output_tokens`; **sem dólares** | o custo é estimado a partir dos tokens |
| **sem modelo no stream**; o modelo que correu está no rollout `$CODEX_HOME/sessions/YYYY/MM/DD/rollout-<ts>-<thread_id>.jsonl`, em `turn_context.model` | o `model_id` é lido do rollout no fim do run |
| rate limits no rollout, em `token_count.rate_limits`: `primary` (300 min) e `secondary` (10080 min) com `used_percent` e `resets_at`, em **todos** os turnos | o gate OpenAI é alimentado por cada run, sem statusline |
| `codex exec resume --json <thread_id> PROMPT` devolve **o mesmo** `thread_id` | o contrato de que o ciclo de vida das worktrees depende está verificado para o Codex |
| `exec resume` aceita `--json`, `-m`, `-c`, `--dangerously-bypass-approvals-and-sandbox`, `--skip-git-repo-check`; **não** aceita `-s` nem `-C` | sandbox num resume só por `-c sandbox_mode=…`; cwd só pelo processo — ver medições em falta |
| modelo desconhecido: `item.completed{type:error}` + `error` + `turn.failed` com `{"status":400,…}` embebido; exit 1 | o normalizador lê o `status` embebido para a taxonomia de causas |
| quota esgotada (fixture de Agosto): `error` + `turn.failed` com "You've hit your usage limit… try again at <data>"; exit 1 | a frase mapeia para `rate_limited` |
| `--strict-config` recusa chaves `-c` desconhecidas; aceita `model_reasoning_effort`, `approval_policy` e `--disable multi_agent` | esforço, política de aprovação e fecho de subagentes têm sintaxe verificada |
| `codex debug models` devolve o catálogo em JSON em 0 s, com `--bundled` offline: `slug`, `display_name`, `description`, `default_reasoning_level`, `supported_reasoning_levels`, `visibility` (list/hide), `priority`, `upgrade{model, retirement_at}` | a lista do selector vem daqui |
| catálogo do dia: `gpt-5.6-sol` (default, esforço low…ultra), `gpt-5.6-terra`, `gpt-5.6-luna`, `gpt-5.5`, `gpt-5.4-mini` (descontinuado → luna, retira a 2026-08-31); ocultos `gpt-reserve`, `codex-auto-review` | os slugs visíveis são o selector; os ocultos são aceites se escritos |
| a linha `Reading additional input from stdin...` sai **sempre** em stderr | sem filtro, todos os runs OpenAI seriam `warning` (o classificador conta bytes de stderr) |
| uma negação da sandbox **não produz evento**: o agente diz-o em texto | não há análogo de `permission_denials`; a causa `tools_denied` não existe em OpenAI |
| sem `--input-format` por stdin, sem `--allowedTools`/`--disallowedTools`, sem `--max-budget-usd` | três capacidades em falta, declaradas na tabela |
| `CODEX_HOME` escolhe a conta e os rollouts; `~/.codex/skills/<nome>/SKILL.md` é onde o Codex lê skills | conta por projecto fica fora desta versão; as skills são linkadas também para lá |

## Objectivo e âmbito

Um job, um projecto e o bloco `security` de um projecto escolhem **plataforma
→ modelo**. Tudo o que corre um agente aceita as duas plataformas, incluindo as
análises de segurança. Os runs OpenAI têm custo **estimado** a partir dos tokens
e de uma tabela de preços, para que os tectos em dólares continuem a
aplicar-se. O gate de rate limit passa a ser por plataforma. Nenhum job
existente muda de comportamento: `platform` ausente é `anthropic`.

Decisões tomadas pelo operador em brainstorming e não reabertas aqui: o nome
agentloop; âmbito completo (jobs, projectos, segurança); custo estimado por
tabela de preços em vez de "não reportado" ou de tectos em tokens; renomeação
total incluindo `CC_*` → `AL_*`.

## Arquitectura

### A tabela de plataformas, em `bin/agentloop`

O bash 3.2 não tem arrays associativos, por isso a "tabela" é um bloco contíguo
`# --- platforms ---` de funções, cada uma com um `case "$platform" in` e nada
fora dele. Acrescentar uma plataforma é acrescentar um ramo a cada função. O
`run_job` deixa de nomear `$CLAUDE_BIN` e o formato do stream directamente e
passa a perguntar à tabela.

| Função | anthropic | openai |
|---|---|---|
| `platform_known <p>` | 0 | 0 |
| `platform_bin <p>` | `$AGENTLOOP_CLAUDE_BIN` | `$AGENTLOOP_CODEX_BIN`, por omissão `command -v codex` |
| `platform_ready <p>` → rc e razão | binário existe | binário existe **e** `codex login status` devolve 0 |
| `platform_argv <p> …` | a linha de hoje, inalterada | ver abaixo |
| `platform_caps <p> <cap>` → rc 0 quando a plataforma **tem** a capacidade | `interactive`, `tool_lists`, `denials`, `budget_flag`, `cost_reported`, `stream_rate_limits`, `families`: tem todas | não tem nenhuma das sete |
| `platform_stderr_filter <p> <file>` | no-op | apaga do `.err` as linhas iguais a `Reading additional input from stdin...` |
| `platform_finish <p> <streamfile> <run-vars…>` | no-op (o `rl_capture` de hoje fica onde está) | localiza o rollout pelo `thread_id`; lê `turn_context.model` → `model_id`; lê o último `token_count.rate_limits` → `rl_capture_openai` |
| `platform_effort_ok <p> <model> <effort>` | low·medium·high·xhigh·max | os `supported_reasoning_levels` do modelo no catálogo |
| `platform_permission_ok <p> <mode>` | acceptEdits·auto·bypassPermissions·manual·dontAsk·plan | read-only·workspace-write·full-access |
| `platform_model_ok <p> <model>` | família ou `claude-*` | slug presente no catálogo (`list` ou `hide`) |
| `platform_default_model <p>` | `opus` | o primeiro `visibility: list` por `priority` |
| `platform_default_permission <p>` | `dontAsk` (job), `bypassPermissions` (segurança) | `workspace-write` (job), `full-access` (segurança) |

`platform_argv openai` monta:

```
exec [resume <thread_id>] --json --skip-git-repo-check
     -C <run_cwd>                       # só num run novo: resume não aceita -C
     -m <slug>
     [-c model_reasoning_effort="<effort>"]
     <permissão>                        # read-only  → -s read-only  -c approval_policy="never"
                                        # workspace-write → -s workspace-write -c approval_policy="never"
                                        # full-access → --dangerously-bypass-approvals-and-sandbox
                                        # num resume, -s vira -c sandbox_mode="…" (a confirmar)
     [--disable multi_agent]            # quando disallowed_tools nomeia Agent
     -- <prompt>                        # `--` a confirmar; ver medições em falta
```

`interactive`, `allowed_tools` e qualquer `disallowed_tools` além de `Agent`
não têm tradução: ver [Configuração](#configuração) para o que acontece.

### O normalizador, `bin/platforms/openai_stream.py`

Python 3, só stdlib, **puro**: lê o JSONL do Codex no stdin, escreve
`stream-json` canónico no stdout, uma linha por evento, sem buffer (`-u` e
`flush` por linha, porque o watchdog mede o crescimento do ficheiro e a
Terminal da dashboard segue-o ao vivo). Copia cada linha crua para
`<streamfile>.raw`. A única outra coisa que conhece é o ficheiro de preços,
recebido por caminho. Uma linha que não é JSON é copiada para o `.raw` e
ignorada, como todos os leitores já fazem com uma linha truncada.

```
python3 -u bin/platforms/openai_stream.py \
  --model <slug> --permission <mode> --cwd <run_cwd> \
  --pricing config/pricing.json --raw-out <streamfile>.raw \
  < <fifo> > <streamfile>
```

Mapeamento, com os nomes que os leitores existentes já procuram:

| Codex | canónico |
|---|---|
| `thread.started{thread_id}` | `{"type":"system","subtype":"init","session_id":<thread_id>,"model":<slug pedido>,"platform":"openai","permissionMode":<mode>,"cwd":<cwd>,"tools":[]}` — **primeira linha**, porque `session_from_stream` lê só as cinco primeiras |
| `turn.started` | nada |
| `item.completed{agent_message}` | `assistant` com um bloco `{"type":"text","text":…}` |
| `item.started{command_execution}` | `assistant` com `{"type":"tool_use","id":<item.id>,"name":"Bash","input":{"command":…}}` |
| `item.completed{command_execution}` | `user` com `{"type":"tool_result","tool_use_id":<item.id>,"content":<aggregated_output, cortado a 8 KB>,"is_error":<exit_code ≠ 0>}`; se nunca houve `item.started` para esse id, o `tool_use` é emitido imediatamente antes |
| `item.*{reasoning}` | nada — o thinking do Claude também não aparece na Timeline |
| `item.completed{error}` | `assistant` com texto `error: <message>`; a mensagem fica guardada para o `result` |
| item de tipo desconhecido (`file_change`, `mcp_tool_call`, `web_search`, `todo_list`, …) | `tool_use` genérico: `name` = o tipo do item, `input` = o item sem `id`, `type` e `status`; e `tool_result` vazio ao completar. Aparece na Timeline em vez de desaparecer; a forma exacta destes itens é uma medição em falta |
| `turn.completed{usage}` | `result` com `subtype:"success"`, `is_error:false`, `num_turns` = eventos `assistant` emitidos, `result` = o último `agent_message`, `session_id`, `usage` nos nomes que o salvamento já soma (`input_tokens`, `cache_read_input_tokens` ← `cached_input_tokens`, `cache_creation_input_tokens` ← `cache_write_input_tokens`, `output_tokens`), `total_cost_usd` (estimado, ou `null`), `cost_basis` (`estimated` ou `none`), `tokens` {input, cached, cache_write, output, reasoning}, `permission_denials:[]`, `platform:"openai"` |
| `error{message}` | guardado; se nenhum `turn.failed` se seguir antes do EOF, o `result` é emitido a partir dele |
| `turn.failed{error.message}` | `result` com `is_error:true`, `subtype:"error_during_execution"`, `result` = a mensagem, e `api_error_status` = o `status` do JSON embebido quando existe, ou **429** quando a mensagem contém `hit your usage limit`. A taxonomia de causas existente lê `api_error_status` sem mudar: 429 → `rate_limited`, outro → `api_error` |
| EOF sem `turn.completed`/`turn.failed` | nada: o run morto cai no salvamento existente (`no_result_event`), que conta os `assistant` e lê o último texto. Os tokens de um run morto são desconhecidos, e a UI diz isso em vez de zero |

Exemplo, o run `02-tool-use.jsonl` normalizado:

```json
{"type":"system","subtype":"init","session_id":"01a071d5-47b0-7343-bcbd-216945ef7927","model":"gpt-5.6-sol","platform":"openai","permissionMode":"read-only","cwd":"/…/probe","tools":[]}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"I’ll inspect the directory and read the requested file."}]},"session_id":"01a071d5-…"}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"tool_use","id":"item_1","name":"Bash","input":{"command":"/bin/zsh -lc 'ls && cat a.txt'"}}]},"session_id":"01a071d5-…"}
{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"item_1","content":"a.txt\nb.txt\nalpha\n","is_error":false}]},"session_id":"01a071d5-…"}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"done"}]},"session_id":"01a071d5-…"}
{"type":"result","subtype":"success","is_error":false,"num_turns":3,"result":"done","session_id":"01a071d5-…","usage":{"input_tokens":32675,"cache_read_input_tokens":28160,"cache_creation_input_tokens":0,"output_tokens":123},"total_cost_usd":null,"cost_basis":"none","tokens":{"input":32675,"cached":28160,"cache_write":0,"output":123,"reasoning":0},"permission_denials":[],"platform":"openai"}
```

### O lançamento e o fim do run

Para `anthropic` o ramo de lançamento do `run_job` fica **exactamente** como
está, incluindo o ramo interactivo. Para `openai`:

```
mkfifo "$logfile.raw.fifo"
( cd "$run_cwd" && exec env "${run_env[@]}" "$codex" "${argv[@]}" ) \
    > "$logfile.raw.fifo" 2> "$logfile.err" < /dev/null &
child=$!                                   # o PID do CLI, como hoje
"$PYTHON" -u "$BIN_DIR/platforms/openai_stream.py" … \
    < "$logfile.raw.fifo" > "$streamfile" &
normalizer=$!
```

- `child` continua a ser o processo do CLI: `stop` (TERM ao `child`), o
  watchdog de CPU (`tree_cpu_seconds "$child"`) e o `wait "$child"` funcionam
  sem alteração. O normalizador termina no EOF do FIFO; `run_job` faz
  `wait "$normalizer"` antes de ler o `result`, para o último evento estar no
  disco. Um normalizador que sai com código ≠ 0 é registado na nota do run
  ("normalizer exited N") e o run classifica-se com o que ficou escrito.
- `bind_session` e `session_from_stream` lêem o stream normalizado: o
  `session_id` é o `thread_id`, e `.session` no run dir passa a conter um
  `thread_id` para runs OpenAI. `wt_find_by_session` não distingue.
- Depois de `wait`: `platform_stderr_filter`, depois `platform_finish` (que
  define `model_id` e alimenta o gate), depois o classificador de hoje, que lê
  `.total_cost_usd`, `.num_turns`, `.session_id`, `.permission_denials`,
  `.api_error_status` como sempre. `rl_capture "$streamfile"` fica onde está e
  é um no-op num stream OpenAI (não há `rate_limit_event`).
- **Um resume corre na plataforma do run que continua**, lida do journal
  (`record.platform`), não na plataforma actual do job. Se o job mudou de
  plataforma entretanto, o resume é recusado com essa frase: a sessão pertence
  ao outro CLI.

## Configuração

### Campos

- **Job:** `platform` ∈ {`anthropic`, `openai`}. Ausente → herda do projecto via
  `resolve` → `anthropic`. `model`, `effort` e `permission_mode` **mantêm o
  nome** e ganham vocabulário por plataforma.
- **Projecto:** `platform`, a plataforma por omissão dos seus jobs.
- **`security` do projecto:** `platform`, levada para o job derivado como o
  modelo já é.

`jobs.example.json` ganha um segundo job de exemplo, desligado, em `openai`.

### Vocabulários

| campo | anthropic | openai |
|---|---|---|
| `model` | família (`opus`…) ou id `claude-*`, como hoje; famílias resolvidas por `effective_model` | um slug do catálogo, usado verbatim; sem famílias |
| `effort` | `low` `medium` `high` `xhigh` `max`; vazio = o CLI decide | os `supported_reasoning_levels` do modelo escolhido (hoje `low`…`max`, mais `ultra` em 5.6-sol e 5.6-terra); vazio = o CLI decide |
| `permission_mode` | inalterado | `read-only`, `workspace-write`, `full-access` (mapeamento em `platform_argv`) |
| `interactive` | como hoje | inválido: o editor desliga-o e o engine recusa o run |
| `allowed_tools`, `disallowed_tools` | como hoje | `disallowed_tools` com `Agent` → `--disable multi_agent`; qualquer outro valor em qualquer dos dois é ignorado com uma linha no `tick.log` |
| `max_budget_usd` | `--max-budget-usd` | sem flag: verificado no fim do run (ver [Custos](#custos)) |
| `claude_config_dir` | como hoje | ignorado num run OpenAI |

### Validação e defaults

- `set-field platform`: aceita só os dois valores. Se o `model`, `effort` ou
  `permission_mode` **actuais** do job não forem válidos na plataforma nova,
  reescreve-os para os defaults dela (`platform_default_model`, esforço vazio,
  `platform_default_permission`) e imprime o que mudou. O editor grava
  `platform` **antes** dos outros três.
- `set-field model|effort|permission_mode`: validados contra a plataforma do
  job (`platform_*_ok`). Um slug OpenAI fora do catálogo é recusado com a lista
  dos visíveis e a sugestão `agentloop resolve-models`.
- `create`: `platform` por omissão `anthropic`; com `platform: openai` no JSON,
  o `model` e o `permission_mode` por omissão são os da plataforma.
- `security_derived_jobs`: `platform` do bloco; `model`, `effort` e
  `permission_mode` validados na derivação com o mesmo fallback-e-aviso que a
  permissão já tem.
- O servidor (`/api/action set_field`) acrescenta `platform` à lista de campos
  aceites; `project-set` deixa `platform` passar como qualquer outro campo.

### Recusas em tempo de run

Uma linha no `tick.log` e o run é saltado, o mesmo tratamento que `cwd missing`
tem hoje: plataforma desconhecida; `platform_ready` falha (binário ausente, ou
`codex` sem login); `interactive: true` em `openai`; `model` fora do catálogo.
Um slug **descontinuado** corre, com uma linha no `tick.log` a nomear o
sucessor.

### Fora desta versão: conta Codex por projecto

`CODEX_HOME` é o análogo de `CLAUDE_CONFIG_DIR` e o CLI honra-o (`--help`:
"auth still uses `$CODEX_HOME`"). Há uma conta Codex nesta instalação, por isso
não entra: nem `codex_home` no projecto, nem `AGENTLOOP_CODEX_HOME` no plist.
O sítio onde entrará é a construção de `run_env` em `run_job`, ao lado de
`CLAUDE_CONFIG_DIR`, e `platform_finish`, que hoje procura o rollout em
`${CODEX_HOME:-$HOME/.codex}/sessions`.

## Catálogo de modelos

`config/models.json` ganha um bloco `openai`, ao lado de `resolved`:

```json
{
  "resolved": { "opus": {"id": "claude-opus-5", "at": 1788585387}, "…": {} },
  "openai": {
    "at": 1788616000,
    "source": "codex debug models",
    "models": [
      {"slug": "gpt-5.6-sol", "display_name": "GPT-5.6-Sol",
       "description": "Reliable agentic workhorse for everyday tasks.",
       "default_effort": "low", "efforts": ["low","medium","high","xhigh","max","ultra"],
       "visibility": "list", "priority": 6, "deprecated_by": "", "retires_at": ""}
    ]
  }
}
```

- Escrito por `agentloop resolve-models [anthropic|openai]` — sem argumento
  faz os dois. Para `openai` corre `codex debug models` e, se falhar,
  `codex debug models --bundled` (`source: "bundled"`). Sem `codex`, o bloco
  fica `{"at": <now>, "available": false, "reason": "codex not installed"}`.
- `models_stale` considera os dois blocos; a passagem diária do tick refresca
  ambos.
- `/api/models` passa a **por plataforma**:

```json
{"platforms": {
  "anthropic": {"available": true, "models": ["claude-opus-5", "…"],
                "efforts": ["low","medium","high","xhigh","max"],
                "permissions": [{"v":"dontAsk","label":"…"}, "…"],
                "default_model": "opus"},
  "openai":    {"available": true, "reason": "", "catalog_at": 1788616000,
                "models": [{"v":"gpt-5.6-sol","label":"GPT-5.6-Sol","desc":"…",
                            "efforts":["low","medium","high","xhigh","max","ultra"],
                            "default_effort":"low","deprecated_by":"","retires_at":"",
                            "priced": true}],
                "efforts": ["low","medium","high","xhigh","max","ultra"],
                "permissions": [{"v":"read-only","label":"…"},
                                {"v":"workspace-write","label":"…"},
                                {"v":"full-access","label":"…"}],
                "default_model": "gpt-5.6-sol"}
}}
```

  O servidor lê `config/models.json`; se o bloco `openai` faltar de todo e o
  `codex` existir, chama `agentloop resolve-models openai` uma vez, em
  síncrono (0 s medido). Só os `visibility: list` vão para `models`; os
  ocultos continuam aceites pelo `set-field`. `priced` diz se
  `config/pricing.json` tem preço para o slug.
- O vocabulário de permissões passa a viver no engine e no servidor, que o
  espelha; a página lê-o de `/api/models`. Um teste pytest pinta a lista do
  servidor à do engine, como `test_the_backoff_curve_matches_the_engine` já faz
  para o backoff.

## Custos

### A tabela de preços

`config/pricing.example.json` é versionado; `install.sh` semeia
`config/pricing.json` a partir dele quando não existe, como faz com
`jobs.json`. O ficheiro real é pessoal: `.gitignore` ganha
`config/pricing.json`.

```json
{
  "_source": "https://openai.com/api/pricing/",
  "_unit": "USD per 1,000,000 tokens",
  "openai": {
    "gpt-5.6-sol":   {"input": null, "cached_input": null, "output": null, "cache_write": 0},
    "gpt-5.6-terra": {"input": null, "cached_input": null, "output": null, "cache_write": 0},
    "gpt-5.6-luna":  {"input": null, "cached_input": null, "output": null, "cache_write": 0},
    "gpt-5.5":       {"input": null, "cached_input": null, "output": null, "cache_write": 0},
    "gpt-5.4-mini":  {"input": null, "cached_input": null, "output": null, "cache_write": 0}
  }
}
```

Os valores são preenchidos na implementação a partir da página de preços da
OpenAI e **confirmados pelo operador**; nunca inventados. Um `null`, ou um slug
ausente, conta como "sem preço".

### A estimativa

Feita pelo normalizador, no `result`:

```
cost = (input − cached) × input
     + cached            × cached_input
     + cache_write       × cache_write
     + output            × output          # tudo por 1 000 000 tokens
```

`output_tokens` é tratado como **incluindo** `reasoning_output_tokens`, que é
como a API da OpenAI reporta (`output_tokens_details.reasoning_tokens` é um
subconjunto). É uma medição em falta: um run em esforço `high` onde o raciocínio
deixe de ser zero confirma `output ≥ reasoning`.

- `cost_basis`: `reported` (Anthropic, `total_cost_usd` do CLI), `estimated`
  (OpenAI com preço) ou `none` (OpenAI sem preço, ou run morto sem `usage`).
- Com `none`, `cost` é gravado como `0` e a UI mostra "—", nunca "$0.00".
- Os tectos diário e global (`daily_cap_for`, `spent_today`,
  `global_daily_cap`) somam `cost` seja qual for a base: as estimativas contam.
- **Limite honesto:** o Codex não tem `--max-budget-usd`. Em OpenAI o tecto por
  run não trava o agente a meio; é verificado no fim e produz o aviso
  "BUDGET LIMITED" de hoje quando `cost ≥ 0.9 × cap`. O editor diz "advisory on
  OpenAI" ao lado do campo.
- Os runs Anthropic passam também a gravar `tokens`, lidos do `usage` do
  `result`, para a linha de tokens do modal.

## Rate limits por plataforma

`data/rate-limits.json` passa a ter um bloco por plataforma:

```json
{
  "anthropic": {"five_hour": {"status":"allowed","utilization":0.62,"resets_at":1788617232,"overage":"rejected","seen_at":1788616210,"source":"statusline"},
                "seven_day": {"…": "…"}},
  "openai":    {"five_hour": {"status":"allowed","utilization":0.05,"resets_at":1788617232,"overage":null,"seen_at":1788616214,"source":"rollout","plan_type":"plus"},
                "seven_day": {"…": "…"}}
}
```

- **Migração:** um ficheiro com `five_hour`/`seven_day` no topo é lido como
  `anthropic` na primeira leitura e reescrito nesta forma.
- **Escritores:** `rl_capture` (stream Claude) e `bin/statusline-rate-limits.sh`
  escrevem em `anthropic`. `rl_capture_openai <rollout>` escreve em `openai`:
  `primary` (300 min) → `five_hour`, `secondary` (10080 min) → `seven_day`,
  `utilization = used_percent / 100`, `resets_at`, `source: "rollout"`,
  `plan_type`, e `status` = `allowed` salvo quando `rate_limit_reached_type`
  vem preenchido, caso em que `status` é esse valor. Como o Codex reporta em
  todos os turnos, cada run OpenAI alimenta o gate; não há statusline OpenAI.
- **Leitores:** `rl_gate <platform>`; `run_job` passa a plataforma do job.
  `fleet_stall_reason`, `cmd_usage` e a razão gravada em `last_rate_limit`
  nomeiam a plataforma e a janela ("the openai five_hour window is 96% used").
- Quota esgotada a meio (a fixture de Agosto): `turn.failed` →
  `api_error_status: 429` → causa `rate_limited`, fora do backoff; e
  `platform_finish` grava a janela como recusada até ao `resets_at` do rollout.

## Journal, base de dados, servidor e hooks

- `record_run` ganha `platform`, `cost_basis` e `tokens`; cada linha de
  `runs.ndjson` leva-os. `state.last_cost` inalterado.
- `index.db`: colunas aditivas `platform TEXT`, `cost_basis TEXT`,
  `tokens TEXT` (JSON), na lista `canon` de `ingest`; `SCHEMA_VERSION` sobe
  para forçar o resync. Backfill do histórico: `platform = "anthropic"`,
  `cost_basis = "reported"`, `tokens` do `result_json.usage` quando existe.
- `/api/data`: cada run leva `platform` e `cost_basis`. `/api/config`: os jobs
  já levam `platform` por serem `jobs.json` passado ao vivo.
- `load_run_detail` e `load_live_detail`: `record.platform`,
  `agent.cost_basis`, `agent.tokens`; `_model_id_from_stream` continua a ler
  `init.model` (o pedido) como fallback do que o engine gravou (o real).
- `parse_turns_text` e `parse_conversation` não mudam: o `tool_use` com
  `input.command` já é o que `_tool_line` procura, e um `user` só com
  `tool_result` é saltado como hoje.
- Hooks: `on-run-end.sh` recebe `AL_PLATFORM`, `AL_COST_BASIS` e `AL_TOKENS`
  (JSON), além dos de hoje.

## UI

### Editor de jobs (`bin/dashboard.html`, `ui/app/editor-domain.js`)

No painel *Agent*, um combo **Platform** (`ed-platform`: Anthropic · OpenAI)
antes do Model. Escolher a plataforma:

1. repovoa `ed-model` a partir de `/api/models.platforms[p]`: Anthropic
   agrupado por família e geração como hoje (`groupModels`); OpenAI plano, na
   ordem do catálogo, com "GPT-5.6-Sol — Reliable agentic workhorse…", e um
   slug descontinuado no fim com "→ gpt-5.6-luna, retires 2026-08-31";
2. reconstrói as paragens do slider de esforço: `EFFORTS` em
   `editor-domain.js` deixa de ser constante e passa a `effortsFor(platform,
   model)`, alimentada só pelo servidor; em OpenAI reconstrói-se outra vez
   quando o modelo muda. `effortIndex`/`effortFromIndex` recebem a lista.
   O teste "a página não tem vocabulário de esforço próprio" continua a valer;
3. troca o vocabulário do Permission mode (`PERMS` deixa de ser constante da
   página e vem de `/api/models`), com o mapeamento na label de cada opção;
4. em OpenAI desliga e desmarca *Interactive*, com "Codex exec has no stdin
   protocol; runs on OpenAI end by themselves" como ajuda.

No painel *Limits*, em OpenAI: uma nota "cost is estimated from tokens with
config/pricing.json; the per-run cap is advisory on OpenAI"; se o modelo não
tiver preço, "no price configured for <slug> — dollar caps will not see this
job's spend". Ao criar: `platform` = a do projecto escolhido, senão Anthropic;
`model` = `default_model` da plataforma. `readForm` inclui `platform` e o
`saveEditor` grava-o primeiro. O `sec-model` deixa de aceitar texto livre em
OpenAI: o catálogo é a autoridade.

### Editor de projectos

Um combo Platform (`pj-platform`, com "— inherit (Anthropic) —" como vazio) no
painel do projecto. No painel *Security*, `sec-platform` antes do Model, e os
controlos de modelo, esforço e permissão seguem o mesmo comportamento por
plataforma que já partilham com o editor de jobs.

### Cartões, tabelas, modal, Overview, Security

- Cartão de job: a plataforma inked antes do modelo ("OpenAI · gpt-5.6-sol"),
  marcada como própria (`own`) quando o job sobrepõe a do projecto.
- Tabela de jobs: badge monocromático da plataforma junto ao modelo.
- Tabela de runs: o mesmo badge na célula do modelo. Custo: reportado "$1.23";
  estimado "~$1.23" com tooltip "estimated from 32,798 tokens with
  config/pricing.json"; sem preço "—" com tooltip "OpenAI reported tokens but
  no price is configured for gpt-5.6-sol"; run morto sem `usage` "—" com
  "tokens unknown: the run ended without a final event".
- Modal do run: linha Platform; Model mostra "pedido → real"; linha Tokens
  (input · cached · output · reasoning) para qualquer run com `tokens`; Cost
  com a base.
- Overview: "Spent today" inclui estimativas; o sublabel diz "includes ~$X
  estimated" quando houve alguma.
- Security: plataforma e modelo no cabeçalho da análise e na tabela de runs do
  projecto.
- `ui/app/*.js` muda → `build/build-ui.sh` → `bin/static/` recommitado.

## Análises de segurança em OpenAI

- `security.platform` vai para o job derivado (`security_derived_jobs`), com
  `model`, `effort` e `permission_mode` validados na derivação; a análise nasce
  em `full-access`, que é o `bypassPermissions` de hoje, com a mesma contenção:
  worktree descartável, a porta validada do ledger (`security_py`), e
  `AL_SECURITY_AGENT` a fechar os verbos de autoridade humana.
- `security_prompt` ganha a plataforma como argumento. O parágrafo "You have no
  `Agent` tool in this run -- the CLI's own tool roster calls it `Task`" é
  Anthropic; em OpenAI passa a "Subagents are switched off for this run
  (`--disable multi_agent`)", com a mesma ordem de fazer a triagem na própria
  sessão. O resto do prompt é shell e não muda.
- `disallowed_tools: Agent` fica no job derivado; `platform_argv openai`
  traduz-o.
- `cmd_skills install` linka `skills/*` também para `~/.codex/skills/<nome>`
  quando `~/.codex` existe; `cmd_skills` (status) reporta os dois destinos. O
  Codex lista as skills ao modelo com o locator do ficheiro (visto no rollout),
  por isso "Invoke the `security-analysis` skill" resolve.
- A causa `tools_denied` nunca dispara em OpenAI; `security_close_analysis` e o
  resto do fecho não mudam.
- **Aceitação:** uma análise real em OpenAI sobre um repositório pequeno, lida
  de ponta a ponta no ledger: `prepare` correu, `checklist` foi consultado,
  findings re-reportados com fingerprints copiados, `finish` chamado, estado
  `done` ou `capped` com razão.

## Skills, instalação e estado

- `install.sh`: `codex` é dependência **opcional** — "✓ codex (codex-cli
  0.148.0, logged in)" ou "– codex not found: jobs on the OpenAI platform are
  refused until it is installed and signed in". Semeia `config/pricing.json`.
- `agentloop status` ganha um bloco *platforms*: versão e conta do `claude`;
  versão, login e idade do catálogo do `codex`; quantos jobs OpenAI não têm
  preço para o seu modelo.
- `agentloop resolve-models [platform]` e `_resolve_models` no tick refrescam
  as duas plataformas.
- `AGENTLOOP_CODEX_BIN` como override; o PATH do plist já inclui
  `/opt/homebrew/bin`.
- README: uma secção *Platforms* (escolher, vocabulários, o que cada uma não
  suporta, custo estimado e a tabela de preços, rate limits), e as secções
  *Models*, *Effort*, *Budgets*, *Security block* e *CLI* actualizadas.

## Erros

| Situação | O que acontece |
|---|---|
| `codex` ausente ou sem login | run recusado antes de gastar um turno, razão no `tick.log`; `install`/`status` dizem-no; o editor mostra-o ao escolher OpenAI |
| catálogo indisponível | `--bundled`; se falhar, `available: false` com razão em `/api/models` e no editor |
| slug fora do catálogo no lançamento | recusado, nomeando o slug e `resolve-models` |
| slug descontinuado | corre; `tick.log` nomeia o sucessor; o editor mostra-o |
| rollout não encontrado depois do run | `model_id` fica o pedido; sem leitura de rate limit; uma linha no `tick.log` |
| normalizador termina com erro | o CLI morre com SIGPIPE, o run cai no salvamento, a nota diz "normalizer exited N" |
| linha malformada no JSONL | copiada para `.raw`, ignorada |
| stderr além da linha conhecida | fica, e o run é `warning` como hoje |
| sem preço para o modelo | sem aviso por run; "—" com tooltip na tabela; nota no editor; contagem em `status` |
| `interactive: true` em OpenAI | o editor impede; o engine recusa o run |
| `say` a um run OpenAI | "this run is not interactive", a frase de hoje |
| stop | TERM ao CLI; EOF no normalizador; sem `result`; o marcador `stopped` do slot decide, como hoje |
| resume de um run cuja plataforma difere da actual do job | recusado: "this session belongs to <platform>; the job now runs on <other>" |
| quota esgotada a meio do run | `rate_limited`, fora do backoff; janela marcada recusada até ao reset |

## Fora desta versão

- Conta Codex por projecto ou por instalação (`CODEX_HOME`).
- Interactivo em OpenAI (não há protocolo de stdin em `codex exec`).
- Allow/deny de ferramentas em OpenAI além de `Agent`.
- Tecto por run que trave a meio em OpenAI; tectos em tokens.
- Aliases de família para OpenAI: o selector tem slugs exactos, como decidido
  em Julho para o Claude.
- Service tier `fast`, imagens (`-i`) e `--output-schema` do Codex.
- Outras plataformas. A tabela deixa cada uma a uma entrada de distância.

## Testes

- **Normalizador** (`tests/test_openai_stream.py`): sobre as fixtures em
  `test/fixtures/codex/` (as nove medições de 2026-09-05 mais a quota de
  Agosto): a primeira linha tem `session_id`; o último evento é `result` quando
  o turno acabou; `parse_turns_text` do servidor desenha o `Bash` com o comando;
  `_salvage_from_stream` sobre uma cópia truncada; a fixture de modelo
  desconhecido dá `api_error_status: 400`; a de quota dá 429; a estimativa
  com preço, sem preço e com `null`; uma linha malformada é saltada e copiada;
  um item de tipo desconhecido vira `tool_use` genérico.
- **Selftest**: `platform_argv` para os dois modos e para um resume, lido do
  argv que `test/fake-codex` grava (`FAKE_ARGV_OUT`), incluindo `</dev/null`,
  `--disable multi_agent` e o mapeamento das três permissões; `platform_caps`;
  `set-field` por plataforma, incluindo a reescrita ao mudar de plataforma;
  `create` com `openai`; recusas em tempo de run; a recusa do resume com
  plataforma diferente; `rl_capture_openai` sobre a fixture do rollout e a
  migração do ficheiro antigo; `rl_gate` por plataforma; o filtro de stderr
  apaga só a linha exacta; `turn_is_over` sobre um stream OpenAI normalizado;
  `security_derived_jobs` com `security.platform`; `cmd_skills` com os dois
  destinos.
- **pytest do servidor**: forma de `/api/models`; a lista de permissões do
  servidor igual à do engine; `set_field platform`; migração da base de dados
  (colunas, backfill); `/api/data` com `platform` e `cost_basis`; detalhe com
  `tokens`; contrato da página: os elementos novos existem, `EFFORTS` vem do
  servidor, o tooltip do custo por base, o badge da plataforma, o editor grava
  `platform` primeiro, *Interactive* desligado em OpenAI.
- **e2e** (`test/e2e.test.sh` com `test/fake-codex`, um stand-in que emite as
  formas medidas, guiado por `FAKE_MODE` complete · undeclared · dirty · hang ·
  quota e `FAKE_SESSION` como thread id): run OpenAI completo, undeclared e
  dirty; resume com o mesmo thread id e reattach da worktree; stop; quota →
  `rate_limited` com `fail_streak` intacto; análise de segurança em OpenAI de
  ponta a ponta.
- **Aceitação, com o CLI real:** um job OpenAI num repositório de rascunho, e a
  análise de segurança descrita acima. Lidos, não só verdes.

## Medições em falta, primeira tarefa do plano

Cada uma é um run pequeno, guardado como fixture ao lado das outras:

1. `codex exec resume` com o processo noutro cwd: opera no cwd actual ou no
   guardado na sessão? E `-c sandbox_mode="workspace-write"` num resume é
   aceite em `--strict-config`?
2. `--` antes do prompt em `codex exec` e em `exec resume`.
3. `-c model_reasoning_effort="ultra"` num modelo que o suporta.
4. Um run em `high`: `reasoning_output_tokens` > 0 e `output_tokens ≥ reasoning`.
5. Um run em `workspace-write` que edita um ficheiro: a forma de `file_change`.
   Se for barato, `web_search` e `mcp_tool_call`.
6. `--disable multi_agent` remove mesmo as ferramentas de subagente: pedir ao
   agente para listar as suas ferramentas, com e sem a flag.
7. Os preços por modelo, da página da OpenAI, confirmados pelo operador.
8. O código de saída de `codex login status` **sem** login não é medível sem
   fazer logout da conta em uso, e não se faz. `platform_ready` trata qualquer
   rc ≠ 0 como "sem login"; se o CLI devolver 0 mesmo sem login, o run falha
   no primeiro turno com causa `api_error`, que é o que acontece hoje com o
   Claude e continua a ser uma linha honesta no `tick.log`.

## Ordem de implementação, para o plano

1. Medições em falta; fixtures para `test/fixtures/codex/`; entrada no
   CHANGELOG.
2. Normalizador e os seus testes.
3. Tabela de plataformas, lançamento por FIFO, `platform_finish`, filtro de
   stderr; `test/fake-codex` e os cenários e2e de run, resume e stop.
4. Esquema de configuração: `set-field`, `create`, `resolve`, validações,
   recusas; casos de selftest.
5. Catálogo: `resolve-models`, `models.json`, `/api/models`.
6. Journal, base de dados, `/api/data`, detalhe, hooks.
7. Tabela de preços e estimativa; tectos.
8. Rate limits por plataforma; `usage`; stall.
9. UI: editores, cartões, tabelas, modal, Overview; contrato da página; build.
10. Segurança em OpenAI: prompt, job derivado, skills; cenário e2e.
11. `install.sh`, `status`, README, CHANGELOG.
12. Aceitação com o CLI real.
