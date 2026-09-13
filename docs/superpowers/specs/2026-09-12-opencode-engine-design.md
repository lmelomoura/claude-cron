# O motor OpenCode: desenho

> Entrega 2 das plataformas. Depende da 1
> ([`2026-09-11-platform-settings-design.md`](2026-09-11-platform-settings-design.md)),
> que deixou o OpenCode *planned*: cartão, binário e versão, e um job que o
> nomeie recusado no lançamento. Este documento fá-lo correr.
>
> Estado: desenho decidido a 2026-09-12 (o operador delegou as escolhas com o
> critério "o mais seguro, o mais profissional, o mais à prova de falhas, e o
> mais próximo do que o Claude e o Codex já entregam"); por implementar.
> Evidência: [`2026-09-12-opencode-measurements/`](2026-09-12-opencode-measurements/README.md).
> Onde este texto e a evidência divergirem, a evidência manda.

---

## Contexto

O agentloop lança um agente headless por job, lê o stream de eventos que o CLI
emite e decide tudo a partir dele: quando o run acabou, que sessão é, quanto
custou, porque falhou, o que mostrar na dashboard. Hoje corre o Claude Code
(`stream-json`, o dialecto canónico) e o Codex CLI (traduzido na fronteira por
`bin/platforms/openai_stream.py`). Este desenho acrescenta o OpenCode pela
mesma regra: traduzir o JSON na fronteira, nunca inferir por terminal, nunca
desenhar sobre um evento que não foi visto. Nenhum leitor aprende um terceiro
dialecto.

O OpenCode é diferente dos outros dois num ponto que atravessa o desenho todo:
não é um CLI de uma conta, é um CLI de **providers**. Os modelos chamam-se
`provider/model`, cada provider tem a sua credencial (ou nenhuma: os modelos
`opencode/*-free` correm sem conta), o preço vem do catálogo do próprio CLI, e
não há janelas de utilização, sandbox do SO nem protocolo de stdin.

### O que ficou medido a 2026-09-12 (opencode-ai 1.18.30)

| Facto | Consequência para o desenho |
|---|---|
| headless: `opencode run --format json --pure --auto -m provider/model [--variant v] --dir d [-s id] [--title t] -- PROMPT`, **sempre com `</dev/null`**: com stdin aberto o CLI lê-o até ao EOF antes de arrancar e fica pendurado sem um byte (13a); texto no stdin é anexado ao prompt (13b); `--` antes do prompt é aceite (33) | a linha de lançamento; o prompt vai no argv, como nas outras duas plataformas |
| eventos, um por linha, todos com `sessionID`: `step_start`, `text`, `tool_use` (sai **uma vez, já concluído**, com `state{status, input, output, error}`), `step_finish{reason, tokens{input, output, reasoning, cache{read, write}}, cost}`, `error{name, data}`; sem modelo no stream; stderr vazio num run são (01, 02, 03) | o normalizador tem o que precisa; o modelo que correu vem do `export` |
| um passo por chamada ao modelo: `step_finish.reason` é `tool-calls` entre ferramentas e `stop` no último; tokens e custo são **por passo**; o fim do run é o fim do processo, exit 0 (02, 05) | o `result` sai no `stop`; o run somado é a soma dos passos |
| o primeiro byte só sai quando o modelo começa a responder; um provider lento leva dezenas de segundos sem output (21, 21b), e um provider que aceita a ligação e nunca responde deixa o CLI pendurado **sem timeout, sem erro e sem um byte** (34b) | o watchdog de stall do motor é a única defesa; ver a linha seguinte |
| **um run pendurado não está parado para o `ps`**: o processo pendurado do 08c, sem um byte de output e sem filhos, soma ~1 s de CPU a cada 75 s (35). O watchdog de hoje dá um run por vivo sempre que o inteiro de CPU da árvore muda entre dois polls de 30 s, por isso esse ralenti mantém-no vivo para sempre, e `timeout_seconds` não tem omissão | o watchdog ganha uma regra estreita: um stream **ainda vazio** ao fim de `stall_timeout_seconds` é um run morto, diga o CPU o que disser; um chão de CPU foi ponderado e rejeitado (mataria `docker build`, `trivy` a puxar políticas, um `clone` numa ligação má: trabalho cujo CPU vive fora da árvore do run) |
| `-s <id>` retoma a mesma sessão, com o mesmo id em todos os eventos, **só com `--dir` no directório em que ela nasceu**; noutro directório o CLI corre o turno numa segunda instância que o `run` não ouve, gasta-o, e pendura-se para sempre (08, 08b, 08c, 08d) | um resume leva `--dir` = o directório retido do run; o motor já recusa resumir sem ele |
| SIGTERM: sai em 1 s com exit 143, a ferramenta em curso morre com ele, nada fica órfão; a sessão sobrevive e retoma (12, 12b) | `stop` e o watchdog funcionam como hoje |
| permissões vivem na configuração, por ferramenta e por padrão de `bash` (`{"bash": {"*": "allow", "git push*": "deny"}}`), entregues por `OPENCODE_CONFIG_CONTENT`; `--auto` aprova o que é `ask` (04, 05, 06, 23) | o vocabulário de `permission_mode` é um bloco gerado pelo motor; `allowed_tools`/`disallowed_tools` traduzem-se para ele |
| `ask` sem `--auto` é **auto-rejeitado** (stderr `! permission requested: …; auto-rejecting`), o `tool_use` sai com `state.status: "error"` e `"The user rejected permission to use this specific tool call."`, e o turno **acaba aí** sem texto final (04, 18) | nunca lançar sem `--auto`; a frase vira `permission_denials` |
| `deny` numa ferramenta tira-a do roster (o modelo recebe `tool: "invalid"` com a lista do que resta); `deny` por padrão falha a chamada com `"The user has specified a rule which prevents you from using this specific tool call. …"` e o turno **continua**; `task: deny` fecha os subagentes (06, 22, 23) | o Codex não tinha nada disto: as capacidades `tool_lists` e `denials` existem aqui |
| por omissão em `run` (agente `build`, `opencode agent list`): `*: allow`, `doom_loop: ask`, `external_directory: ask` (só para as ferramentas de ficheiro), `read *.env: ask`, `question`/`plan_enter`/`plan_exit: deny` (32, 14) | com `--auto`, tudo o que é `ask` passa; o agente nunca fica à espera de uma pergunta |
| **não há sandbox do SO**: `bash` escreve fora do directório e faz `git commit` num worktree (cujo `.git` real fica fora) sem `--auto` e sem perguntar (19, 20); o agente `plan` embutido não é read-only (nega `edit`, mantém `bash`; o que o trava é o prompt) (31, 32) | o isolamento é a worktree, como no Claude; um `read-only` a sério é `edit`, `write`, `bash` e `task` a `deny` |
| tokens: `total = input + output + reasoning + cache.read + cache.write`, `input` **sem** a cache, `reasoning` separado do `output` (11, 24b) | o `result` soma-os por nome; `usage.output_tokens` = output + reasoning |
| custo: o CLI calcula-o do preço do catálogo, `(input×in + (output+reasoning)×out + cache.read×cr + cache.write×cw) / 10⁶`, e reporta-o por passo; confirmado com preço por configuração (24b, 24c) e num provider pago real (34: `0.000426176016`); com preço 0 no catálogo (Zen gratuito, provider custom sem `cost`) vem `0`, **indistinguível de "sem preço"** | preço no catálogo → `reported`; zero → desconhecido, nunca "grátis" |
| `--variant` é o esforço; os valores válidos são as chaves de `variants` de cada modelo no catálogo; **um valor inválido é aceite em silêncio** (11, 11b) | validação nossa, por modelo |
| `--pure` desliga os plugins do operador (um deles reescreveu `ls` para `rtk ls`; outro somou ~3k tokens por passo) e **não tira as skills**: o agente vê `~/.claude/skills/` e `.opencode/skills/` do run (02, 03, 26, 27) | `--pure` sempre; `agentloop skills` já linka para onde o OpenCode lê |
| `--title` evita a chamada a um modelo pequeno que gera o título de cada sessão nova (30; no 16 essa chamada foi a `gpt-5.4-nano`) | `--title` sempre num run novo |
| `--print-logs --log-level ERROR` não escreve nada num run são e é o único sítio onde a razão de um `error{name: "UnknownError"}` aparece (09, 09b, 30) | sempre; o `.err` de um run falhado diz porquê |
| modelo ou provider desconhecido: exit 1, um `error{name: "UnknownError", data{message genérica, ref}}` (09, 10); chave inválida: exit 1, `error{name: "APIError", data{statusCode: 401, isRetryable, …}}` (16); um erro transitório do provider é repetido pelo CLI e o run acaba bem (24c) | `api_error_status` = `statusCode` quando existe |
| `opencode export <id>` (do directório da sessão): `info.model{id, providerID, variant}`, `info.directory`, `info.version`, `info.cost`, `info.tokens`, `info.permission`, mensagens com `modelID`/`providerID`/`cost`/`tokens`/`finish` (14) | `platform_finish` lê daqui o modelo que correu |
| `opencode models --verbose`: por modelo `cost{input, output, cache{read, write}}` por milhão, `limit{context, output}`, `capabilities{toolcall, reasoning, …}`, `variants`, `status`; um id pode ter barra dentro (`pdm_ai/openai/gpt-oss-120b`) (`models-verbose-after-provider-change.txt`) | o catálogo; `provider/model` divide-se na **primeira** barra |
| `opencode auth list` imprime uma caixa com cores ANSI e `N credentials`; não é a lista dos providers utilizáveis, que é o catálogo (`auth-list.txt`) | a prontidão lê-se do catálogo |
| `OPENCODE_CONFIG_DIR` é uma camada a mais sobre `~/.config/opencode` e `~/.opencode`, não uma substituição; `XDG_CONFIG_HOME` e `XDG_DATA_HOME` isolam configuração e conta de facto (15a–15d) | isolamento por job fica fora desta versão, e quando entrar entra para as três plataformas |
| `share: "disabled"` em `OPENCODE_CONFIG_CONTENT` é aceite (33) | vai sempre no bloco: nenhuma sessão vai parar a um link público por configuração do operador |
| `--dir` inexistente: exit 1 em 0 s, `Error: Failed to change directory to …`, sem chamada ao modelo (29) | a recusa de `cwd missing` continua a ser do motor, antes do lançamento |
| não medido: quota/429 (a forma do 16 diz que chegaria como `APIError` com `statusCode: 429`); outros valores de `step_finish.reason`; `doom_loop` | o desenho trata cada um como inferência da forma, com o comportamento mais conservador. (A precedência entre `OPENCODE_CONFIG_CONTENT` e um `opencode.json` do repositório, listada aqui como não medida na primeira versão, foi medida depois da aceitação: 37b, o bloco do ambiente ganha; e 37a mediu o bloco em forma de allowlist sob `--auto`.) |

## Objectivo e âmbito

Um job, um projecto e o bloco `security` de um projecto passam a poder correr
na plataforma `opencode`, com os modelos que o operador tiver configurado nesse
CLI, e tudo o que o scheduler faz para as outras duas plataformas funciona
nesta: a dashboard, o journal, os tectos de custo, o resume de uma sessão
cortada, as análises de segurança. Nenhum job existente muda de
comportamento.

Decisões tomadas, com o critério do operador:

- **Permissões honestas.** Dois modos que dizem o que o CLI impõe:
  `full-access` (omissão) e `read-only`. Nunca sem `--auto`. As listas de
  ferramentas dos jobs passam a funcionar nesta plataforma.
- **Custo verdadeiro.** O número do CLI quando o catálogo tem preço; a tabela
  de preços do operador quando não tem; e "desconhecido", nunca zero, no
  resto.
- **Sem invenções.** Nada de timeouts, cool-downs ou modos que a evidência não
  sustente: o watchdog de stall que já existe, a isenção de backoff que já
  existe, a recusa de resume que já existe.

## Arquitectura

### A tabela de plataformas, em `bin/agentloop`

`PLATFORMS` passa a `"anthropic openai opencode"`; `PLATFORMS_PLANNED` fica
vazio e `platform_planned` responde 1 a tudo: o mecanismo fica para a
plataforma seguinte. `platform_known` inclui `opencode`, e com isso
`job_platform`, `set-field`, `create`, `resolve` e o servidor
(`PLATFORM_PERMISSIONS`, `PLATFORMS_PLANNED`) passam a tratá-lo como as outras.
Um ramo `opencode` em cada função da tabela:

| Função | opencode |
|---|---|
| `platform_bin` / `platform_bin_env` / `platform_cli_name` / `platform_install_hint` | como hoje (`OPENCODE_BIN`, `AGENTLOOP_OPENCODE_BIN`, `opencode`, `brew install opencode`) |
| `platform_check` | binário → `--version` → `opencode models --pure` (limitado a 30 s): `ready` com pelo menos um modelo; `account` = "`N` credentials · providers: `a, b`" (`N` lido de `auth list` sem as cores ANSI, os providers são os prefixos do catálogo); sem modelos, `reason` = "no usable provider: run `opencode auth login`, or configure one in ~/.config/opencode/opencode.json" |
| `platform_ready` | o `ready`/`reason` de `platform_check`, como as outras |
| `platform_caps` | `tool_lists` sim, `denials` sim, `cost_reported` sim; `interactive`, `budget_flag`, `stream_rate_limits`, `families` não. Capacidade nova para as três: **`prepare_inline`**, só Anthropic: a plataforma cujo agente corre `security prepare` ele próprio; nas outras o motor corre-o antes do lançamento |
| `platform_permissions` | `full-access`, `read-only` |
| `platform_permission_ok` | um dos dois |
| `platform_default_permission` | `full-access` para job e para segurança |
| `platform_efforts <model>` | as chaves de `variants` do modelo no catálogo, na ordem do catálogo; nada para um modelo sem `variants` |
| `platform_effort_ok <model> <effort>` | `""` sempre; senão tem de estar em `platform_efforts` (o CLI não valida: 11b) |
| `platform_model_ok <model>` | o id está no catálogo, `active` ou não |
| `platform_catalog_ids` | os ids `status: active`, na ordem do catálogo |
| `platform_models_json` | o catálogo com `enabled` por modelo, mais `priced`, `price`, `tools`, `variants`, `context` |
| `platform_default_model` | o primeiro activado nos Settings, como as outras |
| `platform_stderr_filter` | no-op, por decisão: com `--print-logs --log-level ERROR` um run que não precisou de repetir nenhum pedido não escreve nada (01–03, 11, 30, 34), e um que precisou escreve a linha do erro repetido (24c) e fica `warning`, que é o que se quer de um run que correu bem mas teve o provider a falhar a meio: uma negação auto-rejeitada, um erro repetido e a razão de um `UnknownError` são todos reais, e nenhum é a linha fixa de ruído que o Codex tinha |
| `platform_argv_opencode` | a linha abaixo |
| `platform_finish` | `cd <run_cwd> && opencode export <sid>` (limitado a 30 s) → `PF_MODEL_ID` = `info.model.providerID + "/" + info.model.id`; sem export (falhou, expirou, sessão sem directório), `model_id` fica o pedido e o `tick.log` di-lo. Nada de rate limits |
| `platform_normalizer` (nova) | o caminho do normalizador da plataforma, ou nada: `bin/platforms/openai_stream.py`, `bin/platforms/opencode_stream.py`; é isto que o `run_job` passa a perguntar em vez de `[ "$platform" = "openai" ]` |
| `resolve_models_opencode` | ver [Catálogo](#catálogo-de-modelos) |

`platform_argv_opencode <resume-sid> <run_cwd> <model> <effort> <prompt> <title>`
monta, em `PLATFORM_ARGV`:

```
run --format json --pure --auto --print-logs --log-level ERROR
    -m <provider/model>
    [--variant <effort>]            # só quando validado contra o catálogo
    --dir <run_cwd>                 # sempre, num run novo e num resume
    [--title "agentloop <job> <stamp>"]   # só num run novo
    [-s <session id>]               # resume
    -- <prompt>
```

Cada flag tem medição: `--format json` (01), `--pure` (03, 26), `--auto` (05),
`--print-logs --log-level ERROR` (09b, 30), `--variant` (11), `--dir` (07,
08b), `--title` (30), `-s` (08b, 12b), `--` (33). O processo faz `cd
"$run_cwd"` antes de lançar, como o ramo OpenAI, e o stdin é `</dev/null`
(13a).

A permissão não vai no argv: vai no ambiente do processo, em
`OPENCODE_CONFIG_CONTENT`, construída por `opencode_config_content
<permission> <allowed_tools> <disallowed_tools>`:

```json
{"share": "disabled",
 "permission": {"edit": "deny", "write": "deny", "bash": "deny", "task": "deny"}}
```

- `full-access`: só o que as listas do job acrescentarem (abaixo). O `--auto`
  já aprova o que é `ask` por omissão: `external_directory` (um projecto
  multi-repo edita repositórios irmãos no directório do run), `read *.env`,
  `doom_loop`. O nome diz o que é: sem sandbox do SO, nada impede o `bash`
  de escrever fora do directório (20), e um `deny` em `external_directory`
  só travaria as ferramentas de ficheiro, que o agente contornaria pela
  shell; o isolamento de um run é a worktree, como no Claude.
- `read-only`: os quatro `deny` acima, mais as listas do job. Fica `read`,
  `glob`, `grep`, `list`, `webfetch`, `websearch`, `skill`, `todowrite`.
- `share: "disabled"` sempre (33).

### As listas de ferramentas (capacidade `tool_lists`)

`allowed_tools` e `disallowed_tools` mantêm a forma do Claude e são
traduzidos por uma tabela fixa; um nome fora dela é ignorado com uma linha no
`tick.log` que o nomeia:

| Claude | OpenCode |
|---|---|
| `Bash` | `bash` |
| `Edit`, `MultiEdit` | `edit` |
| `Write` | `write` |
| `Read` | `read` |
| `Glob` | `glob` |
| `Grep` | `grep` |
| `LS` | `list` |
| `WebFetch` | `webfetch` |
| `WebSearch` | `websearch` |
| `Agent`, `Task` | `task` |
| `TodoWrite` | `todowrite` |
| `Skill` | `skill` |

- `disallowed_tools`: cada nome vira `<tool>: "deny"`. `Bash(<padrão>)` vira
  um padrão em `bash` (`{"*": "allow", "<padrão>": "deny"}`), com o `*` do
  Claude mantido (o OpenCode usa a mesma sintaxe de glob nos padrões: 23). A
  forma de prefixo do Claude Code, `Bash(cmd:*)`, não é um glob (para o
  OpenCode o `:*` só casaria com dois pontos literais): traduz-se para o glob
  `cmd*`, que casa o mesmo conjunto que o prefixo, com uma linha no
  `tick.log` a dizê-lo. Um
  padrão noutra ferramenta (`Edit(*.md)`) **alarga-se à ferramenta inteira**:
  numa denylist, fechar mais do que foi pedido é o lado seguro.
- `allowed_tools`: `"*": "deny"` e depois `<tool>: "allow"` por nome;
  `Bash(<padrão>)` vira `bash: {"*": "deny", "<padrão>": "allow"}` (37a: a
  allowlist funciona sob `--auto` como as regras de deny medidas em 23; a
  mesma tradução do prefixo `cmd:*`); em `read-only` uma entrada `Bash(...)`
  é **descartada**, com a linha no `tick.log`: por padrão reabriria uma shell
  inteira sem sandbox por trás (19, 20; `Bash(*)` substituía o próprio deny),
  e a palavra do modo é que o bash fica fechado; um padrão
  noutra ferramenta é **ignorado** (a ferramenta fica fechada), porque numa
  allowlist alargar seria abrir mais do que foi pedido. A linha no `tick.log`
  diz qual.
- Os dois juntos: **deny ganha** para qualquer ferramenta nomeada nos dois,
  como no Claude.
- Uma negação por regra durante o run é um evento (23) e conta como
  `permission_denials`: o run é `error` com a causa `tools_denied`, exactamente
  o que um `--disallowedTools` atingido faz no Claude.

### O normalizador, `bin/platforms/opencode_stream.py`

Python 3, só stdlib, **puro**: lê o JSON do OpenCode no stdin, escreve
`stream-json` canónico no stdout, uma linha por evento, sem buffer (`-u` e
`flush` por linha). Copia cada linha crua para `--raw-out` antes de fazer o
que quer que seja com ela; uma linha que não é JSON é copiada e ignorada. É o
irmão de `openai_stream.py` e resolve os mesmos problemas com a mesma forma.

```
python3 -u bin/platforms/opencode_stream.py \
  --model <provider/model> --permission <mode> --cwd <run_cwd> \
  --catalog config/models.json --pricing config/pricing.json \
  --raw-out <streamfile>.raw < <fifo> > <streamfile>
```

Conhece duas coisas além do stream: o catálogo (para saber se o modelo tem
preço) e a tabela de preços (para estimar quando não tem).

| OpenCode | canónico |
|---|---|
| o **primeiro** evento com `sessionID`, seja qual for | `{"type":"system","subtype":"init","session_id":<sessionID>,"model":<pedido>,"platform":"opencode","permissionMode":<mode>,"cwd":<cwd>,"tools":[]}` **antes** de traduzir esse evento: `session_from_stream` lê só as cinco primeiras linhas |
| `step_start` | nada |
| `text{part.text}` | `assistant` com `{"type":"text","text":…}`; o último texto é o `result.result`. Medido: um `text` por parte, com o texto inteiro |
| `tool_use{part}` | dois eventos de uma vez, porque o CLI só o emite concluído: `assistant` com `{"type":"tool_use","id":<callID>,"name":<nome>,"input":<state.input>}` e `user` com `{"type":"tool_result","tool_use_id":<callID>,"content":<state.output, cortado a 8 KB, ou state.error>,"is_error":<state.status == "error">}`. O nome é o do Claude pela tabela acima invertida (`bash` → `Bash`, com `input.command` intacto, que é o que `_tool_line` desenha; `task` → `Task`); um nome fora da tabela fica como está (`invalid`, um MCP) |
| `tool_use` com `state.status: "error"` e `state.error` a começar por `The user rejected permission` ou `The user has specified a rule which prevents` (04, 23) | além dos dois eventos, uma entrada em `permission_denials`: `{"tool_name":<nome>,"tool_use_id":<callID>,"tool_input":<input>}` |
| `step_finish{tokens, cost, reason}` | soma `tokens.input`, `.output`, `.reasoning`, `.cache.read`, `.cache.write` e `cost`; `reason: "tool-calls"` → continua; `reason: "stop"` → o `result` de sucesso; qualquer outro `reason` (não medido: `length`, `error`, …) → `result` de erro com `"the model stopped: <reason>"` |
| `error{error{name, data}}` | `result` de erro: `result` = `data.message` (com `ref` quando existe), `api_error_status` = `data.statusCode` quando é inteiro (16: 401; um 429 chegaria assim), senão `null`. A taxonomia de causas existente lê-o sem mudar: 429 → `rate_limited`, outro → `api_error`, nenhum → `agent_error` (o `.err` tem a razão: `--print-logs`) |
| EOF sem `result`, com o ÚLTIMO `tool_use` a ser um `ask` auto-rejeitado (`The user rejected permission`) e o último `step_finish` em `tool-calls` (04, 18: o turno morreu numa auto-rejeição). Uma negação por regra (`The user has specified a rule…`, 23) não conta: o turno continua depois dela, e um EOF a seguir a uma é um run morto como outro qualquer | `result` de erro: `"the turn ended on a rejected permission: <tool> …"`, com as negações → causa `tools_denied` |
| EOF sem `result` e sem nada disto | nada: o run morto cai no salvamento existente (`no_result_event`) |

O `result` de sucesso:

```json
{"type":"result","subtype":"success","is_error":false,"num_turns":<eventos assistant>,
 "result":<último texto>,"session_id":"ses_…","platform":"opencode",
 "usage":{"input_tokens":<Σ input>,"cache_read_input_tokens":<Σ cache.read>,
          "cache_creation_input_tokens":<Σ cache.write>,"output_tokens":<Σ output + Σ reasoning>},
 "tokens":{"input":…,"cached":…,"cache_write":…,"output":<Σ output>,"reasoning":<Σ reasoning>},
 "total_cost_usd":<ver Custos>,"cost_basis":"reported|estimated|none",
 "permission_denials":[…],"api_error_status":null}
```

`usage.output_tokens` inclui o raciocínio, para que a linha de tokens do
modal some o que o modelo gerou; `tokens.reasoning` mantém-no à parte.

### O lançamento e o fim do run

O ramo OpenAI do `run_job` (FIFO, normalizador, `exec` do CLI, `child` = o
PID do CLI, `wait` do normalizador antes de ler o `result`) passa a ser **o
ramo de qualquer plataforma com normalizador**: `platform_normalizer
"$platform"` diz se há um; um `case` escolhe o construtor de argv
(`platform_argv_openai` ou `platform_argv_opencode`) e a linha do normalizador
(`openai_stream.py --pricing` ou `opencode_stream.py --catalog --pricing`).
`stop`, o watchdog de CPU, `tree_cpu_seconds`, o `wait` e a nota "normalizer
exited N" funcionam sem alteração.

As recusas antes do lançamento, na ordem que já existe, com o ramo `opencode`
ao lado do `openai`: `interactive: true` recusado ("opencode run has no stdin
protocol: it reads stdin as part of the prompt"); modelo fora do catálogo
recusado, a nomear `resolve-models opencode`; permissão fora do vocabulário
recusada; um `effort` fora dos `variants` do modelo é **retirado** com uma
linha no `tick.log` (passá-lo não muda nada: 11b); um modelo com `tools:
false` corre, com uma linha a dizer que o agente só pode responder em texto;
as listas de ferramentas são traduzidas, não ignoradas.

O ambiente do processo (`run_env`) ganha `OPENCODE_CONFIG_CONTENT`. O que o
motor não toca: a configuração do operador (`~/.config/opencode`), a conta,
os plugins (desligados por `--pure`), as skills (lidas de `~/.claude/skills`,
onde `agentloop skills` já as linka: 26).

Depois de `wait`: `platform_stderr_filter` (no-op), `platform_finish`
(`export` → `model_id`), o classificador de hoje, que lê `.total_cost_usd`,
`.num_turns`, `.session_id`, `.permission_denials`, `.api_error_status` como
sempre.

### Resume

Um resume corre na plataforma do run que continua, lida do journal, com a
recusa que já existe quando o job mudou de plataforma. No OpenCode leva `-s
<session>` **e** `--dir <run_cwd>`, onde `run_cwd` é o directório retido do
run cortado (a worktree reatada, ou o `cwd` do job num run sem isolamento): é
o directório em que a sessão nasceu, a única condição em que o CLI a retoma
(08b). O motor já recusa um resume cujo directório retido desapareceu ("no
open session directory holds it"), por isso o caso do pendurar (08c) não tem
por onde entrar. Um resume não leva `--title`: a sessão já tem um.

### O watchdog, e o run que nunca escreveu

A defesa de trás para tudo o que pendure na mesma (um directório movido à
mão, um provider que aceita a ligação e nunca responde: 34b) é o watchdog de
stall que já existe, e a medição 35 mostrou que hoje ele **não** apanha um
processo OpenCode pendurado: esse processo, sem output e sem filhos, soma
cerca de 1 s de CPU a cada 75 s de ralenti, e o watchdog dá o run por vivo
sempre que o inteiro de CPU da árvore muda entre dois polls de 30 s. Sem
`timeout_seconds`, que não tem omissão, o run seguraria a ranhura para
sempre.

Um chão de CPU ("só conta como vida quando cresce N s por poll") foi
ponderado e **rejeitado**: `tree_cpu_seconds` fecha sobre `pid`/`ppid` e só vê
a árvore do run, e o trabalho legítimo mais lento que este scheduler corre
vive fora dela: um `docker build` (o CPU está no daemon), um `trivy` a puxar
o bundle de políticas pela rede (já pendurou mais de dez minutos neste
repositório), um `git clone` numa ligação má, um `npm install` num registry
lento. Tudo isso sobrevive hoje pelo mesmo tique que mantém o run pendurado
vivo, e um chão trocaria um buraco por outro.

A regra que entra é estreita e não muda o destino de nenhum run que tenha
escrito um byte: **um stream ainda vazio ao fim de `stall_timeout_seconds` é
um run morto, diga o CPU o que diga**. Os dois pendurares medidos (08c, 34b)
têm zero bytes desde o arranque; um run são das três plataformas escreve o
primeiro evento muito antes de vinte minutos (o `init` do Claude e o
`thread.started` do Codex de imediato, o `step_start` do OpenCode quando o
modelo começa a responder, dezenas de segundos medidas). A nota do run diz
qual foi a regra: "stalled: no output at all for Ns (the CLI never started
answering; killed by watchdog)", causa `killed`. O intervalo do poll passa a
ler `AGENTLOOP_WATCHDOG_POLL` (omissão 30 s) só para o e2e conseguir
exercer a regra em segundos, com um stand-in que nunca escreve.

Fica como **limitação declarada**: um provider que morre depois do primeiro
byte deixa um processo OpenCode em ralenti que o sinal de CPU de hoje lê como
vivo; a ferramenta do operador para esse caso é `timeout_seconds`, e o
follow-up é medir o ralenti dos três CLIs (o `claude` e o `codex` parados
podem tiquetaquear da mesma forma) antes de tocar no sinal de CPU para as
três plataformas. Esta regra entra em **commit próprio, com os seus testes**,
separado do resto do motor: é a única parte da entrega que toca um run de
qualquer plataforma, e tem de poder ser revertida sozinha.

## Configuração

### Campos e vocabulários

| campo | opencode |
|---|---|
| `platform` | `opencode`, no job, no projecto ou no bloco `security`, com a herança de hoje |
| `model` | `provider/model` verbatim, do catálogo; sem famílias. A primeira barra separa o provider; o resto é o modelo (`pdm_ai/openai/gpt-oss-120b`) |
| `effort` | uma chave de `variants` do modelo (`low`, `high`, `max`, `non-think`, … consoante o modelo); vazio = o CLI decide; um modelo sem `variants` não aceita esforço |
| `permission_mode` | `full-access` (omissão), `read-only` |
| `interactive` | inválido: o editor desliga-o e o motor recusa o run |
| `allowed_tools`, `disallowed_tools` | funcionam, traduzidos (acima) |
| `max_budget_usd` | sem flag: verificado no fim do run, o aviso BUDGET LIMITED de hoje ("advisory on OpenCode") |
| `claude_config_dir` | ignorado num run OpenCode, como em OpenAI |

### Validação e defaults

- `set-field platform opencode`: aceite quando `usable`; `model`, `effort` e
  `permission_mode` inválidos na plataforma nova são reescritos para os
  defaults dela (`platform_default_model`, esforço vazio, `full-access`) e
  cada reescrita é impressa, como hoje.
- `set-field model|effort|permission_mode`: `platform_*_ok` da plataforma do
  job; um modelo fora do catálogo é recusado com os visíveis e a sugestão
  `agentloop resolve-models opencode`; um esforço fora dos `variants` do
  modelo é recusado a nomeá-los.
- `create` com `platform: opencode`: os defaults da plataforma.
- `security_derived_jobs`: `platform` do bloco; `model` validado também contra
  `tools: true` (uma análise sem ferramentas não pode correr `prepare` nem
  `checklist`), com o fallback-e-aviso que a permissão já tem;
  `permission_mode` `full-access`; `disallowed_tools: Agent` fica no job
  derivado e traduz-se para `task: deny` (22).
- O servidor aceita `platform: opencode` em `set_field` e `project-set` pelas
  mesmas regras.

## Catálogo de modelos

`config/models.json` ganha um bloco `opencode`, ao lado de `resolved` e
`openai`, escrito por `agentloop resolve-models opencode` (sem argumento, os
três) a partir de `opencode models --verbose --pure`, cujo formato é uma linha
`provider/model` seguida de um JSON por modelo:

```json
"opencode": {
  "at": 1789226000, "source": "opencode models --verbose", "version": "1.18.30",
  "models": [
    {"id": "pdm_ai/glm-5.3-flash", "provider": "pdm_ai", "name": "glm-5.3-flash",
     "cost": {"input": 0.033011, "output": 0.139816, "cache_read": 0, "cache_write": 0},
     "priced": true, "context": 197144, "output_limit": 65000,
     "variants": ["max", "high", "non-think"], "tools": true, "reasoning": true,
     "status": "active"}
  ]
}
```

- `priced` é verdadeiro quando qualquer dos quatro preços é maior que zero.
  Zero em todos é "sem preço", não "grátis" (24b: um provider sem `cost`
  configurado lista zeros iguais aos do Zen gratuito).
- A ordem é a do CLI. `status` fica como o CLI o dá; só `active` é visível.
- A passagem diária do tick refresca os três blocos; um refresh que falha
  mantém o bloco anterior, carimbado `stale_at`/`stale_reason`, como o
  OpenAI. Sem `opencode`, o bloco é `{"at": <now>, "available": false,
  "reason": "opencode not installed"}`.
- O parse é um trecho de python inline no engine (`"$PYTHON" - <<'PY'`), como
  os plists já são: `jq` não lê o formato misto.
- `/api/models.platforms.opencode`: `{available, reason, catalog_at, models:
  [{v, label, provider, desc: "", efforts, default_effort: "", priced, price:
  {input, cached_input, output, cache_write}, tools, context}], efforts (a
  união dos visíveis), permissions: [{v: "full-access", label}, {v:
  "read-only", label}], default_model, unpriced}`. O servidor lê o bloco; sem
  bloco e com o binário presente, chama `resolve-models opencode` uma vez,
  em síncrono, como faz para o OpenAI.

## Custos

`cost_basis` por run, decidida pelo normalizador:

| Caso | `cost_basis` | `total_cost_usd` |
|---|---|---|
| o catálogo tem preço para o modelo (`priced: true`) | `reported` | a soma dos `cost` dos passos: o número do CLI, calculado do seu catálogo (34) |
| sem preço no catálogo, com uma linha `opencode.<id>` em `config/pricing.json` (as chaves da tabela: `input`, `cached_input`, `output`, `cache_write`, USD por milhão) | `estimated` | a fórmula do CLI sobre os tokens somados: `(input × input + (output + reasoning) × output + cached × cached_input + cache_write × cache_write) / 10⁶`, em que `input` já exclui a cache (11, 24c) |
| nenhum dos dois, ou um run morto sem `step_finish` | `none` | `null`; o run grava `cost 0`, a UI mostra "—", os tectos em dólares não o vêem |

- **Zero é desconhecido.** Um modelo mesmo gratuito é o operador que o
  declara, com uma linha a zeros em `pricing.json` (`estimated $0.00`).
- `config/pricing.example.json` ganha um bloco `opencode` vazio com a forma
  documentada; `resolve-pricing` não lhe toca (o catálogo do CLI é a fonte do
  CLI; os providers custom são do operador). Uma linha `"source": "manual"`
  nunca é reescrita, como hoje.
- `agentloop platforms` e `status` reportam `unpriced`: os modelos activados
  sem preço no catálogo nem na tabela.
- Os tectos diário e global somam `reported` e `estimated` como sempre.
- Tecto por run: sem flag no CLI; verificado no fim, "BUDGET LIMITED" quando
  `cost ≥ 0.9 × cap`; o editor diz "advisory on OpenCode". Com
  `cost_basis: none` a comparação de hoje (`${cost:-0} >= cap × 0.9`) é
  **inerte em silêncio**: custo desconhecido vale zero e zero nunca chega a
  90% de nada. A entrega fecha esse silêncio para as três plataformas: um
  run com `max_budget_usd` definido e custo desconhecido leva na nota
  "max_budget_usd $X not applied: the cost of this run is unknown (no price
  for <model>)" e a mesma frase no `tick.log`; o estado não muda.

## Janelas de utilização

Não existem: cada provider tem a sua API e nada no stream nem no export fala
de janelas. `rl_gate opencode` deixa passar sempre; `rl_capture` é no-op;
`data/rate-limits.json` não ganha bloco `opencode`; `agentloop usage` diz
"opencode: no usage windows (each provider has its own API)". Um 429 chega
como `APIError` com `statusCode: 429` (inferido da forma do 16, não medido) →
`rate_limited`, fora do backoff como hoje, porque a isenção existe pela razão
"o provider teve um mau dia", que não muda de plataforma; o run seguinte vem
no intervalo do job.

## Journal, base de dados, servidor e hooks

Nada de novo na forma: `record_run` já leva `platform`, `cost_basis` e
`tokens`; `index.db` já tem as colunas; `/api/data` já expõe `platform` e
`cost_basis`; `load_run_detail` já mostra "pedido → real" e a linha de tokens;
`on-run-end.sh` já recebe `AL_PLATFORM`, `AL_COST_BASIS`, `AL_TOKENS`. O valor
`opencode` passa por tudo isto sem tocar em nada. `_model_id_from_stream`
continua a ler `init.model` como fallback do que o `export` deu.

## UI

- **Settings › Platforms**: o cartão OpenCode deixa de dizer *Coming soon*.
  Binário e versão como hoje; a zona de sessão mostra `account` ("0
  credentials · providers: opencode, pdm_ai") ou a razão; a lista de modelos
  carrega do catálogo com, por modelo, o nome, o provider, o preço por milhão
  ou "no price", os esforços (`variants`) e a marca "no tools" quando
  `tools: false`; **Refresh** corre `platform models opencode`; o interruptor
  destranca quando o check passa. `settings.js` deixa de ter texto próprio
  sobre o OpenCode: tudo vem de `supported`, `ready` e do catálogo.
- **Editores** (job e projecto, incluindo o bloco `security`): OpenCode no
  combo Platform; a lista de modelos plana, na ordem do catálogo, "glm-5.3-flash
  (pdm_ai)"; esforços por modelo, como já são no OpenAI; o vocabulário de
  permissão de `/api/models`; *Interactive* desligado e desmarcado com "opencode
  run has no stdin protocol"; no painel *Limits*, "cost is what the OpenCode
  CLI reports from its catalog; a model without a price shows — and does not
  count towards dollar caps unless priced in config/pricing.json; the per-run
  cap is advisory on OpenCode". O chip "planned" e o rótulo "(not supported
  yet)" desaparecem (`jobs-domain.js`, `editor-domain.js` lêem o registo, não
  o nome).
- **Cartões, tabelas, modal, Overview, Security**: o badge "OpenCode" onde
  hoje há "OpenAI"; custo `reported` como "$1.23" (é o número do CLI),
  `estimated` como "~$1.23" e `none` como "—", já assim.
- `ui/app/*.js` muda → `build/build-ui.sh` → `bin/static/` recommitado no
  mesmo commit.

## Análises de segurança em OpenCode

- `security.platform: opencode`; o job derivado nasce em `full-access` com
  `disallowed_tools: Agent` → `task: deny` (22): os subagentes ficam fechados
  **por regra**, como no Claude, e não só por prompt como no Codex.
- O motor corre `security prepare` na worktree antes do lançamento
  (`prepare_inline` é falso), pelo caminho que o OpenAI já usa: a ferramenta
  `bash` do OpenCode espera pelo comando (19), mas o seu tecto de tempo não
  foi medido e `prepare` pode levar minutos num repositório grande.
- `security_prompt` ganha o ramo `opencode`: a skill invocada **por nome** (o
  agente vê `~/.claude/skills`: 26) e nomeada **por caminho**
  (`$SKILLS_DIR/security-analysis/SKILL.md`), as duas portas; o parágrafo do
  `prepare` diz que a fase já correu, como no Codex; o parágrafo dos
  subagentes diz "The `task` tool is closed for this run, by rule" e pede a
  triagem na própria sessão.
- `cmd_skills` não ganha destino novo: o OpenCode lê `~/.claude/skills`, onde
  já linka. O `status` das skills passa a dizer que os três CLIs lêem o
  mesmo link (Claude, OpenCode) ou o seu (`~/.codex/skills`).
- **Aceitação:** uma análise real em OpenCode sobre um repositório pequeno,
  lida de ponta a ponta no ledger: `prepare` correu pelo motor, `checklist`
  foi consultado, findings re-reportados com fingerprints copiados, `finish`
  chamado, estado `done` ou `capped` com razão.

## Skills, instalação e estado

- `install.sh`: `opencode` é dependência opcional, "✓ opencode (1.18.30, 2
  providers)" ou "– opencode not found: jobs on the OpenCode platform are
  refused until it is installed and a provider is configured".
- `agentloop status`: a linha da plataforma passa de "planned" a "enabled —
  1.18.30, 0 credentials · providers: opencode, pdm_ai; 2 of 13 models
  enabled; catalog 2 h ago; 1 enabled model unpriced".
- `agentloop platforms`: `supported: true`, e o resto como as outras.
- README: a tabela *Platforms* ganha a terceira coluna; as secções *Models*,
  *Effort*, *Budgets*, *Settings*, *Security block* e *CLI* actualizadas; uma
  nota sobre o que o OpenCode não isola e sobre `--pure`.
- CHANGELOG: uma entrada que diz o que mudou e o que custava não ter.

## Erros

| Situação | O que acontece |
|---|---|
| `opencode` ausente | run recusado antes de gastar um turno, razão no `tick.log`; `install`/`status` dizem-no; o cartão mostra o comando de instalação |
| binário presente, nenhum provider utilizável (`opencode models` vazio) | `platform_check` não pronto com "no usable provider: run `opencode auth login`, or configure one in ~/.config/opencode/opencode.json"; run recusado |
| catálogo indisponível | o bloco anterior fica com `stale_at`; sem bloco nenhum, `available: false` com razão em `/api/models` e no editor; modelo fora do catálogo recusado no lançamento a nomear `resolve-models opencode` |
| modelo com `tools: false` | um job corre, com a linha "model has no tool calls: the agent can only answer in text"; um bloco `security` cai no default com aviso |
| `effort` fora dos `variants` do modelo | recusado em `set-field`; no lançamento retirado com uma linha (o CLI aceitaria em silêncio e não faria nada) |
| `interactive: true` | o editor impede; o motor recusa: o stdin é engolido como prompt |
| provider ou modelo desconhecido no run (catálogo desactualizado) | `error{UnknownError}` → `agent_error`; a razão (`ProviderModelNotFoundError`) está no `.err`, porque o run leva `--print-logs --log-level ERROR` |
| chave inválida, conta suspensa | `APIError` com `statusCode` 401/403 → `api_error`, fora do backoff; a mensagem do provider é o `result` |
| quota / 429 (não medido) | `APIError` com `statusCode: 429` → `rate_limited`, fora do backoff; sem janela para marcar, o run seguinte vem no intervalo do job |
| ferramenta negada por regra (lista do job ou configuração do operador) | evento no stream, `permission_denials` preenchido, o turno continua; o run é `error` com causa `tools_denied`, como no Claude |
| auto-rejeição de um `ask` (só possível num run lançado sem `--auto`, o que o motor nunca faz) | o turno acaba aí; o `result` de EOF nomeia a ferramenta e o run é `error` com causa `tools_denied`, em vez de um sucesso vazio |
| provider que não responde (34b) | zero bytes desde o arranque: o watchdog mata ao fim de `stall_timeout_seconds` pela regra do stream vazio, diga o CPU o que diga (35); nota "stalled: no output at all…", causa `killed` |
| resume fora do directório da sessão (08c) | não tem por onde entrar: o motor passa `--dir` = o directório retido e recusa resumir sem ele; se acontecer na mesma, zero bytes: a regra do stream vazio |
| provider que morre depois do primeiro byte | limitação declarada: o ralenti do processo (35) mantém o sinal de CPU vivo; `timeout_seconds` é a ferramenta do operador; follow-up com medição dos três CLIs |
| `export` falha ou expira no fim do run | `model_id` fica o pedido; uma linha no `tick.log` |
| normalizador termina com erro | o CLI morre com SIGPIPE, o run cai no salvamento, a nota diz "normalizer exited N" |
| linha malformada no stream | copiada para `.raw`, ignorada |
| stderr | um run que não repetiu pedidos não escreve nada; qualquer byte é real e o run fica `warning` como hoje (um erro transitório repetido pelo CLI, 24c, é exactamente isso: correu bem, quer um olhar) |
| sem preço para o modelo | `cost_basis: none`, "—" com tooltip na tabela, nota no editor, `unpriced` em `status`; com `max_budget_usd` definido, a nota do run e o `tick.log` dizem que o tecto não foi aplicado |
| stop | TERM ao CLI, que sai em 1 s (12); sem `result`; o marcador `stopped` do slot decide, como hoje |
| `say` a um run OpenCode | "this run is not interactive" |
| resume de um run cuja plataforma difere da actual do job | recusado, como hoje |

## Fora desta versão

- Isolamento de configuração e conta por job ou por projecto
  (`XDG_CONFIG_HOME` + `XDG_DATA_HOME`, medido e possível). Quando entrar,
  entra para as três plataformas de uma vez, ao lado de `CLAUDE_CONFIG_DIR` e
  `CODEX_HOME`, não como uma porta das traseiras só para esta.
- Interactivo: `opencode run` não tem protocolo de stdin.
- `--agent` (o `build` é o único agente que um run usa), `--file`, `--share`,
  servidores MCP, os `variants` que não são esforço (`non-think` é aceite como
  qualquer outra chave).
- `doom_loop`: fica no default do CLI (aprovado por `--auto`); não foi medido
  e um `deny` poderia fechar repetições legítimas.
- Preços dos providers custom: são do operador, na tabela; nenhuma fonte
  automática.
- Outras plataformas. A tabela continua a deixar cada uma a uma entrada de
  distância.

## Testes

- **Fixtures** em `test/fixtures/opencode/`: as medições 01, 02, 03, 04, 06,
  09, 11, 12, 16, 18, 22, 23, 24c, 34, o export 14, o catálogo
  `models-verbose-after-provider-change.txt`, o `auth-list.txt` e uma fixture
  sintética de 429 com a forma do 16 (marcada como sintética).
- **Normalizador** (`tests/test_opencode_stream.py`): a primeira linha tem
  `session_id`; o último evento é `result` quando o turno acabou em `stop`;
  `parse_turns_text` do servidor desenha o `Bash` com o comando; a soma de
  tokens e custo por passo (02: três passos); `usage.output_tokens` = output +
  reasoning (11); as duas frases de negação viram `permission_denials` e a
  auto-rejeição em EOF vira `result` de erro (04, 23); `UnknownError` sem
  `api_error_status` (09) e `APIError` com 401 (16) e 429 (sintética); os três
  `cost_basis` (34 reported; 24c com tabela → estimated; sem nada → none) e a
  fórmula com raciocínio; um `reason` desconhecido; `_salvage_from_stream`
  sobre uma cópia truncada; uma linha malformada; um nome de ferramenta fora
  da tabela.
- **Selftest**: `platform_argv_opencode` para um run novo e um resume, lido do
  argv que `test/fake-opencode` grava (`FAKE_ARGV_OUT`), incluindo
  `</dev/null`, `--dir`, `--title` só no run novo, `--variant` só quando
  válido, `--`; `opencode_config_content` para os dois modos, as duas listas,
  padrões de `Bash`, o alargamento e a ignorância dos outros padrões, deny a
  ganhar, `share: disabled` sempre; `platform_caps`; `platform_check` com
  catálogo vazio e cheio; `resolve_models_opencode` sobre a fixture do
  catálogo (`priced`, a barra dentro do id, `stale`); `set-field` por
  plataforma incluindo a reescrita; `create`; as recusas de lançamento; a
  recusa do resume com plataforma diferente; `security_derived_jobs` com
  `tools: false`; `rl_gate opencode`; o `turn_is_over` sobre um stream
  normalizado; a nota "cap not applied" num run com custo desconhecido e
  tecto definido.
- **pytest do servidor**: a forma de `/api/models.platforms.opencode`; a
  lista de permissões igual à do engine; `set_field platform opencode`;
  `unpriced`; contrato da página: os elementos existem, o vocabulário vem do
  servidor, *Interactive* desligado em OpenCode, o badge, a nota de custo, o
  cartão sem *Coming soon*.
- **e2e, a regra do stream vazio** (commit próprio): `test/fake-claude` ganha
  `FAKE_MODE=silent` (nunca escreve um byte, dorme); um job com
  `stall_timeout_seconds: 4` e `AGENTLOOP_WATCHDOG_POLL=2` acaba `error`,
  causa `killed`, nota "no output at all", em segundos; o cenário `hang` de
  hoje (escreve o `init` e dorme) continua a durar até ao `stop`, provando que
  a regra não toca num run que escreveu.
- **e2e** (`test/e2e.test.sh` com `test/fake-opencode`, um stand-in que emite
  as formas medidas, guiado por `FAKE_MODE` complete · tool · deny · reject ·
  error · quota · hang · undeclared · dirty, `FAKE_SESSION` como id, e que
  responde a `--version`, `models`, `models --verbose`, `auth list`, `run`
  e `export`, gravando o argv e o `--dir` com que foi lançado): run completo,
  undeclared e dirty; resume com o mesmo id no mesmo directório e reattach da
  worktree; stop; deny → `tools_denied`; quota → `rate_limited` com
  `fail_streak` intacto; análise de segurança em OpenCode de ponta a ponta.
- **Aceitação, com o CLI real:** um job num repositório de rascunho
  (`pdm_ai/glm-5.3-flash`, o modelo pago que responde), lido de ponta a ponta:
  o stream normalizado, o custo `reported`, o modelo do `export`, um resume;
  e a análise de segurança acima. Lidos, não só verdes.

## Ordem de implementação, para o plano

1. Fixtures para `test/fixtures/opencode/`; `test/fake-opencode`.
2. Normalizador e os seus testes.
3. Tabela de plataformas: registo, `caps`, permissões, `opencode_config_content`
   com as listas, esforços, `model_ok`, `check`/`ready`, `argv`, `finish`
   (`export`), `platform_normalizer`; selftest.
4. Catálogo: `resolve_models_opencode`, `models.json`, `/api/models`.
5. Lançamento: o ramo genérico do `run_job`, as recusas, `run_env`; a nota
   do tecto inerte; e2e de run, resume e stop.
5b. A regra do stream vazio no watchdog, em commit próprio, com o seu e2e.
6. Esquema de configuração: `set-field`, `create`, `resolve`, `project-set`,
   validações; selftest e pytest.
7. Custos: `pricing.example.json`, `unpriced`, `status`/`platforms`.
8. Segurança em OpenCode: `security_derived_jobs`, `security_prompt`, `prepare`
   pelo motor via `prepare_inline`; cenário e2e.
9. UI: Settings, editores, cartões, tabelas, modal; contrato da página; build.
10. `install.sh`, `status`, `usage`, README, CHANGELOG.
11. Aceitação com o CLI real.
