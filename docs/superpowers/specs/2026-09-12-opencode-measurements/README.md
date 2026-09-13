# Medições do OpenCode CLI 1.18.30, a 2026-09-12

Evidência da spec `2026-09-12-opencode-engine-design.md` (a escrever a partir
daqui). Tudo nesta pasta foi capturado a correr o CLI, não escrito de memória;
onde a medição contradisser a documentação ou a spec das Settings
([`../2026-09-11-platform-settings-design.md`](../2026-09-11-platform-settings-design.md),
secção "OpenCode: o ponto de extensão"), a medição manda.

## Contra o quê

- `opencode --version` → `1.18.30` ([`opencode-version.txt`](opencode-version.txt)).
  Instalado por `npm install -g opencode-ai@1.18.30` em `/opt/homebrew/bin/opencode`,
  a mesma versão do OpenCode.app (desktop, Electron) instalado no portátil.
- O CLI e o desktop partilham `~/.config/opencode/` (configuração: providers,
  plugins, agentes) e `~/.local/share/opencode/` (`auth.json`, a base de dados
  de sessões). Não houve nada a copiar: `opencode models` listou de imediato
  os providers do desktop.
- Conta: `auth.json` vazio (`0 credentials`). Os providers com credenciais vêm
  da configuração (`pdm_ai`, um router OpenAI-compatible com chave inline) e
  do OpenCode Zen, cujos modelos `*-free` correm **sem credencial nenhuma**.
  Todos os modelos desta máquina têm custo 0 no catálogo; um custo real só foi
  medido dando um preço por configuração (24b, 24c).
- Modelos usados: `opencode/big-pickle` e `opencode/ling-3.0-flash-fin-free`
  (Zen, gratuitos; o segundo tem `variants`). Prompts triviais, um directório
  de rascunho, nunca um repositório a sério.
- A meio das medições (entre a 33 e a 34) o operador trocou a chave e o
  catálogo do provider `pdm_ai`: os oito modelos sem preço deram lugar a seis
  **com preço** (`models-after-provider-change.txt`,
  `models-verbose-after-provider-change.txt`). Tudo até à 33 foi medido contra
  o catálogo antigo (`models.txt`, `models-verbose.txt`); a 34 é a única
  corrida num modelo pago.
- Cada `NN-nome.jsonl` é o stdout verbatim, `NN-nome.stderr.txt` o stderr,
  `NN-nome.meta.txt` o comando, o modo do stdin, o cwd, o código de saída e a
  duração. Dois nomes foram substituídos em todos os ficheiros, e só esses: o
  directório home do operador por `/Users/me` (a regra do `selftest`) e o
  scratchpad da sessão por `/tmp/probe` (`p`, `q` e `wt` são as suas
  subpastas: `p` e `q` pastas soltas com um ficheiro de texto cada, `wt` um
  `git worktree` de um repositório descartável em `/tmp/probe/repo`). Nenhum
  ficheiro traz chave de API: o `models --verbose` não as inclui, e a chave
  do run 16 é falsa e vem mascarada pelo próprio provider.
- `OPENCODE_CONFIG_CONTENT='{…}'` foi passado no ambiente do processo nas
  medições que o nomeiam; o `.meta.txt` não regista o ambiente, a tabela sim.

## O que ficou provado, em resumo

| Facto | Ficheiros |
|---|---|
| headless: `opencode run --format json [--pure] [--auto] -m provider/model [--variant v] [--dir d] [-s id] [--title t] PROMPT`, **sempre com `</dev/null`**: com stdin aberto o processo lê-o até ao EOF antes de arrancar e fica pendurado sem um byte; texto no stdin é anexado ao prompt | 13a, 13b, 13c |
| eventos, um por linha, todos com `sessionID`: `step_start`, `text{part.text}`, `tool_use{part.tool, part.callID, part.state{status, input, output, metadata, error, title, time}}`, `step_finish{part.reason, part.tokens{total,input,output,reasoning,cache{read,write}}, part.cost}`, `error{error{name, data}}`; **sem modelo no stream**; `stderr` vazio num run são | 01, 02, 03 |
| um turno tem um passo por chamada ao modelo: `step_finish.reason` é `tool-calls` entre ferramentas e `stop` no último; os tokens e o custo são **por passo**, somados dão o run; o fim do run é o fim do processo (exit 0) | 02, 03, 05 |
| o `tool_use` sai **uma vez, já concluído** (`state.status: completed`); um run morto a meio de uma ferramenta não mostra a ferramenta | 02, 12 |
| o primeiro byte no stdout só sai quando o modelo começa a responder; um provider lento pode levar dezenas de segundos sem output (o 21 não respondeu em 120 s, o 21b levou 28 s ao mesmo pedido) | 21, 21b |
| `total = input + output + reasoning + cache.read + cache.write`; `input` **exclui** o que veio da cache; `reasoning` é separado do `output` (ao contrário do Codex) | 11, 24b, 24c |
| `cost` é calculado pelo CLI a partir do preço do catálogo: `(input×in + output×out + reasoning×out + cache.read×cr + cache.write×cw) / 10⁶`; com preço 0 no catálogo (Zen gratuito, provider custom sem `cost`) vem `0`, indistinguível de "sem preço" | 24b, 24c, `models-verbose.txt` |
| **num provider pago a sério** o CLI reporta o custo do catálogo: `cost: 0.000426176016` = (12800×0.033011 + (3+23)×0.139816)/10⁶ em `pdm_ai/glm-5.3-flash`; a mesma fórmula, o raciocínio ao preço do output | 34, `models-verbose-after-provider-change.txt` |
| um provider que **não responde** (o router aceitou a ligação e nunca respondeu para `Nemotron-3.5-Lightning`, confirmado por um POST directo que expirou aos 25 s) deixa o CLI pendurado depois de `llm runtime selected`, sem timeout, sem erro e sem um byte: só um watchdog exterior o termina | 34b |
| **um run pendurado não está parado para o `ps`**: o processo `opencode run` do 08c (um só processo, sem filhos), sem um byte de output, soma cerca de **1 s de CPU a cada 75 s** (2 → 3 → 4 s em 4 minutos). Um watchdog que dá um run por vivo sempre que o inteiro de CPU da árvore muda entre dois polls de 30 s nunca o mata | 35 |
| um id de modelo pode ter barra dentro (`pdm_ai/openai/gpt-oss-120b`): `provider/model` divide-se na **primeira** barra | `models-after-provider-change.txt` |
| `--` antes do prompt é aceite; `share: "disabled"` em `OPENCODE_CONFIG_CONTENT` também (a par de `permission`) | 33 |
| sobrepor por configuração um modelo de um provider embutido (`provider.opencode.models.big-pickle.cost`) parte a resolução do modelo ("Model not found: opencode/big-pickle. Did you mean: big-pickle?"); um provider custom com o mesmo endpoint funciona | 24, 24b |
| `--variant` é o esforço: os valores válidos são as chaves de `variants` de cada modelo no catálogo (`low`/`medium`/`high`, `minimal`…`xhigh`, `max`, `non-think`, consoante o modelo); `--variant high` fez `reasoning > 0`; **um valor inválido é aceite em silêncio** (exit 0) | 11, 11b, `models-verbose.txt` |
| `--dir <d>` é o cwd do run (processo em `p`, ferramentas em `q`) | 07 |
| `-s <id>` retoma **a mesma** sessão (o `sessionID` mantém-se em todos os eventos) **desde que `--dir` seja o directório em que a sessão nasceu**; noutro directório o CLI cria uma instância para o directório da sessão, corre o turno lá (gasta-o) e o `run`, subscrito ao directório errado, nunca escreve nem sai: **pendura-se para sempre sem um byte** | 08, 08b, 08c, 08d |
| `--dir` inexistente: exit 1 em 0 s, `Error: Failed to change directory to …` no stderr, nada no stdout, sem chamada ao modelo | 29 |
| SIGTERM: o processo sai em 1 s com exit 143, a ferramenta em curso (`sleep 40`) morre com ele, nada fica órfão; a sessão sobrevive e retoma com o mesmo id | 12, 12b |
| modelo ou provider desconhecido: exit 1, um só evento `error{name: "UnknownError", data{message: "Unexpected server error. Check server logs for details.", ref}}`, stderr vazio; a razão real (`ProviderModelNotFoundError: Model not found: opencode/does-not-exist.`) só sai com `--print-logs --log-level ERROR`, que num run são não escreve nada | 09, 09b, 10, 30 |
| falha de autenticação (chave inválida num provider normal): exit 1, `error{name: "APIError", data{message, statusCode: 401, isRetryable, responseHeaders}}`; o CLI ainda tentou gerar o título da sessão com um modelo pequeno (`gpt-5.4-nano`) | 16 |
| um erro transitório do provider (`Upstream request failed: Endpoint is unavailable.`) aparece no stderr com `--print-logs` e o CLI repete o pedido: o run acabou bem, exit 0 | 24c |
| permissões: o bloco `permission` da configuração (por `OPENCODE_CONFIG_CONTENT`) mapeia ferramenta → `allow` · `ask` · `deny`, com padrões por comando em `bash` (`{"*": "allow", "echo *": "deny"}`) | 04, 05, 06, 23 |
| `ask` sem `--auto`: **auto-rejeição** (stderr `! permission requested: bash (ls); auto-rejecting`, com cores ANSI), o `tool_use` sai com `state.status: "error"` e `state.error: "The user rejected permission to use this specific tool call."`, e **o turno acaba aí** (`step_finish.reason: tool-calls`, sem texto final, exit 0) | 04, 18 |
| `ask` com `--auto`: aprovado, corre | 05 |
| `deny` numa ferramenta inteira: a ferramenta **sai do roster**; se o modelo a tentar, recebe `tool: "invalid"` com `input.error: "Model tried to call unavailable tool 'bash'. Available tools: edit, glob, grep, invalid, read, skill, task, todowrite, webfetch, websearch, write."` e adapta-se; `task` (subagentes) fecha-se da mesma forma | 06, 22 |
| `deny` por padrão de `bash`: o `tool_use` sai com `state.status: "error"` e `"The user has specified a rule which prevents you from using this specific tool call. Here are some of the relevant rules […]"`, e **o turno continua** | 23 |
| por omissão, em `run`: `bash`, `read` e `write` correm sem perguntar (`edit` não foi exercido); `external_directory` (ferramentas de ficheiro fora do `--dir`) é `ask`; `question`, `plan_enter` e `plan_exit` são `deny` (o agente não pode ficar à espera de uma pergunta ao humano) | 02, 17, 18, 14 (`info.permission`) |
| **não há sandbox ao nível do SO**: `bash` escreve fora do directório e faz `git commit` num worktree (cujo `.git` real fica fora do directório) sem `--auto` e sem pedir nada | 19, 20 |
| `--pure` desliga os plugins externos do operador; sem ele o plugin `rtk.ts` de `~/.config/opencode/plugins/` **reescreveu `ls` para `rtk ls`** e o plugin `superpowers` acrescentou ~3k tokens de instruções a cada passo | 02, 03 |
| `--pure` **não tira as skills**: as corridas 26 e 27 levaram `--pure` e o agente continuou a ver `~/.claude/skills/` e `.opencode/skills/` do run; o que sai são só os plugins (`plugin` da configuração e `~/.config/opencode/plugins/`) | 26, 27 |
| `--title` evita a chamada extra a um modelo pequeno que gera o título de cada sessão nova (0 streams `agent=title` contra 1 sem a flag) | 30, 21b, 16 |
| `opencode export <id>`, do directório da sessão: `{info, messages}` com `info.model{id, providerID, variant}` (o modelo que correu), `info.directory`, `info.version`, `info.cost`, `info.tokens`, `info.permission`, e por mensagem `modelID`, `providerID`, `cost`, `tokens`, `finish`, `path.cwd`; é o análogo do rollout do Codex, com a diferença de o modelo e o custo lá estarem | 14 |
| `opencode models`: uma linha `provider/model`; `--verbose`: cada linha seguida de um JSON com `cost{input, output, cache{read, write}}` por milhão, `limit{context, output}`, `capabilities{toolcall, reasoning, …}`, `variants{…}`, `status`; nesta máquina `pdm_ai/deepseek-v4-flash` e `pdm_ai/qwen3.5-vision` têm `toolcall: false` | `models.txt`, `models-verbose.txt` |
| `opencode auth list`: uma caixa com cores ANSI mesmo sem TTY (`NO_COLOR` não as tira), o caminho do `auth.json` e `N credentials`; não é a lista dos providers utilizáveis, que vem do catálogo | `auth-list.txt` |
| `OPENCODE_CONFIG_DIR` é uma **camada adicional** (carregada entre `~/.config/opencode/*` e `~/.opencode/*`), não uma substituição: os providers do operador continuam a aparecer; o CLI semeia `package.json` e `node_modules` lá dentro | 15a, 15b |
| `XDG_CONFIG_HOME` move `~/.config/opencode` de facto (os providers do operador desaparecem; `~/.opencode/opencode.json(c)` continua a ser lido) e `XDG_DATA_HOME` move `auth.json` e a base de dados de sessões: é este o par que isola conta e configuração por run | 15c, 15d |
| skills: o agente vê `~/.claude/skills/*/SKILL.md` (as 35 desta máquina, pelo `name` do frontmatter) mais a interna `customize-opencode`, e `.opencode/skills/<nome>/SKILL.md` no directório do run; invoca-as com a ferramenta `skill` por nome (`input: {name}`) | 26, 27 |
| `opencode session list` é uma tabela humana, não JSON; o motor não precisa dela | 25 |
| `--agent plan`, o agente embutido "read-only", **não é read-only a sério**: pelas regras nega `edit` (fora das pastas de planos) e `task general`, mas `bash` fica `allow`; o que travou o modelo foi o prompt de sistema ("I'm in Plan Mode (read-only)"), sem tocar em ferramentas | 31, 31b, 32 |
| `opencode agent list` imprime cada agente com as suas regras de permissão: os defaults de `build` são `*: allow`, `doom_loop: ask`, `external_directory: ask` (com `allow` para a pasta de tool-output, o tmp e cada directório de skill), `read *.env: ask`, `read *.env.example: allow`, `question`/`plan_enter`/`plan_exit: deny`; `general` (subagente) acrescenta `todowrite: deny`; `explore` é uma lista de leitura (`grep`, `glob`, `list`, `bash`, `webfetch`, `websearch`, `read`) sobre `*: deny` | 32 |

## Ficheiro a ficheiro

| Ficheiro | Comando | O que prova |
|---|---|---|
| `opencode-version.txt` | `opencode --version` | `1.18.30` |
| `opencode-help.txt`, `opencode-run-help.txt`, `opencode-models-help.txt`, `opencode-auth-help.txt`, `opencode-export-help.txt`, `opencode-session-help.txt` | `--help` | as flags que existem: `run` tem `--format json`, `-m`, `-s`, `--fork`, `--dir`, `--variant`, `--auto`, `--pure`, `--agent`, `--title`, `--file`, `--attach`; não há `--print-json` de sessão nem allow/deny por flag (vive na configuração) |
| `auth-list.txt` | `NO_COLOR=1 opencode auth list` | `0 credentials`, o caminho do `auth.json`, cores ANSI na mesma |
| `models.txt` | `opencode models` | 15 modelos `provider/model`: 7 `opencode/*-free`, 8 `pdm_ai/*` |
| `models-verbose.txt` | `opencode models --verbose` | o catálogo com custo, limites, capacidades, `variants` e `status` por modelo |
| `01-trivial-turn` | `opencode run --format json -m opencode/big-pickle 'Reply with exactly: ok' </dev/null` | `step_start` → `text` → `step_finish{reason: stop, tokens, cost: 0}`; exit 0; stderr vazio; 3 s |
| `02-tool-use-no-auto` | idem, com um prompt que corre `ls` e lê `a.txt`; **sem** `--pure` | `tool_use` de `bash` (`input.command`, `output`, `metadata{exit, truncated}`) e de `read` (`input.filePath`); `step_finish.reason: tool-calls` entre passos; **o plugin `rtk.ts` do operador reescreveu `ls` para `rtk ls`** |
| `03-tool-use-pure` | idem, com `--pure` | o comando fica `ls`; 3 030 tokens de prompt a menos no primeiro passo (os plugins do operador não entram) |
| `04-permission-ask-no-auto` | `OPENCODE_CONFIG_CONTENT='{"permission":{"bash":"ask"}}'`, `--pure`, sem `--auto` | auto-rejeição: stderr `! permission requested: bash (ls); auto-rejecting`, `state.status: error`, `state.error: "The user rejected permission…"`, e o turno acaba sem texto final; exit 0 |
| `05-permission-ask-auto` | idem, com `--auto` | aprovado; corre como o 03 |
| `06-permission-deny-auto` | `{"permission":{"bash":"deny"}}`, `--auto` | `bash` sai do roster: `tool: "invalid"` com a lista das ferramentas disponíveis; o modelo usa `glob` e acaba |
| `07-dir-as-cwd` | `--dir /tmp/probe/q`, processo em `/tmp/probe/p`, prompt `pwd && ls` | o cwd do run é o `--dir` |
| `08-resume-same-session` | `-s <sessão do 07>`, **sem** `--dir`, processo em `p` | 120 s sem um byte, morto pelo alarme (rc 142): a sessão pertence a `q` |
| `08b-resume-same-dir` | `-s <sessão do 07> --dir /tmp/probe/q` | o mesmo `sessionID` em todos os eventos; `pwd` dá `q`; 11 s |
| `08c-resume-other-dir` | `-s <sessão do 07> --dir /tmp/probe/p` | 45 s sem um byte, morto pelo alarme: um resume noutro directório pendura-se |
| `08d-resume-other-dir-logs` | idem, com `--print-logs --log-level DEBUG`, 20 s | os logs mostram a instância de `p` a arrancar, depois `creating instance directory=…/q`, o turno a correr em `q` (`stream … exiting loop`) e nada a chegar ao stdout: o turno é gasto às escuras |
| `09-unknown-model` | `-m opencode/does-not-exist` | exit 1, um `error{name: UnknownError}` genérico com `ref`, stderr vazio |
| `09b-unknown-model-logs` | idem, `--print-logs --log-level ERROR` | o stderr diz `ProviderModelNotFoundError: Model not found: opencode/does-not-exist.` |
| `10-unknown-provider` | `-m nosuchprovider/model` | igual ao 09 |
| `11-variant-high` | `-m opencode/ling-3.0-flash-fin-free --variant high`, um problema de contas | `reasoning: 15`, `output: 12`: o raciocínio é separado do output; `total` = soma das cinco parcelas |
| `11b-variant-bogus` | `--variant bogus` | aceite em silêncio, exit 0: o CLI não valida o variant |
| `12-interrupted-turn` | `sleep 40` numa ferramenta, SIGTERM ao fim de 8 s | sai em 1 s com exit 143; o stream fica só com `step_start`; sem processos órfãos |
| `12b-resume-after-interrupt` | `-s <sessão do 12> --dir /tmp/probe/p` | a sessão interrompida retoma com o mesmo id |
| `13a-stdin-pipe-open` | `sleep 300 \| opencode run … 'Reply with exactly: ok'` | 45 s sem um byte: o `run` lê o stdin até ao EOF antes de arrancar |
| `13b-stdin-text-plus-arg` | `printf 'Reply with exactly: from-stdin\n' \| opencode run … 'Reply with exactly: from-arg'` | respondeu `from-stdin`: o stdin é anexado ao prompt |
| `13c-stdin-closed` | stdin fechado com `<&-` | funciona como com `</dev/null` |
| `14-export-session-03.json` | `opencode export ses_f69f73155ffeAHgrtVv1sVFbr7`, do directório da sessão | a forma do export: `info.model`, `info.directory`, `info.version`, `info.cost`, `info.tokens`, `info.permission`, mensagens com `modelID`/`providerID`/`cost`/`tokens`/`finish`; stderr `Exporting session: <id>` |
| `15a-config-dir-empty-models`, `15b-config-dir-empty-auth-list` | `OPENCODE_CONFIG_DIR=<vazio> opencode models` / `auth list` | os providers do operador continuam lá: a variável acrescenta uma camada, não substitui |
| `15c-xdg-config-home-models` | `XDG_CONFIG_HOME=<vazio> opencode models --print-logs --log-level DEBUG` | só os 7 `opencode/*-free`; os logs listam os caminhos de configuração lidos |
| `15d-xdg-data-home-auth-list` | `XDG_DATA_HOME=<vazio> opencode auth list` | o `auth.json` e a base de dados nascem debaixo do directório novo |
| `16-auth-failure-bogus-key` | `OPENCODE_CONFIG_CONTENT='{"provider":{"openai":{"options":{"apiKey":"sk-bogus…"}}}}' … -m openai/gpt-4o-mini` | exit 1, `error{name: APIError, data{statusCode: 401, isRetryable: false, …}}`; os logs mostram a chamada do título com `gpt-5.4-nano` a falhar primeiro |
| `17-write-file-no-auto` | `--title 'measurement 17'`, sem `--auto`, criar `new.txt` com a ferramenta `write` | `write` corre sem perguntar: `input{content, filePath}`, `output: "Wrote file successfully."`, `metadata{exists, …}`; o ficheiro existe |
| `18-write-outside-dir-no-auto` | sem `--auto`, `write` para `/tmp/probe/q/outside.txt` (fora do `--dir`) | `! permission requested: external_directory (/tmp/probe/q/*); auto-rejecting`; o turno acaba; o ficheiro não existe |
| `19-git-commit-in-worktree-no-auto` | `--dir /tmp/probe/wt` (um `git worktree`), sem `--auto`, `git commit --allow-empty` por `bash` | o commit é feito: `[probe-branch 1c7a5eb] probe`; nada foi perguntado |
| `20-bash-write-outside-dir-no-auto` | sem `--auto`, `echo hi > /tmp/probe/q/outside2.txt` por `bash` | o ficheiro é escrito: `external_directory` só guarda as ferramentas de ficheiro |
| `21-bash-pattern-deny` | `{"permission":{"bash":{"*":"allow","git push*":"deny"}}}`, `--auto`, pedir `git push` | 120 s sem um byte, morto pelo alarme: o provider gratuito não respondeu (ver 21b) |
| `21b-bash-pattern-deny-logs` | idem, `--print-logs --log-level DEBUG`, 30 s | o modelo recusou o `git push` por si (o padrão não chegou a ser exercido); a linha temporal mostra 28 s entre o pedido ao modelo e a resposta, e o `snapshot` que o CLI tira em directórios git |
| `22-task-deny-roster` | `{"permission":{"task":"deny"}}`, pedir ao agente a lista das suas ferramentas | `bash, edit, glob, grep, read, skill, todowrite, webfetch, websearch, write`: sem `task` |
| `23-bash-pattern-deny-echo` | `{"permission":{"bash":{"*":"allow","echo *":"deny"}}}`, `--auto`, pedir `echo …` | `state.status: error` com "The user has specified a rule which prevents you…" e as regras relevantes; o turno continua e acaba em `stop` |
| `24-configured-cost` | `{"provider":{"opencode":{"models":{"big-pickle":{"cost":{…}}}}}}` | exit 1, `UnknownError`: a sobreposição parcial parte a resolução do modelo |
| `24b-configured-cost-custom-provider` | provider custom `zenprobe` (`@ai-sdk/openai-compatible`, `baseURL` do Zen) com `cost{input: 1, output: 2, cache_read: 0.5, cache_write: 0.25}` | `cost: 0.012379` = (11425×1 + 29×2 + 1792×0.5)/10⁶: o CLI calcula o custo do catálogo, `input` sem a cache |
| `24c-configured-cost-reasoning` | idem, `ling-3.0-flash-fin-free --variant high` | `cost: 0.01287` = (11800×1 + 32×2 + **39×2** + 1856×0.5)/10⁶: o raciocínio é cobrado ao preço do output; um erro transitório do provider no stderr, repetido pelo CLI |
| `25-session-list.txt` | `opencode session list` | uma tabela humana (id, título, hora) |
| `26-skills-visible` | `--pure`, pedir ao agente a lista das skills que vê, `--print-logs --log-level DEBUG` | as 35 de `~/.claude/skills/` mais `customize-opencode` |
| `27-project-skill-visible` | `.opencode/skills/probe-skill/SKILL.md` no directório do run, pedir para a invocar | `tool: "skill"` com `input{name: "probe-skill"}` e a resposta ditada pela skill |
| `29-dir-missing` | `--dir /tmp/probe/does-not-exist` | exit 1 em 0 s, `Error: Failed to change directory to …`, sem stdout, sem chamada ao modelo |
| `30-title-flag-skips-title-call` | `--title 'agentloop probe 30' --print-logs --log-level INFO` | zero streams `agent=title` (o 21b, sem `--title`, tem um) |
| `31-agent-plan-auto` | `--agent plan --auto`, pedir `ls`, um `write` e um `echo >` | o modelo recusou tudo em texto ("Plan Mode (read-only)") sem chamar uma ferramenta; exit 0 |
| `31b-export-plan-session.json` | `opencode export <sessão do 31>` | `info.agent: "plan"`; `info.permission` traz só os três `deny` do modo `run`: as regras do agente não vêm no export |
| `32-agent-list.txt` | `opencode agent list` | as regras de permissão de cada agente (`build`, `plan`, `general`, `explore`, `compaction`, `summary`, `title`, e o `image-analyzer` do operador): a fonte dos defaults; o `plan` mantém `bash: allow` |
| `33-dashdash-and-share-disabled` | `OPENCODE_CONFIG_CONTENT='{"share":"disabled","permission":{"task":"deny"}}'`, `-- 'Reply with exactly: dashdash'` | respondeu `dashdash`; exit 0; stderr vazio: o `--` e a chave `share` são aceites |
| `34-paid-provider-cost` | `-m pdm_ai/glm-5.3-flash` (pago, 0.033011 / 0.139816 por 1M), `Reply with exactly: ok` | `cost: 0.000426176016`, `tokens{input:12800, output:3, reasoning:23}`: o custo reportado bate com a fórmula num preço real |
| `34b-paid-provider-cost-logs` | `-m pdm_ai/Nemotron-3.5-Lightning --print-logs --log-level DEBUG`, 40 s | o log pára em `llm runtime selected` e nada mais acontece: o router não responde para este modelo e o CLI espera para sempre; a primeira tentativa (150 s) também não escreveu um byte |
| `35-hung-resume-cpu` | o 08c repetido (resume com `--dir` errado), amostrando de 15 em 15 s o CPU da árvore do processo como o `tree_cpu_seconds` do motor (`ps -eo pid,ppid,time`), o tamanho do stdout e o número de processos, durante 240 s | `cpu=2` aos 15 s, `3` aos 90 s, `4` aos 165 s; `stdout=0` sempre; `procs=1` sempre: o ralenti de um processo bun pendurado é ~13 ms por segundo, e chega para um watchdog que só olha a "mudou ou não mudou" |
| `36-export-pipe-truncation.meta.txt` | durante a aceitação (T12): `opencode export` da sessão da análise de segurança (35 turnos) para um pipe (`$( )`, e `Popen`+`communicate`, de três directórios) e para um ficheiro; o mesmo para a sessão do job (4 turnos) e para `models --verbose` | para o pipe: rc 0 e **65536 bytes**, cortado a meio, não é JSON (o motor registou "export gave no model"); para o ficheiro: 264607 bytes, JSON válido, `info.model` presente; a sessão de 4 turnos (19395 bytes) sai inteira dos dois lados; `models --verbose` são 15435 bytes por 13 modelos (~1,2 KB por modelo: um catálogo de 55+ modelos passaria os 64 KiB). Consequência: toda a captura do stdout do CLI que possa passar 64 KiB vai por ficheiro, nunca por `$( )`. O stream da corrida NÃO sofre do mesmo: o `.raw` da análise de segurança (35 turnos) tem 173232 bytes, 85 eventos, todos parseáveis, o último `step_finish{reason: stop}`, lido pelo normalizador através do FIFO à medida que o CLI escreve; o corte é uma corrida entre uma escrita grande e a saída do processo, não um tecto do pipe |
| `models-after-provider-change.txt`, `models-verbose-after-provider-change.txt` | `opencode models` / `--verbose`, depois da troca de chave | 7 `opencode/*-free` mais 6 `pdm_ai/*` com `cost` real, `limit`, `variants` e `toolcall: true` em todos |

## O que não ficou medido, e porquê

- **Quota esgotada / rate limit.** Os modelos gratuitos do Zen não a
  devolveram durante as medições e não há como a forçar. Pela forma do 16, um
  429 chegaria como `error{name: "APIError", data{statusCode: 429}}`; a spec
  trata-o como inferência da forma, não como facto.
- **`step_finish.reason` além de `stop` e `tool-calls`.** Só esses dois foram
  vistos.
- **Modelos com `toolcall: false`** (`pdm_ai/deepseek-v4-flash`,
  `pdm_ai/qwen3.5-vision`): não foram corridos, para não gastar a conta do
  operador num caso que o catálogo já declara.
- **Janelas de utilização.** Não existem no OpenCode: cada provider tem a sua
  API e nada no stream nem no export fala de janelas.
