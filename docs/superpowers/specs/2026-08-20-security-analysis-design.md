# Análise de segurança por projeto — design

> **Origem:** a proposta de valor do [GitGuard](https://www.gitguard.com.br/)
> (SAST, SCA, segredos e SBOM sobre um repositório, com filtragem de ruído e
> prompts de remediação) trazida para dentro do claude-cron. Brainstorm de
> 2026-08-20. Este documento é o desenho aprovado; o plano de implementação
> vive em `docs/superpowers/plans/`.

**Objectivo:** dar ao claude-cron uma área de segurança autónoma. Escolhes um
projecto registado e uma branch, corres uma análise, recebes um report
descarregável, corriges, corres outra vez e vês uma checklist do que ficou
resolvido, do que não ficou, do que ficou a meio e do que é novo.

---

## O que torna isto diferente do serviço que o inspirou

O GitGuard integra-se em `read-only` e por isso o produto dele acaba onde o
trabalho começa: entrega um prompt para tu ires corrigir. O claude-cron já tem
a máquina que corre agentes com acesso ao código — a mesma que desenvolve
tickets e revê PRs — portanto pode fechar o ciclo. A fase 1 deste desenho não
corrige nada, mas é construída para que a fase 2 seja quase só interface.

Há uma segunda diferença, no motor. O GitGuard precisa de uma camada inteira de
filtragem porque corre motores cegos ao contexto que produzem falsos positivos
em massa. Aqui o SAST é feito por um agente que lê o código à volta e percebe se
o input é sequer alcançável — o ruído não é filtrado depois, não chega a ser
gerado.

---

## Âmbito

**Entra na fase 1:** detecção, ledger com histórico, checklist entre análises e
report descarregável. Funciona num projecto **sem um único job configurado** — o
claude-cron pode ser instalado só para isto.

**Fica para a fase 2:** o botão *Corrigir com agente*, que abre um PR contra a
branch analisada passando por `closing-review-findings`.

**Fica para a fase 3:** alertas de críticos via `config/hooks/on-run-end.sh`,
histórico de postura ao longo do tempo, e análise agendada para quem a quiser.

**Fora de âmbito, por decisão:** subagentes em paralelo no perfil Profundo (a
arquitectura escolhida é de um agente só); leitura de código de terceiros
(`node_modules/`, `vendor/`); e qualquer verificação que envie um segredo para
fora da máquina.

---

## Decisões tomadas, e porquê

| Decisão | Porquê |
|---|---|
| A análise é um **run de primeira classe sem job** | herda watchdog, budget, stream ao vivo, trace turno-a-turno e pesquisa full-text. Uma análise que morre a meio investiga-se onde tudo o resto se investiga. |
| **Facto por branch, decisão por projecto** | comparar `main` com `develop` faria metade dos achados parecerem novos. Mas marcar um falso-positivo em `develop` e vê-lo ressuscitar em `main` seria insuportável. |
| A análise é **por repositório** | num projecto de um só repo é indistinguível de "por projecto". Mantém a chave do ledger simples sem fechar a porta ao multi-repo. |
| **Perfil escolhido na corrida, com tecto** | a baseline de um monorepo é cara; as corridas seguintes são o diff e são baratas. O perfil permite espreitar antes de investir. |
| **Parcial = ocorrências fechadas + juízo do agente** | a contagem dá uma âncora objectiva e verificável; o juízo apanha a correcção que faz o padrão desaparecer sem fechar o buraco. |
| **Segredos: árvore actual + histórico na baseline** | a chave apagada num commit posterior continua comprometida e é o cenário que mais vaza. É Python sobre `git log`, portanto custa zero tokens. |
| **Um agente, não subagentes** | menos peças e um trace legível, que é o que se quer da primeira vez que uma análise dá um resultado estranho. |
| **CVEs pela OSV.dev sob demanda** | uma base de vulnerabilidades não existe sem alguém a publicá-la. Saem nomes e versões; nunca sai código. |

---

## Arquitectura

Código novo em `bin/security/` (módulos Python: camada determinística, cliente
OSV, ledger, geradores de report), orquestrado por um subcomando `security` em
`bin/claude-cron`. O servidor faz *shell out* para ele, como já faz para tudo o
resto — o engine bash continua a ser a única fonte de verdade, e a interface
visual é a única coisa que o utilizador precisa de tocar.

O contrato do agente vive numa skill versionada em `skills/security-analysis/`,
ligada a `~/.claude/skills` por `claude-cron skills install` como as outras
três. Isto segue a regra do repositório: uma regra que o código exige viaja com
o código, nunca só em `config/`, que é git-ignorado.

### Como a análise corre sem ser um job

Todo o run é indexado por `job id` — slots, locks, ficheiros de log, sessões e o
watchdog. Uma análise não tem job, e dar a `run_job` um segundo modo de
identidade tocaria nas suas mil e tal linhas, cujos comentários documentam bugs
antigos causados por variáveis a vazar entre chamadas.

O código oferece um caminho muito mais barato. **`jobs_json` é uma função de
cinco linhas e é o único ponto por onde `job_get`, `resolve`, `job_exists` e
`run_job` leem os jobs** — nove chamadas, todas de leitura. Quem não passa por
lá é exactamente quem não deve ver a análise: o **tick** lê `$JOBS_FILE`
directamente com `jq`, o **servidor** lê-o directamente em Python, e
`write_jobs` escreve directamente no ficheiro.

Portanto `jobs_json` passa a emitir os jobs reais **mais um job derivado por
projecto com segurança activa**, com o id `security-<slug do projecto>`. As
consequências saem por construção, não por disciplina: o tick nunca o agenda, a
área de Jobs nunca o mostra, `config/jobs.json` nunca o contém, e `run_job`
corre-o sem uma linha alterada.

Isto **não** é o "job interno oculto" que foi descartado no brainstorm. Aquele
escrevia em `config/jobs.json` entradas que o utilizador não criou. Aqui esse
ficheiro não é tocado: a entrada é derivada da configuração de segurança que o
utilizador criou no projecto e materializada em memória no momento da leitura.
Apagar essa configuração faz o job desaparecer.

O prefixo `security-` fica **reservado**: `cmd_create` e `cmd_rename` recusam-no,
para que um job real nunca colida com um derivado.

Os parâmetros que variam por corrida — branch e perfil — vivem num pedido em
disco, `data/security/requests/<job-id>.json`, escrito antes do arranque e lido
pelo gerador do prompt e pela criação da worktree.

### As seis fases de uma análise

1. **Preparar** — worktree limpa cortada da branch escolhida, **sem
   provisioning**: ler código não precisa de `.env` nem de containers. Reutiliza
   `bin/worktree-lib.sh` com uma entrada nova que aceita uma branch explícita em
   vez de a derivar do `base` do projecto. O checkout canónico nunca é tocado.
2. **Determinística** — Python, segundos, zero tokens. Segredos (árvore inteira,
   mais o histórico se for a baseline daquela branch), inventário de dependências
   a partir dos lockfiles, SBOM CycloneDX, higiene de repositório (`.env` ou
   chaves versionadas, `.gitignore` em falta). Escreve no ledger imediatamente.
3. **CVEs** — o inventário vai à OSV.dev; os resultados entram no ledger. Também
   instantânea. A partir daqui a página já tem o que mostrar.
4. **Agente** — o run Claude. Faz o SAST no âmbito do perfil, a triagem dos
   achados determinísticos (aquele "segredo" é um exemplo na documentação?
   aquele CVE está no caminho de execução?) e a reverificação dos achados que
   ficaram abertos na corrida anterior.
5. **Consolidar** — calcula o diff contra a análise anterior da mesma branch,
   aplica as decisões de projecto, fecha a análise e gera os reports.
6. **Limpar** — a worktree desaparece.

**O agente nunca escreve no ledger directamente.** Reporta através de um comando
do CLI que valida e persiste. O agente é não-determinístico; a integridade do
histórico que produz a checklist não pode depender de ele ter escrito o JSON
certo.

**Resultado progressivo:** como a camada determinística escreve antes de o agente
arrancar, a interface mostra segredos e CVEs poucos segundos depois do clique, e
os achados de SAST entram à medida que saem. Não é uma funcionalidade do motor —
é uma consequência da ordem das fases.

---

## Modelo de dados

SQLite em `data/security.db`, separado de `data/app.db` (que guarda operador e
sessões). SQLite e não ficheiros JSON porque tudo o que a área faz são queries —
filtrar por severidade, calcular o diff, agregar postura — e porque a fase
determinística escreve enquanto a página lê, o que quer transacções.

**`analysis`** — uma corrida: `project`, `repo`, `branch`, `commit_sha`,
`profile`, `started`, `ended`, `state` (`running` | `done` | `failed` |
`capped`), `spend_usd`, e `run_id`, que liga ao trace completo no histórico de
Runs.

**`finding`** — um achado numa branch: `fingerprint`, `category` (`secret` |
`dependency` | `sast` | `hygiene`), `rule`, `severity`, `title`, `rationale`,
`remediation`, `first_seen_analysis`, `last_seen_analysis`.

**`occurrence`** — os sítios concretos de um achado: `file`, `line`,
`snippet_hash`, `state`. É esta tabela que produz o *"3 de 5 sítios corrigidos"*.

**`decision`** — a decisão humana, ligada ao **projecto** e não à branch:
`state` (`accepted` | `false_positive`), `reason` (obrigatória), `decided_by`,
`decided_at`.

### Fingerprint

`sha256(category + rule + path + hash do trecho normalizado)`, com o trecho
normalizado colapsando espaço em branco, para que reformatar um ficheiro não
ressuscite o report inteiro.

**Excepção para segredos:** o trecho nunca entra no cálculo. Um hash do valor
seria um oráculo do próprio segredo — fraco, mas real. A chave é
`tipo + caminho + ordem da ocorrência no ficheiro`.

### Os estados da checklist

Derivados da comparação com a análise anterior **da mesma branch**, nunca
guardados:

| estado | como é calculado |
|---|---|
| `new` | fingerprint que não existia |
| `open` | existia, continua igual |
| `partial` | algumas ocorrências fechadas, ou o agente marcou mitigado-não-eliminado com justificação |
| `fixed` | desapareceu |
| `regressed` | reapareceu depois de ter estado `fixed` |

`regressed` não estava no pedido original e vale o custo — diz o que `new`
esconde: isto já tinha sido corrigido e voltou, o que normalmente significa que a
correcção fechou o sintoma e não a rota. Deriva-se sem estado novo: o
`fingerprint` reaparece e já existe um `finding` daquela branch cujo
`last_seen_analysis` não é a análise anterior. A linha do `finding` sobrevive ao
`fixed` precisamente para isto.

Só `accepted` e `false_positive` são persistidos, porque só esses são uma decisão
humana. **Consequência a documentar na interface:** se marcares um falso-positivo
e o código daquele sítio mudar, o fingerprint muda e o achado volta como `new`. É
o comportamento correcto — é código diferente — mas é surpreendente se não for
dito.

### Retenção

As análises ficam todas; são pequenas. O SBOM guarda-se apenas o da análise mais
recente de cada branch, que é o único artefacto grande.

---

## Report

Abre com **o que foi analisado**: projecto, repo, branch, commit, perfil, data, e
a **cobertura** — se o tecto cortou a análise, o report diz o que não chegou a ser
visto. Depois o sumário por severidade, a checklist com os seis baldes, e os
achados com localização, porquê e como corrigir. O SBOM vai em anexo.

Formatos: **Markdown, JSON e HTML**. O PDF é o HTML impresso, com CSS de
impressão para o efeito. O JSON é o formato de máquina e é o que a fase 2 dará ao
agente de correcção.

Os reports **não são guardados em disco**: são gerados no momento do download, a
partir do ledger. Assim um risco aceite depois da análise aparece já aceite no
ficheiro que descarregas, em vez de te dar um artefacto congelado que discorda da
página que tens aberta.

**Valores de segredos nunca aparecem, em formato nenhum.** Nem mascarados. O
report dá tipo, ficheiro, linha e fingerprint — o suficiente para agir, e nada
que valha a pena vazar.

---

## Interface

Entrada nova no `sidenav` de `bin/dashboard.html`, entre *Projects* e *Settings*,
seguindo o padrão `data-view` já existente.

**Ecrã de lista** — os projectos registados, todos, tenham jobs ou não, cada um
com a postura por severidade, a última análise e a branch dela.

**Ecrã de projecto** — selector de repo (só aparece em projectos multi-repo),
selector de branch (as branches reais do checkout, mais campo livre), selector de
perfil, botão **Analisar**. Durante a corrida, as fases a progredir e os achados a
entrar. No fim: sumário por severidade, a checklist, a lista filtrável, e os
botões de download. Por baixo, o histórico de análises daquela branch, cada linha
ligada ao run.

**Detalhe de um achado** — ocorrências, porquê, remediação, e as acções **Aceitar
risco** e **Falso-positivo**. A razão é **obrigatória** nas duas: uma decisão sem
motivo escrito é indistinguível de um engano daqui a três meses, e vai sobreviver
a todas as análises futuras.

---

## Configuração por projecto

Quarto separador no editor de projecto, ao lado de `project`, `repos` e `prov`.
Persiste no bloco `security` de `config/projects.json`:

```json
"security": {
  "enabled": true,
  "model": "claude-opus-5",
  "effort": "",
  "claude_config_dir": "",
  "default_profile": "standard",
  "max_budget_usd": 5,
  "daily_budget_usd": 20,
  "min_severity": "medium",
  "ignore_paths": ["tests/fixtures/**"]
}
```

`claude_config_dir` vazio herda o do projecto, que por sua vez herda o do
install — é isto que decide **com que conta Claude** a análise assina, e sem ele
a análise não sabe com que Claude correr. `effort` vazio deixa a decisão ao CLI,
como nos jobs. `daily_budget_usd` é o tecto diário das análises **daquele
projecto**, contado à parte do que os jobs gastam.

Os dois filtros fazem coisas diferentes e é preciso não os confundir.
`ignore_paths` exclui caminhos **da análise**: o agente não os lê e não se paga
por eles. `min_severity` filtra apenas o que é **mostrado e reportado** — tudo o
que é encontrado é guardado no ledger, para que baixar o limiar mais tarde revele
o que já lá estava em vez de obrigar a reanalisar.

Os três perfis definem o alcance do SAST; a camada determinística corre por
inteiro em todos eles. **`quick`** olha só para o código que toca input externo
(handlers HTTP, comandos CLI, consumidores de fila, desserialização, SQL e
`exec`/`eval`). **`standard`** acrescenta o código que esse alcançável chama,
seguindo as chamadas em profundidade. **`deep`** cobre todo o código versionado,
incluindo caminhos que hoje nada invoca.

---

## Falhas e limites

Isto importa mais do que o caminho feliz:

- **Branch inexistente** — recusado antes de se cortar a worktree.
- **Sem rede para a OSV** — a fase de CVEs falha, a análise **continua**, e o
  report declara que o SCA não correu. Uma lacuna dita é útil; uma lacuna
  silenciosa faz confiar num report que não olhou para as dependências.
- **Tecto atingido** — a análise fecha como `capped`, guarda o que apurou, e o
  report diz o que ficou por ver. Nunca finge cobertura.
- **Agente morre** — a análise fica `failed` e os achados determinísticos já
  escritos **ficam**. Investiga-se no run.
- **Duas análises do mesmo repo e branch** — a segunda é recusada. Branches
  diferentes correm em paralelo, ocupando slots do motor como qualquer run: uma
  análise não tem prioridade sobre os jobs, nem eles sobre ela.

---

## Testes

`tests/` (pytest) e `test/` (shell), seguindo o que já existe.

- Fingerprint **estável** perante reformatação e **instável** perante mudança
  real.
- Os seis estados da checklist, incluindo `regressed` e o `partial` por contagem
  de ocorrências.
- Decisões de projecto atravessam branches; decisões não atravessam uma mudança
  de fingerprint.
- OSV indisponível → análise completa com a lacuna declarada no report.
- Tecto → estado `capped` e cobertura declarada.
- Worktree cortada da branch pedida, sem provisioning, e removida no fim.
- Análise recusada em branch inexistente e em corrida duplicada.

**Teste adversarial não-negociável:** injectar um segredo conhecido numa fixture
e assertar que aquela string **não aparece em lado nenhum** — nem no ledger, nem
em nenhum dos três formatos de report, nem no log do run. É a promessa mais fácil
de quebrar por acidente, num `print` de debug ou num campo de contexto.

**Fidelidade das fixtures (nono eixo de `closing-review-findings`):** a fixture da
resposta da OSV.dev tem de ser uma **resposta genuína capturada**, não JSON
escrito à mão a partir da documentação — senão o parser e o teste concordam um
com o outro enquanto ambos discordam do serviço.

---

## Riscos e questões em aberto

1. **Custo da baseline num monorepo.** O tecto protege a carteira mas produz
   `capped`, e um report parcial repetido é um produto mau. Se acontecer com
   frequência, a resposta é o fatiamento por subagentes — deliberadamente fora
   desta fase.
2. **Qualidade do SAST por agente é não-determinística.** Duas corridas sobre
   código intocado podem discordar. A reverificação ancorada no fingerprint
   limita a oscilação, mas não a elimina. Vale medir na prática antes de
   prometer estabilidade.
3. **Cobertura da detecção de segredos.** Um conjunto de padrões próprio começa
   mais pobre do que uma ferramenta madura. Mitigação: começar pelos formatos de
   alto valor e alta confiança (chaves de cloud, tokens de fornecedores comuns,
   chaves privadas) e crescer com base no que aparece.
4. **Dependência da OSV.dev.** É gratuita e pública, mas é um terceiro. A
   degradação está desenhada; a ausência prolongada deixa o SCA inoperante.
