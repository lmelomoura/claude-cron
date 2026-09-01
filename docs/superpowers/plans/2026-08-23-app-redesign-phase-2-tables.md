# Plano de implementação — Fase 2: Jobs, Runs e Projects

> **Para agentes:** SUB-SKILL OBRIGATÓRIA: usar superpowers:subagent-driven-development (recomendado) ou superpowers:executing-plans para executar este plano tarefa a tarefa. Os passos usam checkbox (`- [ ]`) para acompanhamento.

**Objetivo:** dar às três páginas de tabela — Jobs, Runs e Projects — a linguagem visual que o Overview já fala, movendo os seus 876 linhas de renderização para módulos ES sob `ui/app/`.

**Arquitetura:** o padrão da Fase 1, sem alterações. Um `ui/app/chrome.js` novo recolhe as peças genéricas que hoje vivem em `overview.js`; cada página ganha o seu módulo; `jobs-table.js` torna-se o segundo consumidor de `jobs-domain.js`, cumprindo a promessa que justificou mover esse domínio inteiro na fase anterior.

**Stack:** Bash, Python 3 stdlib, módulos ES vanilla empacotados por `esbuild@0.25.0`, pytest, Node (só no harness de teste).

## Restrições globais

- **As dependências de runtime nunca crescem.** Instalar o claude-cron precisa de `jq`, `python3`, `curl`, `git`, `bash` — nunca Node. Os artefactos de build vão committados.
- **Prosa entregue em inglês.** Código, identificadores, docstrings, comentários de código, mensagens de commit, README, CHANGELOG: inglês. Apenas a prosa deste plano e da spec é pt-PT.
- **`esbuild` fixo em `0.25.0`**, invocado por `npx --yes`.
- **`ui/` não pode conter** `innerHTML`, `insertAdjacentHTML`, `outerHTML`, `createContextualFragment`, `DOMParser` nem `setAttribute("on`. O teste `test_the_built_ui_never_builds_dom_from_html_strings` varre tudo sob `ui/`.
- **Toda a classe que a UI usa tem de ter regra no CSS construído.** `test_no_class_the_shipped_ui_uses_lacks_a_css_rule` apanha literais; classes construídas a partir de variáveis passam-lhe ao lado e verificam-se a olho.
- **Cada tarefa escreve a sua entrada no CHANGELOG.md, no mesmo commit.** O selftest compara o último commit que tocou `bin/`, `skills/` ou `test/` com o último que tocou o CHANGELOG.
- **O selftest corre DEPOIS do commit.** A guarda do changelog lê o `git log`, não a árvore de trabalho; corrido antes, está a ler o estado da tarefa anterior.
- **Artefactos committados no mesmo commit que as fontes.** `bash build/build-ui.sh` antes do `git add`; os três artefactos entram juntos.
- **Branch:** `feat/security-analysis`. Sem branches novas.
- **Os testes de caracterização existentes ficam verdes e por editar.**

---

## Estrutura de ficheiros

**Criados:**

| Caminho | Responsabilidade |
|---|---|
| `ui/app/chrome.js` | `pageHeader`, `kpiCard`, `filterBar`, `tableCard`, `tableFooter` — o vocabulário partilhado por todas as páginas |
| `ui/app/jobs-table.js` | A tabela Jobs: colunas, ordenação, filtros, estados vazios |
| `ui/app/projects.js` | A tabela Projects e a sua coluna de segurança |
| `ui/app/runs.js` | A tabela Runs, os seus filtros e paginação |
| `ui/app/run-log.js` | O modal de log, movido sem restyle |

**Modificados:** `ui/app/overview.js` (perde as peças genéricas), `ui/app/index.js`, `ui/app/page.js`, `ui/css/components.css`, `ui/css/pages.css`, `bin/dashboard.html`, `tests/test_page_contract.py`.

---

## Tarefa 1: `chrome.js` — as peças genéricas ganham casa

A revisão final da Fase 1 avisou: `pageHeader` e `kpiCard` são deliberadamente genéricos e vivem num ficheiro chamado `overview.js`. Seis páginas a importá-los de lá é um nome a mentir seis vezes. Move-se agora, com um consumidor.

**Ficheiros:**
- Criar: `ui/app/chrome.js`
- Modificar: `ui/app/overview.js`, `ui/app/index.js`

**Interfaces:**
- Consome: `el()` de `overview.js` — que também se muda, por ser genérico.
- Produz: `ui/app/chrome.js` exporta `el(tag, cls, text)`, `pageHeader({icon, title, subtitle, actions})`, `kpiCard({icon, tone, value, label, sub, title, filter, door})`.

- [ ] **Passo 1: mover, sem alterar uma linha**

Mover `el`, `pageHeader` e `kpiCard` de `ui/app/overview.js` para `ui/app/chrome.js`. O `overview.js` passa a importá-los. Nenhum corpo de função muda neste passo.

- [ ] **Passo 2: confirmar que nada se perdeu**

```bash
grep -n 'function el\|function pageHeader\|function kpiCard' ui/app/*.js
```

Esperado: cada um aparece uma vez, em `chrome.js`.

Atenção: o `overview.js` tem um segundo helper de elemento chamado `mk` (por volta da linha 255) e o `ui/security/dom.js` tem `secEl`. **Não os unificar nesta tarefa** — a duplicação está registada e é deliberada enquanto os dois bundles se mexem. Se `mk` e `el` forem hoje idênticos, dizê-lo no relatório sem agir.

- [ ] **Passo 3: correr a suite**

`pytest -q` — esperado: verde, sem alterações a testes. As dez caracterizações leem estas funções pelo texto da fonte (`_app_js` + `_plainfn`), que continua a encontrá-las.

- [ ] **Passo 4: build, gates, commit**

```bash
bash build/build-ui.sh
pytest -q
git add ui/ bin/static CHANGELOG.md
git commit -m "refactor(ui): the generic chrome gets its own file"
bash bin/claude-cron selftest
git status --porcelain
```

Entrada no CHANGELOG sob `### Changed`.

---

## Tarefa 2: pinar a tabela Jobs

Testes de caracterização sobre o que a tabela Jobs **diz** hoje, antes de lhe tocar.

**O portão desta tarefa não é ver os testes falhar** — passam à primeira, é o que caracterizações fazem. É **prová-los falsificáveis**: para cada um, partir o comportamento, ver vermelho, registar a saída, reverter. Um teste que sobrevive à sua própria quebra não pina nada.

**Ficheiros:** modificar `tests/test_page_contract.py`.

- [ ] **Passo 1: extrair o que é preciso para testar**

`renderJobTable` constrói markup em string. Extrair dela as funções puras que os testes leem — a ordenação e a decisão de coluna — para `ui/app/jobs-domain.js` (que já existe e é o sítio certo: não tem DOM).

Concretamente: `sortJobs(rows, key, dir)` devolvendo a lista ordenada, e o mapa `JOB_COLS` das colunas.

- [ ] **Passo 2: escrever os testes**

Cinco, cada um com a sua quebra:

1. **A ordenação por cada coluna** dá a ordem esperada para um conjunto conhecido.
   *Quebra:* inverter o sinal de `dir` num comparador.
2. **As linhas sem resposta vão para o fim**, não para o topo — um job que nunca correu ordenado por «Last run», um desativado ordenado por «Next».
   *Quebra:* remover o predicado `missing`.
3. **O desempate por id não se inverte com a coluna.** Ordenar por projeto duas vezes (asc e desc) e confirmar que dois jobs do mesmo projeto mantêm a mesma ordem relativa.
   *Quebra:* multiplicar o desempate por `dir`.
4. **Os três filtros estreitam o mesmo conjunto** — projeto, estado e pesquisa aplicados juntos.
   *Quebra:* fazer um deles ignorar os outros.
5. **O estado vazio distingue** «ainda não há jobs» de «os filtros não deixaram passar nada».
   *Quebra:* colapsar os dois ramos num.

- [ ] **Passo 3: correr as cinco quebras**

Para cada uma: aplicar, correr só esse teste, confirmar VERMELHO, registar a mensagem, `git checkout --` para reverter.

**Não commitar até as cinco terem um vermelho registado.**

- [ ] **Passo 4: build, gates, commit**

Entrada no CHANGELOG sob `### Changed`.

---

## Tarefa 3: a tabela Jobs move-se e é restilizada

**Ficheiros:** criar `ui/app/jobs-table.js`; modificar `ui/app/index.js`, `ui/css/`, `bin/dashboard.html`.

**Interfaces:**
- Consome: `jobs-domain.js` (`jobFacts`, `visibleJobs`, `jobFilters`, `sortJobs`), `chrome.js`.
- Produz: `renderJobsPage()` — cabeçalho, KPIs, barra de filtros, cartão-tabela, rodapé.

- [ ] **Passo 1: escrever o teste que falha**

Um teste que lê `renderJobsPage` do bundle e confirma que a tabela tem rodapé com «Showing X to Y of N». Falha porque a função não existe.

- [ ] **Passo 2: construir a página em DOM**

Cabeçalho com `pageHeader`. Quatro KPIs: total, ativos, a correr agora, gasto hoje — cada um com um número e um sublabel de três a cinco palavras. Barra de filtros com a pesquisa e os dropdowns que já existem. Cartão-tabela com as sete colunas de hoje. Rodapé com contagem e pager.

**Nada de strings HTML.** `el()` de `chrome.js`.

- [ ] **Passo 3: apagar o que substitui**

`renderJobTable`, `renderJobHead`, `paintJobFilters` e a bifurcação `renderJobs` saem de `bin/dashboard.html`. `initJobDrag` vai com a tabela.

```bash
grep -n 'function renderJobTable\|function renderJobHead\|function paintJobFilters\|function renderJobs\b' bin/dashboard.html
```

Esperado: sem saída.

- [ ] **Passo 4: correr os pinos da Tarefa 2**

Continuam verdes e por editar. Se um falhar, estava a pinar aparência — dizer, não editar.

- [ ] **Passo 5: ver a página**

Ambos os temas. Uma instalação com jobs em estados diferentes: a correr, ativo, idle, desativado, em backoff, no teto.

- [ ] **Passo 6: build, gates, commit**

---

## Tarefa 4: pinar Projects

Mesmo portão de falsificabilidade da Tarefa 2. Quatro testes:

1. **A contagem de jobs por projeto** é a dos jobs que realmente lhe pertencem.
   *Quebra:* contar todos os jobs.
2. **O favorito ordena primeiro** e a estrela reflete o estado.
   *Quebra:* remover o termo de favorito do comparador.
3. **O isolamento lê três estados**, não dois: sempre, nunca, automático.
   *Quebra:* colapsar «automático» num dos outros.
4. **A pesquisa alcança nome, descrição e diretório**, não só o nome.
   *Quebra:* restringir ao nome.

- [ ] **Passo 1:** extrair as funções puras necessárias para `ui/app/projects.js` ou para o domínio, conforme onde caibam sem DOM
- [ ] **Passo 2:** escrever os quatro testes
- [ ] **Passo 3:** correr as quatro quebras e registar cada vermelho
- [ ] **Passo 4:** build, gates, commit

---

## Tarefa 5: Projects move-se, é restilizada, e ganha a coluna Security

**A única informação nova de toda a fase.** Se algo correr mal nesta fase, é aqui.

**Ficheiros:** criar `ui/app/projects.js`; modificar `ui/app/index.js`, `ui/css/`, `bin/dashboard.html`.

- [ ] **Passo 1: descobrir o que a coluna pode dizer**

Ler o bloco `security` de um projeto em `config/projects.json` e o que a API já devolve. A coluna tem de distinguir pelo menos três casos, e **é aqui que se erra**:

- segurança desativada para este projeto
- ativada mas nunca analisada
- ativada e com uma análise, com a sua postura

«Ativada mas nunca analisada» e «sem achados» não são a mesma coisa, e pintá-las igual é a versão desta página do erro que a área Security já pagou: ausência tratada como prova.

Escrever o teste dos três casos **antes** de renderizar a coluna.

- [ ] **Passo 2:** construir a página em DOM — cabeçalho, KPIs, barra de filtros, cartão-tabela com Project, Jobs, Working directory, Repos, Isolation, Security, ações
- [ ] **Passo 3:** apagar `renderProjects` e o que só ela usava
- [ ] **Passo 4:** correr os pinos da Tarefa 4
- [ ] **Passo 5:** ver a página, ambos os temas, com um projeto de cada um dos três estados de segurança
- [ ] **Passo 6:** build, gates, commit

---

## Tarefa 6: pinar Runs

O maior bloco. Mesmo portão. Cinco testes:

1. **A paginação recua** quando um filtro encolhe o conjunto abaixo da página corrente.
   *Quebra:* remover o clamp de `page`.
2. **A pesquisa alcança o conteúdo dos logs**, não só os nomes.
   *Quebra:* restringir aos nomes.
3. **Duration e Cost ordenam independentemente** — o run mais lento e o mais caro raramente são o mesmo.
   *Quebra:* fazer a ordenação por custo cair na de duração. Este é o defeito histórico que o comentário no código descreve.
4. **A contagem do rodapé** conta o conjunto filtrado, não o total.
   *Quebra:* contar o total.
5. **Que estados oferecem Resume** — já pinado noutro teste; **não repetir**, apenas confirmar que continua verde.

- [ ] **Passo 1–4:** como nas tarefas 2 e 4, com os quatro vermelhos registados

---

## Tarefa 7: Runs move-se e é restilizada

526 linhas, das quais 191 são o modal de log.

**O modal move-se SEM restyle.** Não é uma tabela e não faz parte desta linguagem. Vai para `ui/app/run-log.js` tal como está, e o commit tem de o dizer — senão parece uma omissão em vez de uma decisão.

- [ ] **Passo 1: ler `clearRunFilters` antes de a mover**

104 linhas para uma função chamada «limpar filtros» é grande demais para o que o nome promete. Se fizer três coisas, separá-la — mas **sem mudar comportamento nesta fase**. Dizer no relatório o que ela realmente faz.

- [ ] **Passo 2:** construir a página em DOM — cabeçalho, quatro KPIs, barra de filtros (com a pesquisa a dizer que entra nos logs), cartão-tabela com as sete colunas, rodapé com o pager que já existe
- [ ] **Passo 3:** mover o modal de log para `run-log.js`, sem restyle
- [ ] **Passo 4:** apagar o que se substituiu; confirmar por grep
- [ ] **Passo 5:** correr os pinos da Tarefa 6 e os testes de Resume existentes
- [ ] **Passo 6:** ver a página com runs em cada estado, e abrir um log
- [ ] **Passo 7:** build, gates, commit

---

## Tarefa 8: fechar a fase

- [ ] **Passo 1: todos os portões**

```bash
pytest -q
bash bin/claude-cron selftest
bash test/e2e.test.sh
git status --porcelain
```

- [ ] **Passo 2: provar os artefactos frescos**

```bash
bash build/build-ui.sh
git diff --stat bin/static/    # tem de ser VAZIO
```

- [ ] **Passo 3: olhar para a aplicação inteira**

Navegar Overview → Jobs → Runs → Projects → Security nos dois temas. **A pergunta é se as páginas parecem a mesma aplicação** — que é o objetivo desta fase, e nenhum teste responde.

A área Security não foi tocada por esta fase mas partilha a folha de estilos: confirmar que continua correta.

- [ ] **Passo 4: corrigir a spec contra o que aterrou**

`docs/superpowers/specs/2026-08-23-app-redesign-phase-2-tables-design.md`. A spec regista o que aterrou, não o que se esperava. Uma omissão não se descreve como decisão de design.

- [ ] **Passo 5: rever as entradas do CHANGELOG desta fase** — leem-se como uma mudança coerente? Não acrescentar uma entrada de resumo.

- [ ] **Passo 6: commit**

---

## Auto-revisão

**Cobertura da spec.** Cada secção mapeia para uma tarefa: `chrome.js` → T1; as três páginas → T3, T5, T7; os testes antes de cada uma → T2, T4, T6; a coluna Security → T5 passo 1; o modal sem restyle → T7 passo 3; `clearRunFilters` → T7 passo 1; os portões → T8.

**Consistência de tipos.** `el(tag, cls, text)` é a mesma assinatura em `chrome.js` que tinha em `overview.js`. `kpiCard` mantém `{icon, tone, value, label, sub, title, filter, door}` — o `door` distingue um cartão que é botão de um que nunca foi, e o `title` leva a definição longa que não cabe no sublabel; ambos vieram das correções da Fase 1 e não se reabrem. `sortJobs(rows, key, dir)` é introduzida na T2 e consumida na T3 com essa assinatura.

**Um risco que este plano não resolve.** A T7 é a maior tarefa da fase e chega em último. Se a atenção estiver gasta, é aí que se paga — foi por isso que a ordem é do mais pequeno para o maior, mas isso protege o padrão, não o cansaço. Se a T7 começar a derrapar, parti-la em duas (tabela, depois modal) é preferível a empurrá-la inteira.
