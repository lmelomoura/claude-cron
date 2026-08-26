# Redesenho da aplicação — Fase 2: Jobs, Runs e Projects

**Data:** 2026-08-23
**Branch:** `feat/security-analysis`
**Estado:** desenho escrito sem revisão por secções — ver «Como este documento foi escrito»

## Como este documento foi escrito

A Fase 1 passou por brainstorm interativo: quatro secções apresentadas uma a
uma, cada uma aprovada antes da seguinte. Esta não passou. O utilizador pediu
para arrancar a Fase 2 e ficou offline.

O que isso significa na prática: as decisões estruturais **não são novas**. Já
foram tomadas e aprovadas na Fase 1 — a divisão em quatro fases e a sua ordem,
`ui/app/` com o contrato de `page.js`, DOM em vez de strings, testes de
caracterização antes de restilizar, uma entrada de CHANGELOG por tarefa. Este
documento aplica-as a três páginas; não reabre nenhuma.

O que **é** novo está reunido em «Decisões que este documento toma sozinho», no
fim, para poder ser lido em trinta segundos e revertido sem desfazer o resto.

## Porquê

O Overview fala a linguagem nova. Jobs, Runs e Projects não. Quem navega entre
elas vê a aplicação mudar de identidade a meio — e o desalinhamento é visível
desde que a Fase 1 aterrou.

São as três páginas de tabela, e são o pedaço mais autocontido do que falta:

| Página | Funções | Linhas |
|---|---:|---:|
| Runs | 7 | 526 |
| Projects | 6 | 194 |
| Jobs (tabela) | 4 | 156 |

`bin/dashboard.html` está em 4932 linhas. Esta fase tira-lhe mais 876 de
renderização, além do que o restyle acrescentar em CSS.

**Correção pós-fecho: esta tabela e o "876" não são de fiar.** Vêm do mesmo
script de medição que errou a contagem de `clearRunFilters` em 17 vezes (ver
«Riscos conhecidos», mais abaixo) — contava a distância até à próxima
declaração de topo do ficheiro, não o corpo real da função. Verificado num
caso: as três funções que de facto saíram para `ui/app/jobs-table.js`
(`renderJobHead`, `renderJobTable`, `paintJobFilters`) somam **84 linhas
reais** por contagem de chavetas, não as 107 que o método da "próxima
declaração" produz para as mesmas três. Não vale a pena reverificar cada
número desta tabela um a um — o método que os produziu já está provado
errado — mas nenhum deles deve ler-se como facto assente. O "876" erra por
uma segunda razão, mais simples de verificar: inclui as ~191 linhas do
modal de log, que a Tarefa 7 (ver mais abaixo) acabou por não mover. O que
de facto aconteceu, medido em `git diff --stat` do commit desta spec até ao
fim da fase: `bin/dashboard.html` foi de 4931 para 4579 linhas — 776
apagadas, 424 acrescentadas, líquido de 352 — não os 876 previstos.

## O que cada página passa a ser

As três partilham a mesma anatomia, que é o ponto — hoje cada uma tem a sua.

**Cabeçalho de página.** Ícone contornado em accent, título, uma frase cinzenta
escrita a partir dos números reais, ações à direita. O mesmo `pageHeader()` que
o Overview usa.

**Cartões KPI**, onde há números que valham um. Quatro no máximo. A regra de um
número por rótulo aplica-se: o segundo número de um par vai no sublabel.

**Barra de filtros.** Pesquisa à esquerda, dropdowns em pill, ações à direita.
As três páginas já têm filtros; hoje cada uma os apresenta à sua maneira.

**Cartão-tabela.** Cabeçalhos de 11px em maiúsculas, linhas de ~62px, células
de duas linhas onde a segunda é contexto cinzento, estado como pill, ações
alinhadas à direita — uma primária e um kebab.

**Rodapé com «Showing X to Y of N» e um pager**, mesmo quando há uma página só.
Runs já tem paginação; Jobs e Projects não têm nada.

### Jobs

Colunas como hoje: Job, Project, Status, Schedule, Last run, Next, Today. Os
KPIs vêm do que a página já sabe — total, ativos, a correr agora, gasto de hoje.

A ordenação por coluna mantém-se, incluindo a regra de que as linhas sem
resposta para a coluna ordenada (um job que nunca correu, um desativado sem
«próximo») vão para o fim em vez de fingirem um valor.

### Runs

Colunas como hoje: When, Job, Project, Status, Duration, Cost, Session.
**Duration e Cost ficam colunas separadas** — o comentário no código explica
porquê, e merece sobreviver: juntá-las já deixou cair a ordenação por custo,
tornando o run mais caro do dia impossível de encontrar numa página de 25.

A pesquisa que entra dentro dos logs mantém-se, e a barra de filtros tem de
dizer que é isso que faz.

### Projects

Colunas como hoje: Project, Jobs, Working directory, Repos, Isolation. Mais
uma coluna **Security**, que o mockup pede e a página não tem, lida do bloco
que a Fase 1 do trabalho de segurança já escreve.

A estrela de favorito mantém-se, e mantém o seu efeito: um projeto favorito
sobe ao topo em Jobs.

## Arquitetura

O padrão não muda. Acrescenta-se:

```
ui/app/chrome.js       pageHeader, kpiCard (Tarefa 1); filterBar, tableCard e
                        tableFooter só chegam numa tarefa seguinte -- ver a
                        correção logo abaixo
ui/app/jobs-table.js    o segundo consumidor de jobs-domain.js
ui/app/runs.js          a tabela e os filtros -- o modal de log NÃO se move,
                        ver «Tarefa 7», mais abaixo
ui/app/projects.js      a tabela e a sua coluna de segurança
```

**`chrome.js` existe por causa de um aviso da revisão final da Fase 1.**
`pageHeader` e `kpiCard` são deliberadamente genéricos e vivem em
`ui/app/overview.js`. Seis páginas a importar peças genéricas de um ficheiro
chamado `overview.js` é um nome a mentir seis vezes. Move-se agora, com um
consumidor, em vez de depois com seis.

**Correção pós-fecho: só dois dos cinco chegaram nesta primeira tarefa.**
`pageHeader` e `kpiCard` mudam-se para `chrome.js` na Tarefa 1
(`f63654c`); `filterBar`, `tableCard` e `tableFooter` — que este bloco já
listava aqui como se tivessem chegado juntos — só se juntam a eles numa
tarefa seguinte (`0d1a80b`), e não por planeamento: uma inspeção depois da
Tarefa 3 (Jobs) aterrar apanhou a página de Jobs a ter improvisado a sua
própria tabela e a sua própria barra de filtros em vez de usar os
construtores partilhados que esta spec previa desde o início — a mensagem
desse commit di-lo sem rodeios: *"an inspection after Phase 2 Task 3 landed
found the Jobs page had improvised its own table and filter-bar structure
instead of the shared builders the plan named."* A lição não é o atraso —
é que prever os cinco construtores de uma vez não bastou para os obter de
uma vez; só uma inspeção deliberada, feita depois do facto, apanhou o
desvio antes de Projects e Runs o repetirem uma segunda e terceira vez.

**`jobs-table.js` é o segundo consumidor prometido.** A Fase 1 moveu o domínio
de jobs inteiro para `jobs-domain.js` precisamente para que esta fase não
tivesse de o duplicar. Esta é a fase que cobra essa promessa: a tabela lê
`jobFacts` e `visibleJobs` do módulo, e `renderJobs` — a bifurcação entre
cartões e tabela que ficou em `bin/dashboard.html` — desaparece com ela.

**`paintJobFilters` sai agora — `initPickers` fica.** A correção à spec da
Fase 1 registou que os dois ficaram para trás por desenharem a tabela, e
previa que sairiam juntos nesta fase. Só se confirmou metade:
`paintJobFilters` sai, renomeada `paintJobFilterBar()`, para
`ui/app/jobs-table.js`. `initPickers()` fica em `bin/dashboard.html` — o
próprio ficheiro explica porquê, num comentário deixado exactamente para
isto: a função não constrói só os dois pickers de Jobs, constrói também os
quatro pickers de Runs, e entregar os de Runs não era desta tarefa. Os
OBJETOS dos pickers de Jobs (`projPicker`, `jobStatusPicker`) ficam pela
mesma razão; só o seu repaint (`paintJobPickers()`, alcançado através da
interface da página) é que atravessa para o módulo novo.

## Testes

O mesmo portão da Fase 1, pela mesma razão: **testes de caracterização passam à
primeira, portanto o portão não é vê-los falhar — é prová-los falsificáveis.**
Partir o comportamento, ver vermelho, reverter, registar.

Antes de tocar em cada página:

**Jobs** — a ordenação por cada coluna, e as linhas sem resposta a irem para o
fim; o desempate por id que não se inverte com a coluna; os filtros de projeto,
estado e pesquisa a estreitarem o mesmo conjunto; o estado vazio a distinguir
«ainda não há jobs» de «os filtros não deixaram passar nada».

**Runs** — a paginação (a página corrente a recuar quando o filtro encolhe o
conjunto); a pesquisa a alcançar o conteúdo dos logs e não só os nomes; que
estados oferecem Resume, que já está pinado e não se repete; Duration e Cost a
ordenarem independentemente.

**Projects** — a contagem de jobs por projeto; os favoritos; o modo de
isolamento a ler três estados e não dois; a coluna de segurança a distinguir
«desativado» de «ativo mas nunca analisado».

Não se pina aparência: nomes de classes, ordem de markup, contagem de
elementos, texto de rótulos que vão mudar.

## Riscos conhecidos

**O bloco de Runs é o maior e o mais entrelaçado.** `renderLog` e `paintLog`
(191 linhas juntas) desenham o modal de log, que tem um terminal, realce e
seguimento de scroll. O modal não é uma tabela e não faz parte do redesenho —
**move-se sem ser restilizado**, e isso deve ser dito no commit em vez de
descoberto depois.

**Correção pós-Tarefa 7: não se moveu, nem restilizado nem tal-e-qual.** Ver
a secção própria mais abaixo — a diferença entre "fica para trás" e "move-se
sem restyle" acabou por ser real, não cosmética, e a spec previa a segunda.

**`clearRunFilters` tem 104 linhas.** É grande demais para o que o nome promete
e provavelmente faz mais do que limpar. Lê-se antes de mover; se fizer três
coisas, separa-se — mas o comportamento não muda nesta fase.

**Correção pós-Tarefa 7: a contagem estava errada.** `clearRunFilters` mede
6 linhas, não 104, e faz uma coisa — repõe os cinco campos de filtro, os dois
campos de data, a caixa de pesquisa e a página, e repete a pesquisa em
seguida. Os "104" vieram de um script de medição que contava tudo entre duas
declarações de topo, não o corpo da função; não há três responsabilidades
por separar porque nunca lá estiveram. Ver o relatório da Tarefa 6/7
(`.superpowers/sdd/f2-task-6-7-report.md`) para o que foi de facto verificado.

**A coluna Security em Projects é a única informação nova em toda a fase.**
Tudo o resto é o que já está lá, noutro sítio. Se algo correr mal, é aqui.

## Decisões que este documento toma sozinho

Sem aprovação prévia, porque o utilizador está offline. Cada uma é revertível
isoladamente:

1. **`chrome.js` nasce nesta fase**, levando `pageHeader` e `kpiCard` do
   `overview.js`. Recomendado pela revisão final da Fase 1.
2. **Projects ganha uma coluna Security.** Está no mockup; a página não a tem.
3. **O modal de log move-se sem restyle.** É o único componente que a fase toca
   sem redesenhar, e fá-lo para não inchar o âmbito.

   **Correção pós-Tarefa 7: não aterrou assim.** O modal ficou em
   `bin/dashboard.html`, ponto final — ver a secção própria, mais abaixo,
   para a razão.
4. **A ordem das tarefas é Jobs → Projects → Runs**, do mais pequeno para o
   maior, para que o padrão esteja estabelecido quando chegar às 526 linhas de
   Runs.

## Tarefa 7: o modal de log fica em bin/dashboard.html

**Correção pós-fecho: a versão original desta secção enquadrava isto como
uma escolha de âmbito, pesada e decidida durante a implementação. Não foi
isso que aconteceu.** O que forçou a decisão foi um conflito técnico
concreto com uma regra já em vigor no repositório, e quem decidiu não foi
quem implementava — foi o utilizador, depois de o conflito lhe ser levado.
Ver `.superpowers/sdd/f2-task-6-7-report.md`, secção «O modal de log —
moveu-se sem sink?», para o relato completo; o que se segue é a versão
corrigida.

A opção que esta spec previa — mover `renderLog`, `paintLog` e `openLog`
tal e qual para `ui/app/run-log.js`, sem restyle — entra em conflito
directo com uma regra global que já protegia todo o `ui/`: nada ali pode
construir DOM a partir de strings de HTML (`innerHTML`), e um teste que já
existia antes desta tarefa —
`test_the_built_ui_never_builds_dom_from_html_strings` — varre a árvore
`ui/` inteira, não só `ui/security/`. O modal, tal como está hoje, é
construído quase inteiramente por atribuições a `innerHTML` (as ~191 linhas
de `renderLog`/`paintLog` juntas: os separadores, as linhas `<dl>`, a
timeline, o terminal). Movê-lo tal e qual para dentro de `ui/` teria
introduzido um sink real exactamente onde este teste já vigiava, e teria
sido apanhado de imediato, não descoberto depois.

Este conflito foi levado ao utilizador antes de se tocar no modal — não
resolvido sozinho pela implementação. A decisão foi a opção (B): o modal
fica em `bin/dashboard.html`, tal como estava, e a conversão para
construtores de DOM fica registada como tarefa à parte.

Duas razões adicionais, que continuam válidas mas nunca foram a que decidiu
o ponto: o modal não é uma tabela — é um terminal com seguimento de scroll
ao vivo, realce de sintaxe e uma caixa de entrada — e transformar as suas
191 linhas em construtores de DOM é uma reimplementação, exactamente o tipo
de componente em que um comportamento desaparece em silêncio (uma condição
de scroll mal traduzida, um `keydown` que deixa de ser capturado, um estado
de "a seguir ao vivo" perdido a meio de uma reconstrução). E o modal
desenha o que o agente escreveu — entrada não confiável — pelo que o
`innerHTML` que usa hoje vale a pena remover pelos seus próprios méritos
mesmo depois de resolvido o conflito com a regra do `ui/`, já que ficar em
`bin/dashboard.html` o isenta dessa regra mas não do risco que ela existe
para fechar.

Ficou registado como tarefa à parte: converter `renderLog`/`paintLog` para
construtores de DOM, com os seus próprios testes de caracterização e a sua
própria passagem de falsificabilidade — o mesmo portão que já protegeu as
três tabelas nesta fase.

## Achado do fecho: a Security fala a língua antiga

Secção não prevista nesta spec — é um achado de andar pela aplicação viva
no fecho da fase, e fica aqui porque define o âmbito real da Fase 4, não
porque seja um defeito desta.

Quatro páginas — Overview, Jobs, Runs, Projects — partilham agora uma
anatomia: `pageHeader()`, cartões de `kpiCard()`, `filterBar()`,
`tableCard()` com `tableFooter()`. A Security, que esta fase nunca tocou,
visivelmente não a partilha:

1. **Sem cabeçalho de página.** `view-security` (`bin/dashboard.html`) abre
   com um `<p class="paneblurb">` de prosa solta — "What the last analysis
   of each project found…" — onde qualquer página convertida tem ícone +
   título + uma frase cinzenta + ações à direita, via `pageHeader()`.

2. **Os cartões KPI estão invertidos.** `secIndexCard()`
   (`ui/security/index-screen.js`) põe ícone e RÓTULO na primeira linha
   (`.secidx-card-h`) e o número por baixo (`.secidx-num`) — exactamente a
   inversão que a Fase 1 encontrou e corrigiu nos cartões do Overview.
   `kpiCard()` (`ui/app/chrome.js`) faz o inverso: ícone e número na
   cabeça, rótulo por baixo. Os dois sistemas não partilham as classes que
   desenham o corpo do cartão (`kpi-card-h`/`kpi-card-num`/`kpi-card-label`
   contra `secidx-card-h`/`secidx-num`) — só a caixa exterior (`.card`) é
   comum — por isso corrigir um nunca poderia ter corrigido o outro.

3. **Um parágrafo de prosa explicativa fica a meio da página**, entre os
   cartões e a tabela: `secRenderIndex()` insere um
   `<div class="secpj-caption">` com o texto de `SEC_FLOOR_SCOPE_NOTE`
   logo a seguir aos cartões e antes da secção "Projects" da tabela.

4. **Os títulos de secção** ("Projects", "Recent analyses", "Findings by
   severity") são `<h3>` simples, que herdam o `text-transform:uppercase`
   global de `h3` (`ui/css/components.css`) — o estilo de pequenas
   maiúsculas que nenhuma das quatro páginas convertidas usa: nenhuma tem
   um único `<h3>` no seu próprio HTML gerado, porque os seus cabeçalhos
   vêm todos de `pageHeader()`.

5. **A tabela de projetos não tem rodapé de cartão.** `secIndexProjectsTable`
   não passa por `tableFooter()` — sem "Showing X of N", sem pager, por
   mais projetos que existam.

Nada disto é defeito desta fase — é a costura que ela deixou visível ao
converter quatro das cinco áreas e não tocar na quinta. É exactamente o que
a Fase 4 tem de fechar.

## Fora de âmbito

Os dois editores (Fase 3), as lacunas do índice Security detalhadas na
secção acima (Fase 4), e a conversão do modal de log para DOM (ver
«Tarefa 7», mais acima).

## Verificação

Portões no fim: `pytest`, `claude-cron selftest`, `test/e2e.test.sh`, árvore
limpa, os artefactos construídos no mesmo commit que as fontes.
