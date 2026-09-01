# Reestruturação da área Security — design

> **Origem:** quatro mockups fornecidos em 2026-08-21 (índice, detalhe de
> projecto, findings browser, activity). Usados como **especificação de
> conteúdo**, não como alvo visual: o estilo mantém-se o do Overview actual.
> Este documento é o desenho aprovado; o plano de implementação vive em
> `docs/superpowers/plans/`.

**Objectivo:** transformar a área Security de um ecrã único numa área com
índice, detalhe por projecto, navegador de achados e histórico de eventos —
mostrando o que o ledger já sabe e nunca um número inventado.

---

## O que os mockups pedem e o motor não tinha

Levantado antes de desenhar, contra o schema e o código:

| Mockup | Realidade | Decisão |
|---|---|---|
| Utilizadores (Sofia, Rafael), coluna USER, IP, *top active users* | `CHECK (id = 1)` — **um operador, imposto pelo schema** | Sai tudo. O produto é uma ferramenta local de um programador; atribuição multi-utilizador seria mostrar dados falsos num painel de segurança. |
| Severidade `info` | O motor emite quatro | Entra, **com produtores reais** (ver abaixo) |
| 1 842 331 linhas de código | Nada conta linhas | Entra, contada na fase determinística |
| Ecrã Activity | Não há registo de eventos | Entra, tabela nova |
| *Saved filters* | Sem persistência por vista | Entra, tabela nova |
| *Findings viewed* como evento | — | **Não entra.** Gravar cada visualização é vigiar-se a si próprio e afogaria os eventos reais. |

---

## Arquitectura

### Leitura directa, escrita pela porta única

O servidor abre `data/security.db` **em modo leitura** (`mode=ro` na URI, não
por convenção: assim um `SELECT` mal escrito não pode escrever no ledger nem
por acidente). Todas as escritas continuam a passar por `bin/security/cli.py`.

A regra da porta única sempre foi sobre **escritas** — o que ela protege é o
ledger de um agente não-determinístico, e o agente nunca alcança o servidor. É
também como o servidor já trata as suas outras duas bases: lê `index.db` e
`app.db` directamente.

As consultas vivem em `bin/security/queries.py`, importado pelo servidor
(`sys.path` ganha `BIN_DIR`). O SQL do ledger fica dentro do pacote dono do
schema, em vez de espalhado por um servidor de 2 900 linhas.

### Interface: fontes, bundle, entrega

- Fontes em `ui/security/`, um módulo por ecrã. **Aterrou como `dom.js`**, que
  faz os dois papéis previstos (construtores de DOM e o `fetch` com o token),
  mais `page.js`, que recebe da página o que os módulos precisam dela, e
  `vocabulary.js`, dono das severidades e dos estados — o sítio que impede uma
  quinta cópia de uma lista.
- `esbuild` (dependência de desenvolvimento, versão fixada) agrupa em
  **`bin/static/security.js`**. Não `dist/`, que o `.gitignore` já apaga.
- **O bundle é commitado.** Quem desenvolve a interface precisa de Node; quem
  instala não precisa de nada de novo, e a promessa de instalação do produto
  (jq, python3, curl) mantém-se intacta.
- Rota estática nova no servidor para `/static/*`. **Aterrou sem cache**: relê do
  disco a cada pedido e responde `no-store`; o cache-busting faz-se pela
  impressão digital de conteúdo no `?v=`. Responde **antes** do gate de
  autenticação, de propósito — a página de login precisa do próprio código para
  se desenhar, e o bundle não é secreto.
- `dashboard.html` deixa de conter o JavaScript da área e passa a carregá-lo. O
  CSS fica onde está: os componentes são os do Overview e nenhum muda.

### Contenção

Este trabalho **não toca** em Overview, Jobs, Runs nem Projects. As áreas que
funcionam hoje não entram no diff.

---

## Dados que passam a existir

### Linhas de código

Coluna nova na linha da análise, contada **durante a fase determinística que já
percorre a árvore** — `scan_tree` já abre cada ficheiro de texto versionado, por
isso contar linhas não custa uma segunda passagem. Análises antigas ficam a zero
e o ecrã mostra um traço, nunca um número inventado.

### Severidade `info`

Fica abaixo de `low`, e o piso `min_severity` por omissão (medium) esconde-a —
o comportamento certo para um nível informativo. Dois produtores:

1. **O agente**, para observações que vale a pena registar mas não agir. A skill
   passa a dizer quando.
2. **Uma regra de higiene consultiva**: `.gitignore` em falta — nomeada na spec
   original, nunca construída, e precisamente como o próximo `.env` acaba
   commitado.

**Rejeitado explicitamente:** usar `info` para avisos da OSV que chegam sem
severidade. Hoje caem em `medium`; despromovê-los empurrava-os para baixo do
piso por omissão e escondia CVEs reais. Um CVE de severidade desconhecida é um
CVE por avaliar, não um CVE sem importância.

### Registo de eventos

Tabela nova em `security.db`, escrita pelo CLI como tudo o resto. Regista o que
aconteceu de facto: análise iniciada, análise fechada (com o estado), decisão
tomada (com a razão), configuração de segurança alterada, relatório exportado.
Sem coluna de utilizador e sem IP.

O evento de exportação nasce no servidor, que é quem serve o download — e por
isso é o único que escreve invocando o CLI, como já faz para todas as suas
mutações. Uma exportação é rara; o custo de um subprocesso aí é irrelevante.

### Filtros guardados

Tabela por projecto — nome e a combinação de filtros — com listar, guardar e
apagar pelo CLI. **Não há verbo de renomear**: guardar é um upsert sobre o nome,
o que cobre o caso sem uma primitiva nova. Guardar e apagar são recusados ao
agente; listar não.

---

## Os quatro ecrãs

**Regra que atravessa todos:** os números são a **postura actual**, não somas
históricas. "45 críticos" é o que está aberto na análise mais recente de cada
projecto — não o total de tudo o que já foi encontrado, que só cresce e nunca
significa nada. Onde um número for histórico (total de análises), o cartão di-lo.

### Índice

Cinco cartões: projectos com segurança activa, análises totais, críticos e altos
em aberto, taxa de sucesso.

Duas definições que não podem ficar à interpretação de quem implementa:

- **Em aberto** é tudo o que não está `fixed`, `accepted` nem `false_positive`.
  Inclui `pending` — um achado por re-verificar é exposição por fechar, e
  arrumá-lo com os resolvidos seria a mesma mentira que o `fixed` prematuro.
- **Taxa de sucesso** é `done` sobre as análises **terminadas**
  (`done + capped + failed`). Uma análise a correr não conta para nenhum dos
  lados, e uma `capped` conta como não-sucesso: parou antes de cobrir o âmbito.

A tabela de projectos mostra a postura da **branch por omissão** do projecto;
quando essa nunca foi analisada, a mais recente que houver, **com o nome à
vista** — posturas de branches diferentes não se confundem em silêncio.

**A coluna de tendência não aterrou no índice** — a tabela ficou com projecto,
branch, postura, última análise e número de análises, e a tendência vive no
separador Branches, onde é por branch e tem espaço para dizer alguma coisa. Lá é
o número de achados **em aberto** por análise, pela mesma definição acima, numa
janela real de 30 dias. Com poucas análises fica esparsa, e é honesto que
fique.

Por baixo: análises recentes, e o donut por severidade com as categorias mais
frequentes (agrupadas por `rule`).

### Detalhe do projecto

Cabeçalho com o estado; faixa com perfil por omissão, branch por omissão, linhas
de código e última análise. Cinco separadores:

- **Overview** — postura e o que mudou desde a análise anterior.
- **Runs** — o histórico que já existe, com filtros e o botão de nova análise.
- **Branches** — novo, e sai todo do ledger: cada análise já traz a sua branch.
  Última análise, achados em aberto e tendência, por branch.
- **Findings** — o navegador, no âmbito do projecto.
- **Reports** — os quatro formatos por análise, hoje soltos.

*Settings* continua a ser o editor de projecto que já existe: o botão leva lá,
em vez de duplicarmos o formulário.

### Findings browser

Faixa com total, as cinco severidades e *unique issues* (fingerprints distintos
— a contagem que diz quantos problemas há, contra quantas linhas há).

Filtros por severidade, estado, análise, branch, caminho e categoria, com
pesquisa em mensagem/ficheiro/CVE.

**Correcção à spec, feita na implementação e mantida:** isto não é tudo em SQL.
O estado de um achado **não é uma coluna** — é o resultado de comparar duas
análises através do `checklist()`, a máquina de estados que já existe e já é
testada. Filtrar por estado em SQL exigiria uma segunda cópia dessa máquina
escrita como um `CASE`, que é exactamente a duplicação que este projecto já
pagou três vezes. Portanto: as análises certas escolhem-se em SQL, o
`checklist()` produz as linhas, e a filtragem, a ordenação e a paginação fazem-se
em Python sobre esse conjunto. Com centenas de achados é instantâneo; se algum
dia forem milhares, isso é um problema medido, não presumido.

**O estado de um achado nesta tabela é o que ele tem na análise mais recente da
sua branch.** A checklist compara duas análises; uma lista que atravessa
análises tem de dizer contra qual está a falar. *First seen* é o **instante** da análise mais
antiga **terminada** onde o fingerprint aparece — uma análise que morreu a meio
não faz um achado parecer mais velho do que alguma análise bem-sucedida
confirmou.

### Activity

Separadores por tipo, sem *Users*: **All activity**, Análises, Achados e
Configuração — quatro, não três. O `report_exported` ficou em Configuração por
falta de melhor casa; uma exportação não é bem configuração, e é a costura mais
fraca desta divisão. Tabela com
hora, evento, detalhe, projecto e o que lhe está relacionado. À direita, o
resumo do período e os projectos mais activos — sem *top users*, que com um
operador seria uma lista de um.

---

## Falhas e limites

- **A ligação de leitura é mesmo de leitura** (`mode=ro`), imposto pelo SQLite.
- **Ordenação por lista branca.** Os valores dos filtros vão por parâmetros, mas
  a coluna e a direcção de ordenação são interpoladas por natureza: ficam numa
  lista branca e qualquer outra coisa é recusada na borda. O tamanho de página
  tem tecto.
- **Estados vazios.** `security.db` pode não existir, um projecto pode nunca ter
  sido analisado, uma branch pode ter uma só análise e portanto nenhuma
  comparação. Todos são estados vazios com uma frase que diz o que fazer — nunca
  um 500, nunca um zero que se confunde com "está tudo bem".

---

## Testes

- **`queries.py` contra um ledger de fixture**, cada agregação verificada contra
  números contados à mão, incluindo os casos que enganam: postura da branch por
  omissão quando essa nunca foi analisada, *first seen* quando o fingerprint
  atravessa análises, e a contagem de únicos contra a de linhas.
- **Contrato de página** para os ecrãs novos e para a regra do `textContent`.
- **`selftest`** para os verbos novos do CLI (eventos, filtros guardados).
- **Índices medidos, não presumidos** — e a medição concluiu que quase nenhum era
  preciso: aterrou um só, `event_by_project_time`. O resto do custo resolveu-se a
  não recomputar (memo do `checklist()` por ligação, e uma consulta agrupada onde
  havia um ciclo), que é a correcção certa quando o problema é trabalho repetido
  e não uma varredura de tabela.

### A armadilha do bundle

Existe hoje um teste que varre o bloco Security **dentro do `dashboard.html`** à
procura de `innerHTML`. O código passa a viver em `ui/security/*.js`: esse teste
deixaria de ver o que existe para vigiar **e continuaria a passar**.

Passa a varrer **todas** as fontes em `ui/` — não só `ui/security/`, porque o
bundle pode conter qualquer coisa que a árvore alcance. O bundle construído fica
deliberadamente **de fora**: uma guarda que lê a saída gerada está a uma
reconstrução de deixar de guardar a fonte.

**Correcção à spec, provada na implementação:** a asserção de frescura **não pode
ser por mtime**. O git não guarda mtimes e um clone novo escreve `bin/` antes de
`ui/`, portanto todas as fontes saem mais novas que o bundle e a asserção
falharia a toda a gente que não mudou nada. É uma **impressão digital de
conteúdo** — de `ui/**/*.js`, do `build/build-ui.sh` e do `package.json` —
carimbada no bundle e recomputada pelo selftest.

---

## Sequenciamento

É trabalho grande para um plano só, e o plano sequencia-o para que cada fase
aterre a funcionar em vez de tudo aterrar no fim:

1. **Camada de dados** — `queries.py`, as tabelas novas (eventos, filtros
   guardados), a coluna de linhas de código e a severidade `info` com os seus
   produtores. Verificável por testes sem uma linha de interface.
2. **Infraestrutura da interface** — rota estática, `esbuild` fixado, o bundle
   commitado e a asserção de frescura, com a área Security actual movida para
   `ui/security/` sem mudar o que faz. Um passo puramente mecânico, e o que
   torna todos os seguintes pequenos.
3. **Os ecrãs**, por esta ordem: índice, detalhe do projecto, findings browser,
   activity. Cada um utilizável no fim da sua fase.

## Riscos e questões em aberto

1. **Duas linguagens de código na mesma página.** O resto do dashboard continua
   em JavaScript inline; a área Security passa a módulos agrupados. É deliberado
   e contido, mas é uma fronteira que quem editar a página tem de conhecer.
2. **O bundle nos diffs.** Um artefacto construído commitado polui as revisões.
   O custo é aceite em troca da promessa de instalação; a asserção de frescura é
   o que impede o pior caso, que é um bundle que não corresponde às fontes.
3. **Volume de eventos.** A tabela cresce indefinidamente. Os eventos são
   pequenos e as consultas são paginadas e limitadas por período, mas se algum
   dia um evento de alta frequência for acrescentado, isto precisa de retenção.
