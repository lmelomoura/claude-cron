# Plano de implementação — Fase 3: os editores

> **Para agentes:** SUB-SKILL OBRIGATÓRIA: usar superpowers:subagent-driven-development (recomendado) ou superpowers:executing-plans para executar este plano tarefa a tarefa. Os passos usam checkbox (`- [ ]`) para acompanhamento.

**Objetivo:** dar aos dois editores — job e projeto — a mobília dos artboards aprovados, com o comportamento pinado antes de tocar em qualquer coisa e o contrato de render declarado e guardado.

**Arquitetura:** os dialogs restilizam-se no sítio (markup estático em `bin/dashboard.html`, CSS em `ui/css/pages.css`). Só a parte pura — decisão e mapeamento sem DOM — se muda para `ui/app/editor-domain.js`. A infra de formulário (`makeWizard`, `makePicker`, `createCombo`: 514 linhas, 13 sinks) **não se move**, pela mesma razão do modal de log.

**Stack:** a mesma das fases anteriores.

## Restrições globais

- As dependências de runtime nunca crescem: `jq`, `python3`, `curl`, `git`, `bash`. Nunca Node em runtime.
- Prosa entregue em inglês; a prosa deste plano e da spec é pt-PT.
- `esbuild` fixo em `0.25.0` via `npx --yes`.
- `ui/` não pode conter `innerHTML`, `insertAdjacentHTML`, `outerHTML`, `createContextualFragment`, `DOMParser` nem `setAttribute("on`.
- Cada tarefa escreve a sua entrada no CHANGELOG.md no mesmo commit; o selftest corre DEPOIS do commit.
- Artefactos construídos no mesmo commit que as fontes (`bash build/build-ui.sh` antes do `git add`).
- Branch: `feat/security-analysis`. Os testes existentes ficam verdes e por editar.
- **O restyle não toca em `readForm` nem em `fill`** — os editores gravam dados, e um erro aqui corrompe um job. Mudanças de comportamento nesta fase: zero.
- Testes Node guardados com `@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")`.

---

## Tarefa 1: o contrato de render, declarado e guardado

O contrato existe por construção — o `render()` do poll nunca alcança um dialog de formulário. Esta tarefa escreve-o como teste, para que mover código não o quebre em silêncio.

**Ficheiros:** modificar `tests/test_page_contract.py`; possivelmente `bin/dashboard.html` (um comentário junto ao `render()` a declarar o contrato).

- [ ] **Passo 1: escrever o teste**

A regra: os ids que vivem dentro dos dialogs **de formulário** — `editor`, `projmodal`, `profmodal`, `confirm`, `secreason`, `fsmodal` — não podem ser alcançados pelo `render()` nem pelas funções que ele chama diretamente (`renderRetained`, `renderJobsArea`, `paintNav`, `paintUser`, e os `renderProjectsPage`/`renderRunsPage`/`renderOverviewHead` do bundle, mais o `render` do CCSecurity).

`wtmodal` e `logmodal` ficam **de fora da lista** de propósito: são superfícies de leitura que se atualizam ao vivo por design (o log segue um run em curso; a tabela de worktrees repinta com o poll). O contrato protege *estado por gravar*, não conteúdo vivo.

Forma do teste: extrair os ids de dentro de cada `<dialog>` de formulário por regex sobre o markup estático; extrair os corpos das funções da lista acima (as do dashboard por brace-matching, as do bundle por `_app_js`/`_plainfn`); asserir que nenhum corpo contém `$("<id>")` de um id de formulário. A docstring diz o limite honesto: profundidade de chamada direta, não fecho transitivo.

- [ ] **Passo 2: prová-lo falsificável**

Apontar temporariamente um `$("ed-id")` dentro de `renderJobsArea`, correr o teste, confirmar VERMELHO com o id e a função nomeados, reverter. Registar.

- [ ] **Passo 3: declarar o contrato no código**

Um comentário junto ao `render()` em `bin/dashboard.html`: os dialogs de formulário são montados uma vez, preenchidos ao abrir, e nada dentro deles é repintado pelo poll — com o nome do teste que o impõe.

- [ ] **Passo 4: gates e commit** (pytest → commit → selftest → árvore limpa; entrada no CHANGELOG sob `### Added`)

---

## Tarefa 2: pinar os editores e extrair o puro

O portão das fases anteriores: **caracterizações passam à primeira; o portão é prová-las falsificáveis** — partir, ver vermelho, registar, reverter.

**Ficheiros:** criar `ui/app/editor-domain.js`; modificar `tests/test_page_contract.py`, `bin/dashboard.html`, `ui/app/index.js`, `ui/app/page.js` se necessário.

- [ ] **Passo 1: extrair o puro para `editor-domain.js`**

O critério é «decisão ou mapeamento, sem DOM». Candidatos confirmados: a comparação de snapshots por trás de `edIsDirty` (dois snapshots → booleano), as regras de decisão de `validateProjectStep` (valores → veredicto+mensagem), `getDays`/`getEffort`/`effortGet`/`effortSet` (forma↔job), `collectRepos` (linhas → lista). O que lê `$("…")` diretamente fica na página e passa a *chamar* o puro — extrair a decisão, não a leitura. **Extrair, não reescrever.**

- [ ] **Passo 2: escrever os pinos, cada um com a sua quebra**

1. **O rasto de alterações**: formulário intocado → não avisa; um campo mudado → avisa; snapshot renovado → limpo.
   *Quebra:* comparar por referência em vez de por valor.
2. **O modo duplo**: a criar, a navegação é um stepper numerado e avançar valida o passo; a editar, tabs planas todas alcançáveis.
   *Quebra:* fazer `gotoStep` avançar sem validar.
3. **A validação por passo do projeto** recusa o passo inválido e diz porquê — pelo menos: nome vazio, e um repo mal formado.
   *Quebra:* devolver sempre válido.
4. **`getDays`/`effortGet`/`effortSet`** mapeiam ida e volta sem perda para os valores que o job pode ter.
   *Quebra:* trocar dois níveis de esforço no mapa.
5. **O bloco `security` inteiro com booleano real** — já pinado por `test_saving_always_sends_the_whole_security_block_with_a_real_boolean`; confirmar verde, não duplicar.

- [ ] **Passo 3: as quatro quebras registadas** (aplicar → vermelho → reverter, uma a uma)
- [ ] **Passo 4: gates e commit**

---

## Tarefa 3: o editor de job ganha a mobília do artboard

**Ficheiros:** modificar `bin/dashboard.html` (markup do `<dialog id="editor">`), `ui/css/pages.css`.

O artboard `JobEditor.dc.html` define: controlos de 40px com raio 9px; rótulos 13px/600 com o obrigatório em `--err`; **uma** linha de ajuda cinzenta (12.5px, `--muted`) por campo — a que existe, encurtada onde for parágrafo; grelha de duas colunas para pares (intervalo+janela); o seletor de dias como botões-pill com o estado ativo em accent; o stepper com − e +; o strip de tabs no estilo das páginas; rodapé com a ação destrutiva na ponta esquerda, espaçador, Cancel e primário à direita.

- [ ] **Passo 1:** CSS novo numa secção própria de `ui/css/pages.css` (`/* ---- dialog forms ---- */`), só tokens
- [ ] **Passo 2:** ajustes de markup no dialog — classes novas, sem tocar em ids (os testes e o `fill`/`readForm` dependem deles), sem tocar em `readForm`/`fill`
- [ ] **Passo 3:** os pinos da Tarefa 2 e os testes existentes do editor continuam verdes e por editar
- [ ] **Passo 4:** ver ao vivo — abrir a criar (stepper) e a editar (tabs), percorrer os cinco painéis, ambos os temas; gravar uma edição inócua e confirmar que chega ao `jobs.json` de scratch
- [ ] **Passo 5:** gates e commit

---

## Tarefa 4: o editor de projeto, com o painel Security intacto

**Ficheiros:** modificar `bin/dashboard.html` (markup do `<dialog id="projmodal">`), `ui/css/pages.css`.

Mesma mobília da Tarefa 3 — as classes novas são as mesmas; esta tarefa não inventa nenhuma.

**A restrição extra:** o seletor de modelo/esforço do painel Security é o mesmo do editor de job, por exigência antiga do utilizador, pinado por `test_security_model_and_effort_use_the_job_editors_controls`. O restyle não pode fazê-los divergir — se a mobília nova mudar o aspeto de um, muda o dos dois pelo mesmo CSS.

- [ ] **Passo 1:** aplicar as classes da T3 ao projmodal, painel a painel (project, repos, provisioning, security)
- [ ] **Passo 2:** os testes do editor de projeto (panes, min-severity com Info, bloco security inteiro) verdes e por editar
- [ ] **Passo 3:** ver ao vivo — criar (stepper de 4 passos com validação) e editar, ambos os temas; o painel de repos com 1 e com 2 repos
- [ ] **Passo 4:** gates e commit

---

## Tarefa 5: fechar a fase

- [ ] **Passo 1:** todos os portões (`pytest`, selftest pós-commit, `test/e2e.test.sh`, árvore limpa, rebuild com diff vazio)
- [ ] **Passo 2:** corrigir a spec contra o que aterrou — o que aterrou, não o que se esperava; uma omissão nunca se descreve como decisão
- [ ] **Passo 3:** rever as entradas do CHANGELOG da fase; sem entrada de resumo
- [ ] **Passo 4:** revisão final da fase inteira (modelo mais capaz), com os dialogs abertos ao vivo nos dois temas e nos dois modos — e atenção especial ao caminho de gravação, que é o que esta fase não podia partir

## Auto-revisão

**Cobertura da spec:** contrato de render → T1; pinos → T2; restyle dos dois dialogs → T3, T4; `editor-domain.js` só com o puro → T2; a infra que não se move → restrição global e nota de commit; portões → T5.

**O risco que o plano aceita:** o restyle mexe no markup de dialogs que gravam dados, com `readForm`/`fill` intocados por regra. A rede é: ids intocáveis, pinos da T2, os testes existentes do editor, e a gravação inócua verificada ao vivo nas T3/T4.
