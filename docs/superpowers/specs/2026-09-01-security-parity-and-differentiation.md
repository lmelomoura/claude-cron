# Segurança: paridade com o GitGuard, e o que nos põe à frente — design

> **Origem:** a análise comparativa de 2026-09-01 entre o módulo `security`
> (entregue no PR #18, já em `main` em `18bb1c9`) e o [GitGuard](https://www.gitguard.com.br/),
> o serviço que inspirou o desenho original em
> `2026-08-20-security-analysis-design.md`. Este documento é o desenho; o plano
> de implementação vive em `docs/superpowers/plans/`.

**Objectivo:** fechar a distância de *detecção* face a uma plataforma comercial
madura, sem perder o que já nos distingue dela — o ciclo de vida dos achados —
e construir por cima disso o que ela não pode fazer.

---

## O que se descobriu sobre o GitGuard

A página "Como funciona" diz-nos o essencial: **não há motor próprio**. São
quatro ferramentas open-source, uma por container (`NetworkMode: none`,
utilizador `nobody`), o repositório clonado e apagado no fim.

| Motor | Papel |
|---|---|
| **Semgrep** | SAST — 35+ linguagens; o ruleset OWASP Top 10 tinha 2.360 regras em Janeiro de 2026, com CWE/OWASP por regra |
| **Trivy** | SCA (~20 ecossistemas) + IaC + imagens + licenças |
| **Gitleaks** | Segredos, incluindo o histórico via `git log -p` |
| **Syft** | SBOM em CycloneDX e SPDX |

Por cima: filtro de ruído, monitorização a cada push (GitHub App read-only),
prompt de correcção por achado, e export em JSON/Markdown/HTML/PDF.

**A consequência para nós.** O desenho original partiu de uma premissa correcta
— "eles precisam de filtrar ruído porque correm motores cegos ao contexto" — e
tirou dela a conclusão errada: reescrever os motores em Python. Os motores são
gratuitos. Podemos corrê-los **e** usar o agente como camada de juízo, que é
exactamente o que o Job 2 da skill já faz — só que hoje tria 8 regras
artesanais em vez de milhares de achados.

---

## Estado actual, verificado no código

Este bloco existe porque a análise que deu origem a esta spec produziu três
afirmações que o código desmentiu. O que se segue foi lido nos ficheiros, não
inferido do desenho anterior.

**Já existe, e não é para refazer:**

- Severidade `info`, e é a última na ordem por estar abaixo do `min_severity`
  por omissão (`report.py:17`).
- A regra `missing_gitignore`, severidade `info`, condicionada a `.git` existir
  (`hygiene.py:141`) — são **quatro** regras de higiene, não três.
- Histórico de postura ao longo do tempo: `trend`, `trend_series`, `posture` e
  `activity_summary` em `queries.py`, com série por severidade e a recusa
  explícita de ler direcção através de uma análise `capped`.
- O ledger completo: checklist de seis estados com `regressed`, decisões
  humanas por projecto com razão obrigatória, reverificação do que ficou aberto.
- `coverage_note` como mecanismo de declaração de lacunas, já obrigatório na
  skill — é nele que a degradação dos motores novos vai assentar.

**Confirmado em falta:**

- Nenhuma ocorrência de `cwe` ou `owasp` em `cli.py`, `ledger.py` ou
  `queries.py`; a tabela `finding` não tem colunas para isso.
- `rule` é texto livre. A única validação de vocabulário é de `category`
  (`cli.py:1454`).
- 8 regras de segredos, 5 lockfiles (`package-lock.json`, `requirements.txt`
  apenas *pinned*, `poetry.lock`, `composer.lock`, `go.sum`).
- `_composer` soma `packages` com `packages-dev` sem guardar o *scope*.
- Sem IaC, sem licenças, sem EPSS/KEV, sem `fixed_version`, sem análise por
  push, sem análise de diff de PR.

---

## Decisões tomadas, e porquê

| Decisão | Porquê |
|---|---|
| **Motores como binários opcionais**, detectados em runtime | um utilizador sem nenhum deles continua a ter a análise que tem hoje. A degradação sai pelo `coverage_note`, que já existe e já é obrigatório na skill — não é mecanismo novo, é uma fonte nova a alimentá-lo. Docker daria isolamento melhor ao custo de o exigir a toda a gente e de a fase determinística deixar de ser "segundos". |
| **A taxonomia (A3) vem antes dos motores (A1)** | porque a ordem inversa faz a conta crescer. Meter o Semgrep primeiro produz milhares de achados com `rule` de texto livre e sem classificação, e a migração que teríamos de fazer a seguir é sobre esse volume, não sobre as 181 linhas de hoje. *(Nota de rigor: adicionar **colunas** não é o problema — `ledger.py` já tem `_ANALYSIS_COLUMNS` e faz `ALTER TABLE` guardado por `PRAGMA table_info`, e as colunas `cwe`/`owasp` seguem esse mesmo padrão a qualquer momento. O que o comentário do schema diz não ser retrofitável são **constraints**, como o `UNIQUE(analysis_id, fingerprint)` — e este bloco não acrescenta nenhuma.)* |
| **O mecanismo de migração de fingerprints entra na mesma** | hoje custa pouco — o único ledger existente é de desenvolvimento (7 análises, 2 decisões) e pode ser deitado fora. A partir do primeiro utilizador real passa a ser obrigatório, e escrevê-lo retroactivamente é muito mais caro. |
| **Os motores substituem, não acompanham** | correr Gitleaks *e* `secrets.py` sobre a mesma árvore produz dois achados para uma credencial, com fingerprints diferentes, que a checklist mostra como duas entradas contraditórias. Quando o motor existe, o detector artesanal cala-se; quando não existe, é o fallback. |
| **A fase 2 (correcção com agente) fica fora** | decisão do produto, tomada com o âmbito. Nada nesta spec a impede depois. |
| **Uma branch e um PR por bloco** | é o padrão do repositório (PRs #13, #16, #17, #18) e agora é aplicável, porque a base está toda em `main`. |

---

## Lista A — Paridade

### A3 · Taxonomia e identidade (primeiro, pela janela de schema)

1. **Colunas `cwe` e `owasp` em `finding`**, opcionais, preenchidas pelos
   motores que as trazem (Semgrep e Trivy trazem-nas) e pelo agente.
2. **Vocabulário fechado de `rule` para `category: "sast"`** — 15 a 20 nomes
   canónicos, cada um com o seu CWE, validado em `report-finding` e listado na
   skill. Sem isto, o mesmo bug chamado `sql-injection` numa corrida e `sqli` na
   seguinte tem duas identidades: aparece `fixed` e `new` no mesmo relatório, e
   nenhuma decisão humana volta a casar com ele.
3. **Mecanismo de migração de fingerprints** — tabela de equivalência
   `rule` antiga → nova, aplicada ao ledger, com teste que prova que uma decisão
   `accepted` sobrevive à renomeação da regra.

### A1 · Os quatro motores

4. **Adaptador comum** — detecta o binário, corre-o, normaliza o output para o
   formato de `finding` que o ledger já aceita, e escreve no `coverage_note`
   aquilo que não correu e porquê.
5. **Gitleaks** substitui `secrets.py` quando presente.
   > **Não negociável:** o JSON do Gitleaks traz `Secret` e `Match` com o valor
   > em claro. O adaptador descarta-os à entrada, antes de qualquer coisa tocar
   > no ledger ou num log. O teste adversarial que já existe — a string
   > injectada não aparece em lado nenhum, em formato nenhum — passa a cobrir
   > este caminho.
6. **Trivy** substitui `deps.py` + `osv.py` quando presente: ~20 ecossistemas,
   `fixed_version` e CVSS que hoje não temos.
7. **Syft** para o SBOM — CycloneDX e SPDX.
8. **Semgrep** como pré-passagem de SAST, cujo output o agente tria (Job 2 da
   skill) em vez de o filtrar por heurística.

### A2 · Cobertura ausente

9. **IaC e containers** via Trivy config — Terraform, CloudFormation,
   Kubernetes, Helm, Dockerfile. Nova `category: "iac"`.
10. **Licenças de dependências.** Nova `category: "license"`.

### A4 · Filtro de ruído

11. **`scope` (dev vs runtime) nas dependências** — sem este campo não há como
    suprimir o que só afecta desenvolvimento.
12. **`fixed_version` nos CVEs**, para marcar (nunca esconder) o que não tem
    correcção publicada.
13. **Testes e fixtures suprimidos por omissão**, não só por `ignore_paths`.
14. **`.example`/`.sample`/`.template` excluídos do scan de segredos** —
    `hygiene.py` já os exclui; `secrets.py` filtra o *valor* por
    `_is_placeholder` e não o *ficheiro*.

### A5 · Fluxo

15. **Análise automática a cada push** — hook local ou webhook.
16. **Botão de PDF** — o HTML já tem `@media print`; falta a afordância junto
    aos quatro botões existentes.

---

## Lista B — Diferenciação

Sem os itens que a auditoria mostrou já existirem (ledger, checklist,
reverificação, triagem contextual, postura ao longo do tempo).

17. **Alcançabilidade dos CVEs** — o agente verifica se a função vulnerável é
    sequer chamada. Nem o Trivy nem o Semgrep fazem isto.
18. **Priorização por EPSS + KEV da CISA** — dados públicos e gratuitos que
    dizem quais dos CVEs estão a ser explorados no mundo real. Transforma 200
    achados em três que importam esta semana.
19. **Análise do diff de um PR**, não do repositório inteiro — barata, rápida, e
    é onde a segurança devia entrar.
20. **Política como código** — a análise falha se houver crítico novo, se a
    postura piorar, se um segredo entrar.
21. **Segurança de agentes de IA** — já temos `prompt-injection-in-source`, que
    nenhum dos quatro motores procura. Expande-se para definições de MCP,
    skills, ferramentas com efeitos colaterais e permissões excessivas. É o
    terreno onde somos naturalmente melhores e onde Semgrep e Trivy não chegam.

---

## Falhas e limites

- **Motor ausente** — a análise corre com o que existir e declara a lacuna. É a
  mesma regra que já governa a OSV sem rede.
- **Motor presente mas com versão incompatível** — trata-se como ausente, com o
  `coverage_note` a dizer que versão foi encontrada e qual é exigida. Um parser
  que assume um formato que mudou é pior do que um motor que não correu.
- **Semgrep num monorepo** — é a fonte de custo mais provável. A fase
  determinística deixa de ser "segundos" e passa a ser minutos. Medir antes de
  prometer.
- **Fidelidade das fixtures** — o output de cada motor tem de ser **capturado a
  correr a ferramenta**, nunca escrito à mão a partir da documentação; senão o
  adaptador e o teste concordam um com o outro enquanto ambos discordam do
  motor.

---

## Ordem de execução

Um bloco, uma branch, um PR, com testes a passar no fim de cada um.

1. **`feat/security-taxonomy`** — itens 1 a 3. Primeiro pela janela de schema.
2. **`feat/security-engines`** — itens 4 a 8. O maior salto de cobertura.
3. **`feat/security-coverage`** — itens 9 a 14.
4. **`feat/security-flow`** — itens 15 e 16.
5. **`feat/security-edge`** — itens 17 a 21, cada um avaliável de per si.

---

## Riscos e questões em aberto

1. **A migração de identidades cresce com o adiamento.** As colunas novas são
   aditivas e migram-se a qualquer momento pelo padrão que `ledger.py` já tem.
   O que não escala é a renomeação de regras: feita agora abrange 181 achados
   num ledger de desenvolvimento; feita depois do bloco 2 abrange tudo o que o
   Semgrep e o Trivy tiverem produzido entretanto, em ledgers reais.
2. **Dependência de quatro binários de terceiros.** A degradação está desenhada,
   mas a superfície de manutenção cresce: quatro formatos de output que podem
   mudar de versão para versão.
3. ~~**O custo do Semgrep não está medido.**~~ **Medido em 2026-09-01, e o
   risco não existe.** `semgrep --config=p/owasp-top-ten` sobre este
   repositório (120 ficheiros versionados, ~56k linhas de Python, JavaScript e
   shell): **6 segundos** de parede, 223 regras, 85 ficheiros, 99,9% das linhas
   analisadas. A fase determinística continua a medir-se em segundos. Três
   observações que valem mais do que o número:

   - **Os ficheiros sem extensão são analisados.** `bin/claude-cron` (8.263
     linhas) e `bin/claude-cron-server` (3.473) entram os dois — o Semgrep
     escolhe o analisador pelo shebang, não só pela extensão. A preocupação
     inicial era infundada.
   - **A cobertura de shell é quase nula: 1 regra, contra 147 para Python e 65
     para JavaScript.** O núcleo deste produto são 8.263 linhas de bash. O
     Semgrep **não substitui** o SAST do agente aqui; complementa-o. Um projecto
     cuja lógica viva em shell fica com a cobertura determinística que o
     ecossistema Semgrep tem para shell, que é pouca, e o `coverage_note` tem de
     o dizer.
   - **Os 3 achados são 3 falsos positivos, e do tipo que só o contexto
     resolve.** Todos `insecure-hash-algorithm-md5` (CWE-327), todos em usos
     não-criptográficos de MD5: chaves de cache, ETags, "cheap fingerprint of
     the file head". O filtro de ruído do GitGuard não os apanharia — não são
     ficheiros de teste nem dependências de desenvolvimento. Um agente que lê as
     três linhas à volta suprime-os com justificação escrita em segundos. É a
     validação empírica do argumento central desta spec, num volume que torna a
     triagem barata.
4. **Sobreposição entre motores.** O Trivy também detecta segredos e o Gitleaks
   também. A regra "um motor por categoria" evita achados duplicados, mas
   precisa de ser explícita no adaptador.
