                     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                      BUSCA POR CVES NA API DO NVD

                                gabriel
                     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


Table of Contents
─────────────────

1. setup
2. uso


1 setup
═══════

  *repositório* ->
  ┌────
  │ git clone https://github.com/Gabrielcamisadez/cli
  └────

  *environment* ->
  ┌────
  │ python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
  └────


2 uso
═════

  O script possui duas opções de busca na API, via CPE (common platform
  enumeration) que é um padrão de busca por nome de produtos/sistemas.

  A outra opção é com o parâmetro `keywordSearch' que permite uma busca
  mais personalizada com a API

  *keywordSearch*
  ┌────
  │ python3 cli.py -k "firefox 70"
  └────

  *keywordSearch only CRITICAL CVEs*
  ┌────
  │ python3 cli.py -k "openssh 5" -s CRITICAL
  └────

  ┌────
  │ python3 cli.py -k "vim" -s CRITICAL
  └────


  ┌────
  │ --- Buscando para palavra-chave: vim ---
  │   Resultados encontrados (4 vulnerabilidades):
  │     **ID**: CVE-2020-9769
  │     **Descrição**: Multiple issues were addressed by updating to version 8.1.185
  │ 0. This issue is fixed in macOS Catalina 10.15.4. Multiple issues in Vim....
  │     **Publicado em**: 2020-04-01T18:15:17.630
  │     **CVSS v3.1 Severidade**: CRITICAL (Pontuação: 9.8)
  │     ----------------------------------------------------------------------
  │     **ID**: CVE-2022-0318
  │     **Descrição**: Heap-based Buffer Overflow in vim/vim prior to 8.2....
  │     **Publicado em**: 2022-01-21T12:15:10.053
  │     **CVSS v3.1 Severidade**: CRITICAL (Pontuação: 9.8)
  │     ----------------------------------------------------------------------
  │     **ID**: CVE-2022-3520
  │     **Descrição**: Heap-based Buffer Overflow in GitHub repository vim/vim prior
  │  to 9.0.0765....
  │     **Publicado em**: 2022-12-02T19:15:11.010
  │     **CVSS v3.1 Severidade**: CRITICAL (Pontuação: 9.8)
  │     ----------------------------------------------------------------------
  └────
