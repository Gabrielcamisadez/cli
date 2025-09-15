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
