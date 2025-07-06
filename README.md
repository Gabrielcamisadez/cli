🔎 NVD CLI: Busca de Vulnerabilidades Simplificada
Uma ferramenta de linha de comando (CLI) para buscar Common Vulnerabilities and Exposures (CVEs) na National Vulnerability Database (NVD) do NIST.

# 🚀 Instalação Rápida

* git clone https://github.com/Gabrielcamisadez/cli

# 🔮 Ambiente Virtual 

### Criar o venv
* python3 -m venv venv

### Ativar no Linux/macOS:
* source venv/bin/activate

### Ativar no Windows:
* .\venv\Scripts\activate

# 🔭 Instale as dependências:

* pip install -r requirements.txt

# 💡 Como Usar
Execute o script com python3 cli.py e os argumentos desejados.

Argumentos:
- -k, --keyword: Busca por palavra-chave (ex: "chrome", "windows 10").

- -c, --cpe-select: Seleciona CPEs pré-definidos (veja opções no --help).

- -s, --severity: Filtra por severidade CVSS (LOW, MEDIUM, HIGH, CRITICAL).

- -v, --cvss-version: Exibe métricas CVSS v2.0 ou v3.1.

# Exemplos:
Busca básica por palavra-chave:

> python3 cli.py -k "firefox 40"

Busca por um CPE pré-definido:

> python3 cli.py -c libreoffice_5_3_7_2

Combinar CPE, palavra-chave e severidade CRÍTICA:

> python3 cli.py -c adobe_flash_player_21_npapi -k "rce" -s CRITICAL


