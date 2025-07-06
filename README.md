🔎 NVD CLI: Busca de Vulnerabilidades Simplificada
Uma ferramenta de linha de comando (CLI) para buscar Common Vulnerabilities and Exposures (CVEs) na National Vulnerability Database (NVD) do NIST.

🚀 Instalação Rápida
Clone ou copie o código:

Bash

git clone https://github.com/seu-usuario/seu-repositorio.git # Se tiver um repositório
# Ou apenas crie um arquivo `cli.py` e cole o código.
Crie e ative um ambiente virtual (recomendado):

Bash

python3 -m venv venv
# No Linux/macOS:
source venv/bin/activate
# No Windows:
.\venv\Scripts\activate
Instale as dependências:

Bash

pip install requests
💡 Como Usar
Execute o script com python3 cli.py e os argumentos desejados.

Argumentos:
-k, --keyword: Busca por palavra-chave (ex: "chrome", "windows 10").

-c, --cpe-select: Seleciona CPEs pré-definidos (veja opções no --help).

-s, --severity: Filtra por severidade CVSS (LOW, MEDIUM, HIGH, CRITICAL).

-v, --cvss-version: Exibe métricas CVSS v2.0 ou v3.1.

Exemplos:
Busca básica por palavra-chave:

Bash

python3 cli.py -k "firefox 40"
Busca por um CPE pré-definido:

Bash

python3 cli.py -c libreoffice_5_3_7_2
Combinar CPE, palavra-chave e severidade CRÍTICA:

Bash

python3 cli.py -c adobe_flash_player_21_npapi -k "rce" -s CRITICAL
Pesquisar por Visual C++ Redistributable (use apenas palavra-chave):

Bash

