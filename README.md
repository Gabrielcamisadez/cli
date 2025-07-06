🔎 NVD CLI: Busca de Vulnerabilidades Simplificada
Uma ferramenta de linha de comando para buscar CVEs na National Vulnerability Database (NVD).

🚀 Instalação Rápida
Clone ou copie:

Bash

git clone 
Ambiente virtual (recomendado):

Bash

python3 -m venv venv
source venv/bin/activate # Linux/macOS
.\venv\Scripts\activate   # Windows
Dependências:

Bash

pip install requests
💡 Como Usar
Execute com python3 cli.py e os seguintes argumentos:

-k, --keyword: Busca por palavra-chave (ex: "chrome", "windows 10").

-c, --cpe-select: Seleciona CPEs pré-definidos (veja opções no --help).

-s, --severity: Filtra por severidade CVSS (LOW, MEDIUM, HIGH, CRITICAL).

-v, --cvss-version: Exibe métricas CVSS v2.0 ou v3.1.

Exemplos:
Palavra-chave:

Bash

python3 cli.py -k "firefox 40"
CPE pré-definido:

Bash

python3 cli.py -c libreoffice_5_3_7_2
CPE + Palavra-chave + Severidade CRÍTICA:

Bash

python3 cli.py -c adobe_flash_player_21_npapi -k "rce" -s CRITICAL
Visual C++ Redistributable (apenas palavra-chave):

Bash

python3 cli.py -k "microsoft visual c++ 2005"
🔑 CPEs Pré-definidos Disponíveis
(Veja a lista completa ao rodar python3 cli.py --help)

⚠️ Observação sobre CPEs
A busca por CPEs é muito específica. Para "Visual C++ Redistributable", a busca por palavra-chave (-k) é geralmente mais eficaz devido à forma como a NVD indexa esses componentes.
