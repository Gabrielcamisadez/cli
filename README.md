🔎 NVD CLI: Busca de Vulnerabilidades Simplificada

> git clone https//github.com/Gabrielcamisadez/cli

Uma ferramenta de linha de comando (CLI) para buscar Common Vulnerabilities and Exposures (CVEs) na National Vulnerability Database (NVD) do NIST.

## 🚀 Instalação Rápida

> git clone https://github.com/Gabrielcamisadez/cli

## 🔮 Ambiente Virtual 

### Criar o venv
> python3 -m venv venv

### Ativar no Linux/macOS:
> source venv/bin/activate

### Ativar no Windows:
> .\venv\Scripts\activate

## 🔭 Instale as dependências:

> pip install -r requirements.txt

## 💡 Como Usar
Execute o script com python3 cli.py e os argumentos desejados.

Argumentos:
- -k, --keyword: Busca por palavra-chave (ex: "chrome", "windows 10").

- -c, --cpe-select: Seleciona CPEs pré-definidos (veja opções no --help).

- -s, --severity: Filtra por severidade CVSS (LOW, MEDIUM, HIGH, CRITICAL).

- -v, --cvss-version: Exibe métricas CVSS v2.0 ou v3.1.

## Exemplos:
Busca básica por palavra-chave:

> python3 cli.py -k "firefox 90"

> python3 cli.py -k "chrome"

Busca por um CPE especifico:

> python3 cli.py -c 




