#!/usr/bin/env python3
import requests
import argparse
import json
import sys # Importa o módulo sys para lidar com a saída


def search_nvd(keyword_terms=None, cpe_name=None, cvss_severity=None, cvss_version=None, output_file=None):
    """
    Realiza buscas na NVD usando palavra-chave e/ou CPE(s) de um dicionário pré-definido,
    com filtros opcionais de severidade, versão CVSS e exporta para arquivo.
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Combina os termos de palavra-chave em uma única string, se houver
    keyword = " ".join(keyword_terms) if keyword_terms else None

    if not keyword and not cpe_name:
        print("Erro: Você deve fornecer uma palavra-chave (--keyword) ou um CPE (--cpe).")
        return

    # Define o destino da saída
    output_stream = None
    if output_file:
        try:
            output_stream = open(output_file, 'w', encoding='utf-8')
            print(f"Resultados serão salvos em '{output_file}'")
        except IOError as e:
            print(f"Erro ao abrir o arquivo '{output_file}': {e}", file=sys.stderr)
            return
    else:
        output_stream = sys.stdout # Imprime no terminal por padrão

    all_vulnerabilities = [] # Lista para coletar todas as vulnerabilidades para exportação

    if cpe_name:
        print(f"\n--- Buscando para CPE: {cpe_name} {'com palavra-chave: ' + keyword if keyword else ''} ---", file=output_stream)
        params = {"cpeName": cpe_name}
        if keyword:
            params["keywordSearch"] = keyword
        
        vuls = _perform_nvd_request(base_url, params, cvss_severity, cvss_version, output_stream)
        if vuls:
            all_vulnerabilities.extend(vuls)

    elif keyword:
        print(f"\n--- Buscando para palavra-chave: {keyword} ---", file=output_stream)
        params = {"keywordSearch": keyword}
        vuls = _perform_nvd_request(base_url, params, cvss_severity, cvss_version, output_stream)
        if vuls:
            all_vulnerabilities.extend(vuls)

    # Se um arquivo de saída foi especificado, salve todos os resultados em JSON
    if output_file and all_vulnerabilities:
        try:
            # Reabre o arquivo para garantir que estamos escrevendo o JSON completo
            # ou escreve de uma vez se não foi aberto para printar durante a execução
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(all_vulnerabilities, f, indent=4, ensure_ascii=False)
            print(f"\nTodos os {len(all_vulnerabilities)} resultados foram salvos em '{output_file}' como JSON.")
        except IOError as e:
            print(f"Erro ao salvar os resultados em '{output_file}': {e}", file=sys.stderr)
    elif output_file:
        print(f"\nNenhum resultado para salvar em '{output_file}'.")

    if output_stream != sys.stdout:
        output_stream.close()


def _perform_nvd_request(base_url, params, cvss_severity, cvss_version, output_stream):
    """Função auxiliar para fazer a requisição à NVD e processar a resposta."""
    
    try:
        response = requests.get(base_url, params=params)
        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        
        if cvss_severity:
            initial_count = len(vulnerabilities)
            filtered_vulnerabilities = []
            for vul in vulnerabilities:
                cve = vul["cve"]
                metrics = cve.get("metrics", {})
                
                current_severity = None
                
                if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    if "cvssData" in metrics["cvssMetricV31"][0]:
                        current_severity = metrics["cvssMetricV31"][0]["cvssData"].get("baseSeverity")
                
                if current_severity is None and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    if "cvssData" in metrics["cvssMetricV2"][0]:
                        current_severity = metrics["cvssMetricV2"][0]["cvssData"].get("baseSeverity")

                if current_severity and current_severity.upper() == cvss_severity.upper():
                    filtered_vulnerabilities.append(vul)
            vulnerabilities = filtered_vulnerabilities
            if initial_count > 0 and len(vulnerabilities) == 0:
                print(f"  Aviso: Nenhum resultado encontrado para a severidade '{cvss_severity}'. Pode ser que os CVEs encontrados não tenham essa severidade ou não possuam métricas CVSS.", file=output_stream)

        if vulnerabilities:
            print(f"  Resultados encontrados ({len(vulnerabilities)} vulnerabilidades):", file=output_stream)
            for vulnerability in vulnerabilities:
                cve = vulnerability["cve"]
                cve_id = cve["id"]
                description = cve["descriptions"][0]["value"]
                published_date = cve["published"]
                
                print(f"    **ID**: {cve_id}", file=output_stream)
                print(f"    **Descrição**: {description[:150]}...", file=output_stream) 
                print(f"    **Publicado em**: {published_date}", file=output_stream)

                metrics = cve.get("metrics", {})
                
                displayed_cvss = False
                if cvss_version == "3.1" and "cvssMetricV31" in metrics and metrics["cvssMetricV31"] and "cvssData" in metrics["cvssMetricV31"][0]:
                    cvss_v31 = metrics["cvssMetricV31"][0]["cvssData"]
                    severity = cvss_v31.get("baseSeverity")
                    base_score = cvss_v31.get("baseScore")
                    if severity and base_score is not None:
                        print(f"    **CVSS v3.1 Severidade**: {severity} (Pontuação: {base_score})", file=output_stream)
                        displayed_cvss = True
                elif cvss_version == "2.0" and "cvssMetricV2" in metrics and metrics["cvssMetricV2"] and "cvssData" in metrics["cvssMetricV2"][0]:
                    cvss_v2 = metrics["cvssMetricV2"][0]["cvssData"]
                    severity = cvss_v2.get("baseSeverity")
                    base_score = cvss_v2.get("baseScore")
                    if severity and base_score is not None:
                        print(f"    **CVSS v2.0 Severidade**: {severity} (Pontuação: {base_score})", file=output_stream)
                        displayed_cvss = True
                elif not cvss_version: 
                    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"] and "cvssData" in metrics["cvssMetricV31"][0]:
                        cvss_v31 = metrics["cvssMetricV31"][0]["cvssData"]
                        severity = cvss_v31.get("baseSeverity")
                        base_score = cvss_v31.get("baseScore")
                        if severity and base_score is not None:
                            print(f"    **CVSS v3.1 Severidade**: {severity} (Pontuação: {base_score})", file=output_stream)
                            displayed_cvss = True
                    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"] and "cvssData" in metrics["cvssMetricV2"][0]:
                        cvss_v2 = metrics["cvssMetricV2"][0]["cvssData"]
                        severity = cvss_v2.get("baseSeverity")
                        base_score = cvss_v2.get("baseScore")
                        if severity and base_score is not None:
                            print(f"    **CVSS v2.0 Severidade**: {severity} (Pontuação: {base_score})", file=output_stream)
                            displayed_cvss = True
                
                if not displayed_cvss:
                    print("    **CVSS**: Não disponível", file=output_stream)
                print("    " + "-" * 70, file=output_stream) 
            return vulnerabilities # Retorna as vulnerabilidades para serem coletadas
        else:
            print(f"  Nenhuma vulnerabilidade encontrada com os filtros aplicados para esta consulta.", file=output_stream)
            return [] # Retorna lista vazia
    except requests.exceptions.RequestException as e:
        print(f"  Erro ao fazer a requisição: {e}", file=sys.stderr)
        return []
    except json.JSONDecodeError:
        print("  Erro ao decodificar a resposta JSON. A resposta pode não ser JSON válida.", file=sys.stderr)
        return []
    except Exception as e:
        print(f"  Ocorreu um erro inesperado: {e}", file=sys.stderr)
        return []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Busca vulnerabilidades no NVD por palavra-chave e/ou CPEs pré-definidos.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        "-k", "--keyword", 
        nargs='+',
        help="Termos para buscar na NVD (ex: 'firefox 40 rce'). Separe os termos com espaço."
    )
    
    parser.add_argument(
        "-c", "--cpe",
        help="CPE específico para buscar (ex: 'cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*')."
    )

    parser.add_argument(
        "-s", "--severity", 
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], 
        help="Filtra vulnerabilidades por severidade CVSS (LOW, MEDIUM, HIGH, CRITICAL).\n"
             "Vulnerabilidades sem métricas CVSS não serão filtradas."
    )
    
    parser.add_argument(
        "-v", "--cvss-version", 
        choices=["2.0", "3.1"], 
        help="Especifica qual versão do CVSS exibir (2.0 ou 3.1)."
    )

    # Novo argumento para o arquivo de saída
    parser.add_argument(
        "-o", "--output-file",
        help="Caminho para o arquivo onde os resultados serão salvos (formato JSON). Se não especificado, imprime no terminal."
    )

    args = parser.parse_args()
    
    # Passe o novo argumento output_file para a função search_nvd
    search_nvd(args.keyword, args.cpe, args.severity, args.cvss_version, args.output_file)
