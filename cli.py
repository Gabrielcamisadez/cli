import requests
import argparse
import json

# --- Dicionário de CPEs Pré-definidos ---
# IMPORTANTE: Verifique a exatidão destes CPEs na NVD para garantir resultados precisos.
# Os CPEs são sensíveis a detalhes como versão, edição, idioma, etc.
PREDEFINED_CPES = {
    "adobe_acrobat_8_1": "cpe:2.3:a:adobe:acrobat:8.1.0:*:standard:*:*:*:*:*",
    "adobe_reader_dc": "cpe:2.3:a:adobe:acrobat_reader_dc:*:*:*:*:*:*:*:*",
    "adobe_flash_player_21_npapi": "cpe:2.3:a:adobe:flash_player:21.0.0.242:*:npapi:*:*:*:*:*",
    "adobe_reader_9_3_pt_br": "cpe:2.3:a:adobe:acrobat_reader:9.3:*:*:*:*:*:pt-br:*",
    "libreoffice_5_3_7_2": "cpe:2.3:a:libreoffice:libreoffice:5.3.7.2:*:*:*:*:*:*:*",
    "ms_office_2007_enterprise": "cpe:2.3:a:microsoft:office:2007:*:enterprise:*:*:*:*:*",
    "ms_office_2007_standard": "cpe:2.3:a:microsoft:office:2007:*:standard:*:*:*:*:*",
    "ms_visual_studio_6_enterprise": "cpe:2.3:a:microsoft:visual_studio:6.0:*:enterprise:*:*:*:*:*",
    "mozilla_firefox_40_pt_br": "cpe:2.3:a:mozilla:firefox:40.0:*:*:*:*:*:pt-br:*"
}

def search_nvd(keyword=None, selected_cpes_keys=None, cvss_severity=None, cvss_version=None):
    """
    Realiza buscas na NVD usando palavra-chave e/ou CPE(s) de um dicionário pré-definido,
    com filtros opcionais de severidade e versão CVSS.
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    cpes_to_search = []

    if selected_cpes_keys:
        for key in selected_cpes_keys:
            if key in PREDEFINED_CPES:
                cpes_to_search.append(PREDEFINED_CPES[key])
            else:
                print(f"Aviso: Chave de CPE '{key}' não encontrada nos CPEs pré-definidos. Ignorando.")

    if not keyword and not cpes_to_search:
        print("Erro: Você deve fornecer uma palavra-chave (--keyword) ou selecionar um(ns) CPE(s) (--cpe-select).")
        print(f"Opções de CPE pré-definidos disponíveis: {', '.join(PREDEFINED_CPES.keys())}")
        return

    if cpes_to_search:
        for single_cpe in cpes_to_search:
            friendly_name = next((name for name, cpe_val in PREDEFINED_CPES.items() if cpe_val == single_cpe), single_cpe)
            print(f"\n--- Buscando para CPE: {friendly_name} ({single_cpe}) {'com palavra-chave: ' + keyword if keyword else ''} ---")
            params = {"cpeName": single_cpe}
            if keyword:
                params["keywordSearch"] = keyword
            
            _perform_nvd_request(base_url, params, cvss_severity, cvss_version)
    elif keyword:
        print(f"\n--- Buscando para palavra-chave: {keyword} ---")
        params = {"keywordSearch": keyword}
        _perform_nvd_request(base_url, params, cvss_severity, cvss_version)


def _perform_nvd_request(base_url, params, cvss_severity, cvss_version):
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
                print(f"  Aviso: Nenhum resultado encontrado para a severidade '{cvss_severity}'. Pode ser que os CVEs encontrados não tenham essa severidade ou não possuam métricas CVSS.")

        if vulnerabilities:
            print(f"  Resultados encontrados ({len(vulnerabilities)} vulnerabilidades):")
            for vulnerability in vulnerabilities:
                cve = vulnerability["cve"]
                cve_id = cve["id"]
                description = cve["descriptions"][0]["value"]
                published_date = cve["published"]
                
                print(f"    **ID**: {cve_id}")
                print(f"    **Descrição**: {description[:150]}...") 
                print(f"    **Publicado em**: {published_date}")

                metrics = cve.get("metrics", {})
                
                displayed_cvss = False
                if cvss_version == "3.1" and "cvssMetricV31" in metrics and metrics["cvssMetricV31"] and "cvssData" in metrics["cvssMetricV31"][0]:
                    cvss_v31 = metrics["cvssMetricV31"][0]["cvssData"]
                    severity = cvss_v31.get("baseSeverity")
                    base_score = cvss_v31.get("baseScore")
                    if severity and base_score is not None:
                        print(f"    **CVSS v3.1 Severidade**: {severity} (Pontuação: {base_score})")
                        displayed_cvss = True
                elif cvss_version == "2.0" and "cvssMetricV2" in metrics and metrics["cvssMetricV2"] and "cvssData" in metrics["cvssMetricV2"][0]:
                    cvss_v2 = metrics["cvssMetricV2"][0]["cvssData"]
                    severity = cvss_v2.get("baseSeverity")
                    base_score = cvss_v2.get("baseScore")
                    if severity and base_score is not None:
                        print(f"    **CVSS v2.0 Severidade**: {severity} (Pontuação: {base_score})")
                        displayed_cvss = True
                elif not cvss_version: 
                    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"] and "cvssData" in metrics["cvssMetricV31"][0]:
                        cvss_v31 = metrics["cvssMetricV31"][0]["cvssData"]
                        severity = cvss_v31.get("baseSeverity")
                        base_score = cvss_v31.get("baseScore")
                        if severity and base_score is not None:
                            print(f"    **CVSS v3.1 Severidade**: {severity} (Pontuação: {base_score})")
                            displayed_cvss = True
                    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"] and "cvssData" in metrics["cvssMetricV2"][0]:
                        cvss_v2 = metrics["cvssMetricV2"][0]["cvssData"]
                        severity = cvss_v2.get("baseSeverity")
                        base_score = cvss_v2.get("baseScore")
                        if severity and base_score is not None:
                            print(f"    **CVSS v2.0 Severidade**: {severity} (Pontuação: {base_score})")
                            displayed_cvss = True
                
                if not displayed_cvss:
                    print("    **CVSS**: Não disponível")
                print("    " + "-" * 70) 
        else:
            print(f"  Nenhuma vulnerabilidade encontrada com os filtros aplicados para esta consulta.")

    except requests.exceptions.RequestException as e:
        print(f"  Erro ao fazer a requisição: {e}")
    except json.JSONDecodeError:
        print("  Erro ao decodificar a resposta JSON. A resposta pode não ser JSON válida.")
    except Exception as e:
        print(f"  Ocorreu um erro inesperado: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Busca vulnerabilidades no NVD por palavra-chave e/ou CPEs pré-definidos.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        "-k", "--keyword", 
        help="A palavra-chave para buscar na NVD (ex: 'chrome', 'firefox 40')."
    )
    
    parser.add_argument(
        "-c", "--cpe-select",
        nargs='+',
        help="Selecione um ou mais nomes de CPE pré-definidos para buscar.\n"
             f"Disponíveis: {', '.join(PREDEFINED_CPES.keys())}"
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

    args = parser.parse_args()
    
    search_nvd(args.keyword, args.cpe_select, args.severity, args.cvss_version)
