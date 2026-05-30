import json
import os
from datetime import datetime
from collections import Counter


def exibir_menu():
    print("\n╔══════════════════════════════════════════╗")
    print("║         SecuraPy SIEM — Menu             ║")
    print("╠══════════════════════════════════════════╣")
    print("║  1. Carregar e processar logs            ║")
    print("║  2. Resumo geral                         ║")
    print("║  3. Filtrar eventos                      ║")
    print("║  4. Buscar IP                            ║")
    print("║  5. Top 10 IPs suspeitos                 ║")
    print("║  6. Ver alertas por severidade           ║")
    print("║  7. Enriquecer IPs suspeitos             ║")
    print("║  8. Exportar relatório JSON              ║")
    print("║  9. Iniciar servidor de alertas          ║")
    print("║  0. Sair                                 ║")
    print("╚══════════════════════════════════════════╝")

    try:
        opcao = int(input("\nEscolha uma opção: "))
        if 0 <= opcao <= 9:
            return opcao
        print("Opção inválida. Digite um número entre 0 e 9.")
        return -1
    except ValueError:
        print("Opção inválida. Digite um número entre 0 e 9.")
        return -1


def resumo_geral(eventos, alertas):
    if not eventos:
        print("\n[!] Nenhum evento carregado. Use a opção 1 primeiro.")
        return

    print("\n" + "=" * 44)
    print("           RESUMO GERAL DO SISTEMA")
    print("=" * 44)

    contagem_fonte = Counter(e["fonte"] for e in eventos)
    print(f"\n{'EVENTOS POR FONTE':}")
    print(f"  {'Fonte':<12} {'Quantidade':>10}")
    print(f"  {'-'*24}")
    for fonte, qtd in sorted(contagem_fonte.items()):
        print(f"  {fonte:<12} {qtd:>10}")
    print(f"  {'-'*24}")
    print(f"  {'TOTAL':<12} {len(eventos):>10}")

    print(f"\n{'ALERTAS POR SEVERIDADE':}")
    if not alertas:
        print("  Nenhum alerta gerado.")
    else:
        ordem = ["CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"]
        contagem_sev = Counter(a["severidade"] for a in alertas)
        print(f"  {'Severidade':<12} {'Quantidade':>10}")
        print(f"  {'-'*24}")
        for sev in ordem:
            if sev in contagem_sev:
                print(f"  {sev:<12} {contagem_sev[sev]:>10}")
        print(f"  {'-'*24}")
        print(f"  {'TOTAL':<12} {len(alertas):>10}")

    print("=" * 44)


def filtrar_eventos(eventos, fonte=None, tipo=None, ip=None):
    resultado = eventos

    if fonte is not None:
        resultado = [e for e in resultado if e["fonte"] == fonte]

    if tipo is not None:
        resultado = [e for e in resultado if e["tipo"] == tipo]

    if ip is not None:
        resultado = [e for e in resultado if e["ip"] == ip]

    return resultado


def buscar_ip(ip, eventos, alertas, cache_enriquecimento):
    if not eventos:
        print("\n[!] Nenhum evento carregado. Use a opção 1 primeiro.")
        return

    eventos_ip = filtrar_eventos(eventos, ip=ip)
    alertas_ip = [a for a in alertas if a.get("ip") == ip]

    print("\n" + "=" * 50)
    print(f"  RELATÓRIO DO IP: {ip}")
    print("=" * 50)

    if not eventos_ip:
        print(f"\n  Nenhum evento encontrado para o IP {ip}.")
    else:
        print(f"\n  Total de eventos: {len(eventos_ip)}")
        colunas = ["timestamp", "fonte", "tipo", "detalhes"]
        exibir_tabela(eventos_ip, colunas)

    print(f"\n  Alertas gerados: {len(alertas_ip)}")
    if alertas_ip:
        for alerta in alertas_ip:
            print(f"  [{alerta['severidade']}] {alerta['timestamp']} — {alerta['descricao']}")

    dados_geo = cache_enriquecimento.get(ip)
    if dados_geo:
        print(f"\n  GEOLOCALIZAÇÃO:")
        print(f"    País    : {dados_geo.get('pais', 'N/A')}")
        print(f"    Região  : {dados_geo.get('regiao', 'N/A')}")
        print(f"    Cidade  : {dados_geo.get('cidade', 'N/A')}")
        print(f"    Org     : {dados_geo.get('org', 'N/A')}")
        print(f"    Hostname: {dados_geo.get('hostname', 'N/A')}")
    else:
        print("\n  Sem dados de geolocalização. Use a opção 7 para enriquecer IPs.")

    print("=" * 50)


def top_ips(eventos, n=10):
    if not eventos:
        return []

    contagem = Counter(e["ip"] for e in eventos)
    return contagem.most_common(n)


def exportar_relatorio_json(dados, caminho):
    try:
        os.makedirs(os.path.dirname(caminho), exist_ok=True)
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(dados, f, indent=2, ensure_ascii=False)
        print(f"\n[✓] Relatório exportado com sucesso: {caminho}")
    except OSError as e:
        print(f"\n[ERRO] Não foi possível salvar o relatório: {e}")
    except TypeError as e:
        print(f"\n[ERRO] Dados inválidos para exportação JSON: {e}")


def exibir_tabela(dados, colunas):
    if not dados:
        print("  Nenhum dado para exibir.")
        return

    larguras = {}
    for col in colunas:
        larguras[col] = max(len(col), max((len(str(linha.get(col, ""))) for linha in dados), default=0))

    cabecalho = "  " + "  ".join(f"{col:<{larguras[col]}}" for col in colunas)
    separador = "  " + "  ".join("-" * larguras[col] for col in colunas)

    print(cabecalho)
    print(separador)
    for linha in dados:
        linha_str = "  " + "  ".join(f"{str(linha.get(col, '')):<{larguras[col]}}" for col in colunas)
        print(linha_str)


def exibir_top_ips(eventos, alertas):
    if not eventos:
        print("\n[!] Nenhum evento carregado. Use a opção 1 primeiro.")
        return

    ranking = top_ips(eventos, n=10)
    ips_com_alerta = {a.get("ip") for a in alertas}

    print("\n" + "=" * 44)
    print("         TOP 10 IPs MAIS ATIVOS")
    print("=" * 44)
    print(f"  {'#':<4} {'IP':<20} {'Eventos':>7}  {'Status'}")
    print(f"  {'-'*40}")

    for i, (ip, qtd) in enumerate(ranking, start=1):
        status = "⚠ SUSPEITO" if ip in ips_com_alerta else "OK"
        print(f"  {i:<4} {ip:<20} {qtd:>7}  {status}")

    print("=" * 44)


def exibir_alertas_por_severidade(alertas):
    if not alertas:
        print("\n[!] Nenhum alerta disponível. Carregue e processe os logs primeiro.")
        return

    ordem = ["CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"]
    agrupados = {sev: [] for sev in ordem}

    for alerta in alertas:
        sev = alerta.get("severidade", "INFO")
        if sev in agrupados:
            agrupados[sev].append(alerta)

    for sev in ordem:
        grupo = agrupados[sev]
        if not grupo:
            continue
        print(f"\n  [{sev}] — {len(grupo)} alerta(s)")
        print(f"  {'-'*48}")
        for alerta in grupo:
            ts = alerta.get("timestamp", "??")
            ip = alerta.get("ip", "??")
            desc = alerta.get("descricao", "??")
            print(f"  {ts}  IP: {ip:<18}  {desc}")


def montar_dados_relatorio(eventos, alertas, cache_enriquecimento):
    return {
        "gerado_em": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "resumo": {
            "total_eventos": len(eventos),
            "total_alertas": len(alertas),
            "eventos_por_fonte": dict(Counter(e["fonte"] for e in eventos)),
            "alertas_por_severidade": dict(Counter(a["severidade"] for a in alertas)),
        },
        "top_ips": [{"ip": ip, "eventos": qtd} for ip, qtd in top_ips(eventos, n=10)],
        "alertas": alertas,
        "enriquecimento": cache_enriquecimento,
    }


def gerar_nome_relatorio():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join("saida", f"relatorio_{timestamp}.json")
