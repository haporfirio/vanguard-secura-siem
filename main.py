"""
SecuraPy SIEM - Ponto de Entrada Principal
Integra todos os modulos: coletor, regras, detector, enriquecimento,
servidor de alertas e relatorios em um menu interativo.
"""

import sys

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from coletor import carregar_todos_os_logs
from regras import carregar_regras, aplicar_regras
from detector import (
    detectar_brute_force,
    detectar_port_scan,
    verificar_blacklist,
    gerar_resumo_ameacas,
)
from relatorios import (
    exibir_menu,
    resumo_geral,
    filtrar_eventos,
    buscar_ip,
    exibir_top_ips,
    exibir_alertas_por_severidade,
    exportar_relatorio_json,
    montar_dados_relatorio,
    gerar_nome_relatorio,
    exibir_tabela,
)

try:
    from enriquecimento import enriquecer_alertas
    ENRIQUECIMENTO_OK = True
except Exception as e:
    ENRIQUECIMENTO_OK = False
    _ERRO_ENRIQUECIMENTO = str(e)
    print(f"\n[AVISO] Modulo de enriquecimento indisponivel: {e}")
    print("[AVISO] A opcao 7 (Enriquecer IPs) ficara desabilitada.\n")

PASTA_LOGS = "logs"
ARQUIVO_REGRAS = "config/regras.json"
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}


def main():
    eventos = []
    alertas = []
    resumo = []
    cache_enriquecimento = {}

    print("=" * 50)
    print("       SecuraPy SIEM - Coding for Security")
    print("=" * 50)

    while True:
        opcao = exibir_menu()

        if opcao == 1:
            print("\n[*] Carregando logs...")
            eventos = carregar_todos_os_logs(PASTA_LOGS)
            print(f"[OK] {len(eventos)} eventos carregados.")

            print("[*] Carregando regras...")
            regras = carregar_regras(ARQUIVO_REGRAS)
            print(f"[OK] {len(regras)} regras ativas.")

            print("[*] Aplicando regras...")
            alertas = aplicar_regras(eventos, regras)
            print(f"[OK] {len(alertas)} alertas gerados.")

            print("[*] Detectando anomalias...")
            brute = detectar_brute_force(eventos)
            scan = detectar_port_scan(eventos)
            bl = verificar_blacklist(eventos, BLACKLIST)
            resumo = gerar_resumo_ameacas(brute, scan, bl)
            print(f"[OK] {len(resumo)} ameacas identificadas.")
            print("\n[OK] Processamento concluido. Use as opcoes 2-8 para visualizar.")

        elif opcao == 2:
            resumo_geral(eventos, alertas)

        elif opcao == 3:
            if not eventos:
                print("\n[!] Carregue os logs primeiro (opcao 1).")
                continue
            print("\nDeixe em branco para ignorar o filtro.")
            fonte = input("Fonte (auth/firewall/web): ").strip() or None
            tipo = input("Tipo: ").strip() or None
            ip = input("IP: ").strip() or None
            resultado = filtrar_eventos(eventos, fonte=fonte, tipo=tipo, ip=ip)
            print(f"\n[OK] {len(resultado)} evento(s) encontrado(s).")
            if resultado:
                exibir_tabela(resultado[:50], ["timestamp", "fonte", "tipo", "ip", "detalhes"])
                if len(resultado) > 50:
                    print(f"\n  ... e mais {len(resultado) - 50} eventos.")

        elif opcao == 4:
            if not eventos:
                print("\n[!] Carregue os logs primeiro (opcao 1).")
                continue
            ip = input("\nDigite o IP: ").strip()
            if ip:
                buscar_ip(ip, eventos, alertas, cache_enriquecimento)

        elif opcao == 5:
            exibir_top_ips(eventos, alertas)

        elif opcao == 6:
            exibir_alertas_por_severidade(alertas)

        elif opcao == 7:
            if not ENRIQUECIMENTO_OK:
                print(f"\n[!] Opcao indisponivel: modulo de enriquecimento falhou ao carregar.")
                print(f"    Erro: {_ERRO_ENRIQUECIMENTO}")
                continue
            if not alertas:
                print("\n[!] Nenhum alerta para enriquecer. Use a opcao 1 primeiro.")
                continue
            print("\n[*] Enriquecendo IPs dos alertas (pode levar alguns segundos)...")
            try:
                alertas = enriquecer_alertas(alertas, cache_enriquecimento)
                print(f"[OK] Cache contem {len(cache_enriquecimento)} IP(s) enriquecido(s).")
            except Exception as e:
                print(f"\n[ERRO] Falha ao enriquecer alertas: {e}")
                print("[!] Alertas mantidos sem enriquecimento.")

        elif opcao == 8:
            if not eventos:
                print("\n[!] Carregue os logs primeiro (opcao 1).")
                continue
            dados = montar_dados_relatorio(eventos, alertas, cache_enriquecimento)
            caminho = gerar_nome_relatorio()
            exportar_relatorio_json(dados, caminho)

        elif opcao == 9:
            try:
                from servidor_alertas import iniciar_servidor
                print("\n[*] Iniciando servidor de alertas... (Ctrl+C para parar)")
                iniciar_servidor()
            except KeyboardInterrupt:
                print("\n[OK] Servidor encerrado.")
            except Exception as e:
                print(f"\n[ERRO] Falha ao iniciar servidor: {e}")

        elif opcao == 0:
            print("\nEncerrando SecuraPy. Ate logo!")
            break

        else:
            print("Opcao invalida. Tente novamente.")


if __name__ == "__main__":
    main()
