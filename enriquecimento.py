#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
""" Modulo 5 - Enriquecimento de IPs
        Adiciona contexto geografico e organizacional aos IPs suspeitos
        consultando a API publica do ipinfo.io.
        Classifica IPs em privados (rede interna) e publicos, e consulta
        apenas os publicos para economizar requisicoes.
"""
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
import requests
import json
import ipaddress
from pathlib import Path
import time

CAMINHO_CONFIG = Path("cache_enriq.json").parent / "config" / "cache_enriq.json"

def _carregar_cache(CAMINHO_CONFIG):
    try:
        with open(CAMINHO_CONFIG, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def _salvar_cache(cache, CAMINHO_CONFIG):
      Path(CAMINHO_CONFIG).parent.mkdir(parents=True, exist_ok=True)
      with open(CAMINHO_CONFIG, "w", encoding="utf-8") as f:
          json.dump(cache, f, indent=2, ensure_ascii=False)

def _ip_no_cache(ip, cache):
    ip_str = str(ip)
    for ip_cadastrado in cache:
        if ip_str == ip_cadastrado.get("ip"):
            return ip_cadastrado
    return None

def eh_ip_privado(ip: ipaddress.IPv4Address | ipaddress.IPv6Address):
    primeiro_unpacked_ip = ip.packed[0]
    segundo_unpacked_ip = ip.packed[1]
    return (primeiro_unpacked_ip == 10) or \
           (primeiro_unpacked_ip == 172 and 16 <= segundo_unpacked_ip <= 31) or \
           (primeiro_unpacked_ip == 192 and segundo_unpacked_ip == 168) or \
           (primeiro_unpacked_ip == 127)

class IPInvalidoError(Exception):
    def __init__(self, ip_str):
        super().__init__(f"{ip_str} é inválido.")

def eh_ip_valido(ip_str):
    try:
        return ipaddress.ip_address(ip_str)
    except ValueError:
        raise IPInvalidoError(f"O Ip {ip_str}")

def consultar_ip(ip, cache):
    ip_str = str(ip)
    cache = _carregar_cache(CAMINHO_CONFIG)
    # 1. Se já existir no cache, retorna o dicionário
    dados_cached = _ip_no_cache(ip_str, cache)
    if dados_cached:
        return dados_cached

    novos_dados = {}
    privado = False

    try:
        ip_obj = eh_ip_valido(ip_str)
        if eh_ip_privado(ip_obj):
            privado = True
    except IPInvalidoError as e:
        # Se o IP for inválido, gera um dicionário padrão de erro e não salva no cache
        return {
            "ip": ip_str, "privado": False, "cidade": "Inválido", 
            "regiao": "Inválido", "pais": "Inválido", "org": "Inválido", "hostname": "Inválido"
        }

    # 2. Se for IP privado, monta estrutura de rede interna e salva
    if privado:
        novos_dados = {
            "ip": ip_str,
            "privado": True,
            "cidade": "Rede Interna",
            "regiao": "Rede Interna",
            "pais": "Rede Interna",
            "org": "Rede Interna",
            "hostname": "Rede Interna"
        }
        cache.append(novos_dados)
        # _salvar_cache(cache, CAMINHO_CONFIG)
        return _salvar_cache(cache, CAMINHO_CONFIG)

    # 3. Se for IP público, consulta a API externa
    else:
        novos_dados = {
            "ip": ip_str, "privado": False, "cidade": "Desconhecido", 
            "regiao": "Desconhecido", "pais": "Desconhecido", "org": "Desconhecido", "hostname": "Desconhecido"
        }
        try:
            resposta = requests.get(f"https://ipinfo.io/{ip_str}/json", timeout=5)

            if resposta.status_code == 200:
                dados = resposta.json()
                novos_dados = {
                    "ip": ip_str,
                    "privado": False,
                    "cidade": dados.get("city", "Desconhecido"),
                    "regiao": dados.get("region", "Desconhecido"),
                    "pais": dados.get("country", "Desconhecido"),
                    "org": dados.get("org", "Desconhecido"),
                    "hostname": dados.get("hostname", "Desconhecido")
                }
                cache.append(novos_dados)
                time.sleep(0.2) # Delay amigável para evitar bloqueio na API pública se rodar em massa
                return _salvar_cache(cache, CAMINHO_CONFIG)
                
            else:
                print(f"Código {resposta.status_code}!")
                cache.append(novos_dados)
                _salvar_cache(cache, CAMINHO_CONFIG)
                print(f"Nao foi possivel atualizar o cahce com o {ip}.")
        except Exception as e:
            print(f"[ERRO] Falha ao processar requisição externa para {ip_str}: {e}")

        return _salvar_cache(cache, CAMINHO_CONFIG)

def enriquecer_alertas(alertas, cache):
    """
    Adiciona informacoes de geolocalizacao a uma lista de alertas.

    Parametros:
        alertas (list[dict]): lista de alertas (cada um tem campo "ip")
        cache (dict): cache de consultas de IP
    Retorna:
        list[dict]: mesmos alertas com campo adicional "geolocalizacao"
    Comportamento esperado:
        - Para cada alerta, consulta o IP (usando cache)
        - Adiciona campo "geolocalizacao" ao alerta com os dados retornados
        - IPs privados recebem geolocalizacao com "Rede Interna"
        - IPs repetidos usam o cache (sem consulta duplicada)

    Dicas:
        - Extraia IPs unicos primeiro para minimizar consultas
        - Use um set para coletar IPs unicos: ips = {a["ip"] for a in alertas}
        - Consulte cada IP unico uma vez, depois distribua pelos alertas
    """

    ips_unicos = {alerta["ip"] for alerta in alertas if "ip" in alerta}

    mapa_enriquecimento = {}
    for ip in ips_unicos:
        mapa_enriquecimento[ip] = consultar_ip(ip, cache)

    for alerta in alertas:
        ip_alerta = alerta.get("ip")
        if ip_alerta in mapa_enriquecimento:
            alerta["geolocalizacao"] = mapa_enriquecimento[ip_alerta]

    return alertas

def exibir_enriquecimento(dados_ip):
    """
    Exibe as informacoes de um IP de forma formatada no terminal.

        Parametros:
        dados_ip (dict): dicionario retornado por consultar_ip()

    Comportamento esperado:
        - Exibe IP, cidade, regiao, pais e organizacao de forma legivel
        - Indica se eh IP privado ou publico

    Dicas:
        - Use f-strings com alinhamento: f"{'IP:':<15} {dados['ip']}"
    """
    if not dados_ip:
        print("Nenhum dado de IP disponível para exibição.")
        return

    tipo_ip = "Privado (Interno)" if dados_ip.get("privado") else "Público (Externo)"

    print("-" * 50)
    print(f"{'ANÁLISE DE CONTEXTO DE IP':^50}")
    print("-" * 50)
    print(f"{'IP:':<15} {dados_ip.get('ip')}")
    print(f"{'Tipo:':<15} {tipo_ip}")
    print(f"{'Cidade:':<15} {dados_ip.get('cidade')}")
    print(f"{'Região:':<15} {dados_ip.get('regiao')}")
    print(f"{'País:':<15} {dados_ip.get('pais')}")
    print(f"{'Organização:':<15} {dados_ip.get('org')}")
    print(f"{'Hostname:':<15} {dados_ip.get('hostname')}")
    print("-" * 50)

#+++++++++++++++++++++++++++++++++++++++++

def areaDev():
    ip_dict = {
        0: "10.0.0.1",
        1: "10.255.255.255",
        2: "10.0.0.5",
        3: "172.16.0.1",
        4: "172.31.255.255",
        5: "172.32.0.1",
        6: "172.15.0.1",
        7: "192.168.1.1",
        8: "192.168.1.10",
        9: "192.168.255.255",
        10: "127.0.0.1",
        11: "8.8.8.8",
        12: "185.220.101.1",
        13: "91.240.118.172",
        14: "45.33.32.156",
        15: "1.1.1.1",
        16: "1.2.3.4"
    }
    contador = 0
    while contador < len(ip_dict):
        ip = ip_dict[contador]
        consultar_ip(ip, _carregar_cache(CAMINHO_CONFIG))
        contador += 1
    print(f"=== INICIANDO SIMULAÇÃO DE ENRIQUECIMENTO EM MASSA ({len(ip_dict)} IPs) ===\n")
    
    # 1. Monta uma lista de "alertas" dinamicamente usando todos os IPs do dicionário
    alertas_gerados = []
    for chave, ip in ip_dict.items():
        alertas_gerados.append({
            "id": chave,
            "evento": f"Log de Simulação - Evento {chave}",
            "ip": ip
        })

    # 2. Carrega o cache em disco e processa o lote de alertas de uma só vez

    alertas_enriquecidos = enriquecer_alertas(alertas_gerados, _carregar_cache(CAMINHO_CONFIG))

    # 3. Itera sobre o resultado de todos os alertas processados e exibe na tela
    for alerta in alertas_enriquecidos:
        print(f"\n[ALERTA ID {alerta['id']}] Evento: {alerta['evento']}")
        exibir_enriquecimento(alerta["geolocalizacao"])

if __name__ == "__main__":
    areaDev()