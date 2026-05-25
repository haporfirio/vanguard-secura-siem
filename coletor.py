"""
Modulo 1 - Coletor de Logs
Responsavel por ler arquivos de log de diferentes fontes (auth, firewall, web),
parsear cada linha e normalizar os eventos em um formato padronizado de dicionario.

Formato padronizado de evento:
{
    "timestamp": "2025-02-20 08:15:01",
    "fonte": "auth",              # auth | firewall | web
    "tipo": "FAIL",               # OK | FAIL | BLOCK | ALLOW | GET | POST | DELETE
    "ip": "185.220.101.1",
    "detalhes": "usuario=admin",  # informacoes extras dependendo da fonte
    "linha_original": "..."       # linha crua do log
}
"""

import os


def parsear_linha_auth(linha):
    """
    Parseia uma linha do auth.log e retorna um dicionario normalizado.

    Formato da linha:
        "2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1"

    Retorna:
        dict com chaves: timestamp, fonte, tipo, ip, detalhes, linha_original
        Retorna None se a linha estiver em formato invalido.

    Dicas:
        - Use split() para separar a linha em partes
        - O timestamp sao as 2 primeiras partes juntas (data + hora)
        - O tipo eh a terceira parte (FAIL ou OK)
        - Percorra as partes restantes procurando "ip=" e "usuario="
    """
    if not linha:
        return None
    partes = linha.split()
    if len(partes) < 5:
        return None

    timestamp = partes[0] + " " + partes[1]
    tipo = partes[2]
    ip = None
    detalhes = None

    for parte in partes[3:]:
        if parte.startswith("ip="):
            ip = parte[3:]
        elif parte.startswith("usuario="):
            detalhes = parte

    if ip is None or detalhes is None:
        return None

    return {
        "timestamp": timestamp,
        "fonte": "auth",
        "tipo": tipo,
        "ip": ip,
        "detalhes": detalhes,
        "linha_original": linha,
    }


def parsear_linha_firewall(linha):
    """
    Parseia uma linha do firewall.log e retorna um dicionario normalizado.

    Formato da linha:
        "2025-02-20 08:10:02 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=22"

    Retorna:
        dict com chaves: timestamp, fonte, tipo, ip, detalhes, linha_original
        - O campo "ip" deve conter o IP de origem (src)
        - O campo "detalhes" deve conter proto, dst e dport concatenados
        Retorna None se a linha estiver em formato invalido.

    Dicas:
        - Mesmo principio do auth: split() e procure os campos com "="
        - O IP relevante para seguranca eh o src (origem da conexao)
    """
    if not linha:
        return None
    partes = linha.split()
    if len(partes) < 6:
        return None

    timestamp = partes[0] + " " + partes[1]
    tipo = partes[2]
    ip = None
    detalhes_partes = []

    for parte in partes[3:]:
        if parte.startswith("src="):
            ip = parte[4:]
        else:
            detalhes_partes.append(parte)

    if ip is None:
        return None

    return {
        "timestamp": timestamp,
        "fonte": "firewall",
        "tipo": tipo,
        "ip": ip,
        "detalhes": " ".join(detalhes_partes),
        "linha_original": linha,
    }


def parsear_linha_web(linha):
    """
    Parseia uma linha do web_access.log e retorna um dicionario normalizado.

    Formato da linha:
        "2025-02-20 08:20:01 GET url=/index.html ip=192.168.1.10 status=200"

    Retorna:
        dict com chaves: timestamp, fonte, tipo, ip, detalhes, linha_original
        - O campo "tipo" deve conter o metodo HTTP (GET, POST, DELETE, etc.)
        - O campo "detalhes" deve conter url e status
        Retorna None se a linha estiver em formato invalido.

    Dicas:
        - O metodo HTTP eh a terceira parte da linha (apos data e hora)
        - Cuidado: a URL pode conter caracteres especiais (ex: <script>)
    """
    if not linha:
        return None
    if "url=" not in linha or "ip=" not in linha or "status=" not in linha:
        return None

    partes = linha.split()
    if len(partes) < 3:
        return None

    timestamp = partes[0] + " " + partes[1]
    tipo = partes[2]

    # Use rfind to locate ip= and status= from the end, so URLs with special
    # characters don't break extraction.
    ip_pos = linha.rfind(" ip=")
    status_pos = linha.rfind(" status=")
    url_pos = linha.find(" url=")

    if ip_pos == -1 or status_pos == -1 or url_pos == -1:
        return None

    ip = linha[ip_pos + 4:].split()[0]
    status_part = linha[status_pos + 1:].split()[0]
    url_part = linha[url_pos + 1:ip_pos]

    return {
        "timestamp": timestamp,
        "fonte": "web",
        "tipo": tipo,
        "ip": ip,
        "detalhes": url_part + " " + status_part,
        "linha_original": linha,
    }


def carregar_log(caminho_arquivo, fonte):
    """
    Le um arquivo de log e retorna uma lista de eventos normalizados.

    Parametros:
        caminho_arquivo (str): caminho do arquivo de log
        fonte (str): tipo da fonte - "auth", "firewall" ou "web"

    Retorna:
        list[dict]: lista de eventos normalizados (dicionarios)
        Retorna lista vazia se o arquivo nao existir ou estiver vazio.

    Comportamento esperado:
        - Se o arquivo nao existir, imprime mensagem de erro e retorna []
        - Se uma linha estiver mal formatada, imprime aviso e pula para a proxima
        - Linhas em branco devem ser ignoradas silenciosamente

    Dicas:
        - Use try/except FileNotFoundError para tratar arquivo inexistente
        - Use with open(caminho, "r") as f: para abrir o arquivo
        - Chame a funcao de parsing correta baseado no parametro "fonte"
        - Use if/elif para escolher: parsear_linha_auth, parsear_linha_firewall, parsear_linha_web
    """
    try:
        with open(caminho_arquivo, "r") as f:
            linhas = f.readlines()
    except FileNotFoundError:
        print(f"[ERRO] Arquivo nao encontrado: {caminho_arquivo}")
        return []

    eventos = []
    for linha in linhas:
        linha = linha.strip()
        if not linha:
            continue

        if fonte == "auth":
            evento = parsear_linha_auth(linha)
        elif fonte == "firewall":
            evento = parsear_linha_firewall(linha)
        elif fonte == "web":
            evento = parsear_linha_web(linha)
        else:
            evento = None

        if evento is None:
            print(f"[AVISO] Linha ignorada: {linha}")
        else:
            eventos.append(evento)

    return eventos


def carregar_todos_os_logs(pasta_logs):
    """
    Le todos os arquivos de log da pasta e retorna uma lista unificada de eventos.

    Parametros:
        pasta_logs (str): caminho da pasta contendo os arquivos de log

    Retorna:
        list[dict]: lista com todos os eventos de todas as fontes

    Comportamento esperado:
        - Identifica a fonte pelo nome do arquivo (auth.log -> "auth", etc.)
        - Ignora arquivos que nao sejam .log
        - Imprime quantos eventos foram carregados de cada arquivo

    Dicas:
        - Use os.listdir(pasta) para listar os arquivos
        - Use arquivo.endswith(".log") para filtrar
        - Use "auth" in arquivo para identificar a fonte
        - Chame carregar_log() para cada arquivo encontrado
    """
    try:
        arquivos = os.listdir(pasta_logs)
    except (FileNotFoundError, NotADirectoryError, OSError):
        print(f"[ERRO] Pasta nao encontrada: {pasta_logs}")
        return []

    todos_eventos = []
    for arquivo in arquivos:
        if not arquivo.endswith(".log"):
            continue

        if "auth" in arquivo:
            fonte = "auth"
        elif "firewall" in arquivo:
            fonte = "firewall"
        elif "web" in arquivo:
            fonte = "web"
        else:
            continue

        caminho = os.path.join(pasta_logs, arquivo)
        eventos = carregar_log(caminho, fonte)
        print(f"[INFO] {arquivo}: {len(eventos)} eventos carregados")
        todos_eventos.extend(eventos)

    return todos_eventos
