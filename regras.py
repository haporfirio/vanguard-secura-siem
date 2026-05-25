"""
Modulo 2 - Motor de Regras
Responsavel por carregar regras de deteccao de um arquivo JSON,
avaliar cada evento contra as regras ativas e gerar alertas
quando uma regra eh violada.

Formato de um alerta gerado:
{
    "timestamp": "2025-02-20 08:15:01",
    "regra_id": "R001",
    "regra_nome": "Login com Usuario Privilegiado",
    "severidade": "MEDIA",
    "ip": "185.220.101.1",
    "descricao": "Tentativa de login com usuario admin"
}

Niveis de severidade (baseados na pontuacao):
    >= 9: CRITICA
    >= 7: ALTA
    >= 5: MEDIA
    >= 3: BAIXA
     < 3: INFO
"""

import json


def carregar_regras(caminho_config):
    """
    Le o arquivo regras.json e retorna a lista de regras.

    Parametros:
        caminho_config (str): caminho para o arquivo JSON de regras

    Retorna:
        list[dict]: lista de dicionarios, cada um representando uma regra
        Retorna lista vazia se o arquivo nao existir ou JSON for invalido.

    Comportamento esperado:
        - Se o arquivo nao existir, imprime erro e retorna []
        - Se o JSON for invalido (malformado), imprime erro e retorna []
        - Filtra apenas regras com "ativa": true

    Dicas:
        - Use json.load(f) para ler o arquivo JSON
        - Trate FileNotFoundError e json.JSONDecodeError
        - Use list comprehension para filtrar regras ativas:
          [r for r in regras if r.get("ativa", False)]
    """
    pass


def classificar_severidade(pontuacao):
    """
    Converte uma pontuacao numerica em nivel de severidade.

    Parametros:
        pontuacao (int ou float): valor numerico da severidade

    Retorna:
        str: "CRITICA", "ALTA", "MEDIA", "BAIXA" ou "INFO"

    Mapeamento:
        >= 9  -> "CRITICA"
        >= 7  -> "ALTA"
        >= 5  -> "MEDIA"
        >= 3  -> "BAIXA"
        <  3  -> "INFO"

    Dicas:
        - Use if/elif/else encadeado
        - Comece pelo maior valor e va descendo
    """
    pass


def avaliar_regra(regra, evento):
    """
    Avalia se um evento viola uma regra especifica.

    Parametros:
        regra (dict): dicionario da regra (do JSON de configuracao)
        evento (dict): dicionario do evento normalizado (do coletor)

    Retorna:
        dict: alerta gerado se a regra foi violada
        None: se o evento nao viola a regra

    Comportamento esperado:
        - Primeiro verifica se a fonte do evento bate com a fonte da regra
        - Depois avalia a condicao especifica:
            "usuario_privilegiado": verifica se o usuario esta na lista de alvo
            "porta_critica": verifica se a porta bloqueada esta na lista critica
            "path_traversal": verifica se a URL contem padroes de traversal
            "xss": verifica se a URL contem padroes de XSS
            "reconhecimento": verifica se a URL esta na lista de suspeitas

    Dicas:
        - Use regra["condicao"] para decidir qual verificacao fazer
        - Para "usuario_privilegiado": extraia o usuario do campo "detalhes"
          (ex: "usuario=admin" -> "admin") e veja se esta em regra["usuarios_alvo"]
        - Para "porta_critica": extraia dport do "detalhes" e veja se esta em regra["portas_criticas"]
        - Para padroes na URL: use any(padrao in url for padrao in regra["padroes"])
        - O alerta retornado deve ter: timestamp, regra_id, regra_nome, severidade, ip, descricao
    """
    pass


def aplicar_regras(eventos, regras):
    """
    Aplica todas as regras a todos os eventos e retorna os alertas gerados.

    Parametros:
        eventos (list[dict]): lista de eventos normalizados
        regras (list[dict]): lista de regras ativas

    Retorna:
        list[dict]: lista de alertas gerados

    Comportamento esperado:
        - Para cada evento, testa todas as regras
        - Se avaliar_regra retorna um alerta (nao None), adiciona a lista
        - Um mesmo evento pode gerar multiplos alertas (violar varias regras)

    Dicas:
        - Use dois loops for aninhados: para cada evento, para cada regra
        - resultado = avaliar_regra(regra, evento)
        - if resultado is not None: alertas.append(resultado)
    """
    pass
