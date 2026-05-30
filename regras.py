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


# def carregar_regras(caminho_config):
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

def carregar_regras(caminho_config):
      try:
          with open(caminho_config, "r") as f:
              dados = json.load(f)
      except FileNotFoundError:
          print(f"[ERRO] Arquivo de regras não encontrado: {caminho_config}")
          return []
      except json.JSONDecodeError:
          print(f"[ERRO] JSON inválido em: {caminho_config}")
          return []

      regras = dados.get("regras", [])
      regras_ativas = [r for r in regras if r.get("ativa", False)]
      return regras_ativas


# def classificar_severidade(pontuacao):
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

def classificar_severidade(pontuacao):
      if pontuacao >= 9:
          return "CRITICA"
      elif pontuacao >= 7:
          return "ALTA"
      elif pontuacao >= 5:
          return "MEDIA"
      elif pontuacao >= 3:
          return "BAIXA"
      else:
          return "INFO"

def extrair_valor(detalhes, chave):
      """
      Pega o valor de 'chave=valor' dentro da string detalhes.
      Ex: extrair_valor("proto=TCP dport=22", "dport") -> "22"
      Retorna None se a chave nao existir.
      """
      for parte in detalhes.split():
          if parte.startswith(f"{chave}="):
              return parte.split("=", 1)[1]
      return None


def avaliar_regra(regra, evento):
      """
      Avalia se um evento viola uma regra. Retorna dict de alerta ou None.
      """
      if evento.get("fonte") != regra.get("fonte"):
          return None

      condicao = regra.get("condicao")
      detalhes = evento.get("detalhes", "")
      disparou = False

      if condicao == "usuario_privilegiado":
          usuario = extrair_valor(detalhes, "usuario")
          if usuario and usuario in regra.get("usuarios_alvo", []):
              disparou = True

      elif condicao == "porta_critica":
          if evento.get("tipo") == "BLOCK":
              porta_str = extrair_valor(detalhes, "dport")
              try:
                  porta = int(porta_str) if porta_str else None
                  if porta in regra.get("portas_criticas", []):
                      disparou = True
              except ValueError:
                  pass

      elif condicao in ("path_traversal", "xss"):
          url = extrair_valor(detalhes, "url") or ""
          if any(p in url for p in regra.get("padroes", [])):
              disparou = True

      elif condicao == "reconhecimento":
          url = extrair_valor(detalhes, "url") or ""
          if any(u in url for u in regra.get("urls_suspeitas", [])):
              disparou = True

      if not disparou:
          return None

      return {
          "timestamp": evento.get("timestamp"),
          "regra_id": regra.get("id"),
          "regra_nome": regra.get("nome"),
          "severidade": classificar_severidade(regra.get("severidade_base", 0)),
          "ip": evento.get("ip"),
          "descricao": regra.get("descricao", ""),
      }


def aplicar_regras(eventos, regras):
      """
      Para cada evento, testa todas as regras. Retorna lista de alertas gerados.
      Um mesmo evento pode gerar varios alertas (violar varias regras).
      """
      alertas = []
      for evento in eventos:
          for regra in regras:
              resultado = avaliar_regra(regra, evento)
              if resultado is not None:
                  alertas.append(resultado)
      return alertas
