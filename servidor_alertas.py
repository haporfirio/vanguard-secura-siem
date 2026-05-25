"""
Modulo 4a - Servidor de Alertas em Tempo Real
Servidor TCP que aceita conexoes de multiplos clientes (consoles de monitoramento)
e faz broadcast de alertas de seguranca para todos os clientes conectados.

Comandos suportados pelo cliente:
    /status    - mostra quantos clientes conectados e alertas na sessao
    /historico - envia os ultimos 10 alertas
    /sair      - desconecta do servidor
"""

import socket
import threading
from datetime import datetime

# Configuracao
HOST = "0.0.0.0"
PORTA = 9999
MAX_CLIENTES = 10

# Estado global do servidor
clientes = {}       # {conexao: endereco}
lock = threading.Lock()
historico_alertas = []


def formatar_alerta(alerta_dict):
    """
    Converte um dicionario de alerta em string formatada para exibicao.

    Parametros:
        alerta_dict (dict): alerta com chaves timestamp, severidade, regra_nome, ip, descricao

    Retorna:
        str: alerta formatado, ex:
        "[08:15:01] [CRITICA] Brute Force - 185.220.101.1 - 10 tentativas de login"

    Dicas:
        - Use f-string para montar a mensagem
        - Extraia a hora do timestamp (ultimos 8 caracteres ou split)
    """
    pass


def broadcast_alerta(alerta):
    """
    Envia um alerta para todos os clientes conectados.

    Parametros:
        alerta (dict ou str): alerta a ser enviado

    Comportamento esperado:
        - Se alerta for dict, formata com formatar_alerta() primeiro
        - Adiciona ao historico_alertas
        - Percorre todos os clientes e envia a mensagem
        - Se falhar ao enviar para um cliente, remove-o da lista
        - Usa lock para evitar problemas de concorrencia

    Dicas:
        - Use with lock: ao acessar o dicionario de clientes
        - Envolva o send() em try/except para capturar clientes desconectados
        - Use conexao.send(mensagem.encode()) para enviar
    """
    pass


def remover_cliente(conexao):
    """
    Remove um cliente da lista de conectados.

    Parametros:
        conexao: objeto socket do cliente

    Comportamento esperado:
        - Remove do dicionario de clientes (com lock)
        - Fecha a conexao
        - Imprime log no console do servidor

    Dicas:
        - Use with lock: ao modificar o dicionario
        - Use try/except ao fechar a conexao (pode ja estar fechada)
    """
    pass


def tratar_cliente(conexao, endereco):
    """
    Gerencia a comunicacao com um cliente individual.
    Esta funcao roda em uma thread separada para cada cliente.

    Parametros:
        conexao: objeto socket do cliente
        endereco: tupla (ip, porta) do cliente

    Comportamento esperado:
        1. Registra o cliente no dicionario (com lock)
        2. Envia mensagem de boas-vindas
        3. Loop principal: recebe comandos do cliente
           - /status: envia numero de clientes e alertas
           - /historico: envia ultimos 10 alertas
           - /sair: remove cliente e encerra
        4. Trata desconexoes inesperadas

    Dicas:
        - Use while True com conexao.recv(1024).decode()
        - Se recv retornar string vazia, o cliente desconectou
        - Use if/elif para tratar cada comando
        - Envolva tudo em try/except (ConnectionResetError, etc.)
    """
    pass


def iniciar_servidor(host=HOST, porta=PORTA):
    """
    Inicia o servidor TCP de alertas.

    Parametros:
        host (str): endereco para bind (padrao: "0.0.0.0")
        porta (int): porta para bind (padrao: 9999)

    Comportamento esperado:
        - Cria socket TCP
        - Faz bind no host:porta
        - Fica em loop aceitando conexoes
        - Para cada conexao, cria uma thread com tratar_cliente
        - Trata KeyboardInterrupt (Ctrl+C) para encerrar graciosamente

    Dicas:
        - servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        - servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        - Use daemon=True nas threads para que encerrem com o programa
    """
    pass


if __name__ == "__main__":
    iniciar_servidor()
