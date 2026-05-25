"""
Modulo 4b - Cliente de Alertas
Conecta ao servidor de alertas e recebe notificacoes em tempo real.
Permite enviar comandos: /status, /historico, /sair
"""

import socket
import threading

HOST = "127.0.0.1"
PORTA = 9999


def receber_alertas(cliente):
    """
    Thread que fica ouvindo mensagens do servidor e exibindo no terminal.

    Parametros:
        cliente: objeto socket conectado ao servidor

    Comportamento esperado:
        - Loop infinito recebendo dados com recv(4096)
        - Se receber string vazia, servidor desconectou
        - Exibe cada mensagem recebida no terminal
        - Trata erros de conexao (ConnectionResetError, etc.)

    Dicas:
        - Use while True com try/except
        - dados = cliente.recv(4096).decode()
        - if not dados: break
    """
    pass


def conectar_servidor(host=HOST, porta=PORTA):
    """
    Conecta ao servidor de alertas e inicia a interacao.

    Parametros:
        host (str): endereco do servidor
        porta (int): porta do servidor

    Comportamento esperado:
        1. Cria socket e conecta ao servidor
        2. Inicia thread para receber alertas (receber_alertas)
        3. Loop principal lendo input do usuario e enviando ao servidor
        4. Se o usuario digitar /sair, desconecta
        5. Trata erros de conexao

    Dicas:
        - cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        - cliente.connect((host, porta))
        - thread = threading.Thread(target=receber_alertas, args=(cliente,), daemon=True)
        - Use try/except ConnectionRefusedError para tratar servidor offline
    """
    pass


if __name__ == "__main__":
    conectar_servidor()
