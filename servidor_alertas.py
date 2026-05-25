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

    hora = alerta_dict["timestamp"].split(" ")[1]
    severidade = alerta_dict["severidade"]
    regra = alerta_dict["regra_nome"]
    ip = alerta_dict["ip"]
    descricao = alerta_dict["descricao"]
    
    return f"[{hora}] [{severidade}] {regra} - {ip} - {descricao}"

def broadcast_alerta(alerta):
    if isinstance(alerta, dict):
        mensagem = formatar_alerta(alerta)
    else:
        mensagem = alerta

    historico_alertas.append(mensagem)

    with lock:
        clientes_copia = list(clientes.keys())

    for conexao in clientes_copia:
        try:
            conexao.send((mensagem + "\n").encode())
        except (ConnectionResetError, BrokenPipeError,OSError):
            remover_cliente(conexao)
    
def remover_cliente(conexao):
    with lock:
        if conexao in clientes:
            endereco = clientes.pop(conexao)
            print(f"[SERVIDOR] Cliente {endereco} desconectado")
    try:
        conexao.close()
    except OSError:
        pass

def tratar_cliente(conexao, endereco):
    with lock:
        clientes[conexao] = endereco
    try:

        conexao.send("Conectado ao servidor de alertas!\n".encode())

        while True:
            dados = conexao.recv(1024).decode()
            
            if not dados:
                break

            dados = dados.strip()

            if dados == "/status":
                msg = f"Clientes conectados: {len(clientes)} | Alertas na sessao: {len(historico_alertas)}\n"
                conexao.send(msg.encode())

            elif dados == "/historico":
                if not historico_alertas:
                    conexao.send("Nenhum alerta registrado.\n".encode())
                else:
                    for alerta in historico_alertas[-10:]:
                        conexao.send((alerta + "\n").encode())

            elif dados == "/sair":
                break

            else:
                conexao.send("Comando invalido. Use /status, /historico ou /sair. \n".encode())

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass

    finally:
        remover_cliente(conexao)

def iniciar_servidor(host=HOST, porta=PORTA):
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((host, porta))
    servidor.listen(MAX_CLIENTES)

    print(f"[SERVIDOR] Aguardando conexoes em {host}:{porta}...")

    try:
        while True:
            conexao, endereco = servidor.accept()
            print(f"[SERVIDOR] Nova conexao de {endereco}")

            thread = threading.Thread(target=tratar_cliente, args=(conexao, endereco), daemon=True)
            
            thread.start()

    except KeyboardInterrupt:
        print("\n[SERVIDOR] Encerrando...")
    
    finally:
        servidor.close()

if __name__ == "__main__":
    iniciar_servidor()
