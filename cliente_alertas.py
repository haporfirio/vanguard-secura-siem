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
    try:
        while True:
            dados = cliente.recv(4096).decode()

            if not dados:
                print("\n[CLIENTE] Servidor desconectado.")
                break

            print(dados, end="")

    except (ConnectionRefusedError, BrokenPipeError, OSError):
        print("\n[CLIENTE] Conexao encerrada.")


def conectar_servidor(host=HOST, porta=PORTA):
    cliente = None

    try:

        cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cliente.connect((host, porta))

        print(f"[CLIENTE] Conectado ao servidor {host}:{porta}")
        print("Comandos: /status, /historico, /sair")

        thread = threading.Thread(target=receber_alertas, args=(cliente,), daemon=True)
        thread.start()

        while True:
            comando = input("")
            cliente.send(comando.encode())

            if comando == "/sair":
                break

    except ConnectionRefusedError:
        print("[CLIENTE] Servidor offline ou inacessivel.")
    
    except (ConnectionResetError, BrokenPipeError, OSError):
        print("[CLIENTE] Conexao perdida.")

    finally:
        if cliente is not None:
            cliente.close()

        print("[CLIENTE] Desconectado.")

if __name__ == "__main__":
    conectar_servidor()
