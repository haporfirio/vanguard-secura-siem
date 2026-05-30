"""
  Modulo 3 - Detector de Anomalias
  Analisa conjunto de eventos para identificar padroes de ataque
  (brute force, port scan, IPs em blacklist).
  """

from regras import classificar_severidade, extrair_valor


def detectar_brute_force(eventos, threshold=5):
      """
      Conta FAILs de auth por IP. Retorna IPs que atingiram threshold.
      Severidade: >20 CRITICA | >10 ALTA | >5 MEDIA | >=threshold BAIXA
      """
      contagem = {}
      usuarios = {}

      for evento in eventos:
          if evento.get("fonte") != "auth" or evento.get("tipo") != "FAIL":
              continue
          ip = evento.get("ip")
          if not ip:
              continue
          contagem[ip] = contagem.get(ip, 0) + 1
          if ip not in usuarios:
              usuarios[ip] = set()
          usuario = extrair_valor(evento.get("detalhes", ""), "usuario")
          if usuario:
              usuarios[ip].add(usuario)

      resultado = {}
      for ip, n in contagem.items():
          if n >= threshold:
              if n > 20:
                  sev = "CRITICA"
              elif n > 10:
                  sev = "ALTA"
              elif n > 5:
                  sev = "MEDIA"
              else:
                  sev = "BAIXA"
              resultado[ip] = {
                  "tentativas": n,
                  "usuarios": usuarios[ip],
                  "severidade": sev,
              }
      return resultado


def detectar_port_scan(eventos, threshold=3):
      """
      Conta portas unicas bloqueadas por IP. Retorna IPs que atingiram threshold.
      Severidade: >10 CRITICA | >5 ALTA | >=threshold MEDIA
      """
      portas_por_ip = {}

      for evento in eventos:
          if evento.get("fonte") != "firewall" or evento.get("tipo") != "BLOCK":
              continue
          ip = evento.get("ip")
          if not ip:
              continue
          porta_str = extrair_valor(evento.get("detalhes", ""), "dport")
          if not porta_str:
              continue
          try:
              porta = int(porta_str)
          except ValueError:
              continue
          if ip not in portas_por_ip:
              portas_por_ip[ip] = set()
          portas_por_ip[ip].add(porta)

      resultado = {}
      for ip, portas in portas_por_ip.items():
          quantidade = len(portas)
          if quantidade >= threshold:
              if quantidade > 10:
                  sev = "CRITICA"
              elif quantidade > 5:
                  sev = "ALTA"
              else:
                  sev = "MEDIA"
              resultado[ip] = {
                  "portas": portas,
                  "quantidade": quantidade,
                  "severidade": sev,
              }
      return resultado


def verificar_blacklist(eventos, blacklist):
      """
      Interseccao entre IPs dos eventos e blacklist.
      Retorna (ips_encontrados: set, contagem_por_ip: dict).
      """
      ips_eventos = {evento["ip"] for evento in eventos if evento.get("ip")}
      ips_encontrados = ips_eventos & blacklist

      contagem = {}
      for evento in eventos:
          ip = evento.get("ip")
          if ip in ips_encontrados:
              contagem[ip] = contagem.get(ip, 0) + 1

      return ips_encontrados, contagem


def gerar_resumo_ameacas(brute_force, port_scan, blacklist_resultado):
      """
      Consolida as 3 deteccoes em lista ordenada de ameacas (mais grave primeiro).
      Cada ameaca: {ip, deteccoes, pontuacao, severidade, detalhes}
      """
      blacklist_ips, blacklist_contagem = blacklist_resultado
      todos_ips = set(brute_force.keys()) | set(port_scan.keys()) | set(blacklist_ips)

      ameacas = []
      for ip in todos_ips:
          deteccoes = []
          pontuacao = 0
          detalhes = {}

          if ip in brute_force:
              deteccoes.append("brute_force")
              pontuacao += 5 + brute_force[ip]["tentativas"]
              detalhes["brute_force"] = brute_force[ip]

          if ip in port_scan:
              deteccoes.append("port_scan")
              pontuacao += 5 + port_scan[ip]["quantidade"]
              detalhes["port_scan"] = port_scan[ip]

          if ip in blacklist_ips:
              deteccoes.append("blacklist")
              pontuacao += 5
              detalhes["blacklist"] = {"contagem_eventos": blacklist_contagem.get(ip, 0)}

          ameacas.append({
              "ip": ip,
              "deteccoes": deteccoes,
              "pontuacao": pontuacao,
              "severidade": classificar_severidade(pontuacao),
              "detalhes": detalhes,
          })

      ameacas.sort(key=lambda a: a["pontuacao"], reverse=True)
      return ameacas