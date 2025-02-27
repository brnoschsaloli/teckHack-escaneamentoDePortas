import socket

def guess_os_from_banner(banner):
    banner_lower = banner.lower()
    if "windows" in banner_lower:
        return "Possivelmente Windows"
    elif any(x in banner_lower for x in ["ubuntu", "debian", "linux", "centos", "fedora"]):
        return "Possivelmente Linux"
    elif any(x in banner_lower for x in ["freebsd", "openbsd", "netbsd"]):
        return "Possivelmente BSD"
    else:
        return "Sistema operacional não identificado"

def scan_port_tcp(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)  # Timeout ajustado para 3 segundos
    try:
        s.connect((host, port))
    except socket.timeout:
        return "filtered", f"TCP - Porta {port}: Filtrada (Timeout)"
    except ConnectionRefusedError:
        return "closed", None
    except Exception:
        return "closed", None
    else:
        try:
            service = socket.getservbyport(port, "tcp")
        except Exception:
            service = "Desconhecido"
        
        # Envia um caractere para provocar a resposta (banner)
        try:
            s.send(b'\n')
        except Exception:
            pass
        
        try:
            banner = s.recv(2048).decode('utf-8', errors='ignore')
        except socket.timeout:
            banner = ""
        except Exception:
            banner = ""
        
        if banner:
            os_guess = guess_os_from_banner(banner)
            return "open", f"TCP - Porta {port}: Aberta - Serviço: {service} | Banner: {banner.strip()} | OS: {os_guess}"
        else:
            return "open", f"TCP - Porta {port}: Aberta - Serviço: {service} | Banner: N/A | OS: Não identificado"
    finally:
        s.close()

def scan_port_udp(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1)
    try:
        s.sendto(b'', (host, port))
        data, addr = s.recvfrom(1024)
    except socket.timeout:
        return "filtered", f"UDP - Porta {port}: Open|Filtered (Sem resposta)"
    except Exception:
        return "closed", None
    else:
        try:
            service = socket.getservbyport(port, "udp")
        except Exception:
            service = "Desconhecido"
        banner = data.decode('utf-8', errors='ignore').strip()
        return "open", f"UDP - Porta {port}: Aberta - Serviço: {service} | Banner: {banner if banner else 'N/A'}"
    finally:
        s.close()

def scan_host(host, start_port, end_port, protocol):
    closed_count = 0
    for port in range(start_port, end_port + 1):
        if protocol.lower() == 'tcp':
            status, output = scan_port_tcp(host, port)
        elif protocol.lower() == 'udp':
            status, output = scan_port_udp(host, port)
        else:
            print("Protocolo inválido. Use 'tcp' ou 'udp'.")
            return

        if status == "open":
            print(output)
        elif status == "closed" or status == "filtered":
            closed_count += 1

    print(f"\nTotal de portas fechadas: {closed_count}")

if __name__ == "__main__":
    host = input("Digite o endereço IP ou hostname: ")
    protocol = input("Digite o tipo de protocolo (tcp/udp): ")
    start_port = int(input("Digite a porta inicial: "))
    end_port = int(input("Digite a porta final: "))
    scan_host(host, start_port, end_port, protocol)