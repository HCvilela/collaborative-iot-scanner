import sys
from scapy.all import conf, srp, Ether, ARP, sniff
from scapy.layers.dhcp import DHCP, BOOTP
import ipaddress
import wmi
import threading

# --- Instanciação da Classe OUI ---
try:
    from ouilookup import OuiLookup
    OUI_LOOKUP_INSTANCE = OuiLookup()
except ImportError:
    print("Erro: A biblioteca 'ouilookup' não foi encontrada. "
          "Certifique-se de que 'ouilookup' está instalado.", file=sys.stderr)
    OUI_LOOKUP_INSTANCE = None
except Exception as e:
    print(f"Erro ao carregar o banco de dados OUI: {e}", file=sys.stderr)
    print("Por favor, execute 'ouilookup --update' no terminal.", file=sys.stderr)
    OUI_LOOKUP_INSTANCE = None
# --- Fim da Instanciação ---


def find_active_interface():
    """
    Identifica a interface de rede ativa, seu IP e sua sub-rede (CIDR)
    usando WMI.
    """
    try:
        c = wmi.WMI()
        
        route_table = c.Win32_IP4RouteTable(Destination='0.0.0.0', Mask='0.0.0.0')
        if not route_table:
            raise StopIteration("Nenhuma rota padrão (0.0.0.0) encontrada no WMI.")
        
        default_route = route_table[0]
        iface_index = default_route.InterfaceIndex
        
        adapter_config = c.Win32_NetworkAdapterConfiguration(
            InterfaceIndex=iface_index, 
            IPEnabled=True
        )
        if not adapter_config:
            raise StopIteration(f"Nenhuma configuração de adaptador encontrada para o Índice {iface_index}.")
            
        adapter = adapter_config[0]
        
        iface_ip = adapter.IPAddress[0]
        netmask = adapter.IPSubnet[0]
        
        iface_description = adapter.Description
        scapy_iface = None
        for if_name, if_obj in conf.ifaces.items():
            if if_obj.description == iface_description:
                scapy_iface = if_obj
                break
        
        if not scapy_iface:
             raise StopIteration(f"Não foi possível mapear o adaptador WMI '{iface_description}' para uma interface Scapy/Npcap.")

        iface_name_for_sniff = scapy_iface.name 

        try:
            ip_iface = ipaddress.ip_interface(f"{iface_ip}/{netmask}")
            subnet_cidr = str(ip_iface.network)
        except ValueError:
            raise StopIteration("Não foi possível calcular a rede a partir do IP/Netmask.")

        return iface_name_for_sniff, iface_ip, subnet_cidr
        
    except StopIteration as e:
        print(f"Erro: Não foi possível encontrar uma interface de rede ativa. Causa: {e}", file=sys.stderr)
        return None, None, None
    except Exception as e:
        print(f"Erro inesperado ao obter interface via WMI: {e}", file=sys.stderr)
        return None, None, None

def active_arp_scan(subnet_cidr: str):
    """
    Executa uma varredura ARP na sub-rede fornecida.
    """
    print(f"Iniciando varredura ARP em {subnet_cidr}...")
    try:
        ether_layer = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_layer = ARP(pdst=subnet_cidr)
        packet = ether_layer / arp_layer

        ans, unans = srp(packet, timeout=2, verbose=0)

        devices = []
        for sent, received in ans:
            devices.append({
                'ip': received.psrc,
                'mac': received.hwsrc
            })
        
        print(f"Scan concluído. {len(devices)} dispositivos encontrados.")
        return devices

    except Exception as e:
        print(f"Erro durante a varredura ARP: {e}", file=sys.stderr)
        print("Certifique-se de executar como Administrador e que o Npcap está instalado.", file=sys.stderr)
        return []

def get_mac_vendor(mac_address: str):
    """
    Consulta o fabricante (OUI) de um endereço MAC.
    """
    if not OUI_LOOKUP_INSTANCE:
        return "Erro OUI (Falha na inicialização)"
    if not mac_address:
        return "N/A"
        
    try:
        result_list = OUI_LOOKUP_INSTANCE.query(mac_address)
        
        if result_list:
            vendor_dict = result_list[0]
            return list(vendor_dict.values())[0]
        else:
            return "Desconhecido"
            
    except Exception as e:
        print(f"\n[DEBUG] Erro inesperado ao consultar OUI para {mac_address}: {e}\n", file=sys.stderr)
        return "Erro OUI"

# --- Módulo de Análise Passiva ---

def _dhcp_packet_callback(packet, user_callback):
    """
    Função de callback interna para processar pacotes DHCP.
    """
    if packet.haslayer(DHCP):
        try:
            if packet[DHCP].options[0][1] == 3: # 'message-type' == 3 (Request)
                mac_address = packet[Ether].src
                hostname = "N/A"
                
                for opt in packet[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == 'hostname':
                        hostname = opt[1].decode('utf-8', errors='ignore')
                        break
                
                if user_callback:
                    user_callback({'mac': mac_address, 'hostname': hostname})

        except IndexError:
            pass # Pacote malformado
        except Exception as e:
            print(f"Erro no callback DHCP: {e}", file=sys.stderr)

# --- REVERTIDO E MODIFICADO ---
# Revertido ao estado anterior (sem 'stop_event', sem loop)
# 'test_duration_sec' foi renomeado para 'timeout'
def start_passive_monitor(iface_name: str, on_device_found_callback, timeout: int = None):
    """
    Inicia o sniffing passivo de DHCP na interface especificada.
    Esta função é bloqueante e será executada em uma thread.
    Ela irá parar automaticamente após o 'timeout'.
    """
    if timeout:
        print(f"\nIniciando monitoramento passivo (DHCP) em '{iface_name}' por {timeout} segundos...")
    else:
        print(f"\nIniciando monitoramento passivo (DHCP) em '{iface_name}'.")

    try:
        sniff(
            iface=iface_name,
            filter="udp and (port 67 or 68)",
            prn=lambda pkt: _dhcp_packet_callback(pkt, on_device_found_callback),
            store=0,
            timeout=timeout # O sniff irá parar sozinho após este tempo
        )
        print("Monitoramento passivo concluído.")
    except Exception as e:
        print(f"Erro ao iniciar o sniffing: {e}", file=sys.stderr)
        print("Certifique-se de executar como Administrador.", file=sys.stderr)