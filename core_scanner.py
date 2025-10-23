import sys
from scapy.all import conf, srp, Ether, ARP, sniff
from scapy.layers.dhcp import DHCP, BOOTP
import ipaddress
import wmi

# --- CORREÇÃO: Corrigir a importação do módulo ---
# A importação anterior 'from OuiLookup import ...' falhou.
# O nome do *módulo* (pacote) é 'ouilookup' (minúsculo).
# O nome da *classe* dentro dele é 'OuiLookup' (maiúsculo).
try:
    from ouilookup import OuiLookup  # <-- CORREÇÃO AQUI
    
    # Instancia a classe uma vez. Isso carrega o banco de dados.
    OUI_LOOKUP_INSTANCE = OuiLookup()
except ImportError:
    print("Erro: A biblioteca 'ouilookup' não foi encontrada. "
          "Certifique-se de que 'ouilookup' está instalado.", file=sys.stderr)
    OUI_LOOKUP_INSTANCE = None
except Exception as e:
    # Se o 'ouilookup --update' não foi executado, o arquivo .json
    # pode não existir, causando uma falha aqui.
    print(f"Erro ao carregar o banco de dados OUI: {e}", file=sys.stderr)
    print("Por favor, execute 'ouilookup --update' no terminal.", file=sys.stderr)
    OUI_LOOKUP_INSTANCE = None
# --- FIM DA CORREÇÃO ---


# Decisão de Arquitetura (Refatorada #5):
# (Lógica WMI - Sem alteração)
def find_active_interface():
    """
    Identifica a interface de rede ativa, seu IP e sua sub-rede (CIDR)
    usando WMI.
    Retorna (iface_guid, ip_address, subnet_cidr) ou (None, None, None).
    """
    try:
        c = wmi.WMI()
        
        # 1. Encontrar a rota padrão (0.0.0.0)
        route_table = c.Win32_IP4RouteTable(Destination='0.0.0.0', Mask='0.0.0.0')
        
        if not route_table:
            raise StopIteration("Nenhuma rota padrão (0.0.0.0) encontrada no WMI.")
        
        default_route = route_table[0]
        iface_index = default_route.InterfaceIndex
        
        # 2. Encontrar o adaptador de rede com base no InterfaceIndex
        adapter_config = c.Win32_NetworkAdapterConfiguration(
            InterfaceIndex=iface_index, 
            IPEnabled=True
        )
        
        if not adapter_config:
            raise StopIteration(f"Nenhuma configuração de adaptador encontrada para o Índice {iface_index}.")
            
        adapter = adapter_config[0]
        
        # 3. Extrair os detalhes da interface
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

        # 4. Calcular o CIDR da sub-rede
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
    (Sem alteração)
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
        print(f"Erro ao iniciar o varredura ARP: {e}", file=sys.stderr)
        print("Certifique-se de executar como Administrador e que o Npcap está instalado.", file=sys.stderr)
        return []

# --- CORREÇÃO: Usar a API documentada ---
def get_mac_vendor(mac_address: str):
    """
    Consulta o fabricante (OUI) de um endereço MAC.
    """
    if not OUI_LOOKUP_INSTANCE:
        return "Erro OUI (Falha na inicialização)"
    if not mac_address:
        return "N/A"
        
    try:
        # A documentação mostra o uso de 'query(mac)'
        # em uma instância da classe.
        result_list = OUI_LOOKUP_INSTANCE.query(mac_address)
        
        # A saída documentada é uma lista de dicionários:
        # [{'0000AA000000': 'XEROX CORPORATION'}]
        if result_list:
            # Pega o primeiro (e único) dicionário da lista
            vendor_dict = result_list[0]
            # Pega o primeiro (e único) valor (o nome do fabricante)
            return list(vendor_dict.values())[0]
        else:
            return "Desconhecido"
            
    except Exception as e:
        # Captura qualquer outro erro inesperado
        print(f"\n[DEBUG] Erro inesperado ao consultar OUI para {mac_address}: {e}\n", file=sys.stderr)
        return "Erro OUI"
# --- FIM DA CORREÇÃO ---


# --- Módulo de Análise Passiva ---
# (Sem alteração)
def _dhcp_packet_callback(packet, user_callback):
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
            pass 
        except Exception as e:
            print(f"Erro no callback DHCP: {e}", file=sys.stderr)

def start_passive_monitor(iface_name: str, on_device_found_callback, test_duration_sec=None):
    if test_duration_sec:
        print(f"\nIniciando monitoramento passivo (DHCP) em '{iface_name}' por {test_duration_sec} segundos...")
    else:
        print(f"\nIniciando monitoramento passivo (DHCP) em '{iface_name}'.")

    try:
        sniff(
            iface=iface_name,
            filter="udp and (port 67 or 68)",
            prn=lambda pkt: _dhcp_packet_callback(pkt, on_device_found_callback),
            store=0,
            timeout=test_duration_sec
        )
    except Exception as e:
        print(f"Erro ao iniciar o sniffing: {e}", file=sys.stderr)
        print("Certifique-se de executar como Administrador.", file=sys.stderr)