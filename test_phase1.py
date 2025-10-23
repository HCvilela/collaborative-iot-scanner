import core_scanner
import time
import sys

def test_active_scan():
    """
    Testa a descoberta de interface e a varredura ativa.
    """
    print("--- INICIANDO TESTE: VARREDURA ATIVA (ARP) ---")
    
    iface, ip, subnet = core_scanner.find_active_interface()
    
    if not iface:
        print("Falha no Teste: Nenhuma interface ativa encontrada. Encerrando.")
        return None

    print(f"Interface Ativa Detectada: {iface}")
    print(f"IP da Interface: {ip}")
    print(f"Sub-rede Alvo (CIDR): {subnet}")
    print("-" * 30)

    devices = core_scanner.active_arp_scan(subnet)
    
    if not devices:
        print("Nenhum dispositivo encontrado pela varredura ativa.")
    else:
        print("\n--- RESULTADOS DA VARREDURA ATIVA ---")
        print(f"{'IP':<16} | {'MAC':<18} | {'Fabricante (OUI)':<30}")
        print("-" * 70)
        
        for device in devices:
            vendor = core_scanner.get_mac_vendor(device['mac'])
            print(f"{device['ip']:<16} | {device['mac']:<18} | {vendor:<30}")
    
    print("--- TESTE ATIVO CONCLUÍDO ---")
    return iface


def passive_test_callback(device_info):
    """
    Callback para o teste passivo.
    """
    print("\n[Monitor Passivo] Novo Dispositivo Detectado (DHCP):")
    print(f"  MAC: {device_info.get('mac')}")
    print(f"  Hostname: {device_info.get('hostname')}")
    vendor = core_scanner.get_mac_vendor(device_info.get('mac'))
    print(f"  Fabricante: {vendor}")


def test_passive_scan(iface_name):
    """
    Testa o monitoramento passivo (DHCP Sniffing).
    """
    if not iface_name:
        print("Não é possível iniciar teste passivo sem uma interface.")
        return
        
    print("\n--- INICIANDO TESTE: MONITORAMENTO PASSIVO (DHCP) ---")
    print("Por favor, force um dispositivo na sua rede a se reconectar")
    print("(ex: desative e reative o Wi-Fi no seu celular) para gerar tráfego DHCP.")
    
    # --- CORREÇÃO: Removido try/except e adicionado 'test_duration_sec' ---
    core_scanner.start_passive_monitor(
        iface_name=iface_name,
        on_device_found_callback=passive_test_callback,
        test_duration_sec=60  # Executa o teste por 60 segundos
    )
    
    print("\n--- TESTE PASSIVO CONCLUÍDO (60 segundos) ---")


if __name__ == "__main__":
    print("Iniciando Teste da Fase 1 (Lógica Central)...")
    print("Certifique-se de que este script está sendo executado como Administrador.")
    
    # (Chamada ao initialize_oui_database REMOVIDA)
    
    try:
        active_interface = test_active_scan()
        
        if active_interface:
            test_passive_scan(active_interface)
            
    except PermissionError:
        print("\n[ERRO FATAL] Permissão Negada.", file=sys.stderr)
        print("Por favor, execute este script de teste 'Como Administrador'.", file=sys.stderr)
        sys.exit(1)
    except ImportError as e:
        if "Npcap" in str(e) or "winpcap" in str(e):
            print(f"\n[ERRO FATAL] Dependência Faltando: {e}", file=sys.stderr)
            print(f"O Scapy não encontrou o Npcap. Por favor, instale-o.", file=sys.stderr)
            sys.exit(1)
        else:
            raise e