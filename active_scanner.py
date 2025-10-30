import threading
import queue
import core_scanner

class ActiveScanner:
    """
    Encapsula toda a lógica de execução da Varredura Ativa.
    
    Esta classe gerencia sua própria fila (queue) e thread
    para executar a varredura ARP sem bloquear a UI.
    """
    
    def __init__(self):
        """Inicializa o scanner e sua fila de comunicação."""
        self.scan_queue = queue.Queue()
        self.thread = None

    def get_queue(self) -> queue.Queue:
        """
        Permite que a UI (main.py) obtenha a referência da fila
        para poder processar os resultados.
        """
        return self.scan_queue

    def start_scan(self, subnet_to_scan: str):
        """
        Inicia a varredura ativa em uma nova thread.
        
        Argumentos:
            subnet_to_scan (str): A sub-rede em notação CIDR
                                  (ex: "192.168.1.0/24").
        """
        
        # Limpa a fila de resultados anteriores
        # (Embora a UI já faça isso, é uma boa prática)
        while not self.scan_queue.empty():
            self.scan_queue.get_nowait()
            
        self.thread = threading.Thread(
            target=self._scan_worker,
            args=(subnet_to_scan,),
            daemon=True
        )
        self.thread.start()

    def _scan_worker(self, subnet_to_scan: str):
        """
        Função de trabalho (executada na thread) que realiza a varredura.
        
        Esta é a lógica que foi movida do 'main.py'.
        """
        try:
            # 1. Executa a varredura ARP (função de bloqueio)
            devices = core_scanner.active_arp_scan(subnet_to_scan)
            
            if not devices:
                self.scan_queue.put({
                    'type': 'status', 
                    'data': 'Varredura concluída. Nenhum dispositivo encontrado.'
                })
                return

            self.scan_queue.put({
                'type': 'status', 
                'data': f"Encontrados {len(devices)} dispositivos. Obtendo fabricantes..."
            })

            # 2. Enriquecer dados (OUI)
            for device in devices:
                vendor = core_scanner.get_mac_vendor(device['mac'])
                device_data = (
                    device['ip'], 
                    device['mac'], 
                    vendor, 
                    "N/A (Obtido via DHCP)" # Hostname não é pego por ARP
                )
                # Coloca o dispositivo formatado na fila
                self.scan_queue.put({'type': 'result', 'data': device_data})
            
        except Exception as e:
            # Em caso de erro, informa a UI
            self.scan_queue.put({'type': 'error', 'data': f"Erro na varredura: {e}"})
        finally:
            # 3. Sinaliza para a UI que a thread terminou
            self.scan_queue.put({'type': 'done'})