import threading
import queue
import core_scanner

class PassiveScanner:
    """
    Encapsula toda a lógica de execução do Monitor Passivo (DHCP Sniffing).
    
    Esta classe gerencia sua própria fila (queue), thread e o evento
    de parada (stop_event) para permitir que o monitoramento seja
    iniciado e interrompido de forma confiável pela UI.
    """
    
    def __init__(self):
        """Inicializa o scanner e suas variáveis de estado."""
        self.passive_queue = queue.Queue()
        self.stop_event = None  # threading.Event()
        self.thread = None      # threading.Thread()

    def get_queue(self) -> queue.Queue:
        """
        Permite que a UI (main.py) obtenha a referência da fila
        para poder processar os resultados.
        """
        return self.passive_queue

    def start_scan(self, iface_name: str):
        """
        Inicia o monitoramento passivo em uma nova thread.
        
        Argumentos:
            iface_name (str): O nome da interface que o Scapy usará
                              para o sniffing.
        """
        
        # Limpa a fila de resultados anteriores
        while not self.passive_queue.empty():
            self.passive_queue.get_nowait()
            
        # Cria um novo Evento de Parada.
        self.stop_event = threading.Event()
        
        self.thread = threading.Thread(
            target=self._scan_worker,
            args=(iface_name,),
            daemon=True
        )
        self.thread.start()

    def stop_scan(self):
        """
        Sinaliza para a thread de monitoramento que ela deve parar.
        """
        if self.stop_event:
            self.stop_event.set()

    def _scan_worker(self, iface_name: str):
        """
        Função de trabalho (executada na thread) que escuta
        o tráfego DHCP.
        
        Esta é a lógica que foi movida do 'main.py'.
        """
        
        # O 'on_device_found' (callback) agora vive dentro do worker,
        # pois ele é o único que precisa dela.
        def on_device_found(device_info: dict):
            """
            Callback interno que é passado para o Scapy.
            Ele enriquece os dados e os coloca na fila da UI.
            """
            try:
                vendor = core_scanner.get_mac_vendor(device_info.get('mac'))
                device_data = (
                    device_info.get('mac'),
                    vendor,
                    device_info.get('hostname')
                )
                # Coloca o dispositivo (tupla) na fila
                self.passive_queue.put(device_data)
            except Exception as e:
                # Trata erros na consulta OUI, etc.
                self.passive_queue.put({
                    'type': 'error', 
                    'data': f"Erro no callback: {e}"
                })

        try:
            # --- O Loop de Sniffing Confiável ---
            # Continua em loop, chamando o 'sniff' com timeout,
            # até que o 'stop_event' (controlado pela UI) seja acionado.
            while not self.stop_event.is_set():
                core_scanner.start_passive_monitor(
                    iface_name=iface_name,
                    on_device_found_callback=on_device_found,
                    stop_event=self.stop_event,
                    timeout_per_loop=1  # O 'sniff' acorda a cada 1 seg
                )
        
        except Exception as e:
            # Se a thread falhar por um motivo inesperado
            self.passive_queue.put({
                'type': 'error', 
                'data': f"Erro no monitor: {e}"
            })
            
        finally:
            # --- Sinaliza para a UI que a thread terminou ---
            # Isso é crucial para a UI reabilitar o botão "Iniciar"
            self.passive_queue.put({'type': 'done'})