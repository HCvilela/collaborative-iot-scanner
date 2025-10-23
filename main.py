import customtkinter as ctk
from tkinter import ttk
import threading
import queue
import core_scanner
import pythoncom
import ctypes
import sys

# Define a aparência padrão
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- Configuração da Janela Principal ---
        self.title("Scanner de Rede")
        self.geometry("800x600")
        self.minsize(600, 400)

        # --- Variáveis de Estado ---
        self.scan_queue = queue.Queue()
        self.passive_queue = queue.Queue()
        self.passive_thread = None
        # self.passive_stop_event = None # Removido (reversão)
        self.active_interface_name = None

        # --- Layout Principal (Tabs) ---
        self.tab_view = ctk.CTkTabview(self, anchor="w")
        self.tab_view.pack(expand=True, fill="both", padx=10, pady=10)

        self.tab_active = self.tab_view.add("Varredura Ativa")
        self.tab_passive = self.tab_view.add("Monitor Passivo")

        # --- Configuração da Tab 1: Varredura Ativa ---
        self.setup_active_scan_tab()
        
        # --- Configuração da Tab 2: Monitor Passivo ---
        self.setup_passive_scan_tab()
        
        self.passive_toggle_button.configure(state="disabled")

    def setup_active_scan_tab(self):
        """Cria os widgets para a aba de varredura ativa."""
        
        top_frame = ctk.CTkFrame(self.tab_active, fg_color="transparent")
        top_frame.pack(side="top", fill="x", padx=10, pady=10)

        self.scan_button = ctk.CTkButton(
            top_frame,
            text="Escanear Rede",
            command=self.start_active_scan_thread
        )
        self.scan_button.pack(side="left")

        self.scan_status_label = ctk.CTkLabel(top_frame, text="", text_color="gray")
        self.scan_status_label.pack(side="left", padx=15)

        # --- Área de Resultados (Tabela/Treeview) ---
        columns = ('ip', 'mac', 'vendor', 'hostname')
        self.results_tree = ttk.Treeview(
            self.tab_active,
            columns=columns,
            show='headings'
        )
        
        self.results_tree.heading('ip', text='Endereço IP')
        self.results_tree.heading('mac', text='Endereço MAC')
        self.results_tree.heading('vendor', text='Fabricante (OUI)')
        self.results_tree.heading('hostname', text='Nome do Host')

        self.results_tree.column('ip', width=120, anchor='w')
        self.results_tree.column('mac', width=140, anchor='w')
        self.results_tree.column('vendor', width=250, anchor='w')
        self.results_tree.column('hostname', width=150, anchor='w')

        self.results_tree.pack(side="bottom", fill="both", expand=True, padx=10, pady=10)

    def setup_passive_scan_tab(self):
        """Cria os widgets para a aba de monitoramento passivo."""
        
        top_frame = ctk.CTkFrame(self.tab_passive, fg_color="transparent")
        top_frame.pack(side="top", fill="x", padx=10, pady=10)

        # --- MODIFICADO (Reversão) ---
        # O botão não é mais um 'toggle'
        self.passive_toggle_button = ctk.CTkButton(
            top_frame,
            text="Iniciar Monitor (30s)", # Texto alterado
            command=self.start_passive_scan, # Comando alterado
            fg_color="green", # Cor padrão
            hover_color="dark green"
        )
        # --- FIM DA MODIFICAÇÃO ---
        self.passive_toggle_button.pack(side="left")
        
        self.passive_status_label = ctk.CTkLabel(
            top_frame, 
            text="Aguardando. (Execute uma Varredura Ativa primeiro para definir a interface)", 
            text_color="gray"
        )
        self.passive_status_label.pack(side="left", padx=15)

        # Treeview para resultados passivos
        columns = ('mac', 'vendor', 'hostname')
        self.passive_tree = ttk.Treeview(
            self.tab_passive,
            columns=columns,
            show='headings'
        )
        self.passive_tree.heading('mac', text='Endereço MAC')
        self.passive_tree.heading('vendor', text='Fabricante (OUI)')
        self.passive_tree.heading('hostname', text='Nome do Host')
        self.passive_tree.column('mac', width=140, anchor='w')
        self.passive_tree.column('vendor', width=250, anchor='w')
        self.passive_tree.column('hostname', width=150, anchor='w')
        
        self.passive_tree.pack(side="bottom", fill="both", expand=True, padx=10, pady=10)


    # --- Lógica da Varredura Ativa (Multithreading) ---

    def start_active_scan_thread(self):
        """Inicia a varredura em uma thread separada para não congelar a UI."""
        
        # Não permite nova varredura se uma já estiver rodando
        if self.scan_button.cget("state") == "disabled":
            return
            
        self.scan_button.configure(state="disabled", text="Escaneando...")
        self.scan_status_label.configure(text="Procurando interface ativa...")
        
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        self.process_scan_queue() 

        thread = threading.Thread(
            target=self.active_scan_worker,
            args=(self.scan_queue,),
            daemon=True
        )
        thread.start()

    def active_scan_worker(self, queue: queue.Queue):
        """Função de trabalho da varredura ativa (executa na thread)."""
        try:
            pythoncom.CoInitialize()
            
            iface, ip, subnet = core_scanner.find_active_interface()
            if not iface:
                queue.put({'type': 'error', 'data': 'Nenhuma interface de rede ativa encontrada.'})
                return

            self.active_interface_name = iface
            queue.put({'type': 'status', 'data': f"Interface: {iface} | Varrendo sub-rede {subnet}..."})

            devices = core_scanner.active_arp_scan(subnet)
            if not devices:
                queue.put({'type': 'status', 'data': 'Varredura concluída. Nenhum dispositivo encontrado.'})
                return

            queue.put({'type': 'status', 'data': f"Encontrados {len(devices)} dispositivos. Obtendo fabricantes..."})

            for device in devices:
                vendor = core_scanner.get_mac_vendor(device['mac'])
                device_data = (device['ip'], device['mac'], vendor, "N/A (Obtido via DHCP)")
                queue.put({'type': 'result', 'data': device_data})
            
        except Exception as e:
            queue.put({'type': 'error', 'data': f"Erro: {e}"})
        finally:
            queue.put({'type': 'done'}) # Sinaliza que a thread terminou

    def process_scan_queue(self):
        """Executa na thread principal (UI). Processa mensagens da fila ativa."""
        try:
            while not self.scan_queue.empty():
                message = self.scan_queue.get_nowait()
                
                msg_type = message.get('type')
                msg_data = message.get('data')

                if msg_type == 'result':
                    self.results_tree.insert('', 'end', values=msg_data)
                
                elif msg_type == 'status':
                    self.scan_status_label.configure(text=msg_data)
                
                elif msg_type == 'error':
                    self.scan_status_label.configure(text=msg_data, text_color="red")
                
                elif msg_type == 'done':
                    # A thread terminou, reativa o botão
                    self.scan_button.configure(state="normal", text="Escanear Rede")
                    if "Erro" not in self.scan_status_label.cget("text"):
                        self.scan_status_label.configure(text="Varredura concluída.")
                    
                    if self.active_interface_name:
                        self.passive_toggle_button.configure(state="normal")
                        self.passive_status_label.configure(text=f"Pronto para monitorar em '{self.active_interface_name}'.")
                    return # Para de verificar a fila
            
            self.after(100, self.process_scan_queue)

        except queue.Empty:
            self.after(100, self.process_scan_queue)


    # --- Lógica do Monitor Passivo (Revertida e Modificada) ---

    def start_passive_scan(self):
        """Inicia o monitoramento passivo por 30 segundos."""
        
        # Não permite nova varredura se uma já estiver rodando
        if self.passive_toggle_button.cget("state") == "disabled":
            return

        # Limpa resultados antigos
        for item in self.passive_tree.get_children():
            self.passive_tree.delete(item)

        self.process_passive_queue() # Inicia o loop de verificação da fila

        self.passive_thread = threading.Thread(
            target=self.passive_scan_worker,
            args=(
                self.passive_queue,
                self.active_interface_name
            ),
            daemon=True
        )
        self.passive_thread.start()
        
        self.passive_status_label.configure(
            text=f"Monitorando DHCP em '{self.active_interface_name}' por 30 segundos...", 
            text_color="white"
        )
        # Desabilita o botão durante a execução
        self.passive_toggle_button.configure(
            text="Monitorando (30s)...",
            state="disabled"
        )

    def passive_scan_worker(self, queue: queue.Queue, iface_name: str):
        """Função de trabalho do monitor passivo (executa na thread)."""
        
        def on_device_found(device_info):
            """Callback que coloca os dados do DHCP na fila."""
            vendor = core_scanner.get_mac_vendor(device_info.get('mac'))
            device_data = (
                device_info.get('mac'),
                vendor,
                device_info.get('hostname')
            )
            queue.put(device_data)

        try:
            core_scanner.start_passive_monitor(
                iface_name=iface_name,
                on_device_found_callback=on_device_found,
                timeout=30  # Executa por 30 segundos
            )
        except Exception as e:
            queue.put({'type': 'error', 'data': f"Erro no monitor: {e}"})
        finally:
            # Sinaliza para a UI que a thread terminou
            queue.put({'type': 'done'})

    def process_passive_queue(self):
        """Executa na thread principal (UI) para atualizar a tabela passiva."""
        try:
            while not self.passive_queue.empty():
                message = self.passive_queue.get_nowait()
                
                if isinstance(message, dict):
                    msg_type = message.get('type')
                    if msg_type == 'done':
                        # A thread de 30s terminou
                        self.passive_status_label.configure(
                            text=f"Monitoramento concluído. Pronto para iniciar em '{self.active_interface_name}'.",
                            text_color="gray"
                        )
                        self.passive_toggle_button.configure(
                            text="Iniciar Monitor (30s)",
                            state="normal"
                        )
                        return # Para o loop de verificação da fila
                    
                    elif msg_type == 'error':
                        self.passive_status_label.configure(text=message.get('data'), text_color="red")

                else:
                    # Se não for um dict, é um dispositivo
                    device_data = message
                    self.passive_tree.insert('', 0, values=device_data)
        
        except queue.Empty:
            pass # Fila vazia, normal
        
        finally:
            # Reagenda a verificação APENAS se a thread ainda estiver viva
            if self.passive_thread and self.passive_thread.is_alive():
                self.after(200, self.process_passive_queue)
            else:
                # Se a thread morreu, mas não pegamos o 'done' (improvável),
                # reabilitamos o botão por segurança.
                if self.passive_toggle_button.cget("state") == "disabled":
                    self.passive_toggle_button.configure(
                            text="Iniciar Monitor (30s)",
                            state="normal"
                        )
                    self.passive_status_label.configure(
                        text=f"Pronto para monitorar em '{self.active_interface_name}'.",
                        text_color="gray"
                    )


if __name__ == "__main__":
    app = App()
    
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    if not is_admin():
        ctk.CTkMessageBox(
            title="Erro de Permissão", 
            message="O Scapy exige privilégios de Administrador.\n\nPor favor, feche o aplicativo e execute-o 'Como Administrador'.", 
            icon="cancel"
        )
    else:
        app.mainloop()