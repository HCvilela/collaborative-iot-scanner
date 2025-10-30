import customtkinter as ctk
from tkinter import ttk
import tkinter.messagebox
import tkinter
import threading
import queue
import core_scanner
import pythoncom
import ctypes
import sys

# --- NOVAS IMPORTAÇÕES ---
# Importa os módulos que criamos nas Fases 1 e 2
from ui_components import ReportDeviceWindow
from persistence_manager import save_device_registration
# --- FIM DAS NOVAS IMPORTAÇÕES ---

# Define a aparência padrão
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- Configuração da Janela Principal ---
        self.title("Scanner de Rede")
        self.geometry("1050x600") # Largura aumentada para acomodar a sidebar
        self.minsize(800, 400)

        # --- Variáveis de Estado ---
        self.scan_queue = queue.Queue()
        self.passive_queue = queue.Queue()
        self.init_queue = queue.Queue()
        
        self.passive_thread = None
        self.passive_stop_event = None
        
        self.active_interface_name = None
        self.active_subnet = None
        
        # Novo estado para o dispositivo selecionado
        self.selected_device_data = None

        # --- REFATORAÇÃO DO LAYOUT (Grid) ---
        # A janela agora tem 2 colunas:
        # Coluna 0: A área principal com as tabs (expansível)
        # Coluna 1: A nova sidebar (fixa)
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=0) # Não expande
        self.grid_rowconfigure(0, weight=1)

        # --- Layout Principal (Tabs) ---
        self.tab_view = ctk.CTkTabview(self, anchor="w")
        # .grid() é usado no lugar de .pack()
        self.tab_view.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.tab_active = self.tab_view.add("Varredura Ativa")
        self.tab_passive = self.tab_view.add("Monitor Passivo")

        # --- Nova Sidebar ---
        self.sidebar_frame = ctk.CTkFrame(self, width=250)
        self.sidebar_frame.grid(row=0, column=1, padx=(0, 10), pady=10, sticky="nsw")
        # --- FIM DA REFATORAÇÃO DO LAYOUT ---

        # --- Configuração dos Componentes ---
        self.setup_active_scan_tab()
        self.setup_passive_scan_tab()
        self.setup_sidebar() # Configura a nova sidebar
        
        # Inicia a descoberta de interface (sem alteração)
        self.initial_interface_find()

    def setup_sidebar(self):
        """Cria e popula os widgets da nova barra lateral."""
        
        # Configura o grid da sidebar (1 coluna)
        self.sidebar_frame.grid_rowconfigure(6, weight=1) # Espaço
        self.sidebar_frame.grid_columnconfigure(0, weight=1)
        
        # Título
        self.sidebar_title = ctk.CTkLabel(
            self.sidebar_frame, 
            text="Dispositivo Selecionado", 
            font=ctk.CTkFont(weight="bold")
        )
        self.sidebar_title.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        # Labels de Informação
        self.sidebar_ip_label = ctk.CTkLabel(self.sidebar_frame, text="IP: N/A", anchor="w")
        self.sidebar_ip_label.grid(row=1, column=0, padx=10, pady=2, sticky="w")
        
        self.sidebar_mac_label = ctk.CTkLabel(self.sidebar_frame, text="MAC: N/A", anchor="w")
        self.sidebar_mac_label.grid(row=2, column=0, padx=10, pady=2, sticky="w")
        
        self.sidebar_vendor_label = ctk.CTkLabel(self.sidebar_frame, text="Fabricante: N/A", anchor="w")
        self.sidebar_vendor_label.grid(row=3, column=0, padx=10, pady=2, sticky="w")
        
        self.sidebar_hostname_label = ctk.CTkLabel(self.sidebar_frame, text="Hostname: N/A", anchor="w")
        self.sidebar_hostname_label.grid(row=4, column=0, padx=10, pady=2, sticky="w")
        
        # Botão de Relatar
        self.report_button = ctk.CTkButton(
            self.sidebar_frame, 
            text="Relatar Dispositivo", 
            command=self.open_report_window, 
            state="disabled" # Começa desabilitado
        )
        self.report_button.grid(row=5, column=0, padx=10, pady=15, sticky="ew")

    def setup_active_scan_tab(self):
        """Cria os widgets para a aba de varredura ativa."""
        
        top_frame = ctk.CTkFrame(self.tab_active, fg_color="transparent")
        top_frame.pack(side="top", fill="x", padx=10, pady=10)

        self.scan_button = ctk.CTkButton(
            top_frame,
            text="Escanear Rede",
            command=self.start_active_scan_thread,
            state="disabled" 
        )
        self.scan_button.pack(side="left")

        self.scan_status_label = ctk.CTkLabel(top_frame, text="Detectando interface...", text_color="gray")
        self.scan_status_label.pack(side="left", padx=15)

        # Tabela (Treeview)
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
        
        # --- VINCULA O EVENTO DE CLIQUE ---
        self.results_tree.bind("<<TreeviewSelect>>", self.on_device_select)
        # --- FIM DA VINCULAÇÃO ---

    def setup_passive_scan_tab(self):
        """Cria os widgets para a aba de monitoramento passivo."""
        
        top_frame = ctk.CTkFrame(self.tab_passive, fg_color="transparent")
        top_frame.pack(side="top", fill="x", padx=10, pady=10)

        self.passive_start_button = ctk.CTkButton(
            top_frame,
            text="Iniciar Monitor", 
            command=self.start_passive_scan, 
            fg_color="green",
            hover_color="dark green",
            state="disabled" 
        )
        self.passive_start_button.pack(side="left", padx=(0, 5))
        
        self.passive_stop_button = ctk.CTkButton(
            top_frame,
            text="Parar Monitor", 
            command=self.stop_passive_scan, 
            fg_color="red",
            hover_color="dark red",
            state="disabled" 
        )
        self.passive_stop_button.pack(side="left", padx=(5, 0))
        
        self.passive_status_label = ctk.CTkLabel(
            top_frame, 
            text="Detectando interface...", 
            text_color="gray"
        )
        self.passive_status_label.pack(side="left", padx=15)

        # Tabela (Treeview)
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
        
        # --- VINCULA O EVENTO DE CLIQUE ---
        self.passive_tree.bind("<<TreeviewSelect>>", self.on_device_select)
        # --- FIM DA VINCULAÇÃO ---

    # --- NOVAS FUNÇÕES DE EVENTO ---
    def on_device_select(self, event):
        """
        Chamado quando o usuário clica em um item em QUALQUER Treeview.
        Atualiza a sidebar com os dados do item selecionado.
        """
        widget = event.widget # Identifica qual Treeview foi clicado
        
        # Pega o ID da linha selecionada (ex: 'I001')
        selected_item_id = widget.selection()
        if not selected_item_id:
            return # Se o clique foi para desmarcar, não faz nada
        
        # Pega os valores da linha
        item_data = widget.item(selected_item_id[0])['values']
        
        # Limpa a seleção da *outra* tabela para evitar confusão
        if widget == self.results_tree:
            self.passive_tree.selection_remove(self.passive_tree.selection())
        else:
            self.results_tree.selection_remove(self.results_tree.selection())
        
        # Extrai os dados baseado na tabela clicada
        if widget == self.results_tree: # Tabela Ativa
            ip, mac, vendor, hostname = item_data
        else: # Tabela Passiva
            mac, vendor, hostname = item_data
            ip = "N/A (Passivo)" # Monitor passivo não captura IP
            
        # Armazena os dados no estado da App (formato padronizado)
        self.selected_device_data = {
            'ip': ip,
            'mac': mac,
            'vendor': vendor,
            'hostname': hostname
        }
        
        # Atualiza as labels da sidebar
        self.sidebar_ip_label.configure(text=f"IP: {ip}")
        self.sidebar_mac_label.configure(text=f"MAC: {mac}")
        self.sidebar_vendor_label.configure(text=f"Fabricante: {vendor}")
        self.sidebar_hostname_label.configure(text=f"Hostname: {hostname}")
        
        # Habilita o botão de relatar
        self.report_button.configure(state="normal")

    def clear_selection(self):
        """Limpa a seleção da tabela e reseta a sidebar."""
        # Remove a seleção visual
        self.results_tree.selection_remove(self.results_tree.selection())
        self.passive_tree.selection_remove(self.passive_tree.selection())
        
        # Limpa o estado
        self.selected_device_data = None
        
        # Reseta as labels da sidebar
        self.sidebar_ip_label.configure(text="IP: N/A")
        self.sidebar_mac_label.configure(text="MAC: N/A")
        self.sidebar_vendor_label.configure(text="Fabricante: N/A")
        self.sidebar_hostname_label.configure(text="Hostname: N/A")
        
        # Desabilita o botão
        self.report_button.configure(state="disabled")

    def open_report_window(self):
        """
        Abre a janela modal (de 'ui_components.py')
        e passa a função de callback.
        """
        if not self.selected_device_data:
            return
            
        # Cria a instância da janela modal
        modal = ReportDeviceWindow(
            master=self,
            device_data=self.selected_device_data,
            on_save_callback=self.handle_save_registration # Passa a função de callback
        )
        modal.grab_set() # Torna a janela modal

    def handle_save_registration(self, data_from_modal: dict):
        """
        Callback que é chamado pela janela modal.
        Recebe os dados do formulário e os passa para o
        módulo de persistência para salvar.
        """
        try:
            # Chama a função do 'persistence_manager.py'
            save_device_registration(data_from_modal)
            
            # Atualiza o status para o usuário
            status_text = f"Registro salvo para {data_from_modal.get('mac')}"
            self.scan_status_label.configure(text=status_text, text_color="green")
            
            # Limpa a seleção
            self.clear_selection()
            
        except Exception as e:
            # Mostra erro se o salvamento falhar
            self.scan_status_label.configure(text=f"Falha ao salvar: {e}", text_color="red")
            
    # --- FIM DAS NOVAS FUNÇÕES ---

    # --- Lógica de Inicialização (Sem alteração, exceto 'prime') ---
    def initial_interface_find(self):
        thread = threading.Thread(
            target=self.interface_finder_worker,
            args=(self.init_queue,),
            daemon=True
        )
        thread.start()
        self.process_init_queue()

    def interface_finder_worker(self, queue: queue.Queue):
        try:
            pythoncom.CoInitialize()
            iface, ip, subnet = core_scanner.find_active_interface()
            
            if not iface:
                queue.put({'type': 'error', 'data': 'Nenhuma interface de rede ativa encontrada.'})
            else:
                # "Acorda" o Npcap/Scapy (Workaround do bug)
                core_scanner.prime_network_interface(iface, ip)
                queue.put({'type': 'success', 'iface': iface, 'subnet': subnet})
        except Exception as e:
            queue.put({'type': 'error', 'data': f"Erro de WMI: {e}"})

    def process_init_queue(self):
        try:
            message = self.init_queue.get_nowait()
            
            if message.get('type') == 'success':
                self.active_interface_name = message.get('iface')
                self.active_subnet = message.get('subnet')
                
                self.scan_button.configure(state="normal")
                self.passive_start_button.configure(state="normal")
                
                status_text = f"Pronto. (Interface: {self.active_interface_name})"
                self.scan_status_label.configure(text=status_text, text_color="gray")
                self.passive_status_label.configure(text=status_text, text_color="gray")

            elif message.get('type') == 'error':
                error_text = message.get('data')
                self.scan_status_label.configure(text=error_text, text_color="red")
                self.passive_status_label.configure(text=error_text, text_color="red")

        except queue.Empty:
            self.after(100, self.process_init_queue)

    # --- Lógica da Varredura Ativa ---
    def start_active_scan_thread(self):
        """Inicia a varredura ativa (botão)."""
        self.clear_selection() # Limpa a sidebar
        self.scan_button.configure(state="disabled", text="Escaneando...")
        self.scan_status_label.configure(text=f"Varrendo {self.active_subnet}...")
        
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
        """Thread worker da varredura ativa."""
        try:
            devices = core_scanner.active_arp_scan(self.active_subnet)
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
            queue.put({'type': 'done'}) 

    def process_scan_queue(self):
        """Processa a fila da varredura ativa (na thread da UI)."""
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
                    self.scan_button.configure(state="normal", text="Escanear Rede")
                    if "Erro" not in self.scan_status_label.cget("text"):
                        self.scan_status_label.configure(text="Varredura concluída.")
                    return 
            
            self.after(100, self.process_scan_queue)

        except queue.Empty:
            self.after(100, self.process_scan_queue)


    # --- Lógica do Monitor Passivo "Start/Stop" ---
    def start_passive_scan(self):
        """Inicia o monitoramento passivo (botão Iniciar)."""
        self.clear_selection() # Limpa a sidebar
        for item in self.passive_tree.get_children():
            self.passive_tree.delete(item)

        self.passive_stop_event = threading.Event()
        self.process_passive_queue() 

        self.passive_thread = threading.Thread(
            target=self.passive_scan_worker,
            args=(
                self.passive_queue,
                self.passive_stop_event,
                self.active_interface_name
            ),
            daemon=True
        )
        self.passive_thread.start()
        
        self.passive_status_label.configure(
            text=f"Monitorando DHCP em '{self.active_interface_name}'...", 
            text_color="white"
        )
        self.passive_start_button.configure(state="disabled")
        self.passive_stop_button.configure(state="normal")

    def stop_passive_scan(self):
        """Para o monitoramento passivo (botão Parar)."""
        self.passive_status_label.configure(text="Parando...", text_color="gray")
        self.passive_stop_button.configure(state="disabled")
        
        if self.passive_stop_event:
            self.passive_stop_event.set() # Sinaliza para a thread parar

    def passive_scan_worker(self, queue: queue.Queue, stop_event: threading.Event, iface_name: str):
        """Thread worker do monitor passivo."""
        
        def on_device_found(device_info):
            vendor = core_scanner.get_mac_vendor(device_info.get('mac'))
            device_data = (
                device_info.get('mac'),
                vendor,
                device_info.get('hostname')
            )
            queue.put(device_data)

        # Loop de 'sniffing'
        while not stop_event.is_set():
            core_scanner.start_passive_monitor(
                iface_name=iface_name,
                on_device_found_callback=on_device_found,
                stop_event=stop_event,
                timeout_per_loop=1
            )
        
        queue.put({'type': 'done'}) # Sinaliza para a UI

    def process_passive_queue(self):
        """Processa a fila do monitor passivo (na thread da UI)."""
        
        keep_polling = True
        
        try:
            while not self.passive_queue.empty():
                message = self.passive_queue.get_nowait()
                
                if isinstance(message, dict):
                    msg_type = message.get('type')
                    if msg_type == 'done':
                        # A thread worker confirmou que parou
                        self.passive_status_label.configure(
                            text=f"Monitoramento parado. (Interface: {self.active_interface_name})",
                            text_color="gray"
                        )
                        self.passive_start_button.configure(state="normal")
                        self.passive_stop_button.configure(state="disabled")
                        keep_polling = False 
                        break 
                    
                    elif msg_type == 'error':
                        self.passive_status_label.configure(text=message.get('data'), text_color="red")

                else:
                    # Se não for um dict, é um dispositivo
                    device_data = message
                    self.passive_tree.insert('', 0, values=device_data)
        
        except queue.Empty:
            pass 
        
        if keep_polling:
            self.after(200, self.process_passive_queue)

if __name__ == "__main__":
    
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    if not is_admin():
        root = tkinter.Tk()
        root.withdraw()
        tkinter.messagebox.showerror(
            "Erro de Permissão", 
            "O Scapy exige privilégios de Administrador.\n\nPor favor, feche o aplicativo e execute-o 'Como Administrador'."
        )
        root.destroy()
    else:
        app = App()
        app.mainloop()