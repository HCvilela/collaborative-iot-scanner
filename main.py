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

# --- IMPORTAÇÕES MODULARIZADAS ---
from ui_components import ReportDeviceWindow
from persistence_manager import save_device_registration
from active_scanner import ActiveScanner
from passive_scanner import PassiveScanner
# --- FIM DAS IMPORTAÇÕES ---

# Define a aparência padrão
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- Configuração da Janela Principal ---
        self.title("Scanner de Rede")
        self.geometry("1050x600") 
        self.minsize(800, 400)

        # --- Variáveis de Estado (UI) ---
        self.init_queue = queue.Queue()
        self.active_interface_name = None
        self.active_subnet = None
        self.selected_device_data = None
        
 
        # As classes de scanner agora gerenciam suas próprias threads e estado
        self.active_scanner = ActiveScanner()
        self.passive_scanner = PassiveScanner()

        # A UI (main) apenas obtém as filas para processar os resultados
        self.scan_queue = self.active_scanner.get_queue()
        self.passive_queue = self.passive_scanner.get_queue()
    

        # --- Layout (Grid) --
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=0) 
        self.grid_rowconfigure(0, weight=1)

        self.tab_view = ctk.CTkTabview(self, anchor="w")
        self.tab_view.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.tab_active = self.tab_view.add("Varredura Ativa")
        self.tab_passive = self.tab_view.add("Monitor Passivo")

        self.sidebar_frame = ctk.CTkFrame(self, width=250)
        self.sidebar_frame.grid(row=0, column=1, padx=(0, 10), pady=10, sticky="nsw")

        # --- Configuração dos Componentes ---
        self.setup_active_scan_tab()
        self.setup_passive_scan_tab()
        self.setup_sidebar() 
        
        self.initial_interface_find()

    def setup_sidebar(self):
        """Cria e popula os widgets da nova barra lateral."""
        
        self.sidebar_frame.grid_rowconfigure(6, weight=1) 
        self.sidebar_frame.grid_columnconfigure(0, weight=1)
        
        self.sidebar_title = ctk.CTkLabel(
            self.sidebar_frame, 
            text="Dispositivo Selecionado", 
            font=ctk.CTkFont(weight="bold")
        )
        self.sidebar_title.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        
        self.sidebar_ip_label = ctk.CTkLabel(self.sidebar_frame, text="IP: N/A", anchor="w")
        self.sidebar_ip_label.grid(row=1, column=0, padx=10, pady=2, sticky="w")
        
        self.sidebar_mac_label = ctk.CTkLabel(self.sidebar_frame, text="MAC: N/A", anchor="w")
        self.sidebar_mac_label.grid(row=2, column=0, padx=10, pady=2, sticky="w")
        
        self.sidebar_vendor_label = ctk.CTkLabel(self.sidebar_frame, text="Fabricante: N/A", anchor="w")
        self.sidebar_vendor_label.grid(row=3, column=0, padx=10, pady=2, sticky="w")
        
        self.sidebar_hostname_label = ctk.CTkLabel(self.sidebar_frame, text="Hostname: N/A", anchor="w")
        self.sidebar_hostname_label.grid(row=4, column=0, padx=10, pady=2, sticky="w")
        
        self.report_button = ctk.CTkButton(
            self.sidebar_frame, 
            text="Relatar Dispositivo", 
            command=self.open_report_window, 
            state="disabled"
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
        
        self.results_tree.bind("<<TreeviewSelect>>", self.on_device_select)

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
        
        self.passive_tree.bind("<<TreeviewSelect>>", self.on_device_select)

    # --- Funções de Evento (Sidebar e Modal) ---
    def on_device_select(self, event):
        """Atualiza a sidebar quando um dispositivo é clicado."""
        widget = event.widget 
        
        selected_item_id = widget.selection()
        if not selected_item_id:
            return 
        
        item_data = widget.item(selected_item_id[0])['values']
        
        if widget == self.results_tree:
            self.passive_tree.selection_remove(self.passive_tree.selection())
        else:
            self.results_tree.selection_remove(self.results_tree.selection())
        
        if widget == self.results_tree: # Tabela Ativa
            ip, mac, vendor, hostname = item_data
        else: # Tabela Passiva
            mac, vendor, hostname = item_data
            ip = "N/A (Passivo)"
            
        self.selected_device_data = {
            'ip': ip,
            'mac': mac,
            'vendor': vendor,
            'hostname': hostname
        }
        
        self.sidebar_ip_label.configure(text=f"IP: {ip}")
        self.sidebar_mac_label.configure(text=f"MAC: {mac}")
        self.sidebar_vendor_label.configure(text=f"Fabricante: {vendor}")
        self.sidebar_hostname_label.configure(text=f"Hostname: {hostname}")
        
        self.report_button.configure(state="normal")

    def clear_selection(self):
        """Limpa a seleção da tabela e reseta a sidebar."""
        self.results_tree.selection_remove(self.results_tree.selection())
        self.passive_tree.selection_remove(self.passive_tree.selection())
        self.selected_device_data = None
        self.sidebar_ip_label.configure(text="IP: N/A")
        self.sidebar_mac_label.configure(text="MAC: N/A")
        self.sidebar_vendor_label.configure(text="Fabricante: N/A")
        self.sidebar_hostname_label.configure(text="Hostname: N/A")
        self.report_button.configure(state="disabled")

    def open_report_window(self):
        """Abre a janela modal de 'ui_components.py'."""
        if not self.selected_device_data:
            return
            
        modal = ReportDeviceWindow(
            master=self,
            device_data=self.selected_device_data,
            on_save_callback=self.handle_save_registration 
        )
        modal.grab_set()

    def handle_save_registration(self, data_from_modal: dict):
        """Callback que salva os dados (de 'persistence_manager.py')."""
        try:
            save_device_registration(data_from_modal)
            status_text = f"Registro salvo para {data_from_modal.get('mac')}"
            self.scan_status_label.configure(text=status_text, text_color="green")
            self.clear_selection()
        except Exception as e:
            self.scan_status_label.configure(text=f"Falha ao salvar: {e}", text_color="red")
            
    # --- Lógica de Inicialização da Aplicação ---
    def initial_interface_find(self):
        """Inicia a thread para encontrar a interface de rede."""
        thread = threading.Thread(
            target=self.interface_finder_worker,
            args=(self.init_queue,),
            daemon=True
        )
        thread.start()
        self.process_init_queue()

    def interface_finder_worker(self, queue: queue.Queue):
        """Thread worker que chama o WMI e "prepara" (primes) a interface."""
        try:
            pythoncom.CoInitialize()
            iface, ip, subnet = core_scanner.find_active_interface()
            
            if not iface:
                queue.put({'type': 'error', 'data': 'Nenhuma interface de rede ativa encontrada.'})
            else:
                core_scanner.prime_network_interface(iface, ip)
                queue.put({'type': 'success', 'iface': iface, 'subnet': subnet})
        except Exception as e:
            queue.put({'type': 'error', 'data': f"Erro de WMI: {e}"})

    def process_init_queue(self):
        """Processa o resultado da descoberta de interface (na thread da UI)."""
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

    # --- Lógica de Delegação (Varredura Ativa) ---
    def start_active_scan_thread(self):
        """Delega a varredura ativa para o módulo ActiveScanner."""
        self.clear_selection() 
        self.scan_button.configure(state="disabled", text="Escaneando...")
        self.scan_status_label.configure(text=f"Varrendo {self.active_subnet}...")
        
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        self.process_scan_queue() # Inicia o processador da fila
        
        # --- REFATORADO ---
        # A lógica da thread foi movida para o 'active_scanner'
        self.active_scanner.start_scan(self.active_subnet)
        # --- FIM ---

    # (LÓGICA DO WORKER REMOVIDA)

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


    # --- Lógica de Delegação (Monitor Passivo) ---
    def start_passive_scan(self):
        """Delega o início do monitor para o PassiveScanner."""
        self.clear_selection() 
        for item in self.passive_tree.get_children():
            self.passive_tree.delete(item)

        self.process_passive_queue() # Inicia o processador da fila
        
        # --- REFATORADO ---
        self.passive_scanner.start_scan(self.active_interface_name)
        # --- FIM ---
        
        self.passive_status_label.configure(
            text=f"Monitorando DHCP em '{self.active_interface_name}'...", 
            text_color="white"
        )
        self.passive_start_button.configure(state="disabled")
        self.passive_stop_button.configure(state="normal")

    def stop_passive_scan(self):
        """Delega a parada do monitor para o PassiveScanner."""
        self.passive_status_label.configure(text="Parando...", text_color="gray")
        self.passive_stop_button.configure(state="disabled")
        
        self.passive_scanner.stop_scan()

    def process_passive_queue(self):
        """Processa a fila do monitor passivo (na thread da UI)."""
        
        keep_polling = True
        
        try:
            while not self.passive_queue.empty():
                message = self.passive_queue.get_nowait()
                
                if isinstance(message, dict):
                    msg_type = message.get('type')
                    if msg_type == 'done':
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