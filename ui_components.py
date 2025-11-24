import customtkinter as ctk

class ReportDeviceWindow(ctk.CTkToplevel):
    """
    Esta classe define a janela modal (pop-up) que
    serve como formulário para registrar um novo dispositivo.
    """
    
    def __init__(self, master, device_data: dict, on_save_callback: callable):

        super().__init__(master)
        
        self.on_save_callback = on_save_callback
        
        self.title("Relatar Dispositivo")
        self.geometry("450x380")
        self.resizable(False, False)
        
        # --- Configuração Modal ---
        # Garante que esta janela fique no topo e bloqueie a janela principal
        self.grab_set()
        self.transient(master)

        # --- Estrutura do Formulário ---
        # Usamos grid para alinhar labels e entries
        self.grid_columnconfigure(1, weight=1) # Coluna 1 (entries) expande

        # --- Campos do Formulário ---

        # 1. Endereço MAC (Read-only, pois é o ID)
        mac_label = ctk.CTkLabel(self, text="Endereço MAC:")
        mac_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.mac_entry = ctk.CTkEntry(self, width=250)
        self.mac_entry.insert(0, device_data.get('mac', ''))
        self.mac_entry.configure(state="readonly") # MAC não pode ser editado
        self.mac_entry.grid(row=0, column=1, padx=10, pady=10, sticky="we")

        # 2. Fabricante (OUI) (Editável, pode ser corrigido)
        vendor_label = ctk.CTkLabel(self, text="Fabricante (OUI):")
        vendor_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.vendor_entry = ctk.CTkEntry(self, width=250)
        # O helper limpa "N/A" ou "Erro" dos dados pré-preenchidos
        self.vendor_entry.insert(0, self._clean_data(device_data.get('vendor')))
        self.vendor_entry.grid(row=1, column=1, padx=10, pady=10, sticky="we")

        # 3. Hostname (Editável, pode ser corrigido)
        hostname_label = ctk.CTkLabel(self, text="Nome do Host (Hostname):")
        hostname_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")
        self.hostname_entry = ctk.CTkEntry(self, width=250)
        self.hostname_entry.insert(0, self._clean_data(device_data.get('hostname')))
        self.hostname_entry.grid(row=2, column=1, padx=10, pady=10, sticky="we")

        # 4. Tipo de dispositivo (Novo campo)
        tipo_label = ctk.CTkLabel(self, text="Tipo de dispositivo:")
        tipo_label.grid(row=3, column=0, padx=10, pady=10, sticky="w")
        self.tipo_entry = ctk.CTkEntry(self, width=250, placeholder_text="Ex: Smartphone, Câmera, TV")
        self.tipo_entry.grid(row=3, column=1, padx=10, pady=10, sticky="we")

        # 5. Fabricante do produto (Novo campo)
        fabricante_label = ctk.CTkLabel(self, text="Fabricante do produto:")
        fabricante_label.grid(row=4, column=0, padx=10, pady=10, sticky="w")
        self.fabricante_entry = ctk.CTkEntry(self, width=250, placeholder_text="Ex: Samsung, Intelbras, Apple")
        self.fabricante_entry.grid(row=4, column=1, padx=10, pady=10, sticky="we")

        # 6. Modelo do dispositivo (Novo campo)
        modelo_label = ctk.CTkLabel(self, text="Modelo do dispositivo:")
        modelo_label.grid(row=5, column=0, padx=10, pady=10, sticky="w")
        self.modelo_entry = ctk.CTkEntry(self, width=250, placeholder_text="Ex: Galaxy S23, Mibo iC3")
        self.modelo_entry.grid(row=5, column=1, padx=10, pady=10, sticky="we")

        # --- Botão Salvar ---
        save_button = ctk.CTkButton(self, text="Salvar Registro", command=self.save_and_close)
        save_button.grid(row=6, column=0, columnspan=2, padx=10, pady=20, sticky="s")
        
        # Foco no primeiro campo editável
        self.vendor_entry.focus()

    def _clean_data(self, data_str: str):
        """
        Helper para limpar dados 'N/A' ou 'Erro' antes de preencher
        o formulário, melhorando a usabilidade.
        """
        if not data_str:
            return ""
        # Lista de strings que consideramos "não-informativas"
        if any(tag in data_str for tag in ["N/A", "Erro OUI", "Desconhecido"]):
            return ""
        return data_str

    def save_and_close(self):
        """
        Etapa final: Coleta os dados, envia para o callback 
        e fecha a janela.
        """
        
        # 1. Coleta os dados de todos os 6 campos
        final_data = {
            "mac": self.mac_entry.get(),
            "vendor_oui": self.vendor_entry.get(),
            "hostname": self.hostname_entry.get(),
            "tipo_dispositivo": self.tipo_entry.get(),
            "fabricante_produto": self.fabricante_entry.get(),
            "modelo_dispositivo": self.modelo_entry.get()
        }
        
        # 2. Chama o callback (a função do main.py)
        if self.on_save_callback:
            self.on_save_callback(final_data)
            
        # 3. Fecha a janela modal
        self.destroy()