import os
import json
import sys

# --- Constantes de Persistência ---

# Define o nome da subpasta
DATA_FOLDER = "Registros de dispositivos"

# Define o nome do arquivo de texto
# Usamos a extensão .jsonl (JSON Lines), pois cada linha
# será um objeto JSON independente, como planejado.
DATA_FILE = os.path.join(DATA_FOLDER, "registro_global.jsonl")

# --- Funções de Interface ---

def save_device_registration(device_data: dict):
    """
    Salva um único registro de dispositivo no arquivo de texto
    'registro_global.jsonl'.

    Esta função é 'append-only' (apenas incrementa) e
    é thread-safe (o modo 'a' lida com concorrência).
    
    Argumentos:
        device_data (dict): Um dicionário contendo os dados
                            coletados do formulário.
    """
    try:
        # Passo 1: Garantir que o diretório exista
        # 'exist_ok=True' evita erros se a pasta já existir
        os.makedirs(DATA_FOLDER, exist_ok=True)
        
        # Passo 2: Converter o dicionário em uma string JSON
        # 'ensure_ascii=False' garante a codificação correta de caracteres (ex: 'ç' ou 'ã')
        line_to_append = json.dumps(device_data, ensure_ascii=False)
        
        # Passo 3: Abrir o arquivo em modo 'append' ('a')
        # 'encoding="utf-8"' é crucial para salvar caracteres especiais
        with open(DATA_FILE, "a", encoding="utf-8") as f:
            # Escreve a linha JSON e um caractere de nova linha
            f.write(line_to_append + "\n")
            
    except PermissionError:
        # Isso pode acontecer se a pasta estiver protegida (ex: C:\)
        print(f"Erro: Permissão negada ao tentar salvar em '{DATA_FOLDER}'.", file=sys.stderr)
    except Exception as e:
        print(f"Erro inesperado ao salvar o registro: {e}", file=sys.stderr)

