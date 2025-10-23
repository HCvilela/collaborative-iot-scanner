# Scanner de Rede para Windows 11

Este projeto é um scanner de rede leve para Windows 11, desenvolvido em Python, Scapy e CustomTkinter.

## Requisitos Essenciais

Antes de executar, você **DEVE** atender a dois requisitos:

1.  **Privilégios de Administrador:** A ferramenta usa Scapy para captura de pacotes, o que exige permissões elevadas. Você deve executar o script "Como Administrador".
2.  **Npcap Instalado:** O Scapy depende do driver Npcap (o sucessor do WinPcap) para funcionar no Windows.
    * **[Baixe o instalador do Npcap aqui](https://npcap.com/)** (Instale com as opções padrão).

## Como Executar

1.  **Clone o Repositório:**
    ```sh
    git clone [URL-do-seu-repositorio]
    cd [nome-do-repositorio]
    ```

2.  **Crie e Ative o Ambiente Virtual:**
    ```sh
    # Criar
    python -m venv venv
    
    # Ativar (PowerShell)
    .\venv\Scripts\Activate.ps1
    ```

3.  **Instale as Dependências:**
    ```sh
    pip install -r requirements.txt
    ```

4.  **Atualize o Banco de Dados de Fabricantes (OUI):**
    (Execute este comando *uma vez* para baixar o banco de dados de MACs)
    ```sh
    ouilookup --update
    ```

5.  **Execute a Aplicação:**
    **Importante:** Abra um novo terminal (PowerShell ou CMD) **Como Administrador**, ative o `venv` novamente (passo 2) e execute:
    ```sh
    python main.py
    ```

---
*Esta aplicação foi desenvolvida seguindo o `Plano de desenvolvimento.txt`.*