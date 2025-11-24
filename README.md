# Scanner de Rede para Windows 11

Este projeto é um scanner de rede leve e modular para Windows,
desenvolvido em **Python**, utilizando **Scapy** para manipulação de
pacotes e **CustomTkinter** para uma interface gráfica moderna.

O sistema permite identificar dispositivos conectados à rede local (IP,
MAC, Fabricante e Hostname) através de métodos ativos (ARP) e passivos
(DHCP Sniffing).

## 📋 Pré-requisitos do Sistema

Antes de começar, certifique-se de que seu ambiente possui as
ferramentas abaixo instaladas:

1.  **Python (3.10 ou superior):**
    -   Necessário para executar o código.
    -   **Importante:** Durante a instalação, marque a opção **"Add
        Python to PATH"**.
    -   https://www.python.org/downloads/
2.  **Npcap (Driver de Captura):**
    -   O Scapy depende deste driver para funcionar no Windows (sucessor
        do WinPcap).
    -   Instale com as opções padrão (garanta que a opção "Install Npcap
        in WinPcap API-compatible Mode" esteja marcada se disponível).
    -   https://npcap.com/#download
3.  **Git (Opcional):**
    -   Necessário para clonar o repositório via terminal. Caso não
        tenha, você pode baixar o projeto como `.zip`.
    -   https://git-scm.com/downloads
4.  **Privilégios de Administrador:**
    -   A varredura de rede exige acesso de baixo nível à interface de
        rede. O terminal **deve** ser executado como Administrador.

------------------------------------------------------------------------

## 🚀 Instalação e Execução

Siga os passos abaixo para configurar o ambiente:

### 1. Obter o Código

Abra seu terminal (PowerShell ou CMD) e clone o repositório (ou extraia
o `.zip`):

``` powershell
git clone [URL-do-seu-repositorio]
cd scanner-rede
```

### 2. Criar o Ambiente Virtual (Recomendado)

``` powershell
# Criar o ambiente virtual
python -m venv venv

# Ativar o ambiente (PowerShell)
.
env\Scripts\Activate.ps1
# Se der erro de permissão:
# Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 3. Instalar Dependências

``` powershell
pip install -r requirements.txt
```

### 4. Configurar Banco de Dados de Fabricantes

Execute **uma única vez**:

``` powershell
ouilookup --update
```

### 5. Executar a Aplicação

⚠️ **Importante:** o terminal deve estar aberto como **Administrador**.

1.  Abra o PowerShell/CMD como **Administrador**.
2.  Navegue até a pasta do projeto.
3.  Ative o ambiente virtual (`.
env\Scripts\Activate.ps1`).
4.  Execute o programa:

``` powershell
python main.py
```

------------------------------------------------------------------------

## 🛠️ Solução de Problemas Comuns

-   **Erro "Scapy/Npcap não encontrado":** Verifique se o Npcap está
    instalado.
-   **Erro de Permissão/Access Denied:** Certifique-se de abrir o
    terminal como **Administrador**.
-   **Interface Gráfica não aparece / erro de `customtkinter`:**
    Confirme se as dependências foram instaladas dentro do ambiente
    virtual.
