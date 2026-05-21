# SSH Scanner — Detecção Proativa de OpenSSH Vulnerável

Scanner proativo para identificação de servidores SSH com **OpenSSH** possivelmente vulnerável às CVEs mais críticas conhecidas.

---

## CVEs Cobertas

| CVE | Nome | Condição | Severidade |
|-----|------|----------|------------|
| **CVE-2024-6387** | regreSSHion | OpenSSH < 9.8p1 | CRITICAL |
| **CVE-2023-48795** | Terrapin | OpenSSH < 9.6 | HIGH |

### CVE-2024-6387 — regreSSHion
Race condition no handler de sinal `SIGALRM` do servidor OpenSSH permite **RCE não autenticado** como root em sistemas Linux com glibc. Afeta todas as versões do OpenSSH anteriores à **9.8p1**.

### CVE-2023-48795 — Terrapin
Prefix truncation attack no handshake SSH (protocolo binário) que permite a um adversário MITM remover mensagens de extensão de segurança negociadas no início da sessão. Afeta OpenSSH < **9.6**.

---

## Como funciona

O script conecta diretamente na porta SSH dos alvos e lê o **banner de identificação** (ex: `SSH-2.0-OpenSSH_9.7`), sem enviar nenhuma credencial. Com a versão em mãos, compara contra as versões fixadas de cada CVE e classifica o host.

```
Alvo → Conexão TCP porta 22 → Leitura do banner SSH → Parse da versão OpenSSH
     → Comparação com versões fixadas → Classificação + Log + CSV
```

---

## Requisitos

```bash
pip install requests packaging urllib3 dnspython
```

## Utilização

```bash
# IP individual
python ssh_scanner.py --ip 192.168.1.10

# Faixa CIDR
python ssh_scanner.py --cidr 10.0.0.0/24

# Múltiplos CIDRs
python ssh_scanner.py --cidr 10.0.0.0/24 192.168.1.0/24

# ASN (prefixos resolvidos via RIPE Stat, fallback para bgp.tools)
python ssh_scanner.py --asn AS12345

# Combinação de entradas
python ssh_scanner.py --asn AS12345 --cidr 10.0.0.0/8 --ip 1.2.3.4

# A partir de um arquivo (um IP, CIDR ou ASN por linha)
python ssh_scanner.py --file alvos.txt

# Portas adicionais (além da 22)
python ssh_scanner.py --cidr 10.0.0.0/24 --ports 22 2222 22222
```

### Parâmetros opcionais

| Parâmetro | Padrão | Descrição |
|-----------|--------|-----------|
| `--ports` | 22 | Porta(s) SSH a varrer |
| `--workers` | 60 | Threads simultâneas para o scan SSH |
| `--timeout` | 3.0 | Timeout da conexão SSH em segundos |
| `--dns-workers` | 200 | Threads simultâneas para resolução DNS reversa |
| `--dns-timeout` | 1.5 | Timeout das queries DNS em segundos |
| `--no-confirm` | — | Pula a confirmação antes de iniciar (útil em automações) |

> A resolução DNS é executada em lote **antes** do scan SSH, com fila dedicada de threads, evitando que a latência do DNS impacte na velocidade da varredura.

---

## Saída

Todos os resultados são gravados em `./logs/`:

| Arquivo | Conteúdo |
|---------|----------|
| `ssh_scan_<timestamp>.log` | Log completo da varredura |
| `ssh_scan_<timestamp>_vulneraveis.txt` | Apenas hosts vulneráveis |
| `ssh_scan_<timestamp>_resultados.csv` | Todos os hosts SSH com status |
| `ssh_scan_<timestamp>_formato_cert.txt` | Saída estruturada com IP, porta, timestamp, domínio e detalhes |

### Formato de saída estruturado

```
IP               | Porta | Timestamp (UTC)      | Dominio                 | Detalhes
192.168.1.10     | 22    | 2026-05-20T00:39:33Z | host.exemplo.com        | cve-2024-6387;ssh;SSH-2.0-OpenSSH_9.7
192.168.1.20     | 22    | 2026-05-20T12:46:03Z | host2.exemplo.com       | cve-2023-48795;cve-2024-6387;ssh;SSH-2.0-OpenSSH_9.4
```

### Status dos hosts

| Status | Significado |
|--------|-------------|
| `VULNERÁVEL` | Versão OpenSSH confirmada abaixo da versão corrigida |
| `SEGURO` | Versão OpenSSH confirmada em versão corrigida ou superior |
| `VERSÃO-OCULTA` | SSH detectado mas versão não exposta — não confirmado seguro |
| `SSH-NÃO-OPENSSH` | Servidor SSH encontrado mas não é OpenSSH |

---

## Remediação

Atualize o OpenSSH para a versão **9.8p1 ou superior** (cobre ambas as CVEs):

```bash
# Ubuntu / Debian — via repositório do sistema
sudo apt update && sudo apt install --only-upgrade openssh-server
ssh -V

# CentOS / RHEL / Rocky
sudo dnf update openssh-server
ssh -V

# Compilação a partir do fonte (versão mais recente)
wget https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-9.9p1.tar.gz
tar xzf openssh-9.9p1.tar.gz
cd openssh-9.9p1 && ./configure && make && sudo make install
```

Após atualizar, reinicie o serviço:
```bash
sudo systemctl restart sshd
```

---

## Referências

- NVD CVE-2024-6387: https://nvd.nist.gov/vuln/detail/CVE-2024-6387
- NVD CVE-2023-48795: https://nvd.nist.gov/vuln/detail/CVE-2023-48795
- OpenSSH Release Notes: https://www.openssh.com/releasenotes.html

---

## Se Liga

Este script é destinado ao uso em sua própria infraestrutura ou sob autorização explícita.  
A varredura não autorizada pode violar diversas legislações, então use com cautela.

Quaisquer ações e consequências resultantes do uso indevido desta ferramenta são de sua própria responsabilidade.

Se tiver sugestões de melhoria ou encontrar bugs, abra uma issue ou envie um Pull Request. Toda contribuição é bem-vinda! 🚀
