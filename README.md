<img width="810" height="220" alt="image" src="https://github.com/user-attachments/assets/4280eea6-7556-4f35-901c-3ca47d89e971" />

Scanner para identificação de servidores com softwares SSH possivelmente vulnerável às CVEs CVE-2024-6387 e CVE-2023-48795.

---

## CVEs Cobertas

| CVE                | Nome        | Condição        | Severidade |
| ------------------ | ----------- | --------------- | ---------- |
| **CVE-2024-6387**  | regreSSHion | OpenSSH < 9.8p1 | CRITICAL   |
| **CVE-2023-48795** | Terrapin    | OpenSSH < 9.6   | HIGH       |

### CVE-2024-6387 — regreSSHion

Race condition no handler de sinal `SIGALRM` do servidor OpenSSH permite **RCE não autenticado** como root em sistemas Linux com glibc. Afeta todas as versões do OpenSSH anteriores à **9.8p1**.

### CVE-2023-48795 — Terrapin

Prefix truncation attack no handshake SSH (protocolo binário) que permite a um adversário MITM remover mensagens de extensão de segurança negociadas no início da sessão. Afeta OpenSSH < **9.6**.

## Como funciona

O script conecta diretamente na porta SSH dos alvos e lê o **banner de identificação** (ex: `SSH-2.0-OpenSSH_9.7`), sem enviar nenhuma credencial. Com a versão em mãos, compara contra as versões fixadas de cada CVE e classifica o host.

```
Alvo → Conexão TCP porta 22 → Leitura do banner SSH → Identificação do software
     → Parse da versão OpenSSH → Comparação com versões fixadas → Classificação + Log + CSV
```

O script também identifica o **fabricante/software SSH** a partir do banner, reconhecendo:

| Banner                          | Fabricante identificado |
| ------------------------------- | ----------------------- |
| `SSH-2.0-OpenSSH_9.7`           | OpenSSH                 |
| `SSH-2.0-ROSSSH`                | Mikrotik                |
| `SSH-2.0-Cisco-1.25`            | Cisco                   |
| `SSH-2.0-dropbear_2022.83`      | Dropbear                |
| `SSH-2.0-libssh-0.9.6`          | libssh                  |
| `SSH-2.0-AsyncSSH_2.13.2`       | AsyncSSH                |
| `SSH-2.0-paramiko_2.9.5`        | Paramiko                |
| `SSH-2.0-Bitvise-...`           | Bitvise                 |
| `SSH-2.0-WolfSSH_1.4.14`        | wolfSSH                 |
| Outros não mapeados             | Nome extraído do banner |

## Requisitos

```bash
pip install requests packaging urllib3 dnspython
```

> `dnspython` é opcional, mas altamente recomendado — a resolução reversa paralela é significativamente mais rápida com ele. Sem `dnspython`, o script usa `socket` como fallback.

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

| Parâmetro       | Padrão | Descrição                                                |
| --------------- | ------ | -------------------------------------------------------- |
| `--ports`       | 22     | Porta(s) SSH a varrer                                    |
| `--workers`     | 60     | Threads simultâneas para o scan SSH                      |
| `--timeout`     | 3.0    | Timeout da conexão SSH em segundos                       |
| `--dns-workers` | 200    | Threads simultâneas para resolução DNS reversa           |
| `--dns-timeout` | 1.5    | Timeout das queries DNS em segundos                      |
| `--no-confirm`  | —      | Pula a confirmação antes de iniciar (útil em automações) |

> A resolução DNS é executada em lote **antes** do scan SSH, com fila dedicada de threads, evitando que a latência do DNS impacte na velocidade da varredura.

## Saída

Todos os resultados são gravados em `./logs/`:

| Arquivo                                       | Conteúdo                                                          |
| --------------------------------------------- | ----------------------------------------------------------------- |
| `ssh_scan_<timestamp>.log`                    | Log completo da varredura (todos os hosts SSH encontrados)        |
| `ssh_scan_<timestamp>_vulneraveis.txt`        | Apenas hosts classificados como `VULNERÁVEL`                      |
| `ssh_scan_<timestamp>_resultados.csv`         | Todos os hosts SSH com status completo                            |
| `ssh_scan_<timestamp>_formato_estruturado.csv`| CSV estruturado com IP, porta, timestamp, domínio, fabricante e CVEs |

### CSV estruturado (`formato_estruturado.csv`)

Colunas presentes:

| Coluna          | Descrição                                      |
| --------------- | ---------------------------------------------- |
| `IP`            | Endereço IP do host                            |
| `PORTA`         | Porta SSH onde o banner foi capturado          |
| `TIMESTAMP_UTC` | Timestamp ISO 8601 UTC do momento do scan      |
| `DOMINIO`       | Hostname via DNS reverso (PTR) ou `SEM-PTR`    |
| `FABRICANTE`    | Fabricante identificado a partir do banner     |
| `SW_NAME`       | Nome do software SSH extraído do banner        |
| `SW_VERSAO`     | Versão do software SSH                         |
| `CVEs`          | CVEs afetadas separadas por `;` (minúsculas)   |
| `BANNER`        | Banner SSH completo capturado                  |

Exemplo de linhas:

```
IP               | PORTA | TIMESTAMP_UTC        | DOMINIO                  | FABRICANTE | SW_NAME | SW_VERSAO | CVEs                          | BANNER
192.168.1.10     | 22    | 2026-05-20T00:39:33Z | host.exemplo.com         | OpenSSH    | OpenSSH | 9.7       | cve-2024-6387;cve-2023-48795  | SSH-2.0-OpenSSH_9.7
192.168.1.20     | 22    | 2026-05-20T12:46:03Z | host2.exemplo.com        | OpenSSH    | OpenSSH | 9.4       | cve-2023-48795;cve-2024-6387  | SSH-2.0-OpenSSH_9.4
192.168.1.30     | 22    | 2026-05-20T12:47:11Z | router.exemplo.com       | Mikrotik   | ROSSSH  | N/D       |                               | SSH-2.0-ROSSSH
```

> Ao final da varredura, se houver hosts vulneráveis, o script exibe automaticamente uma **prévia das primeiras 20 linhas** do CSV estruturado no terminal.

### Status dos hosts

| Status              | Significado                                                        |
| ------------------- | ------------------------------------------------------------------ |
| `VULNERÁVEL`        | Versão OpenSSH confirmada abaixo da versão corrigida               |
| `SEGURO`            | Versão OpenSSH confirmada em versão corrigida ou superior          |
| `VERSÃO-OCULTA`     | SSH detectado mas versão não exposta — não confirmado seguro       |
| `SSH-NÃO-OPENSSH`   | Servidor SSH encontrado mas não é OpenSSH (Dropbear, Cisco, etc.) |
| `NÃO-SSH`           | Porta respondeu mas o banner não corresponde ao protocolo SSH      |

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

## Referências

- NVD CVE-2024-6387: <https://nvd.nist.gov/vuln/detail/CVE-2024-6387>
- NVD CVE-2023-48795: <https://nvd.nist.gov/vuln/detail/CVE-2023-48795>
- OpenSSH Release Notes: <https://www.openssh.com/releasenotes.html>

## Aviso Legal

Este script é destinado ao uso em sua própria infraestrutura ou sob autorização explícita.
A varredura não autorizada pode violar diversas legislações, então use com cautela.

Quaisquer ações e consequências resultantes do uso indevido desta ferramenta são de sua própria responsabilidade.

Se tiver sugestões de melhoria ou encontrar bugs, abra uma issue ou envie um Pull Request. Toda contribuição é bem-vinda! 🚀
