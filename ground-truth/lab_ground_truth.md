# Attack Path Analyzer and Auto-Remediation
## Lab Ground Truth

Date: 2026-11-16

### 1. Lab Environment
Network: VMware Host-only (VMnet1)
Subnet: 192.168.75.0/24
Internet access: Isolated lab

### 2. Lab Hosts

| Host | IP Address | Role |
|---|---|---|
| Kali Linux | 192.168.75.10 | Security scanning and analysis |
| Metasploitable 2 | 192.168.75.20 | Intentionally vulnerable target |
| Ubuntu Server | 192.168.75.30 | Critical database server |

### 3. Verified Discovery
- Nmap discovered all 3 hosts as up.
- Metasploitable 2: 23 open TCP ports in the latest full service scan.
- Ubuntu Server: TCP port 22 open (SSH).
- Ubuntu Server: TCP port 5432 closed from Kali.
- PostgreSQL 16 cluster is online on Ubuntu.
- PostgreSQL listen_addresses = localhost.

### 4. Verification Status
- Service discovery: Completed for the initial lab baseline.
- Vulnerability verification: Pending.
- Attack path validation: Pending.
- Remediation testing: Pending.

### 5. Metasploitable 2 - Open TCP Ports

Scan target: 192.168.75.20
Tool: Nmap 7.95
Scan type: TCP connect scan with service detection (-sT -sV)
Result: 23 open TCP ports among the default 1000 scanned ports.

| Port | Service / Detection | Version / Notes |
|---|---|---|
| 21 | FTP | vsftpd 2.3.4 |
| 22 | SSH | OpenSSH 4.7p1 |
| 23 | Telnet | Service identification uncertain |
| 25 | SMTP | Service identification uncertain |
| 53 | DNS | ISC BIND 9.4.2 |
| 80 | HTTP | Service identification uncertain in latest scan |
| 111 | RPC | rpcbind |
| 139 | NetBIOS/SMB | Service identification uncertain |
| 445 | SMB | Samba smbd 3.X - 4.X |
| 512 | Remote exec | Service identification uncertain |
| 513 | Remote login | Service identification uncertain |
| 514 | Remote shell | Service identification uncertain |
| 1099 | Java RMI | GNU Classpath grmiregistry |
| 1524 | Bind shell | Nmap identifies Metasploitable root shell |
| 2049 | RPC/NFS-related | rpcbind in latest scan |
| 2121 | FTP-related | Service identification uncertain |
| 3306 | MySQL-related | Service identification uncertain |
| 5432 | PostgreSQL-related | Service identification uncertain |
| 5900 | VNC | Protocol 3.3 |
| 6000 | X11 | Access denied |
| 6667 | IRC | UnrealIRCd |
| 8009 | AJP | Service identification uncertain |
| 8180 | Unknown | Service identification uncertain |

Note: Service detection does not prove exploitability.
The earlier scan identified some services more specifically.
Temporary network connectivity issues affected an intermediate scan.


### 6. Ubuntu Critical Database Server

Host: Ubuntu Server 24.04.5 LTS
IP address: 192.168.75.30
Role: Critical database asset

#### Network Scan
Scanner: Kali Linux (192.168.75.10)
Tool: Nmap 7.95
Scan type: TCP connect and service detection (-sT -sV)

- 22/tcp: OPEN - SSH - OpenSSH 9.6p1
- Other 999 default scanned TCP ports: CLOSED
- 5432/tcp: CLOSED from Kali (connection refused)

#### PostgreSQL Verification
- PostgreSQL version: 16
- Cluster: main
- Cluster status: online
- Local port: 5432
- listen_addresses: localhost
- Project database: attack_path_db
- Application database user: attack_path_user
- Local database authentication: Previously tested successfully

#### Security Observations
- SSH is reachable from the lab network.
- PostgreSQL is running locally.
- PostgreSQL is not directly reachable from Kali on TCP 5432.
- No confirmed exploit path to the critical database server yet.


### 7. Potential Vulnerabilities - Verification Queue

The following items are candidates for further investigation.
They are NOT confirmed exploitable vulnerabilities.

| Host | Port | Finding | Status |
|---|---|---|---|
| Metasploitable 2 | 21/tcp | vsftpd 2.3.4 - investigate known security issues | Pending verification |
| Metasploitable 2 | 23/tcp | Telnet service - investigate insecure plaintext authentication | Pending verification |
| Metasploitable 2 | 445/tcp | Samba service - investigate version and known vulnerabilities | Pending verification |
| Metasploitable 2 | 1524/tcp | Root shell service reported by Nmap - investigate exposure safely | Pending verification |
| Metasploitable 2 | 6667/tcp | UnrealIRCd - investigate known security issues | Pending verification |
| Ubuntu DB | 22/tcp | SSH exposed to the isolated lab network - review access controls | Security review pending |

### 8. Attack Path Validation

Entry point: Kali Linux (192.168.75.10)
Potential intermediate host: Metasploitable 2 (192.168.75.20)
Critical asset: Ubuntu DB (192.168.75.30)

Candidate path for analysis:
Kali -> Metasploitable 2 -> Ubuntu DB

Status: HYPOTHETICAL - NOT VALIDATED.

Important:
- Network reachability alone does not prove exploitability.
- No verified compromise or lateral movement has been demonstrated.
- PostgreSQL on Ubuntu is currently restricted to localhost.
- The attack graph must distinguish hypothetical edges from validated edges.


### H2 to H3 Connectivity Verification
- Source: Metasploitable 2 (192.168.75.20)
- Destination: Ubuntu DB (192.168.75.30)
- Test: ping -c 4 192.168.75.30
- Result: 4 packets transmitted, 4 received, 0% packet loss.
- Conclusion: Network reachability confirmed. Exploitability and lateral movement remain unverified.
