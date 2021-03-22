# MERCYv2
Desarrollo del CTF MERCERY V2


## 1. Configuración de la VM

- Download: https://www.vulnhub.com/entry/digitalworldlocal-mercy-v2,263/

## 2. Escaneo de Puertos

```
nmap -n -P0 -p- -sC -sV -O -T5 -oA full 10.10.10.143
Nmap scan report for 10.10.10.143
Host is up (0.00078s latency).
Not shown: 65525 closed ports
PORT     STATE    SERVICE     VERSION
22/tcp   filtered ssh
53/tcp   open     domain      ISC BIND 9.9.5-3ubuntu0.17 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.9.5-3ubuntu0.17-Ubuntu
80/tcp   filtered http
110/tcp  open     pop3        Dovecot pop3d
|_pop3-capabilities: CAPA SASL AUTH-RESP-CODE RESP-CODES PIPELINING UIDL TOP STLS
139/tcp  open     netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp  open     imap        Dovecot imapd (Ubuntu)
|_imap-capabilities: more IMAP4rev1 ID have LITERAL+ Pre-login post-login LOGIN-REFERRALS listed capabilities OK LOGINDISABLEDA0001 IDLE ENABLE SASL-IR STARTTLS
445/tcp  open     netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
993/tcp  open     ssl/imaps?
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-08-24T13:22:55
|_Not valid after:  2028-08-23T13:22:55
|_ssl-date: TLS randomness does not represent time
995/tcp  open     ssl/pop3s?
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server
| Not valid before: 2018-08-24T13:22:55
|_Not valid after:  2028-08-23T13:22:55
|_ssl-date: TLS randomness does not represent time
8080/tcp open     http        Apache Tomcat/Coyote JSP engine 1.1
| http-methods: 
|_  Potentially risky methods: PUT DELETE
|_http-open-proxy: Proxy might be redirecting requests
| http-robots.txt: 1 disallowed entry 
|_/tryharder/tryharder
|_http-title: Apache Tomcat
MAC Address: 00:0C:29:0E:13:4F (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Host: MERCY; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -2h39m58s, deviation: 4h37m07s, median: 0s
|_nbstat: NetBIOS name: MERCY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: mercy
|   NetBIOS computer name: MERCY\x00
|   Domain name: \x00
|   FQDN: mercy
|_  System time: 2021-03-22T01:34:28+08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-03-21T17:34:28
|_  start_date: N/A
```

- Llama la atención TCP/80 y TCP/22 que aparecen como FILTERED. Un probable PORT KNOCKING.


<

