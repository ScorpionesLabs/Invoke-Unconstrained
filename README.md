# Invoke-unconstrained  
A tool to fully automate exploitation of a compromised machine with unconstrained delegation.  
  
In an effort to avoid EDRs and XDRs, we decided to find a way to fully automate the exploitation of `unconstrained delegation` without using a domain joined machine.  
We found that there are ways to do it, but they have many steps and might be complex to understand, so we decided to create a full automation that sets up the attack.  
while also creating a snapshot of the old state to revert changes after exploitation.  

### How to Use  
The use is quite simple, first of all, the tool supports `plain-text` password and `pass the hash` both, and also kerberos authentication.  
 
Fully automate an exploitation:  
  
```
Invoke-unconstrained.py -u LABS\DEG$ -p aad3b435b51404eeaad3b435b51404ee:fd8d7a6f868dc2d81aaf3eb3a9ea6adc -t DEG$ -ah ATT28.labs.local -aip 10.0.0.12  10.0.0.5
```

in the exmaple above, we compromised the machine account named `DEG$` which has unconstrained delegation, by using the machine credentials, we authenticated to the LDAP services  
and add SPNs after a new machine that does not exists in the domain `ATT28`, this SPN will be added to the 

### Credits

1. Omri Baso From [Scorpiones Labs](https://www.scorpiones.io/).  
2. Some of the code snippets were taken from the [krbrelayx](https://github.com/dirkjanm/krbrelayx/tree/master) Project.  
