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

in the exmaple above, we compromised the machine account named `DEG$` which has unconstrained delegation, by using the machine credentials, we authenticated to the LDAP services and add SPNs after a new machine that does not exists in the domain `ATT28`, this SPN will be added, in addition, we will also populate the `msds-additionaldnshostname` to set a another DNS name that points to the `unconstrained delegation` machine, this where the attack lays,  we then add another DNS record pointing to the IP at the `-aip` argument.  
#### Sumup:  
`-u` - username we want to attack with, usually we would use the machine account we are attacking itself, this must be with backslash, not forward slash.  
`-t` - Target with unconstrained delegation.  
`-ah` - attacker hostname that will be added \(does not need to exists as an actual machine\).  
`-aip` - attacker IP address that will be added under the attacker hostname. 
`-p` - password, supports plaintext and NTLM aswell.  

Sucessfull output will look as follows:  

![image](https://github.com/ScorpionesLabs/delegator/assets/50461376/a16d91e3-ac86-483e-a8fc-f94c0bfc84f4)

#### Reverting Changes:

We also added a module to remove the SPNs and unpopulate the `msds-additionaldnshostname` attribute, the module will also try to remove the DNS Record but it might not succeed because of insufficent permissions depending on the domain user we are using.
```
Invoke-unconstrained.py -u LABS\Administrator -p aad3b435b51404eeaad3b435b51404ee:47bf8039a8506cd67c524a03ff84ba4e -r .\DEG-2023-10-17--18-20-42.961041 10.0.0.5
```

As can be seen above, on each exploitation, a state file is created which shows that changes made that needs to reverted.  


### Credits

1. Omri Baso From [Scorpiones Labs](https://www.scorpiones.io/).  
2. Some of the code snippets were taken from the [krbrelayx](https://github.com/dirkjanm/krbrelayx/tree/master) Project.  
