
import sys
import argparse
import re
import socket
from struct import unpack, pack
from impacket.structure import Structure
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.types import Principal
from impacket.krb5 import constants
from ldap3 import NTLM, Server, Connection, ALL, LEVEL, BASE, MODIFY_DELETE, MODIFY_ADD, MODIFY_REPLACE, SASL, KERBEROS
import ldap3
from impacket.ldap import ldaptypes
import dns.resolver
import datetime

class DNS_RECORD(Structure):
    """
    dnsRecord - used in LDAP
    [MS-DNSP] section 2.3.2.2
    """
    structure = (
        ('DataLength', '<H-Data'),
        ('Type', '<H'),
        ('Version', 'B=5'),
        ('Rank', 'B'),
        ('Flags', '<H=0'),
        ('Serial', '<L'),
        ('TtlSeconds', '>L'),
        ('Reserved', '<L=0'),
        ('TimeStamp', '<L=0'),
        ('Data', ':')
    )

# Note that depending on whether we use RPC or LDAP all the DNS_RPC_XXXX
# structures use DNS_RPC_NAME when communication is over RPC,
# but DNS_COUNT_NAME is the way they are stored in LDAP.
#
# Since LDAP is the primary goal of this script we use that, but for use
# over RPC the DNS_COUNT_NAME in the structures must be replaced with DNS_RPC_NAME,
# which is also consistent with how MS-DNSP describes it.

class DNS_RPC_NAME(Structure):
    """
    DNS_RPC_NAME
    Used for FQDNs in RPC communication.
    MUST be converted to DNS_COUNT_NAME for LDAP
    [MS-DNSP] section 2.2.2.2.1
    """
    structure = (
        ('cchNameLength', 'B-dnsName'),
        ('dnsName', ':')
    )

class DNS_COUNT_NAME(Structure):
    """
    DNS_COUNT_NAME
    Used for FQDNs in LDAP communication
    MUST be converted to DNS_RPC_NAME for RPC communication
    [MS-DNSP] section 2.2.2.2.2
    """
    structure = (
        ('Length', 'B-RawName'),
        ('LabelCount', 'B'),
        ('RawName', ':')
    )

    def toFqdn(self):
        ind = 0
        labels = []
        for i in range(self['LabelCount']):
            nextlen = unpack('B', self['RawName'][ind:ind+1])[0]
            labels.append(self['RawName'][ind+1:ind+1+nextlen].decode('utf-8'))
            ind += nextlen + 1
        # For the final dot
        labels.append('')
        return '.'.join(labels)

class DNS_RPC_NODE(Structure):
    """
    DNS_RPC_NODE
    [MS-DNSP] section 2.2.2.2.3
    """
    structure = (
        ('wLength', '>H'),
        ('wRecordCount', '>H'),
        ('dwFlags', '>L'),
        ('dwChildCount', '>L'),
        ('dnsNodeName', ':')
    )

class DNS_RPC_RECORD_A(Structure):
    """
    DNS_RPC_RECORD_A
    [MS-DNSP] section 2.2.2.2.4.1
    """
    structure = (
        ('address', ':'),
    )

    def formatCanonical(self):
        return socket.inet_ntoa(self['address'])

    def fromCanonical(self, canonical):
        self['address'] = socket.inet_aton(canonical)


class DNS_RPC_RECORD_NODE_NAME(Structure):
    """
    DNS_RPC_RECORD_NODE_NAME
    [MS-DNSP] section 2.2.2.2.4.2
    """
    structure = (
        ('nameNode', ':', DNS_COUNT_NAME),
    )

class DNS_RPC_RECORD_SOA(Structure):
    """
    DNS_RPC_RECORD_SOA
    [MS-DNSP] section 2.2.2.2.4.3
    """
    structure = (
        ('dwSerialNo', '>L'),
        ('dwRefresh', '>L'),
        ('dwRetry', '>L'),
        ('dwExpire', '>L'),
        ('dwMinimumTtl', '>L'),
        ('namePrimaryServer', ':', DNS_COUNT_NAME),
        ('zoneAdminEmail', ':', DNS_COUNT_NAME)
    )

class DNS_RPC_RECORD_NULL(Structure):
    """
    DNS_RPC_RECORD_NULL
    [MS-DNSP] section 2.2.2.2.4.4
    """
    structure = (
        ('bData', ':'),
    )

# Some missing structures here that I skipped

class DNS_RPC_RECORD_NAME_PREFERENCE(Structure):
    """
    DNS_RPC_RECORD_NAME_PREFERENCE
    [MS-DNSP] section 2.2.2.2.4.8
    """
    structure = (
        ('wPreference', '>H'),
        ('nameExchange', ':', DNS_COUNT_NAME)
    )

# Some missing structures here that I skipped

class DNS_RPC_RECORD_AAAA(Structure):
    """
    DNS_RPC_RECORD_AAAA
    [MS-DNSP] section 2.2.2.2.4.17
    [MS-DNSP] section 2.2.2.2.4.17
    """
    structure = (
        ('ipv6Address', '16s'),
    )

class DNS_RPC_RECORD_SRV(Structure):
    """
    DNS_RPC_RECORD_SRV
    [MS-DNSP] section 2.2.2.2.4.18
    """
    structure = (
        ('wPriority', '>H'),
        ('wWeight', '>H'),
        ('wPort', '>H'),
        ('nameTarget', ':', DNS_COUNT_NAME)
    )

class DNS_RPC_RECORD_TS(Structure):
    """
    DNS_RPC_RECORD_TS
    [MS-DNSP] section 2.2.2.2.4.23
    """
    structure = (
        ('entombedTime', '<Q'),
    )
    def toDatetime(self):
        microseconds = self['entombedTime'] / 10.
        return datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=microseconds)

def get_dns_zones(connection, root):
    connection.search(root, '(objectClass=dnsZone)', search_scope=LEVEL, attributes=['dc'])
    zones = []
    for entry in connection.response:
        if entry['type'] != 'searchResEntry':
            continue
        zones.append(entry['attributes']['dc'])
    return zones

def get_next_serial(dnsserver, dc, zone, tcp):
    # Create a resolver object
    dnsresolver = dns.resolver.Resolver()
    # Check if DNS-server is present
    if dnsserver:
       server = dnsserver
    else:
        server = dc
   

    # Is our host an IP? In that case make sure the server IP is used
    # if not assume lookups are working already
    try:
        socket.inet_aton(server)
        dnsresolver.nameservers = [server]
        
    except socket.error:
        pass

    try:
        print("Zone is:",zone)
        res = dnsresolver.resolve(zone, 'SOA',tcp=tcp)
        for answer in res:
            return answer.serial + 1
        
    except Exception:
        print("ERROR Zone is:",zone)
        exit()





def print_m(string):
    sys.stderr.write('\033[94m[-]\033[0m %s\n' % (string))

def print_o(string):
    sys.stderr.write('\033[92m[+]\033[0m %s\n' % (string))

def print_f(string):
    sys.stderr.write('\033[91m[!]\033[0m %s\n' % (string))


def ldap2domain(ldap):
    return re.sub(',DC=', '.', ldap[ldap.find('DC='):], flags=re.I)[3:]

def print_record(record, ts=False):
    try:
        rtype = RECORD_TYPE_MAPPING[record['Type']]
    except KeyError:
        rtype = 'Unsupported'
    if ts:
        print('Record is tombStoned (inactive)')
    print_o('Record entry:')
    print(' - Type: %d (%s) (Serial: %d)' % (record['Type'], rtype, record['Serial']))
    if record['Type'] == 0:
        tstime = DNS_RPC_RECORD_TS(record['Data'])
        print(' - Tombstoned at: %s' % tstime.toDatetime())
    # A record
    if record['Type'] == 1:
        address = DNS_RPC_RECORD_A(record['Data'])
        print(' - Address: %s' % address.formatCanonical())
    # NS record or CNAME record
    if record['Type'] == 2 or record['Type'] == 5:
        address = DNS_RPC_RECORD_NODE_NAME(record['Data'])
        # address.dump()
        print(' - Address: %s' %  address['nameNode'].toFqdn())
    # SRV record
    if record['Type'] == 33:
        record_data = DNS_RPC_RECORD_SRV(record['Data'])
        # record_data.dump()
        print(' - Priority: %d' %  record_data['wPriority'])
        print(' - Weight: %d' %  record_data['wWeight'])
        print(' - Port: %d' %  record_data['wPort'])
        print(' - Name: %s' %  record_data['nameTarget'].toFqdn())
    # SOA record
    if record['Type'] == 6:
        record_data = DNS_RPC_RECORD_SOA(record['Data'])
        # record_data.dump()
        print(' - Serial: %d' %  record_data['dwSerialNo'])
        print(' - Refresh: %d' %  record_data['dwRefresh'])
        print(' - Retry: %d' %  record_data['dwRetry'])
        print(' - Expire: %d' %  record_data['dwExpire'])
        print(' - Minimum TTL: %d' %  record_data['dwMinimumTtl'])
        print(' - Primary server: %s' %  record_data['namePrimaryServer'].toFqdn())
        print(' - Zone admin email: %s' %  record_data['zoneAdminEmail'].toFqdn())

def new_record(rtype, serial):
    nr = DNS_RECORD()
    nr['Type'] = rtype
    nr['Serial'] = serial
    nr['TtlSeconds'] = 180
    # From authoritive zone
    nr['Rank'] = 240
    return nr


def print_operation_result(result):
    if result['result'] == 0:
        print_o('LDAP operation completed successfully')
        return True
    else:
        print_f('LDAP operation failed. Message returned from server: %s %s' %  (result['description'], result['message']))
        return False

RECORD_TYPE_MAPPING = {
    0: 'ZERO',
    1: 'A',
    2: 'NS',
    5: 'CNAME',
    6: 'SOA',
    33: 'SRV',
    65281: 'WINS'
}

A_RECORD_TYPE = 1




def DNSRecordModfier(CONNECTION_BIND, LDAP_HANDLE, RECORD_TARGET, DATA_FOR_RECORD ,DNS_IP , LDAP_SERVER = None, ACTION = 0):
        
        ADD_RECORD = 0 
        REMOVE_RECORD = 1
        QUERY_RECORD = 2

        if not LDAP_SERVER:
            LDAP_SERVER = DNS_IP


        domainroot = LDAP_HANDLE.info.other['defaultNamingContext'][0]
        forestroot = LDAP_HANDLE.info.other['rootDomainNamingContext'][0]
        dnsroot = 'CN=MicrosoftDNS,DC=DomainDnsZones,%s' % domainroot  
        #dnsroot = 'CN=MicrosoftDNS,CN=System,%s' % domainroot   
   

        zone = ldap2domain(domainroot)

        target = RECORD_TARGET
        if target.lower().endswith(zone.lower()):
            target = target[:-(len(zone)+1)]

        searchtarget = 'DC=%s,%s' % (zone, dnsroot)
    # print s.info.naming_contexts
        CONNECTION_BIND.search(searchtarget, '(&(objectClass=dnsNode)(name=%s))' % ldap3.utils.conv.escape_filter_chars(target), attributes=['dnsRecord','dNSTombstoned','name'])
        targetentry = None
        for entry in CONNECTION_BIND.response:
            if entry['type'] != 'searchResEntry':
                continue

            targetentry = entry
        #input()

        if ACTION == REMOVE_RECORD and not targetentry:
            print_f('Target record not found!')
            return
        
        if ACTION == QUERY_RECORD:
            if (targetentry):
                print_o('Found record %s' % targetentry['attributes']['name'])
                for record in targetentry['raw_attributes']['dnsRecord']:
                    dr = DNS_RECORD(record)
                    # dr.dump()
                    print(targetentry['dn'])
                    print_record(dr, targetentry['attributes']['dNSTombstoned'])
                    continue
            else:
                print("[+] DNS Record not found")
            

            return 

        if ACTION == ADD_RECORD:
            # Only A records for now
            addtype = 1
            # Entry exists
            if targetentry:
                for record in targetentry['raw_attributes']['dnsRecord']:
                    dr = DNS_RECORD(record)
                    if dr['Type'] == 1:
                        address = DNS_RPC_RECORD_A(dr['Data'])
                        print_f('Record already exists and points to %s ' % address.formatCanonical())
                        return False
                        
                # If we are here, no A records exists yet
                print(get_next_serial(DNS_IP, LDAP_SERVER, zone, 0))
                record = new_record(addtype, get_next_serial(DNS_IP, LDAP_SERVER, zone, 0))
                record['Data'] = DNS_RPC_RECORD_A()
                record['Data'].fromCanonical(DATA_FOR_RECORD)
                print_m('Adding extra record')
                CONNECTION_BIND.modify(targetentry['dn'], {'dnsRecord': [(MODIFY_ADD, record.getData())]})
                if(print_operation_result(CONNECTION_BIND.result)):
                    return True
            else:
                      
                node_data = {
                    # Schema is in the root domain (take if from schemaNamingContext to be sure)
                    'objectCategory': 'CN=Dns-Node,%s' % LDAP_HANDLE.info.other['schemaNamingContext'][0],
                    'dNSTombstoned': False,
                    'name': target
                }
                record = new_record(addtype, get_next_serial(DNS_IP, LDAP_SERVER, zone, 0))
                record['Data'] = DNS_RPC_RECORD_A()
                record['Data'].fromCanonical(DATA_FOR_RECORD)
                record_dn = 'DC=%s,%s' % (target, searchtarget)
                node_data['dnsRecord'] = [record.getData()]
                print_m('Adding new record')
                CONNECTION_BIND.add(record_dn, ['top', 'dnsNode'], node_data)
                if(print_operation_result(CONNECTION_BIND.result)):
                    return True

        elif ACTION == REMOVE_RECORD:
            addtype = 0
            if len(targetentry['raw_attributes']['dnsRecord']) > 1:
                print_m('Target has multiple records, removing the one specified')
                targetrecord = None
                for record in targetentry['raw_attributes']['dnsRecord']:
                    dr = DNS_RECORD(record)
                    if dr['Type'] == 1:
                        tr = DNS_RPC_RECORD_A(dr['Data'])
                        if tr.formatCanonical() == DATA_FOR_RECORD:
                            targetrecord = record

                if not targetrecord:
                    print_f('Could not find a record with the specified data')
                    return
                CONNECTION_BIND.modify(targetentry['dn'], {'dnsRecord': [(MODIFY_DELETE, targetrecord)]})
                if(print_operation_result(CONNECTION_BIND.result)):
                    return True
            else:
                print_m('Target has only one record, tombstoning it')
                diff = datetime.datetime.today() - datetime.datetime(1601,1,1)
                tstime = int(diff.total_seconds()*10000)
                # Add a null record
                record = new_record(addtype, get_next_serial(DNS_IP, LDAP_SERVER, zone, 0))
                record['Data'] = DNS_RPC_RECORD_TS()
                record['Data']['entombedTime'] = tstime
                CONNECTION_BIND.modify(targetentry['dn'], {'dnsRecord': [(MODIFY_REPLACE, [record.getData()])],
                                            'dNSTombstoned': [(MODIFY_REPLACE, True)]})
                if(print_operation_result(CONNECTION_BIND.result)):
                    return True


