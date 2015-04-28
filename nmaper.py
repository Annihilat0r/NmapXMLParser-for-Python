import nmap
import ipgetter
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from DB_config import Base, CurrentScan


nm = nmap.PortScanner()
#nm.scan('scanme.nmap.org',arguments='')  ###Uncomment for use your external IP
scan_dict={'1':ipgetter.myip(), '2':'127.0.0.1', '3': 'scanme.nmap.org'}
print('Choose host for scan:')
print('1: External IP')
print('2: localhost')
print('3: scanme.nmap.org')
host_for_scan = input()
print('Enter port range (20-80)')
ports = input()
print('Nmap scans host %s for %s ports... please wait...' %(scan_dict[host_for_scan], ports))
nm.scan(scan_dict[host_for_scan],ports=ports)  #DEMO scan you localhost
print ('Nmap query:', nm.command_line())
engine = create_engine('sqlite:///sqlalchemy_example.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
session.query(CurrentScan).delete()

for host in nm.all_hosts():
    for proto in nm[host].all_protocols():
        lport = nm[host][proto].keys()
        for port in lport:
            try:
                state = nm[host][proto][port]['state']
                scan = CurrentScan(name=host, proto=proto, port=port, port_state=state)
                session.add(scan)
            except: pass

print('')
print("QUERY FROM TABLE 'CurrentScan'")
print('_____________________________________')
print('  #   Host Name  Proto Port   State')
for scan in session.query(CurrentScan):
    print ('| %s | %s | %s | %s | %s |' % (scan.id, scan.name, scan.proto, scan.port, scan.port_state))


input()
print (nm)
input()
