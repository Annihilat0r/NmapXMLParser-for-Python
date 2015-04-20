import nmap
import ipgetter
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from DB_config import Base, CurrentScan


nm = nmap.PortScanner()
# nm.scan(ipgetter.myip(),arguments='')  ###Uncomment for use your external IP
nm.scan(ports='20-85')  #DEMO scan you localhost
print 'Nmap query:', nm.command_line()
engine = create_engine('sqlite:///sqlalchemy_example.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
session.query(CurrentScan).delete()

for host in nm.all_hosts():
    for proto in nm[host].all_protocols():
        lport = nm[host][proto].keys()
        lport.sort()
        for port in lport:
            try:
                state = nm[host][proto][port]['state']
                scan = CurrentScan(name=host, proto=proto, port=port, port_state=state)
                session.add(scan)
            except: pass

print ''
print "QUERY FROM TABLE 'CurrentScan'"
print '_____________________________________'
print '  #   Host Name  Proto Port   State'
for scan in session.query(CurrentScan):
    print ('| %s | %s | %s | %s | %s |' % (scan.id, scan.name, scan.proto, scan.port, scan.port_state))
raw_input()