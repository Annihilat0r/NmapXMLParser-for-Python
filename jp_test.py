__author__ = 'dare7'
import nmap
import ipgetter
from libnmap.parser import NmapParser
from libnmap.plugins.backendpluginFactory import BackendPluginFactory
from libnmap.objects.report import NmapReport
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from tables_config import  ConfigNmap, base



class NmapWrapper:
    def __init__(self):
        self.target_ports = "22-443"
        self.external_address = "127.0.0.1"
        self.db_string = "mysql://root:@127.0.0.1/tokio"  # for prod change

    def config(self):
        """
        Configures nmap parameter external address and ports for scan
        ports1  = '20-443', ports2 = '1-1024' , ports3 = '1-65565'
        :return: external address, ports
        """
        session = self.db_connect()
        self.external_address = str(session.query(ConfigNmap).filter(ConfigNmap.property == "ext_ip").one().value)
        self.target_ports = str(session.query(ConfigNmap).filter(ConfigNmap.property == "ports1").one().value)

    def db_connect(self):
        """
        Connect to DB
        :return: session
        """
        engine = create_engine(self.db_string)
        base.metadata.create_all(engine)
        base.metadata.bind = engine
        db_session = sessionmaker(bind=engine)
        return db_session()

    def launch(self):
        """
        launches nmap scan
        :return: nmap report as object type NmapObject
        """
        nm = nmap.PortScanner()
        self.config() #get ip and ports for scan
        nm.scan(self.external_address, self.target_ports)
        result = nm.get_nmap_last_output()
        nm_report = NmapParser.parse_fromstring(result)
        self.write_result(nm_report)
        return nm_report

    def write_result(self, nm_report):
        """
        Writes nmap input report (JSON) to db as BLOB
        :param id: input report of type NmapObject
        :return: None
        """
        report_db = BackendPluginFactory.create(plugin_name='sql', url=self.db_string)
        nm_report.save(report_db)

    def get_report(self, report_id, raw_data=False):
        """
        returs nmap report from DB, converts JSON to dictionary string
        :param id: report id
        :return:
        if raw_data == False: nmap report
        if raw_data == True: raw nmap report
        """
        report_db = BackendPluginFactory.create(plugin_name='sql', url=self.db_string)
        rep = report_db.get(report_id)
        if raw_data:
            rep = rep.get_raw_data()
        return rep

    def get_all_reports(self, raw_data=False):
        """
        returs ALL nmap report from DB, converts JSON to dictionary string
        :return:
        if raw_data == False: all_reports list
        if raw_data == True: dict {report ID : raw nmap report}
        """
        raw_list = {}
        report_db = BackendPluginFactory.create(plugin_name='sql', url=self.db_string)
        all_reports = report_db.getall()
        if raw_data == True:
            for n in all_reports:
                raw_list[int(n[0])] = n[1].get_raw_data()
            return raw_list
        return all_reports

def first_start():
    '''
    for first start - write to BD table "nmap_config" nmap config parameters
    '''
    engine = create_engine("mysql://root:@127.0.0.1/tokio")
    base.metadata.create_all(engine)
    base.metadata.bind = engine
    db_session = sessionmaker(bind=engine)
    session = db_session()
    session.query(ConfigNmap).delete()
    new_config_nmap = ConfigNmap(property='ext_ip', value = '127.0.0.1')
####new_config_nmap = ConfigNmap(property='ext_ip', value = str(ipgetter.myip()))  ###uncoment for prod
    session.add(new_config_nmap)
    port_config_nmap = ConfigNmap(property='ports1', value = '20-443')
    session.add(port_config_nmap)
    port_config_nmap = ConfigNmap(property='ports2', value = '1-1024')
    session.add(port_config_nmap)
    port_config_nmap = ConfigNmap(property='ports3', value = '1-65565')
    session.add(port_config_nmap)
    session.commit()
    #debug. delete for prod
    print('SELECT * FROM config_nmap')
    s = session.query(ConfigNmap).all()
    for sa in s:
        print(sa.property, '=', sa.value)


def main():
    print('\n '
              'Welcome to jp_test (Nmap-to-DB) \n '
              '1: Do scan \n '
              '2: Get one report from DB \n '
              '3: Get all reports from DB \n '
              '4: Config DB for nmsp parameters \n '
              '5: Exit')
    chose = int(input())
    if chose == 1:
        print(nm.launch()) #For start scan
    if chose == 2:
        print('Write a number of report:')
        a = input()
        print(nm.get_report(a, True)) #get report #1
    if chose == 3:
        print(nm.get_all_reports(True)) #get all reports raw_data
    if chose == 4:
        first_start()
    if chose != 5:  # do comment for cancel recursive work
        main()

nm = NmapWrapper()
main()