from jp_test import NmapWrapper

nm = NmapWrapper()
nm.sniffer_detect()
print(nm.get_sniffer_detect_report())
