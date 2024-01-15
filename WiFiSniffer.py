import os
import utils as ut
from sniffer import Sniffer
import scapy.all as scapy
from scapy.layers import dot11

'''
Esta clase no está en uso, ya que resulta más sencillo generar los paquetes que capturarlos.
No se ha borrado por si en el futuro se implementa.
'''
class WiFiSniffer(Sniffer):

    def __init__(self, iface, pkts_captured, num_of_pkts_to_cap, layer, list_of_pkts_cap):
        super(WiFiSniffer, self).__init__(iface, pkts_captured, num_of_pkts_to_cap, layer, list_of_pkts_cap)

    def sniff_WiFi_Packets(self):

        self.set_iface(self.get_iface() + 'mon')
        print("\n")
        ut.print_pretty_message('Success', ' Capturando paquetes WiFi ...', False, None)

        packets = self.start_packets_capture()

        print("\n")
        ut.print_pretty_message('Success', ' Capturados {} paquetes WiFi.', True, str(self.get_pkts_captured()))
        print("\n")
        ut.print_pretty_message('Success', ' Guardando los paquetes en el directorio {} ...', True,
                                os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'WiFi'))
        j = 0
        for packet in packets:
            self.save_packet_in_directory(os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'WiFi'), packet, j)
            j += 1

        print("\n")
        ut.print_pretty_message('Success', ' Todos los paquetes se han guardado correctamente', False, None)

    def start_packets_capture(self):
        if self.get_num_of_pkts_to_cap() is not None:
            t1 = scapy.AsyncSniffer(iface=self.get_iface(), prn=self.handle_packets,
                                    count=self.get_num_of_pkts_to_cap(), store=1,
                                    monitor=True)
        else:
            t1 = scapy.AsyncSniffer(iface=self.get_iface(), prn=self.handle_packets,
                                    store=1, monitor=True)
        t1.start()
        t1.join()
        return self.get_list_of_pkts_cap()

    def run(self):
        print("\n")
        ut.print_pretty_message('Success', ' Poniendo interfaz WiFi en modo monitor ...', False, None)
        ut.put_if_monitor_mode(self.get_iface())

        if not os.path.exists(os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'WiFi')):
            os.makedirs(os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'WiFi'))
        self.sniff_WiFi_Packets()

        print("\n")
        ut.print_pretty_message('Success', ' Poniendo interfaz WiFi en modo managed ...', False, None)
        ut.put_if_managed_mode(self.get_iface())

'''def test():
    wifisniff = WiFiSniffer('wlp3s0f0', 0, 50, dot11.Dot11, [])
    wifisniff.run()

test()'''