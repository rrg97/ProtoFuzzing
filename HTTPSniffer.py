import utils as ut
import multiprocessing
from traffic_generator import Traffic_Generator
from sniffer import Sniffer
from scapy.layers.http import *
from scapy.sendrecv import AsyncSniffer
import os
from scapy.utils import rdpcap


class HTTPSniffer(Sniffer):

    def __init__(self, iface, num_of_pkts_to_cap, layer):
        super(HTTPSniffer, self).__init__(iface, num_of_pkts_to_cap, layer)

    def sniff_HTTP_Packets(self):
        print("\n")
        ut.print_pretty_message('Success', ' Capturando paquetes HTTP ...', False, None)

        packets = self.start_packets_capture()

        print("\n")
        ut.print_pretty_message('Success', ' Capturados {} paquetes HTTP.', True, str(self.pkts_captured))
        print("\n")
        ut.print_pretty_message('Success', ' Guardando los paquetes en el directorio {} ...', True,
                                os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'HTTP'))
        j = 0

        if not os.path.exists(os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'HTTP', 'HTTPRequest')):
            os.makedirs(os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'HTTP', 'HTTPRequest'))

        if not os.path.exists(os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'HTTP', 'HTTPResponse')):
            os.makedirs(os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'HTTP', 'HTTPResponse'))

        for packet in packets:
            if packet.haslayer(HTTPRequest):
                method = str(packet['HTTP Request'].Method)[2:-1]
                if not os.path.exists(os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'HTTP', 'HTTPRequest', method)):
                    os.makedirs(os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'HTTP', 'HTTPRequest', method))
                self.save_packet_in_directory(os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'HTTP', 'HTTPRequest'), packet,
                                              j, method)
                j += 1
            if packet.haslayer(HTTPResponse):
                self.save_packet_in_directory(os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'HTTP', 'HTTPResponse'),
                                              packet, j)
                j += 1

        print("\n")
        ut.print_pretty_message('Success', ' Todos los paquetes se han guardado correctamente', False, None)
        self.pkts_captured = 0

    def handle_packets(self, packet):
        """
        Función que inspecciona la capa de cada paquete y si coincide con layer, lo guarda en
        la lista.
        :param packet: Paquete capturado.
        """
        if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            ut.print_pretty_message('Success', ' Capturado paquete -> {}', True, packet.summary())
            self.pkts_captured += 1
            self.list_of_pkts_cap.append(packet)

    def start_packets_capture(self):
        tg = Traffic_Generator()
        t = AsyncSniffer(iface=self.iface, prn=self.handle_packets, store=1)
        p1 = multiprocessing.Process(target=tg.generate_http_traffic2, args=())

        p1.start()
        t.start()
        p1.join()
        t.stop()

        return self.list_of_pkts_cap

    def run(self):
        if not os.path.exists(os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'HTTP')):
            os.makedirs(os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'HTTP'))
        self.sniff_HTTP_Packets()


'''def test():
    http_sniff = HTTPSniffer('wlp3s0f0', None, [HTTPRequest, HTTPResponse])
    http_sniff.run()'''
