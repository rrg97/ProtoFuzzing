import os
from datetime import datetime
import utils as ut
from scapy.sendrecv import AsyncSniffer
from scapy.utils import wrpcap


class Sniffer:

    def __init__(self, iface, num_of_pkts_to_cap, layer):
        """
        :param iface: Interfaz de red inalámbrica.
        :param num_of_pkts_to_cap: Número de paquetes a capturar.
        :param layer: Capa objetivo de los paquetes a capturar.
        list_of_pkts_cap: Lista con los paquetes capturados.
        """
        self.iface = iface
        self.pkts_captured = 0
        self.num_of_pkts_to_cap = num_of_pkts_to_cap
        self.layer = layer
        self.list_of_pkts_cap = []

    def handle_packets(self, packet):
        """
        Función que inspecciona la capa de cada paquete y si coincide con layer, lo guarda en
        la lista.
        :param packet: Paquete capturado.
        """
        if packet.haslayer(self.layer):
            ut.print_pretty_message('Success', ' Capturado paquete -> {}', True, packet.summary())
            self.pkts_captured += 1
            self.list_of_pkts_cap.append(packet)

    def start_packets_capture(self):
        """
        Si se ha especificado el número de paquetes, se inicia el Sniffer
        con el parámetro count.
        :return:
        """
        if self.num_of_pkts_to_cap is not None:
            t1 = AsyncSniffer(iface=self.iface, prn=self.handle_packets,
                              count=self.num_of_pkts_to_cap, store=1)
        else:
            t1 = AsyncSniffer(iface=self.iface, prn=self.handle_packets,
                              store=1)
        t1.start()
        t1.join()
        return self.list_of_pkts_cap
                
    def save_packet_in_directory(self, path_to_save, packet, i, *args):
        """
        Guarda un paquete en la ruta path_to_save.
        El nombre del paquete está formado por el string pcap, el número
        de paquete y la fecha.
        :param path_to_save: Ruta donde se guardan los paquetes.
        :param packet: Paquete a guardar.
        :param i: Número de paquete.
        :param args: Argumentos opcionales.
        """
        now = datetime.now()
        dt_string = now.strftime("%d%m%Y%H%M%S")
        pname = "pcap%d" % i + dt_string + ".pcap"

        if args:
            if not os.path.exists(os.path.join(path_to_save, args[0])):
                os.makedirs(os.path.join(path_to_save, args[0]))
            wrpcap(os.path.join(path_to_save, args[0], pname), packet)
        else:
            wrpcap(os.path.join(path_to_save, pname), packet)


