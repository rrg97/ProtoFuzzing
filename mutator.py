from datetime import datetime
import subprocess
import random
import os
from scapy.contrib.mqtt import *
from scapy.utils import *
from scapy.layers.http import *
from scapy.layers.dot11 import *
from scapy.layers.inet import *
import pyradamsa
import utils as ut
import logging


class Mutator:

    def __init__(self, protocol):
        """
        :param protocol: protocolo de los paquetes a mutar.
        num_of_pkts_mutated: número de paquetes que se mutan al finalizar el proceso.
        """
        self.protocol = protocol
        self.num_of_pkts_mutated = 0

    '''def get_protocol(self):
        return self.__protocol'''

    '''def set_protocol(self, protocol):
        self.__protocol = protocol'''

    def save_mutated_packet(self, path_to_save, packet, i):
        """
        Recibe un paquete mutado y lo guarda en path_to_save.
        El nombre del paquete está formado por el string pcapfuzz, la fecha, el número de paquete actual y
        un número aleatorio entre 0 y 1000.
        :param path_to_save: ruta donde se guarda el paquete.
        :param packet: paquete a guardar
        :param i: número de paquete
        """
        rand_number = random.randint(0, 1000)
        now = datetime.now()
        dt_string = now.strftime("%d%m%Y%H%M%S")
        pname = "pcapfuzz%d%d" % (i, rand_number) + dt_string + ".pcap"

        wrpcap(os.path.join(path_to_save, pname), packet)
        self.num_of_pkts_mutated += 1

    def return_single_packet_mutated(self, packet, is_proxy_fuzzer_call):
        """
        Recibe un paquete sin mutar y lo devuelve mutado.
        Si se llama desde el modo proxy, se imprimen mensajes informativos y se borran
        campos de las capas IP y TCP.
        Está implementado un comportamiento muy parecido para los protocolos que usan TCP o UDP.
        En el caso de los paquetes WiFi es distinto, ya que las capas cambian y las longitudes de bytes
         también.
        Para los paquetes HTTPResponse no funcionaba bien el método usado para MQTT o HTTPRequest, por eso
        se ha puesto a parte, pero el resultado es el mismo.

        :param packet: paquete a devolver mutado
        :param is_proxy_fuzzer_call: indica si esta función se ha llamado desde el modo proxy
        :return: paquete mutado
        """
        if is_proxy_fuzzer_call:
            if self.protocol == 'MQTT':
                p_type = ut.return_mqtt_int_type_to_str_type(packet[self.protocol].type)
                print('\n Tipo de paquete: {}'.format(p_type))
                logging.info('\n Tipo de paquete: {}'.format(p_type))

            if packet.haslayer(HTTPRequest):
                method = str(packet['HTTP Request'].Method)[2:-1]
                print('\n Tipo de método: {}'.format(method))
                logging.info('\n Tipo de método: {}'.format(method))

            ut.print_pretty_message('Success', ' Realizando mutación sobre el paquete entero', False, None)
            logging.info('Realizando mutación sobre el paquete entero')

        if packet.haslayer(HTTPResponse):
            try:
                rad = pyradamsa.Radamsa()
                payload = rad.fuzz(bytes(packet[self.protocol]))
            except Exception as e:
                print(e)
        else:
            protocol_data = str(bytes(packet[self.protocol]))
            cmd = 'echo ' + protocol_data[1:] + '| radamsa'
            try:
                payload = subprocess.check_output(cmd, shell=True)
            except subprocess.CalledProcessError:
                rad = pyradamsa.Radamsa()
                payload = rad.fuzz(bytes(packet[self.protocol]))

        if is_proxy_fuzzer_call:
            packet[TCP].remove_payload()
            packet[TCP].add_payload(payload[0:65000])

            del packet[IP].id
            del packet[IP].chksum
            del packet[TCP].chksum
            del packet[IP].len
            print('\n ########## Paquete mutado ##########')
            packet.show()
        else:
            if packet.haslayer(TCP):
                new_pkt = Ether() / IP() / TCP(sport=1200, dport=5000) / Raw(load=payload[0:65000])
            elif packet.haslayer(UDP):
                new_pkt = Ether() / IP() / UDP(sport=1200, dport=5000) / Raw(load=payload[0:65000])
            elif packet.haslayer(Dot11):
                packet['Dot11'].remove_payload()
                new_pkt = RadioTap() / packet['Dot11'] / Raw(load=payload[0:1000])
            return new_pkt

        return packet

    def mutate_entire_packet(self, file_to_mutate, i, path_to_save):
        """
        Muta un paquete y después lo guarda en path_to_save
        :param file_to_mutate: Archivo con el paquete a mutar
        :param i: Número de paquete
        :param path_to_save: Ruta donde se guardará el paquete
        """
        new_packet = self.return_single_packet_mutated(file_to_mutate[0], False)
        self.save_mutated_packet(path_to_save, new_packet, i)
