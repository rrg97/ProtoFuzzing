import multiprocessing
import os

from scapy.contrib.mqtt import *
import utils as ut
from sniffer import Sniffer
from traffic_generator import Traffic_Generator
from scapy.sendrecv import AsyncSniffer


class MQTTSniffer(Sniffer):

    def __init__(self, iface, num_of_pkts_to_cap, layer):
        super(MQTTSniffer, self).__init__(iface, num_of_pkts_to_cap, layer)

    def sniff_MQTT_Packets(self):
        """
        Captura paquetes MQTT usando el TrafficGenerator y un bróker público MQTT.
        Una vez capturados los guarda en las carpetas correspondientes.

        TODO: Implementar opción de capturar un número específico de paquetes,
            pasado por el usuario en el atributo num_of_pkts_to_cap
        """
        i = 0
        print("\n")
        ut.print_pretty_message('Success', ' Empezando captura número {}...', True, str(i + 1))

        while i < 5:
            if i > 0:
                print("\n")
                ut.print_pretty_message('Success', ' Empezando captura número {}...', True, str(i))

            print("\n")
            ut.print_pretty_message('Success', ' Capturando paquetes MQTT ...', False, None)
            packets = self.start_packets_capture()

            print("\n")
            ut.print_pretty_message('Success', ' Capturados {} paquetes MQTT.', True, str(self.pkts_captured))
            print("\n")
            ut.print_pretty_message('Success', ' Guardando los paquetes en el directorio {} ...', True,
                                    os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'MQTT'))

            j = 0

            for packet in packets:
                p_type = ut.return_mqtt_int_type_to_str_type(packet['MQTT'].type)
                self.save_packet_in_directory(os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'MQTT'), packet, j, p_type)
                j += 1
            print("\n")
            ut.print_pretty_message('Success', ' Todos los paquetes se han guardado correctamente', False, None)

            i += 1

            self.pkts_captured = 0

    def start_packets_capture(self):
        """
        Inicia un sniffer asíncrono como un hilo y ejecuta en otro hilo el generador de tráfico.
        :return: Lista con los paquetes MQTT capturados.
        """
        tg = Traffic_Generator()
        t = AsyncSniffer(iface=self.iface, prn=self.handle_packets, store=1)

        p1 = multiprocessing.Process(target=tg.generate_mqtt_traffic, args=())
        p1.start()
        t.start()
        p1.join()
        t.stop()

        return self.list_of_pkts_cap

    def run(self):
        """
        Crea las carpetas necesarias en caso de que no existan.
        Empieza la captura de paquetes MQTT.
        """
        if not os.path.exists(os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'MQTT')):
            os.makedirs(os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, 'MQTT'))
        self.sniff_MQTT_Packets()
