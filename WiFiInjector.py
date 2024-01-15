import logging
import utils as ut
from scapy.layers.dot11 import *
from scapy.sendrecv import *
import scapy2dict


class WiFiInjector:

    def __init__(self, protocol, host, iface, mut):
        self.protocol = protocol
        self.host = host
        self.dest_mac_addr = ut.get_mac_addr_by_ip(host)
        self.iface = iface
        self.ap_mac_addr = '22:22:22:22:22:22'
        self.mut = mut
        self.send_mutated_pkt = False
        self.mutate_entire_packet = True
        self.field_packets_dictionary = ut.get_packet_field_dict('WiFi')

    # Para enviar los paquetes hay que poner la interfaz en modo monitor y establecer el canal de la red.
    # Del resto de campos hay que cambiar las direcciones MAC, en este caso del dispositivo SUT: addr1, ya
    # que addr2 es el propio origen.addr3 es el BSSID
    # También se pueden definir diferentes tipos de inyección, dependiendo del tipo de paquete:
    # asociación, control, reasociación, etc.

    def create_beacon_packet(self, addr1):
        """
        Se crea un paquete Beacon con los valores del punto de acceso falso, el nombre del punto de acceso, etc.
        :param addr1: Dirección MAC de los equipos que recibirán los beacons. En el caso de que sea ff:ff:ff:ff:ff:ff,
        se envía tipo broadcast.
        :return: paquete Beacon
        """
        SSID = 'Test'
        if addr1 is None:
            dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=self.ap_mac_addr, addr3=self.ap_mac_addr)
        else:
            dot11 = Dot11(type=0, subtype=8, addr1=addr1, addr2=self.ap_mac_addr, addr3=self.ap_mac_addr)
        # beacon layer
        beacon = Dot11Beacon()
        # putting ssid in the frame
        ESSID = Dot11Elt(ID="SSID", info=SSID, len=len(SSID))
        # stack all the layers and add a RadioTap
        frame = RadioTap() / dot11 / beacon / ESSID

        return frame

    def create_probe_response_packet(self, source):
        """
        Función que crea un paquete Probe Response con unos valores determinados.
        :param source: Dirección MAC al que se contestará con este paquete.
        :return:Paquete Probe response.
        """
        dot11 = Dot11(type=0, subtype=5, addr1=source, addr2=self.ap_mac_addr, addr3=self.ap_mac_addr)
        probeResp = Dot11ProbeResp(cap=0x0114, beacon_interval=0x64, timestamp=12345)
        ssid = Dot11Elt(ID=0, len=len('Test'), info='Test')
        capability = Dot11Elt(ID=1, info='\x96\x18\x24\x30\x48\x60\x6c')
        ds = Dot11Elt(ID=3, len=1, info='\x01')
        frame = RadioTap() / dot11 / probeResp / ssid / capability / ds

        return frame

    def send_beacon_frame(self):
        """
        Función que envía un paquete Beacon.
        """
        frame = self.create_beacon_packet(None)
        sendp(frame, iface=self.iface, verbose=False)

    def recv_probe_requests(self, packet):
        """
        Función que comprueba si el paquete que ha llegado es Probe Request, y en ese caso
        o se responde con un Probe Response mutado o con uno sin mutar.
        :param packet:
        """
        if packet.type == 0 and packet.subtype == 4 and packet.addr2 == self.dest_mac_addr:
            if self.send_mutated_pkt:
                frame = self.create_probe_response_packet(packet.addr2)
                self.send_mutated_packet(frame)
                self.number_of_pkts_sent += 1
            else:
                self.send_probe_response(packet.addr2)
            packet.show()

    def send_probe_response(self, source):
        """
        Función que envía un paquete Probe Response.
        :param source: Dirección MAC del equipo al que se contesta.
        """
        frame = self.create_probe_response_packet(source)
        sendp(frame, iface=self.iface, verbose=False)

    def send_mutated_packet(self, packet):
        """
        Función que envía un paquete mutado entero o por un valor concreto.
        TODO: Hay que implementar la mutación por campos específicos.
        IMPORTANTE: Si se quiere probar esta clase, comentar todo el código
        de dentro del else, ya que si no va a dar error.

        :param packet: Paquete que se quiere mutar.
        """
        if self.mutate_entire_packet:
            packet = self.mut.return_single_packet_mutated(packet, False)
        else:
            pkt_dict = scapy2dict.to_dict(packet['Dot11'], strict=True)
            field_to_mut = self.field_packets_dictionary['Dot11'].pop(0)
            while 1:
                self.field_packets_dictionary['Dot11'].append(field_to_mut)
                if field_to_mut in pkt_dict['Dot11']:
                    break
                field_to_mut = self.field_packets_dictionary['Dot11'].pop(0)
            logging.info('Realizando mutación sobre el campo {}'.format(field_to_mut))
            ut.print_pretty_message('Success', ' Realizando mutación sobre el campo {}', True, field_to_mut)
            packet = self.mut.return_single_Dot11_packet_mutated_by_field(packet, field_to_mut)

        print('\n ########## Paquete mutado ##########')
        packet.show()
        ut.print_pretty_message('Success', ' Enviando paquete mutado... ({})', True,
                                time.strftime("%a, %d %b %Y %H:%M:%S"))
        logging.info('Enviando paquete mutado... ({})',
                     time.strftime("%a, %d %b %Y %H:%M:%S"))
        self.number_of_pkts_sent += 1
        sendp(packet, iface=self.iface, verbose=False)

    def run(self):
        """
        Función que inicia todo el proceso.
        En la fase 1 se envían paquetes Beacon mutados.
        En la fase 2 se envían Beacons válidos y se contestan los Probe Response
        del equipo que se quiere probar con Probe Responses.
        La idea es implementar más fases en el futuro, en las que se manden
        paquetes de Autenticación, Asociación, etc.

        IMPORTANTE: Si hubiera algún problema con airmon-ng y no se pusiera
        la tarjeta de red en modo managaed, probar a ejecutar el comando
        sudo service network-manager restart o lo correspondiente en la
        distribución de Linux empleada.
        """
        if not os.path.exists(os.path.join(ut.PATH_TO_SESSIONS, 'Injector', self.protocol)):
            os.makedirs(os.path.join(ut.PATH_TO_SESSIONS, 'Injector', self.protocol))

        ut.set_file_logger(os.path.join(ut.PATH_TO_SESSIONS, 'Injector', 'WiFi', ut.session_file_name))
        ut.put_if_monitor_mode(self.iface)
        self.iface = self.iface + 'mon'

        ### Fase 1: Se empiezan mandando paquetes de tipo Beacon mutados hasta que se haga CTRL-C.
        try:
            ut.print_pretty_message('Success', ' Mandando paquetes Beacon mutados ...', False, None)
            logging.info('Mandando paquetes Beacon mutados ...')
            while 1:
                frame = self.create_beacon_packet(self.dest_mac_addr)
                self.send_mutated_packet(frame)
        except KeyboardInterrupt:
            print('Se han enviado {} paquetes mutados en la fase 1.'.format(str(self.number_of_pkts_sent)))
            logging.info('Se han enviado {} paquetes mutados en la fase 1.'.format(str(self.number_of_pkts_sent)))
        finally:
            self.number_of_pkts_sent = 0

        ### Fase 2: Se envían paquetes Beacon válidos y mientras se capturan los Probe Request. Cada vez que se recibe
        ### Probe Req, se envía un Probe Response mutado.
        try:
            t = AsyncSniffer(iface=self.iface, prn=self.recv_probe_requests, store=0)
            t.start()
            while 1:
                self.send_beacon_frame()
        except KeyboardInterrupt:
            t.stop()
            print('Se han enviado {} paquetes mutados en la fase 2.'.format(str(self.number_of_pkts_sent)))
            logging.info('Se han enviado {} paquetes en la fase 2.'.format(str(self.number_of_pkts_sent)))
            self.number_of_pkts_sent = 0
        finally:
            ut.put_if_managed_mode(self.iface)


'''def test():
    mut_class = ut.get_class_from_string('WiFi' + 'Mutator' + '.' + 'WiFi' + 'Mutator')
    mut = mut_class('Dot11')

    wifi_inj = WiFiInjector('WiFi', '192.168.1.26', gma(), ut.get_mac_addr_by_ip('192.168.1.26'), '22:22:22:22:22:22',
                            'wlp3s0f0', mut)
    wifi_inj.run()


test()'''
