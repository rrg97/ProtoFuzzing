from scapy.layers.http import *
from scapy.layers.inet import *
import utils as ut
import multiprocessing
import logging
import time
from scapy2dict import to_dict
import subprocess
from scapy.contrib.mqtt import *


class proxyFuzzer:
    def __init__(self, dest_port, dest_host, iface, mut, transport_prot, target_layer, bi_or_uni_fuzzing, protocol,
                 time_to_exec):
        """
        Constructor de la clase
        :param ipv4tables_rule: regla iptables para IPv4
        :param ipv6tables_rule: regla iptables para IPv6
        :param dest_port: puerto de destino de las comunicaciones
        :param dest_host: IP del equipo 1 de la comunicación
        :param iface: interfaz de red inalámbrica usada
        :param mut: objeto Mutator
        :param transport_prot: capa del protocolo de transporte usado
        :param target_layer: capa del protocolo usado
        :param bi_or_uni_fuzzing: fuzzing unidireccional o bidireccional
        :param protocol: protocolo usado
        :param time_to_exec: tiempo durante el que se ejecutará
        packets_forged: nº de paquete mutado que se envía
        mutate_packet: indica si se muta un paquete o no
        mutate_entire_pkt: indica si se muta el paquete entero
        field_packets_dictionary: diccionario con los campos de cada paquete del protocolo
        """
        self.dest_port = dest_port
        self.dest_host = dest_host
        self.iface = iface
        self.mut = mut
        self.transport_prot = transport_prot
        self.target_layer = target_layer
        self.bi_or_uni_fuzzing = bi_or_uni_fuzzing
        self.protocol = protocol
        self.time_to_exec = time_to_exec
        self.packets_forged = 0
        self.mutate_pkt = False
        self.mutate_entire_pkt = True
        self.field_packets_dictionary = ut.get_packet_field_dict(self.protocol)

    def set_ip_tables_rules(self, ipv4tables_rule, ipv6tables_rule):
        """
        Añade las reglas iptables de IPv4 e IPv6.
        """
        subprocess.check_output(ipv4tables_rule, shell=True, stderr=subprocess.STDOUT)
        subprocess.check_output(ipv6tables_rule, shell=True, stderr=subprocess.STDOUT)

    def reset_iptables_rules(self):
        """
        Resetea las reglas iptables de IPv4 e IPv6
        """
        subprocess.check_output("iptables -F", shell=True, stderr=subprocess.STDOUT)
        subprocess.check_output("ip6tables -F", shell=True, stderr=subprocess.STDOUT)

    def packet_modify(self, packet):
        """
        Recibe los paquetes de NetFilterQueue y realiza o no mutación.
        Finalmente reenvía el paquete recibido con o sin modificaciones.
        :param packet: Paquete que llega a la cola de NetFilterQueue
        """
        pkt = IP(packet.get_payload())
        if pkt.haslayer(self.target_layer):
            field_to_mut = None
            if self.mutate_pkt:
                logging.info('Paquete sin mutar: ' + str(pkt.payload))
                packet_fuzz = self.mutate_packet(pkt, field_to_mut)

                packet.set_payload(bytes(packet_fuzz))
                logging.info('Paquete mutado: ' + str(packet_fuzz.payload))
                print("\n")
                logging.info('Mandando paquete ...')

                self.packets_forged += 1
                ut.print_pretty_message('Success', ' Mandando paquete mutado nº {}', True, self.packets_forged)
                self.mutate_pkt = False
            else:
                ut.print_pretty_message('Success', ' Mandando paquete sin mutar ...', False, None)
                self.mutate_pkt = True
        packet.accept()

    def packet_modify_MQTT(self, packet):
        """
            Recibe los paquetes MQTT de NetFilterQueue y realiza o no mutación.
            Finalmente reenvía el paquete recibido con o sin modificaciones.
            :param packet: Paquete que llega a la cola de NetFilterQueue
        """
        pkt = IP(packet.get_payload())
        if pkt.haslayer(self.target_layer):
            p_type = ut.return_mqtt_int_type_to_str_type(pkt['MQTT'].type)
            field_to_mut = None
            if self.mutate_pkt:
                if p_type != 'Disconnect' and not self.mutate_entire_pkt:
                    field_to_mut = self.field_packets_dictionary[p_type].pop(0)
                    self.field_packets_dictionary[p_type].append(field_to_mut)

                logging.info('Paquete sin mutar: ' + str(pkt.payload))
                packet_fuzz = self.mutate_packet(pkt, field_to_mut)

                packet.set_payload(bytes(packet_fuzz))
                logging.info('Paquete mutado: ' + str(packet_fuzz.payload))
                print("\n")
                logging.info('Mandando paquete ...')

                self.packets_forged += 1
                ut.print_pretty_message('Success', ' Mandando paquete mutado nº {}', True, self.packets_forged)
                self.mutate_pkt = False
            else:
                ut.print_pretty_message('Success', ' Mandando paquete {} sin mutar ...', True, p_type)
                self.mutate_pkt = True
        packet.accept()

    def packet_modify_HTTP(self, packet):
        """
        Recibe los paquetes HTTP de NetFilterQueue y realiza o no mutación.
        Finalmente reenvía el paquete recibido con o sin modificaciones.
        :param packet: Paquete que llega a la cola de NetFilterQueue
        """
        pkt = IP(packet.get_payload())
        if pkt.haslayer(self.target_layer):
            if self.mutate_pkt:
                if pkt.haslayer(HTTPRequest):
                    pkt_dict = to_dict(pkt['HTTPRequest'], strict=True)
                    field_to_mut = self.field_packets_dictionary['HTTPRequest'].pop(0)
                    while 1:
                        self.field_packets_dictionary['HTTPRequest'].append(field_to_mut)
                        if field_to_mut in pkt_dict['HTTP Request']:
                            break
                        field_to_mut = self.field_packets_dictionary['HTTPRequest'].pop(0)
                else:
                    pkt_dict = to_dict(pkt['HTTPResponse'], strict=True)
                    field_to_mut = self.field_packets_dictionary['HTTPResponse'].pop(0)
                    while 1:
                        self.field_packets_dictionary['HTTPResponse'].append(field_to_mut)
                        if field_to_mut in pkt_dict['HTTP Response']:
                            break
                        field_to_mut = self.field_packets_dictionary['HTTPResponse'].pop(0)

                logging.info('Paquete sin mutar: ' + str(pkt.payload))
                packet_fuzz = self.mutate_packet(pkt, field_to_mut)

                packet.set_payload(bytes(packet_fuzz))
                logging.info('Paquete mutado: ' + str(packet_fuzz.payload))
                print("\n")
                logging.info('Mandando paquete ...')

                self.packets_forged += 1
                ut.print_pretty_message('Success', ' Mandando paquete mutado nº {}', True, self.packets_forged)
                self.mutate_pkt = False
            else:
                ut.print_pretty_message('Success', ' Mandando paquete HTTP sin mutar ...', False, None)
                self.mutate_pkt = True

        packet.accept()

    def mutate_packet(self, packet, field):
        """
        Devuelve un paquete mutado entero, con una capa mutada o con un campo mutado.
        :param packet: Paquete Scapy que se quiere mutar.
        :param field: Campo que será != None si el paquete no es Disconnect y que sirve para indicar qué campo se muta.
        :return: Paquete mutado.
        """
        if self.mutate_entire_pkt:
            packet = self.mut.return_single_packet_mutated(packet, True)
            self.mutate_entire_pkt = False
        else:
            if field is not None:
                packet = self.mut.return_single_packet_mutated_by_field(packet, field, True)
            else:
                packet = self.mut.return_single_packet_mutated_by_field(packet, None, True)
            self.mutate_entire_pkt = True

        return packet

    def intercept_packets(self, start_exec_time):
        """
        Crea una cola NetFilter, la asocia a la función packet_modify y lo inicia.
        Función que intercepta los paquetes según las iptables definidas.
        :param start_exec_time: Tiempo inicial desde el que se empieza a contar la ejecución.
        """
        try:
            from netfilterqueue import NetfilterQueue
            nfqueue = NetfilterQueue()

            if self.protocol == 'MQTT':
                nfqueue.bind(1, self.packet_modify_MQTT)
            elif self.protocol == 'HTTP':
                nfqueue.bind(1, self.packet_modify_HTTP)

            print("\n")
            logging.info('Empezando la captura y modificación de paquetes ...')
            ut.print_pretty_message('Success',
                                    ' Empezando la captura y modificación de paquetes ...\n(Ctrl+C para abortar)',
                                    False, None)

            start_exec_time.value = time.time()
            nfqueue.run()

        except KeyboardInterrupt:
            pass

    def run(self, client):
        """
        Lanza los arpspoofers según la opción bi_or_uni_fuzzing.
        Si se ha definido time_to_exec como != 0, se hace un join para que termine
        en ese tiempo (en segundos). Después se necesita matar al arpspoofer con wmctrl, ya que no se ha encontrado
        otra manera más simple de hacerlo.
        Si time_to_exec es 0, se hace un join sin tiempo definido y el arpspoofer se para inmediatamente
        después de este thread.

        :param client: Dirección IP del cliente.

        TODO: Para el modo 2 de bi_or_uni_fuzzing habría que definir otras reglas iptables
            y una cola NetFilterQueue distinta, definiendo --queue-num igual a 2. Se puede hacer usando la misma cola,
            pero funcionaría más lento.
        """
        try:
            if not os.path.exists(os.path.join(ut.PATH_TO_SESSIONS, 'ProxyFuzzer', self.protocol)):
                os.makedirs(os.path.join(ut.PATH_TO_SESSIONS, 'ProxyFuzzer', self.protocol))

            ut.set_file_logger(os.path.join(ut.PATH_TO_SESSIONS, 'ProxyFuzzer', self.protocol, ut.session_file_name))
            start_exec_time = multiprocessing.Value('d', 0.0)

            if self.bi_or_uni_fuzzing == 1:
                cmd2 = ' arpspoof -i ' + self.iface + ' -t ' + self.dest_host + ' ' + client
                p2 = subprocess.Popen('xterm' + ' -e ' + cmd2, shell=True)
                self.set_ip_tables_rules('iptables -A FORWARD -j NFQUEUE -p ' + self.transport_prot + ' -d ' + client
                                         + ' --queue-num 1',
                                         'ip6tables -A FORWARD -j NFQUEUE -p ' + self.transport_prot + ' -d '
                                         + ut.convert_ipv4_to_ipv6(client) + ' --queue-num 1')

            if self.bi_or_uni_fuzzing == 0:
                cmd3 = ' arpspoof -i ' + self.iface + ' -t ' + client + ' ' + self.dest_host
                p3 = subprocess.Popen('xterm' + ' -e ' + cmd3, shell=True)
                self.set_ip_tables_rules('iptables -A FORWARD -j NFQUEUE -p ' + self.transport_prot + ' -d '
                                         + self.dest_host + ' --queue-num 1',
                                         'ip6tables -A FORWARD -j NFQUEUE -p ' + self.transport_prot + ' -d '
                                         + ut.convert_ipv4_to_ipv6(self.dest_host) + ' --queue-num 1')

            if self.bi_or_uni_fuzzing == 2:
                cmd2 = ' arpspoof -i ' + self.iface + ' -t ' + self.dest_host + ' ' + client
                p2 = subprocess.Popen('xterm' + ' -e ' + cmd2, shell=True)
                cmd3 = ' arpspoof -i ' + self.iface + ' -t ' + client + ' ' + self.dest_host
                p3 = subprocess.Popen('xterm' + ' -e ' + cmd3, shell=True)

            p1 = multiprocessing.Process(target=self.intercept_packets, args=(start_exec_time,))
            p1.start()
            if self.time_to_exec != 0:
                p1.join(self.time_to_exec)
                p1.terminate()
                os.system("wmctrl -lp | awk '/arpspoof/{print $3}' | xargs kill")
            else:
                p1.join()

        except KeyboardInterrupt:
            p1.terminate()
        finally:
            print(ut.return_execution_elapsed_time(start_exec_time.value, time.time()))
            logging.info(ut.return_execution_elapsed_time(start_exec_time.value, time.time()))
            ut.print_pretty_message('Success', ' Reseteando iptables ...', False, None)
            self.reset_iptables_rules()
            ut.print_pretty_message('Success', ' Desactivando ip_forwarding ...', False, None)
            ut.reset_ip_forwarding()


'''def test():
    protocol = 'MQTT'
    mut_class = ut.get_class_from_string(protocol + 'Mutator' + '.' + protocol + 'Mutator')
    mut = mut_class(protocol, None, None)
    layer = ut.get_prot_layer_from_string(protocol)
    pf = proxyFuzzer("iptables -A FORWARD -j NFQUEUE -p tcp -d 192.168.1.232 --queue-num 1",
                     "ip6tables -A FORWARD -j NFQUEUE -p tcp -d 0:0:0:0:0:FFFF:C0A8:01E8 --queue-num 1",
                     1883, '192.168.1.226', 'wlp3s0f0', mut, 'TCP', layer, 1, protocol, 0)

    print("\n")
    ut.print_pretty_message('Success', ' Activando IP forwarding ...', False, None)
    ut.set_ip_forwarding()

    print("\n")
    ut.print_pretty_message('Success', ' Aplicando reglas iptables ...', False, None)
    pf.set_ip_tables_rules()

    pf.run('192.168.1.232')


test()'''
