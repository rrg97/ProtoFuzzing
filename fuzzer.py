import time
import utils as ut
import sys
import os
from sniffer import Sniffer
from mutator import Mutator
from injector import Injector
import importlib
from proxy_fuzzer import proxyFuzzer


class Fuzzer:
    def __init__(self):
        """
        supported_protocols: Protocolos soportados por la herramienta.
        """
        self.__supported_protocols = ['MQTT', 'HTTP', 'WiFi']

    def get_supported_protocols(self):
        return self.__supported_protocols

    def is_protocol_supported(self, protocol):
        return protocol in self.__supported_protocols

    def run(self):
        """
        Imprime el banner de bienvenida
        Pide los datos necesarios para empezar a hacer fuzzing:
        - Protocolo
        - Interfaz de red
        - Puerto
        - Equipo o equipos a mutar
        - Modo de funcionamiento
        - Protocolo de transporte a utilizar
        - Tiempo durante el que se realizará fuzzing

        En el caso de que se elija el protocolo WiFi, se procederá de manera diferente, ya que
        se trata de un protocolo a nivel de enlace, por lo que no se pueden usar los modos usados
        para los protocolos de nivel de aplicación. Sin embargo, se accederá solamente desde el modo Injector,
        aunque no herede de la clase Injector.

        Ejecuta Sniffer, Mutator, Injector y ProxyFuzzer según sea elegido por el usuario.
        """
        print('\n ###### Protocolos soportados ###### ')
        print('\n\t -> ' + '\n\t -> '.join(self.get_supported_protocols()))

        print("\n")
        ut.print_pretty_message('Input', ' Escoja el protocolo sobre el que desea realizar fuzzing:', False, None)

        protocol = input()
        while not self.is_protocol_supported(protocol):
            print("\n")
            ut.print_pretty_message('Warning', ' El protocolo que ha elegido no está soportado por el fuzzer', False,
                                    None)
            print("\n")
            ut.print_pretty_message('Input', ' Escoja de nuevo el protocolo sobre el que desea realizar fuzzing:',
                                    False, None)
            protocol = input()

        port = -1
        while not (0 <= port <= 65353):
            try:
                print("\n")
                ut.print_pretty_message('Input', ' Introduzca el puerto que se va a emplear durante el test [0, '
                                                 '65353]: ', False,
                                        None)
                port = int(input())
            except ValueError:
                print("\n")
                ut.print_pretty_message('Warning', ' Introduzca valores enteros.', False, None)

        list_of_ifaces = ut.retrieve_ifaces()

        print('\n ###### Interfaces inalámbricas del sistema ###### ')
        print('\n\t -> ' + '\n\t -> '.join(list_of_ifaces))

        print("\n")
        ut.print_pretty_message('Input', ' Elija una de estas interfaces de red para completar el proceso de fuzzing: ',
                                False,
                                None)
        iface = input()
        while iface not in list_of_ifaces:
            print("\n")
            ut.print_pretty_message('Warning', ' Interfaz no correcta.', False, None)
            print("\n")
            ut.print_pretty_message('Input',
                                    ' Elija una de las interfaces listadas arriba: ', False,
                                    None)
            iface = input()

        fuzzer_mode = 0
        while not (fuzzer_mode == 1 or fuzzer_mode == 2):
            try:
                print("\n")
                ut.print_pretty_message('Input',
                                        ' Introduzca el modo de fuzzer a usar: 1. Proxy Fuzzer | 2. Injector Fuzzer :',
                                        False,
                                        None)
                fuzzer_mode = int(input())
            except ValueError:
                print("\n")
                ut.print_pretty_message('Warning', ' Solo se permiten valores enteros.', False, None)

        if fuzzer_mode == 2:
            if not os.path.exists(os.path.join(ut.PATH_TO_SESSIONS, 'Injector')):
                os.makedirs(os.path.join(ut.PATH_TO_SESSIONS, 'Injector'))

            if protocol == 'WiFi':
                print("\n")
                ut.print_pretty_message('Input',
                                        ' Inserte la dirección del equipo al que desea hacer fuzzing: ',
                                        False,
                                        None)

                hostname = input()

                while not ut.is_valid_ipv4(hostname):
                    ut.print_pretty_message('Warning', ' Introduzca una dirección IP correcta.', False, None)

                    print("\n")
                    ut.print_pretty_message('Input',
                                            ' Inserte de nuevo la dirección del equipo al que desea hacer fuzzing: ',
                                            False,
                                            None)
                    hostname = input()
                from WiFiInjector import WiFiInjector
                mut_class = ut.get_class_from_string('WiFi' + 'Mutator' + '.' + 'WiFi' + 'Mutator')
                mut = mut_class('Dot11')
                wifi_inj = WiFiInjector('WiFi', hostname, iface, mut)
                wifi_inj.run()
            else:
                respuesta = ''
                while not (respuesta == 'S' or respuesta == 'N' or respuesta == 's' or respuesta == 'n'):
                    print("\n")
                    ut.print_pretty_message('Input',
                                            ' ¿Desea realizar captura de paquetes? (S/N): ',
                                            False,
                                            None)
                    respuesta = input()
                repetir_captura = (respuesta == 'S' or respuesta == 's')

                if repetir_captura:
                    ut.print_pretty_message('Success', ' Empezando el proceso de captura de paquetes ... ({})', True,
                                            time.strftime("%a, %d %b %Y %H:%M:%S"))

                    sniff_class = ut.get_class_from_string(protocol + 'Sniffer' + '.' + protocol + 'Sniffer')
                    layer = ut.get_prot_layer_from_string(protocol)
                    sniffer = sniff_class(iface, None, layer)
                    sniffer.run()

                print('\n')
                ut.print_pretty_message('Success', ' Empezando el proceso de mutación ... ({})', True,
                                        time.strftime("%a, %d %b %Y %H:%M:%S"))

                mut_class = ut.get_class_from_string(protocol + 'Mutator' + '.' + protocol + 'Mutator')
                mutator = mut_class(protocol, os.path.join(ut.PATH_TO_VALID_PACKETS_DIR, protocol),
                                    os.path.join(ut.PATH_TO_MUTATED_PACKETS_DIR, protocol))
                mutator.mutate_packets()

                time.sleep(1)
                print('\n')
                ut.print_pretty_message('Success', ' Proceso de mutación completado ... ({})', True,
                                        time.strftime("%a, %d %b %Y %H:%M:%S"))
                time.sleep(1)
                print('\n')

                print("\n")
                ut.print_pretty_message('Input',
                                        ' Inserte la dirección del equipo al que desea hacer fuzzing: ',
                                        False,
                                        None)

                hostname = input()

                while not ut.is_valid_ipv4(hostname):
                    ut.print_pretty_message('Warning', ' Introduzca una dirección IP correcta.', False, None)

                    print("\n")
                    ut.print_pretty_message('Input',
                                            ' Inserte de nuevo la dirección del equipo al que desea hacer fuzzing: ',
                                            False,
                                            None)
                    hostname = input()

                ut.print_pretty_message('Success', ' Empezando el proceso de envío de paquetes mutados ... ({})', True,
                                        time.strftime("%a, %d %b %Y %H:%M:%S"))

                inj_class = ut.get_class_from_string(protocol + 'Injector' + '.' + protocol + 'Injector')
                inj = inj_class(protocol, hostname, port)
                inj.run()

        elif fuzzer_mode == 1:
            if not os.path.exists(os.path.join(ut.PATH_TO_SESSIONS, 'ProxyFuzzer')):
                os.makedirs(os.path.join(ut.PATH_TO_SESSIONS, 'ProxyFuzzer'))

            print("\n")
            ut.print_pretty_message('Input',
                                    ' Inserte la dirección del cliente {}: ',
                                    True,
                                    protocol)
            client = input()

            while not ut.is_valid_ipv4(client):
                ut.print_pretty_message('Warning', ' Introduzca una dirección IP correcta.', False, None)
                print("\n")
                ut.print_pretty_message('Input',
                                        ' Inserte de nuevo la dirección del cliente {}: ',
                                        True,
                                        protocol)
                client = input()
            print("\n")
            ut.print_pretty_message('Input',
                                    ' Inserte la dirección del servidor {}: ',
                                    True,
                                    protocol)
            server = input()
            while not ut.is_valid_ipv4(server):
                ut.print_pretty_message('Warning', ' Introduzca una dirección IP correcta.', False, None)
                print("\n")
                ut.print_pretty_message('Input',
                                        ' Inserte de nuevo la dirección del servidor {}: ',
                                        True,
                                        protocol)
                server = input()

            print('\n')
            ut.print_pretty_message('Input', 'Elija una de las tres opciones siguientes: ', False)
            fuzzing_bi_uni = -1
            while fuzzing_bi_uni < 0 or fuzzing_bi_uni > 2:
                try:
                    fuzzing_bi_uni = int(input(
                        '\n 0. Fuzzing a servidor ' + server + '\n 1. Fuzzing a cliente ' + client + '\n 2. Fuzzing a '
                                                                                                     'ambos'))
                except ValueError:
                    print("\n")
                    ut.print_pretty_message('Warning', ' Introduzca el valor 0, 1 ó 2.', False, None)

            print("\n")
            ut.print_pretty_message('Input', ' Escoja el protocolo de transporte que se va a usar: ', False, None)

            transport_prot = input()
            while transport_prot not in ut.TRANSPORT_PROTOCOLS:
                print("\n")
                ut.print_pretty_message('Warning', ' El protocolo que ha elegido no es correcto',
                                        False,
                                        None)
                print("\n")
                ut.print_pretty_message('Input', ' Escoja de nuevo el protocolo de transporte: ',
                                        False, None)
                transport_prot = input()

            while 1:
                try:
                    print("\n")
                    ut.print_pretty_message('Input',
                                            'Introduzca el tiempo en segundos durante el que desea que se realice (0 '
                                            'es indefinido) '
                                            'fuzzing: ',
                                            False,
                                            None)
                    time_to_exec = int(input())
                    break
                except ValueError:
                    print("\n")
                    ut.print_pretty_message('Warning', ' Introduzca valores enteros.', False, None)

            mut_class = ut.get_class_from_string(protocol + 'Mutator' + '.' + protocol + 'Mutator')
            mut = mut_class(protocol, None, None)
            layer = ut.get_prot_layer_from_string(protocol)
            pf = proxyFuzzer(port, server, iface, mut, transport_prot, layer, fuzzing_bi_uni, protocol, time_to_exec)

            print("\n")
            ut.print_pretty_message('Success', ' Activando IP forwarding ...', False, None)
            ut.set_ip_forwarding()

            print("\n")
            ut.print_pretty_message('Success', ' Aplicando reglas iptables ...', False, None)

            pf.run(client)


if __name__ == '__main__':
    try:
        ut.set_spanish_locale_time()
    except Exception as e:
        print(e)

    fuzzer = Fuzzer()
    print('\n\n')
    ut.print_banner()
    print('\n')
    time.sleep(1)

    fuzzer.run()
