import logging
from datetime import datetime

import pyfiglet
import os
import subprocess
import locale
import random
import colorama
import shutil
import string
import time
import ipaddress
import re
from scapy.layers.http import *

DIRNAME = os.path.abspath(os.getcwd())
COOL_BANNERS = ['slant', '3-d', '5lineoblique', \
                'alphabet', 'banner3-D', 'doh', 'isometric1', 'alligator', \
                'dotmatrix', 'bulbhead', 'standard', 'computer', 'chunky', 'shadow', \
                'whimsy', 'starwars', 'fuzzy', 'gradient', 'isometric2', 'alligator2']

PATH_TO_VALID_PACKETS_DIR = os.path.join(DIRNAME, 'paquetes_validos')
PATH_TO_MUTATED_PACKETS_DIR = os.path.join(DIRNAME, 'paquetes_mutados')
PATH_TO_SESSIONS = os.path.join(DIRNAME, 'sesiones')

LIST_OF_MQTT_PACKET_TYPES = ['Publish', 'Connack', 'Pingresp', 'Pingreq', 'Unsuback', \
                             'Unsubscribe', 'Suback', 'Subscribe', 'Pubcomp', 'Pubrel', 'Pubrec', 'Puback', \
                             'Disconnect', 'Connect']

LIST_OF_HTTP_PACKETS_TYPES = []

LIST_OF_HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS']
MQTT_DICT_FOR_MUTATE_SPEFICIC_FIELD = {
    'Connect': ['protolevel', 'usernameflag', 'passwordflag', 'willretainflag', 'willQOSflag', 'willflag', 'cleansess',
                'protoname', \
                'reserved', 'klive', 'clientId', \
                'username', 'password'],
    'Connack': ['sessPresentFlag', 'retcode'],
    'Publish': ['topic', 'msgid', 'value'],
    'Puback': ['msgid'],
    'Pubrec': ['msgid'],
    'Pubrel': ['msgid'],
    'Pubcomp': ['msgid'],
    'Subscribe': ['msgid', 'topics'],
    'Suback': ['msgid', 'retcode'],
    'Unsubscribe': ['msgid', 'topics'],
    'Unsuback': ['msgid'],
}

HTTP_DICT_FOR_MUTATE_SPECIFIC_FIELD = {
    'HTTPRequest': ['Method', 'Path', 'Http-Version'] + GENERAL_HEADERS + REQUEST_HEADERS +
                   COMMON_UNSTANDARD_GENERAL_HEADERS + COMMON_UNSTANDARD_REQUEST_HEADERS,
    'HTTPResponse': ['Http-Version', 'Status-Code', 'Reason-Phrase'] + GENERAL_HEADERS + RESPONSE_HEADERS +
                    COMMON_UNSTANDARD_GENERAL_HEADERS + COMMON_UNSTANDARD_RESPONSE_HEADERS
}

WIFI_DICT_FOR_MUTATED_SPECIFIC_FIELD = {
    'Beacon': ['timestamp', 'beacon_interval', 'cap'],
    'Disassociation': ['reason'],
    'Association Request': ['cap', 'listen_interval'],
    'Association Response': ['cap', 'status', 'AID'],
    'Reassociation Request': ['cap', 'listen_interval', 'current_AP'],
    'Reassociation Response': ['cap', 'status', 'AID'],
    'Probe Response': ['timestamp', 'beacon_interval', 'cap'],
    'Authentication': ['algo', 'seqnum', 'status'],
    'Deauthentification': ['reason']
}

dot11_subtypes = {
    0: {  # Management
        0: "Association Request",
        1: "Association Response",
        2: "Reassociation Request",
        3: "Reassociation Response",
        4: "Probe Request",
        5: "Probe Response",
        6: "Timing Advertisement",
        8: "Beacon",
        9: "ATIM",
        10: "Disassociation",
        11: "Authentication",
        12: "Deauthentification",
        13: "Action",
        14: "Action No Ack",
    },
    1: {  # Control
        4: "Beamforming Report Poll",
        5: "VHT NDP Announcement",
        6: "Control Frame Extension",
        7: "Control Wrapper",
        8: "Block Ack Request",
        9: "Block Ack",
        10: "PS-Poll",
        11: "RTS",
        12: "CTS",
        13: "Ack",
        14: "CF-End",
        15: "CF-End+CF-Ack",
    },
    2: {  # Data
        0: "Data",
        1: "Data+CF-Ack",
        2: "Data+CF-Poll",
        3: "Data+CF-Ack+CF-Poll",
        4: "Null (no data)",
        5: "CF-Ack (no data)",
        6: "CF-Poll (no data)",
        7: "CF-Ack+CF-Poll (no data)",
        8: "QoS Data",
        9: "QoS Data+CF-Ack",
        10: "QoS Data+CF-Poll",
        11: "QoS Data+CF-Ack+CF-Poll",
        12: "QoS Null (no data)",
        14: "QoS CF-Poll (no data)",
        15: "QoS CF-Ack+CF-Poll (no data)"
    },
    3: {  # Extension
        0: "DMG Beacon"
    }
}

session_file_name = "session_%s" % datetime.now().strftime("%d-%m-%Y-%H:%M:%S") + '.log'
TRANSPORT_PROTOCOLS = ['TCP', 'UDP']


def print_banner():
    """
    Imprime el banner de bienvenida de la herramienta.
    Escoge un estilo de banner aleatorio de COOL_BANNERS.
    Lo imprime centrado según las columnas de la consola.
    """
    f = pyfiglet.Figlet(font=random.choice(COOL_BANNERS))

    print(*[x.center(shutil.get_terminal_size().columns) for x in f.renderText("ProtoFuzzer").split("\n")], sep="\n")


def clear_screen():
    """
    Limpia la consola.
    """
    if os.name == 'posix':
        _ = os.system('clear')
    else:
        _ = os.system('cls')


def show_help():
    pass


def retrieve_ifaces():
    """
    Recupera las interfaces inalámbricas del equipo.
    :return: Lista de interfaces inalámbricas.
    """
    result = subprocess.check_output(["iwconfig"], shell=False, stderr=subprocess.STDOUT)
    # result = subprocess.check_output(["iwconfig"], shell=False)
    # print(result.stdout.readlines())

    # print(str(result, 'utf-8'))
    ifaces = re.findall(r'.*?\n*(wl\w+)  IEEE 802\.11.*?', str(result, 'utf-8'), re.DOTALL)

    return ifaces


def host_exists_and_responds(hostname):
    """
    Envía 2 pings al hostname.
    :param hostname: Dirección IP del equipo.
    :return: Retorna error si el resultado es != de 0.
    """
    command = ['ping', '-c', '2', hostname]

    return subprocess.call(command) == 0


def number_files_folder(directory):
    """
    Devuelve el número de archivos que contiene un directorio.
    :param directory: Ruta del directorio.
    :return: Número de archivos del directorio.
    """
    return (len([name for name in os.listdir(directory) if os.path.isfile(os.path.join(directory, name))]))


def get_system_locale_time():
    """
    Recupera los tiempos locales disponibles en el sistema.
    :return: Tiempos locales del sistema.
    """
    command = ['locale', '-a']
    subprocess_return = subprocess.run(command, stdout=subprocess.PIPE)

    return subprocess_return.stdout.decode('utf-8')


def set_spanish_locale_time():
    """
    Establece el tiempo local de España.
    """
    try:
        out = get_system_locale_time()
        list_of_locale = out.split('\n')

        locale_es = ''

        for item in list_of_locale:
            if "es_ES.utf8" in item:
                locale_es = item
                break
            elif "es_ES" in item:
                locale_es = item
                break

        if locale_es != '':
            locale.setlocale(locale.LC_TIME, locale_es)
    except Exception as e:
        print(e)


def print_pretty_message(type_message, message_content, has_format_value, *args):
    """
    Imprime un mensaje formateado dependiendo del tipo de mensaje que sea.
    :param type_message: Warning, Success, Error, Input.
    :param message_content: Contenido del mensaje a mostrar.
    :param has_format_value: True si trae parámetros a formatear dentro del str.
    :param args:Parámetros a formatear.
    """
    if type_message == 'Warning':
        if has_format_value:
            print('[' + colorama.Fore.YELLOW + '!' + colorama.Fore.WHITE + ']' + message_content.format(
                *args) + colorama.Fore.RESET)
        else:
            print('[' + colorama.Fore.YELLOW + '!' + colorama.Fore.WHITE + ']' + message_content + colorama.Fore.RESET)
    elif type_message == 'Success':
        if has_format_value:
            print('[' + colorama.Fore.GREEN + '+' + colorama.Fore.WHITE + ']' + message_content.format(
                *args) + colorama.Fore.RESET)
        else:
            print('[' + colorama.Fore.GREEN + '+' + colorama.Fore.WHITE + ']' + message_content + colorama.Fore.RESET)

    elif type_message == 'Input':
        if has_format_value:
            print('[' + colorama.Fore.BLUE + '*' + colorama.Fore.WHITE + ']' + message_content.format(
                *args) + colorama.Fore.RESET)
        else:
            print('[' + colorama.Fore.BLUE + '*' + colorama.Fore.WHITE + ']' + message_content + colorama.Fore.RESET)
    else:
        if has_format_value:
            print('[' + colorama.Fore.RED + '-' + colorama.Fore.WHITE + ']' + message_content.format(
                *args) + colorama.Fore.RESET)
        else:
            print('[' + colorama.Fore.RED + '-' + colorama.Fore.WHITE + ']' + message_content + colorama.Fore.RESET)


def return_mqtt_int_type_to_str_type(packet_type):
    """
    Devuelve el tipo de paquete como str equivalente al número pasado.
    :param packet_type: Tipo de paquete como int.
    :return: String del tipo de paquete.
    """
    msg_type = ''
    if (packet_type == 1):
        msg_type = 'Connect'
    elif (packet_type == 2):
        msg_type = 'Connack'
    elif (packet_type == 3):
        msg_type = 'Publish'
    elif (packet_type == 4):
        msg_type = 'Puback'
    elif (packet_type == 5):
        msg_type = 'Pubrec'
    elif (packet_type == 6):
        msg_type = 'Pubrel'
    elif (packet_type == 7):
        msg_type = 'Pubcomp'
    elif (packet_type == 8):
        msg_type = 'Subscribe'
    elif (packet_type == 9):
        msg_type = 'Suback'
    elif (packet_type == 10):
        msg_type = 'Unsubscribe'
    elif (packet_type == 11):
        msg_type = 'Unsuback'
    elif (packet_type == 12):
        msg_type = 'Pingreq'
    elif (packet_type == 13):
        msg_type = 'Pingresp'
    elif (packet_type == 14):
        msg_type = 'Disconnect'
    return msg_type


def return_mqtt_str_to_int_type(packet_type):
    """
    Devuelve el número equivalente al tipo de paquete pasado.
    :param packet_type: Tipo de paquete MQTT como str.
    :return: Número equivalente al tipo escrito.
    """
    msg_type = ''
    if (packet_type == 'Connect'):
        msg_type = '1'
    elif (packet_type == 'Connack'):
        msg_type = '2'
    elif (packet_type == 'Publish'):
        msg_type = '3'
    elif (packet_type == 'Puback'):
        msg_type = '4'
    elif (packet_type == 'Pubrec'):
        msg_type = '5'
    elif (packet_type == 'Pubrel'):
        msg_type = '6'
    elif (packet_type == 'Pubcomp'):
        msg_type = '7'
    elif (packet_type == 'Subscribe'):
        msg_type = '8'
    elif (packet_type == 'Suback'):
        msg_type = '9'
    elif (packet_type == 'Unsubscribe'):
        msg_type = '10'
    elif (packet_type == 'Unsuback'):
        msg_type = '11'
    elif (packet_type == 'Pingreq'):
        msg_type = '12'
    elif (packet_type == 'Pingresp'):
        msg_type = '13'
    elif (packet_type == 'Disconnect'):
        msg_type = '14'
    return msg_type


def set_ip_forwarding():
    """
    Activa la opción ip_forwarding.
    """
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")


def reset_ip_forwarding():
    """
    Desactiva la opción ip_forwarding.
    """
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")


def get_random_string(length):
    """
    Devuelve una secuencia de caracteres aleatoria de la longitug length pasada.
    :param length: Longitud de caracteres deseada.
    :return: Str aleatorio.
    """
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))

    return result_str


def put_if_monitor_mode(iface):
    """
    Pone la interfaz pasada en modo monitor.
    :param iface: Interfaz de red inalámbrica como str.
    """
    command = ['airmon-ng', 'start', iface]

    subprocess.run(command)


def put_if_managed_mode(iface):
    """
    Pone la interfaz pasada en modo managed.
    :param iface: Interfaz de red inalámbrica como str.
    """
    command = ['airmon-ng', 'stop', iface]

    subprocess.run(command)


def get_mac_addr_by_ip(ip):
    """
    Retorna la MAC dada la IP.
    :param ip: Dirección ip como str.
    """
    p1 = subprocess.Popen(['ping', ip, '-c1'], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    out, err = p1.communicate()
    # arp list
    p2 = subprocess.Popen(['arp', '-n'], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
    out, err = p2.communicate()
    mac = re.findall('.*?' + ip + '.*?ether.*?(\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}).*?', str(out, 'utf-8'), re.DOTALL)
    return mac[0]


def get_connected_ap_mac_addr():
    """
    Saca por pantalla la MAC del AP con el que se tiene establecida una conexión.
    """
    cmd = ["nmcli -f BSSID,ACTIVE dev wifi list | awk '$2 ~ /sí/ {print $1}'"]
    address = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (out, err) = address.communicate()
    print(out)


def return_execution_elapsed_time(start_time, end_time):
    """
    Retorna el tiempo de ejecución dado el tiempo de inicio y de fin.
    :param start_time: Tiempo de inicio como float.
    :param end_time: Tiempo de fin como float.
    :return: Str formateado con tiempo total de ejecución.
    """
    days = 0
    elapsed_time = start_time - end_time

    if elapsed_time >= 86400:
        days = int(elapsed_time / 86400)
    elapsed = time.strftime("%H:%M:%S", time.gmtime(time.time() - start_time))
    if days == 0:
        return '\n' + f"Tiempo total de ejecución: {elapsed}"
    else:
        return '\n' + f"Tiempo total de ejecución: {days}:{elapsed}"


def get_class_from_string(import_path):
    """
    Devuelve la clase dada una ruta de importación separada por puntos.
    :param import_path: Ruta de importación como str.
    :return: str de la clase.
    """
    components = import_path.split('.')
    mod = __import__(components[0])
    for comp in components[1:]:
        mod = getattr(mod, comp)
    return mod


def get_prot_layer_from_string(protocol):
    """
    Función que devuelve la ruta hasta la capa que representa al protocolo en cuestión.
    :param protocol: Protocolo pasado como str.
    :return: Ruta hasta la capa del protocolo como str.
    """
    dict_prot_layers = {
        'MQTT': 'scapy.contrib.mqtt.MQTT',
        'HTTP': 'scapy.layers.http.HTTPRequest',
        'WiFi': 'scapy.layers.dot11.Dot11'
    }

    return get_class_from_string(dict_prot_layers[protocol])


def is_valid_ipv4(ip):
    """
    Función que devuelve True si una dirección IPv4 es correcta y False en caso contrario.
    :param ip: Dirección IP como str.
    :return: True o False.
    """
    try:
        ipaddress.IPv4Network(ip)
        return True
    except ValueError:
        return False


def set_file_logger(path):
    """
    Función que establece un logger para redireccionar la salida a un fichero .log que se pasa.
    :param path: La ruta al archivo .log que se va a usar para ir guardando la salida.
    """
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                        datefmt='%d-%m-%Y %H:%M:%S',
                        filename=path,
                        filemode='a')


def get_packet_field_dict(protocol):
    """
    Dado un protocolo se devuelve un diccionario con los campos que tiene para mutar.
    :param protocol: Protocolo del que se quiere recuperar el diccionario de campos.
    :return: Diccionario con los campos del paquete del protocolo pasado.
    """
    if protocol == 'MQTT':
        return MQTT_DICT_FOR_MUTATE_SPEFICIC_FIELD
    elif protocol == 'HTTP':
        return HTTP_DICT_FOR_MUTATE_SPECIFIC_FIELD
    elif protocol == 'WiFi':
        return WIFI_DICT_FOR_MUTATED_SPECIFIC_FIELD


def get_dot11_frame_type(type, subtype):
    return dot11_subtypes[type][subtype]


def convert_ipv4_to_ipv6(ipv4):
    return ipaddress.IPv6Address('2002::' + ipv4).compressed
