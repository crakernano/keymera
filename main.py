import requests
import argparse
import socket
import subprocess
from os import path
import sys
import json
from bs4 import BeautifulSoup


def scanHeaders(target):
    try:
        url = requests.get(url=target)
        cabeceras = dict(url.headers)

        for cabecera in cabeceras:
            print(cabecera + " : " + cabeceras[cabecera])
    except:
        print("No se pudo establecer la cabecera")


def banner(ip, port):
    sk = socket.socket()
    sk.connect((ip, int(port)))
    print(str(sk.recv(1024)))


def scan_ports(target):
    ports = []
    for port in range(1, 65536):
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = sk.connect_ex((target, port))

        if result == 0:
            print(" Port %s OPEN" % port)
            ports.append(port)
        sk.close()

    return ports


def scan_subdomin():

    if path.exists('Subdominios.txt'):
        wordlist = open('Subdominios.txt', 'r')
        wordlist = wordlist.read().split('\n')
        for subdominio in wordlist:
            url = "http://" + subdominio + "." + parser.target
            try:
                requests.get(url)
            except requests.ConnectionError:
                pass
            else:
                print("- Subdominio descubierto " + url)

            for subdominio in wordlist:
                url = "https://" + subdominio + "." + parser.target
                try:
                    requests.get(url)
                except requests.ConnectionError:
                    pass
                else:
                    print("- Subdominio descubierto " + url)
    else:
        print("Subdominio no valido")


def scan_tecnology(target):
    subprocess.run("wad -u" + target + "> tecnologias.txt", shell=True)
    # parseado del resultado
    file = open("tecnologias.txt", "r")
    tecnologias = file.read()
    tecnologias = tecnologias.split("[")
    tecnologias = tecnologias[1].split("]")
    tecnologias = tecnologias[0]
    for tecnologia in tecnologias:
        nuevo = tecnologia.replace('\n', '')
        nuevo = nuevo.replace('     ', '')
        nuevo = nuevo.replace('"', '')
        nuevo = nuevo.replace("}", '')
        print(nuevo)
        print("-" * 50)


def scan_users(target):
    usuarios = []
    cabecera = {'Usert-Agent': 'Firefox'}
    peticion = requests.get(url=target + "/wp-json/wp/v2/users", headers=cabecera)

    binary = peticion.text
    output = json.loads(binary)

    for usuario in output:
        usuarios.append(usuario['slug'])
        print(usuario['slug'])

    return usuarios


def scan_worpress(target):
    cabecera = {'Usert-Agent': 'Firefox'}
    peticion = requests.get(url=target, headers=cabecera)
    soup = BeautifulSoup(peticion.text, "html.parser")
    version = 0
    for v in soup.find_all('meta'):
        print(v.get('name'))
        if v.get('name') == 'generator':
            version = v.get('content')


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-v", "--verbosity",
                        help="increase output verbosity")

    parser.add_argument("-t", "--target",
                        help="increase output verbosity")

    parser.add_argument("--headers",
                        action="store_true",
                        help="increase output verbosity")

    parser.add_argument("-p", "--port",
                        help="increase output verbosity")

    parser.add_argument("-b", "--banner",
                        action="store_true",
                        help="increase output verbosity")

    parser.add_argument("-sp", "--scan_ports",
                        action="store_true",
                        help="increase output verbosity")

    parser.add_argument("-ss", "--scan_subdomin",
                        action="store_true",
                        help="increase output verbosity")

    parser.add_argument("-st", "--scan_tecnology",
                        action="store_true",
                        help="increase output verbosity")

    parser.add_argument("-su", "--scan_users",
                        action="store_true",
                        help="increase output verbosity")

    parser.add_argument("-sw", "--scan_worpress",
                        action="store_true",
                        help="increase output verbosity")

    args = parser.parse_args()

    if args.verbosity:
        print("verbosity turned on")

    if args.headers:
        scanHeaders(args.target)

    if args.banner:
        banner(args.target, args.port)

    if args.scan_ports:
        scan_ports(args.target)

    if args.scan_subdomin:
        scan_subdomin(args.target)

    if args.scan_tecnology:
        scan_tecnology(args.target)

    if args.scan_users:
        scan_users(args.target)

    if args.scan_worpress:
        scan_worpress(args.target)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
