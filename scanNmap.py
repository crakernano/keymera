import os
import sys
import time
import nmap3
import socket

from colorama import Fore, Style
from tabulate import tabulate


def os_scan(target,  nmap):
    resultados = nmap.nmap_os_detection(target)
    print(Fore.GREEN+"\t"+"-----------------------------------------")
    print(Fore.GREEN+"\t"+"|            DETECCION DE SO            |")
    print(Fore.GREEN+"\t"+"-----------------------------------------")
    print(Style.RESET_ALL)

    table = []

    for i in resultados:
        os = i["name"]
        certeza = i["accuracy"]
        row = [os, certeza]
        table.append(row)

    headers = ["SO", "CERTEZA (%)"]
    print(tabulate(table, headers, tablefmt="pretty"))


def version(target, nmap):
    nmap = nmap3.Nmap()
    resultados = nmap.nmap_version_detection(target)
    print(Fore.GREEN+"\t"+"-----------------------------------------")
    print(Fore.GREEN+"\t"+"|        DETECCION DE VERSIONES         |")
    print(Fore.GREEN+"\t"+"-----------------------------------------")
    print(Style.RESET_ALL)

    table = []

    for i in resultados:
        protocolo = i["protocol"]
        port = i["port"]
        state = i["state"]
        service = i["service"]

        for i in service.keys():

            if "product" in i:
                producto = service["product"]
            else:
                producto = ""

            if "name" in i:
                nombre = service["name"]

            else:
                nombre = ""

            if "version" in i:
                version = service["version"]

            else:
                version = ""

        row = [protocolo, port, state, producto, nombre, version]
        table.append(row)

    headers = ["PROTOCOLO",
               "PUERTO",
               "ESTADO",
               "PRODUCTO",
               "NOMBRE",
               "VERSIÓN"]

    print(tabulate(table, headers, tablefmt="pretty"))


def syn_scan(target, nmap):
    nmap = nmap3.NmapScanTechniques()
    resultados = nmap.nmap_syn_scan(target)

    resultados = resultados[target]
    table = []
    for i in resultados:
        protocolo = i['protocol']
        port = i['portid']
        state = i['state']
        service = i['service']

        for j in service.keys():
            if "name" in j:
                nombre = service['name']
            else:
                nombre = ""

            if "method" in j:
                metodo = service["method"]
            else:
                metodo = ""

            if "conf" in j:
                conf = service["conf"]
            else:
                conf = ""

        row = [protocolo, port, state, nombre, metodo, conf]
        table.append(row)

    headers = ["PROTOCOLO",
               "PUERTO",
               "ESTADO",
               "NOMBRE",
               "METODO",
               "CONFIGURACIÓN"]

    print(tabulate(table, headers, tablefmt="pretty"))


def ports(target, nmap):
    resultados = nmap.scan_top_ports(target)
    print(Fore.GREEN+"\t"+"---------------------------------------")
    print(Fore.GREEN+"\t"+"|        DETECCION DE PUERTOS         |")
    print(Fore.GREEN+"\t"+"---------------------------------------")
    print(Style.RESET_ALL)

    table = []
    for i in resultados[target]:
        protocolo = i["protocol"]
        puerto = i["portid"]
        estado = i["state"]
        servicio = i["service"]

        row = [protocolo, puerto, estado]
        table.append(row)

        for i in servicio.keys():
            if "name" in i:
                nombre = servicio["name"]

    headers = ["protocolo", "puerto", "estado"]
    print(tabulate(table, headers, tablefmt="pretty"))
    return table


def escanear(target):
    nmap = nmap3.Nmap()
    os_scan(target, nmap)


def host_discovery(target, nmap):
    resultados = nmap.nmap_no_portscan(target)
    hosts = resultados["hosts"]
    resultados = resultados['runtime']
    resumen = resultados['summary']

    print(Fore.YELLOW+resumen)

    for host in hosts:
        print(Fore.RED+"#"*50)
        print(Fore.RED+"#                 "+host["addr"]+" - "+host["state"]+"               #")
        print(Fore.RED+"#"*50)
        print(Style.RESET_ALL)

        escanear(host["addr"])
        puertos = ports(host["addr"], nmap)

        for i in puertos:
            if 22 in i:
                if "open" in i:
                    print("Intentando ataque de fuerza bruta por SSH")

        syn_scan(host["addr"], nmap)
        version(host["addr"], nmap)
        print("#"*50)
        print(Fore.YELLOW+" FIN DEL ANALISIS DE "+host["addr"])
        print(Style.RESET_ALL)
        print("#"*50)


def descubrir(target):
    nmap = nmap3.NmapHostDiscovery()
    host_discovery(target, nmap)


def nmap_fill_scan(target):
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        octetos = ip.split(".")
        ip = octetos[0]+"."+octetos[1]+"."+octetos[2]+"."+"1"

        print("Escaneando red..."+ip)
        time.sleep(1)
        descubrir(target)
        print("Fin del escaneo")

    except KeyboardInterrupt:
        print("Escaner Cancelado")
        sys.exit()
