#!/usr/bin/python3

import os, re, subprocess
import requests, json
import pyfiglet
from pyfiglet import Figlet
from bs4 import BeautifulSoup
from progress.spinner import Spinner


red = "\033[1;31;49m"
yellow = "\033[1;33;49m"
black = "\033[1;30;49m"
white ="\033[1;37;49m"
ansi_escape_seq = re.compile(r'\x1b[^m]*m')
weak_protocols = ["SSLv1", "SSLv1.0", "SSLv2", "SSLv2.0", "SSLv3", "SSLv3.0", "TLSv1.0", "TLSv1.1"]

def nmap(host):
    flags = ["sudo", "nmap", host]
    inputs = input("What flags you want otherwise it's -Pn -sS -v: ")
    if not inputs:
        flags += ["-Pn", "-sS", "-v"]
    # nmap = subprocess.Popen(flags, stdout=subprocess.PIPE, universal_newlines=True)
    
    ports = []
    spinner = Spinner("Nmapping host...")
    """
    while True:
        spinner.next()
        line = nmap.stdout.readline()
        if line == "" and nmap.poll() is not None:
            break
        if line:
            if re.search("/.*open", line):
                ports.append(line.strip())
    """
    ports.append("4342/tr open fdsjfkldsfjkdsfj")
    lengths = [29, len(host) + 6, len(sorted(ports, key=len)[-1]) + 9]
    longest = sorted(lengths)[-1]
    
    open_ports = []
    print("\n\n+{dash}+\n|Host: {host}{space1}|\n+{dash}+\n|PORT{space2}STATE{space3}SERVICE{space4}|\n+{dash}+".format(host=host,space1=" "*(longest-len(host)-4),space2=" "*10,space3=" "*3,space4=" "*(longest-27),dash="-"*(longest+2)))
    for p in ports:
        items = p.split()
        service = " ".join(items[2:])
        print("|{port}{space1}{state}{space2}{service}{space3}|".format(port=items[0],space1=" "*(14-len(items[0])),state=items[1],space2=" "*(8-len(items[1])),service=service,space3=" "*(longest-len(service)-20)))
        open_ports.append(re.compile(r'/.*').sub('', items[0]))
    print("+{dash}+\n".format(dash="-"*(longest+2)))
        
    return open_ports


def sslscan(host):
    sslscan = subprocess.Popen(["sslscan", host], stdout=subprocess.PIPE, universal_newlines=True)

    sslscan_results = open("sslscan_results.txt", "w+")
    ciphers = set()
    spinner = Spinner("Scanning host...")
    while True:
        spinner.next()
        line = sslscan.stdout.readline()
        if line == "" and sslscan.poll() is not None:
            break
        if line:
            if re.search(r'TLS.+bits', line) or re.search(r'SSL.+bits', line):
                line = ansi_escape_seq.sub('', line)
                ciphersuite = line.split()[4].strip()
                ciphers.add(ciphersuite)
            sslscan_results.write(line)
    sslscan_results.close()
    
    highlight = weak_insecure_ciphers(ciphers)

    print("\n\nPrinting out results...\n")
    sslscan_results = open("sslscan_results.txt", "r")
    to_highlight = []
    for line in sslscan_results:
        if re.search(r'bits', line):
            if cipher_weakness_check(line, highlight):
                to_highlight.append(line.strip())
            else:
                if len(to_highlight) >= 1:
                    draw_border(to_highlight, highlight)
                    to_highlight.clear()
                print("  " + line, end="")
        elif ssl_weakness_check(line):
            to_highlight.append(line.strip())
        else:
            if len(to_highlight) >= 1:
                draw_border(to_highlight, highlight)
                to_highlight.clear()
            print(line, end="")
    sslscan_results.close()
    os.remove("sslscan_results.txt")



# checks for weak and insecure ciphers against ciphersuite.info api.
# creates a local file with these ciphers if file doesn't exist for use when
# on a network that needs a proxy to hit external sites.
# ISSUE: doesn't have all the openssl names, have to use
#        https://testssl.sh/openssl-iana.mapping.html
def weak_insecure_ciphers(ciphers_to_check):
    if not os.path.isfile("weak-cipher-suites-data.txt"):
        weak_ciphers_response = requests.get("https://ciphersuite.info/api/cs/security/weak")
        insecure_ciphers_response = requests.get("https://ciphersuite.info/api/cs/security/insecure")
        openssl_iana_mapping = requests.get("https://testssl.sh/openssl-iana.mapping.html")
        with open("openssl-iana-mapping.txt", "w+") as mappings:
            mappings.write(openssl_iana_mapping.text)
        
        weak_cipher_data = json.loads(weak_ciphers_response.text.rstrip())["ciphersuites"]
        ciphers = [list(k.keys())[0] for k in weak_cipher_data] # iana name
        ciphers = [list(i.values())[0]["openssl_name"] for i in weak_cipher_data if list(i.values())[0]["openssl_name"]]
        ciphers += [list(i.values())[0]["gnutls_name"] for i in weak_cipher_data if list(i.values())[0]["gnutls_name"]]
        
        insecure_cipher_data = json.loads(insecure_ciphers_response.text.rstrip())["ciphersuites"]
        ciphers += [list(k.keys())[0] for k in insecure_cipher_data]
        ciphers += [list(i.values())[0]["openssl_name"] for i in insecure_cipher_data if list(i.values())[0]["openssl_name"]]
        ciphers += [list(i.values())[0]["gnutls_name"] for i in insecure_cipher_data if list(i.values())[0]["gnutls_name"]]
        
        cipher_mapping = {} # iana_name: openssl_name
        openssl = subprocess.Popen(["grep '<td>' openssl-iana-mapping.txt | sed 's/<\/*t.><\/*t.>//g;s/\[.*\]//g' | awk '{print $1,$NF}' | sort | uniq"], stdout=subprocess.PIPE, shell=True)
        while True:
            line = openssl.stdout.readline().decode('utf-8')
            if line == "" and openssl.poll() is not None:
                break
            if line:
                l = line.split()
                cipher_mapping[l[1]] = l[0]
        #os.remove("openssl-iana-mapping.txt")

        openssl_ciphers = []
        for cipher in ciphers:
            if cipher in cipher_mapping.keys():
                openssl_ciphers.append(cipher_mapping.get(cipher))
        
        ciphers += openssl_ciphers
        with open("weak-cipher-suites-data.txt", "w+") as data:
            data.write("\n".join(ciphers))
    
    highlight = []
    found = False
    with open("weak-cipher-suites-data.txt", "r") as ciphers_data:
        all_ciphers = [i.rstrip() for i in ciphers_data]
    for cipher in ciphers_to_check:
        if cipher in all_ciphers:
            highlight.append(cipher)
    return highlight


def ssl_weakness_check(line):
    result = False
    if re.search(r'not.*TLS Fallback SCSV', line) or re.search(r'Compression.*enabled', line) or re.search(r'Insecure.*session renegotiation', line):
        result = True
    if (re.search(r'Secure Algorithm', line) or re.search(r'Key Strength', line) or re.search(r'Not valid', line)) and red in line:
        result = True
    return result


def cipher_weakness_check(line, highlight):
    split_line = line.split()
    protocol = split_line[1]
    bits = split_line[2]
    cipher = split_line[4]
    key_exchange = ""
    if len(split_line) >= 6:
        key_exchange = split_line[5]
    if protocol in weak_protocols or (int(bits) < 128) or (cipher in highlight) or (key_exchange == "DHE 1024 bits"):
        return True
    return False


def sslyze(host):
    """
    flags = ["sslyze", "--hide_rejected_ciphers", "--http_get", host]
    options = ["--reneg", "--compression", "--heartbleed", "--fallback", "--tlsv1_2", "--tlsv1_1", "--tlsv1", "--sslv3", "--sslv2"]
    proxy = input("Proxy?(y/n): ")
    if proxy == "y":
         proxy_url = input("Format http://USER:PW@HOST:PORT/: ")
         flags.append("https_tunnel={}".format(proxy_url))
    
    sslyze_results = open("sslyze_results.txt", "w+")
    ciphers = set()
    spinner = Spinner("Scanning host...")
    for o in options:
        sslyze = subprocess.Popen(flags + [o], stdout=subprocess.PIPE, universal_newlines=True)
        while True:
            spinner.next()
            line = sslyze.stdout.readline()
            if line == "" and sslyze.poll() is not None:
                break
            if line:   
                if re.search(r'TLS.+bits', line) or re.search(r'SSL.+bits', line):
                    ciphersuite = line.split()[0].strip()
                    ciphers.add(ciphersuite)
                sslyze_results.write(line)
    sslyze_results.close()
    subprocess.call("sed -i 's/-*//g;/Plugin\|PLUGIN\|SCAN\|HOST\|=>/s/^.*$//;/^[[:space:]]*$/d' sslyze_results.txt", shell=True)
    """
    
    highlight = []#weak_insecure_ciphers(ciphers)

    print("\n\nPrinting out results...\n")
    sslyze_results = open("sslyze_results.txt", "r")
    to_highlight = []
    border_section = False
    for line in sslyze_results:
        if border_section:
            if re.search(r'rejected', line):
                print(to_highlight[0])
                to_highlight.clear()
                border_section = False
            elif re.search(r'\*', line):
                to_highlight.pop()
                draw_border(to_highlight, highlight, True)
                to_highlight.clear()
                border_section = False
            else:
                to_highlight.append(line.strip())
                continue
        if re.search(r'\* (TLSV1|TLSV1_1|SSLV.*) Cipher Suites', line):
            to_highlight.append(line.strip())
            border_section = True
            continue
        if re.search(r'bits', line):
            c = line.split()[0].strip()
            if c in highlight:
                to_highlight.append(line.strip())
            else:
                if len(to_highlight) >= 1:
                    draw_border(to_highlight, highlight, True)
                    to_highlight.clear()
                print(line.rstrip())
        elif re.search(r'VULNERABLE', line):
            to_highlight.append(line.strip())
        else:
            if len(to_highlight) >= 1:
                draw_border(to_highlight, highlight, True)
                to_highlight.clear()
            print(line, end="")
    sslyze_results.close()
    #os.remove("sslyze_results.txt")


def draw_border(lines, highlight, sslyze_flag=False):
    draw = ""
    prepend_space = ""
    dash = ""
    space = ""
    if sslyze_flag:
        prepend_space = " " * 5
        dash = "-" * (len(lines[0])+2)
        if re.search(r'\*', lines[0]):
            dash = "-" * (len(lines[6])+2)
    else:
        dash = "-" * 80

    if len(lines) == 1:
        line = lines[0]
        if not sslyze_flag:
            length = len(ansi_escape_seq.sub('', line))
            space = " " * (78-length)
        if re.search(r'TLS.*bits', line) or re.search(r'SSL.*bits', line):
            line = colour_keywords(line, highlight, sslyze_flag)
        draw += "{prepend_space}{colour}+{dash}+\n{prepend_space}| {default_colour}{line}{colour}{space} |\n{prepend_space}+{dash}+\n{default_colour}".format(prepend_space=prepend_space,dash=dash,space=space,line=line,colour=red,default_colour=white)
        print(draw, end="")
    else:
        draw += "{prepend_space}{colour}+{dash}+\n{default_colour}".format(prepend_space=prepend_space,dash=dash,colour=red,default_colour=white)
        for i in lines:
            if not sslyze_flag:
                space = " " * (78-len(i))
                i = colour_keywords(i, highlight, sslyze_flag)
            else:
                space = " " * (len(dash)-len(i)-2)
                if re.search(r'V.*Cipher Suites', i) or re.search(r'TLS.*bits', i) or re.search(r'SSL.*bits', i):
                    i = colour_keywords(i, highlight, sslyze_flag)
            draw += "{prepend_space}{colour}| {default_colour}{line}{colour}{space} |\n{default_colour}".format(prepend_space=prepend_space,colour=red,default_colour=white,line=i,space=space)
        draw += "{prepend_space}{colour}+{dash}+{default_colour}".format(prepend_space=prepend_space,colour=red,default_colour=white,dash=dash)
        print(draw)


def colour_keywords(line, highlight, sslyze_flag):
    if not sslyze_flag:
        protocol = line.split()[1]
        if protocol in weak_protocols:
            index = line.find(protocol)
            line = colour_keyword(line, index, len(protocol))
    if sslyze_flag and re.search(r'V.*Cipher Suites', line):
        line = colour_keyword(line, 0, len(line))
        return line

    bits = line.split()[1]
    if not sslyze_flag:
        bits = line.split()[2]
    if int(bits) < 128:
        line = colour_keyword(line, line.find(bits), 8)
    
    if re.search(r'DHE 1024 bits', line):
        line = colour_keyword(line, line.find('DHE 1024 bits'), 13)

    cipher = line.split()[0]
    if not sslyze_flag:
        cipher = line.split()[4]
    if cipher in highlight:
        line = colour_keyword(line, line.find(cipher), len(cipher))
    
    return line


def colour_keyword(line, index, length):
    return line[:index] + yellow + line[index:index+length] + white + line[index+length:]


def nikto(host, open_ports):
    if "80" in open_ports:
        nikto = subprocess.call(["nikto", "-host", host, "-port", "80", "Save", "."], stdout=file, stderr=subprocess.PIPE, universal_newlines=True)
          
    nikto = subprocess.call(["nikto", "-host", host, "-port", "443", "Save", "."], stdout=file, stderr=subprocess.PIPE, universal_newlines=True)


if __name__ == "__main__":
    title = Figlet(font="slant")
    print(title.renderText("combo meal"))
    order = input("What would you like to order?:\n\n+{dash}+\n|{space_one}MENU{space_one}|\n+{dash}+\n| nmap portalicious sandwich (1) |\n| sslyze spicy fries (2){space_two}|\n| nikto cola (3){space_three}|\n+{dash}+\n\nOrder me: ".format(dash="-"*32,space_one=" "*14,space_two=" "*9,space_three=" "*17))
    options = order.split(" ")
    host = input("Host?: ")
    proxy = input("Proxy required?: ")
    open_ports = []
    if '1' in options:
        open_ports = nmap(host)
    if '2' in options:
        if host:
            print("an order of sslyze fries coming up")
            sslyze(host)
         else:
            sslyze_flag = input("Do you wanna use sslyze or nah (y/n)? ")
            if sslyze_flag == "y":
                sslyze(host)
            else:
                sslscan(host)
    if '3' in options:
        nikto(host, open_ports)



