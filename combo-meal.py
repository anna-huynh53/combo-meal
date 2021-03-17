#!/usr/bin/python3

import argparse
import os, subprocess, re
import requests, json
from progress.spinner import Spinner

title = """
                        __                                  __
  _________  ____ ___  / /_  ____     ____ ___  ___  ____ _/ /
 / ___/ __ \/ __ `__ \/ __ \/ __ \   / __ `__ \/ _ \/ __ `/ / 
/ /__/ /_/ / / / / / / /_/ / /_/ /  / / / / / /  __/ /_/ / /  
\___/\____/_/ /_/ /_/_.___/\____/  /_/ /_/ /_/\___/\__,_/_/  
""" 
red = "\033[1;31;49m"
yellow = "\033[1;33;49m"
black = "\033[1;30;49m"
white ="\033[1;37;49m"
ansi_escape_seq = re.compile(r'\x1b[^m]*m')
weak_protocols = ["SSLv1", "SSLv1.0", "SSLv2", "SSLv2.0", "SSLv3", "SSLv3.0", "TLSv1.0", "TLSv1.1"]
weak_key_exchanges = ["DHE 1024 bits"]

def nmap(host, user_flags):
    flags = ["sudo", "nmap", host]
    if user_flags:
        flags += user_flags
    else:
        flags += ["-Pn", "-sS", "-v"]
    nmap = subprocess.Popen(flags, stdout=subprocess.PIPE, universal_newlines=True)
    
    ports = []
    spinner = Spinner("Nmapping host...")
    while True:
        spinner.next()
        line = nmap.stdout.readline()
        if line == "" and nmap.poll() is not None:
            break
        if line:
            if re.search("/.*open", line):
                ports.append(line.strip())

    # for printing out results
    lengths = [29, len(host) + 6, len(sorted(ports, key=len)[-1]) + 9]
    longest = sorted(lengths)[-1]
    
    # if port 80 and/or 443 is open and nikto is also called, will nikto those ports
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

    ciphersuites = set()
    spinner = Spinner("Scanning host...")
    with open("sslscan_results.txt", "w+") as sslscan_results:
        while True:
            spinner.next()
            line = sslscan.stdout.readline()
            if line == "" and sslscan.poll() is not None:
                break
            if line:
                if re.search(r'TLS.+bits', line) or re.search(r'SSL.+bits', line):
                    # strips the colour from the line
                    line = ansi_escape_seq.sub('', line)
                    ciphersuite = line.split()[4].strip()
                    ciphersuites.add(ciphersuite)
                sslscan_results.write(line)
    
    highlight = get_weak_insecure_ciphers(ciphersuites)

    to_highlight = []
    print("\n\nPrinting out results...\n")
    with open("sslscan_results.txt", "r") as sslscan_results:
        for line in sslscan_results:
            if re.search(r'bits', line):
                if check_weak_cipher(line, highlight):
                    to_highlight.append(line.strip())
                else:
                    if len(to_highlight) >= 1:
                        draw_border(to_highlight, highlight)
                        to_highlight.clear()
                    print("  " + line, end="")
            elif check_weak_ssl(line):
                to_highlight.append(line.strip())
            else:
                if len(to_highlight) >= 1:
                    draw_border(to_highlight, highlight)
                    to_highlight.clear()
                print(line, end="")
    os.remove("sslscan_results.txt")


# checks for weak and insecure ciphers using the ciphersuite.info api.
# as this api does not list all the openssl names, maps the iana names to
# openssl names using https://testssl.sh/openssl-iana.mapping.html.
# creates a local file with these ciphers if file doesn't exist for use when
# on a network that needs a proxy to hit external sites.
def get_weak_insecure_ciphers(ciphers_to_check):
    if not os.path.isfile("weak-cipher-suites-data.txt"):
        weak_ciphers_response = requests.get("https://ciphersuite.info/api/cs/security/weak")
        insecure_ciphers_response = requests.get("https://ciphersuite.info/api/cs/security/insecure")
        
        weak_cipher_data = json.loads(weak_ciphers_response.text.strip())["ciphersuites"]
        ciphers = [list(k.keys())[0] for k in weak_cipher_data] # iana name
        ciphers = [list(i.values())[0]["openssl_name"] for i in weak_cipher_data if list(i.values())[0]["openssl_name"]]
        ciphers += [list(i.values())[0]["gnutls_name"] for i in weak_cipher_data if list(i.values())[0]["gnutls_name"]]
        
        insecure_cipher_data = json.loads(insecure_ciphers_response.text.strip())["ciphersuites"]
        ciphers += [list(k.keys())[0] for k in insecure_cipher_data]
        ciphers += [list(i.values())[0]["openssl_name"] for i in insecure_cipher_data if list(i.values())[0]["openssl_name"]]
        ciphers += [list(i.values())[0]["gnutls_name"] for i in insecure_cipher_data if list(i.values())[0]["gnutls_name"]]
        
        iana_openssl_mapping = requests.get("https://testssl.sh/openssl-iana.mapping.html")
        with open("iana-openssl-mapping.txt", "w+") as mappings:
            mappings.write(iana_openssl_mapping.text)
        cipher_mapping = {} # iana_name: openssl_name
        openssl = subprocess.Popen(["grep '<td>' iana-openssl-mapping.txt | sed 's/<\/*t.><\/*t.>//g;s/\[.*\]//g' | awk '{print $1,$NF}' | sort | uniq"], stdout=subprocess.PIPE, shell=True)
        while True:
            line = openssl.stdout.readline().decode('utf-8')
            if line == "" and openssl.poll() is not None:
                break
            if line:
                split_line = line.split()
                cipher_mapping[split_line[1]] = split_line[0]
                cipher_mapping[split_line[0]] = split_line[1]
        #os.remove("iana-openssl-mapping.txt")

        openssl_ciphers = []
        for cipher in ciphers:
            if cipher in cipher_mapping.keys():
                if cipher_mapping.get(cipher):
                    openssl_ciphers.append(cipher_mapping.get(cipher))
        
        ciphers += openssl_ciphers
        with open("weak-cipher-suites-data.txt", "w+") as data:
            data.write("\n".join(ciphers))
    
    highlight = []
    found = False
    with open("weak-cipher-suites-data.txt", "r") as ciphers_data:
        all_ciphers = [i.strip() for i in ciphers_data]
    for cipher in ciphers_to_check:
        if cipher in all_ciphers or re.search(r'SHA$', cipher):
            highlight.append(cipher)
    return highlight


def check_weak_cipher(line, highlight):
    split_line = line.split()
    protocol = split_line[1]
    bits = split_line[2]
    cipher = split_line[4]
    key_exchange = ""
    if len(split_line) >= 6:
        key_exchange = split_line[5]
    if protocol in weak_protocols or (int(bits) < 128) or (cipher in highlight) or (key_exchange in weak_key_exchanges):
        return True
    return False


# should probably fix this
def check_weak_ssl(line):
    result = False
    if re.search(r'not.*TLS Fallback SCSV', line) or re.search(r'Insecure session renegotiation', line) or re.search(r'Compression enabled', line) or re.search(r'[0-9] vulnerable to heartbleed', line):
        result = True
    if (re.search(r'Secure Algorithm', line) or re.search(r'Key Strength', line) or re.search(r'Not valid', line)) and red in line:
        result = True
    return result


def sslyze(host, user_flags):
    flags = ["sslyze", "--hide_rejected_ciphers", "--http_get", host]
    options = ["--fallback", "--reneg", "--compression", "--heartbleed", "--tlsv1_2", "--tlsv1_1", "--tlsv1", "--sslv3", "--sslv2"]
    if user_flags:
        flags += user_flags
    
    ciphersuites = set()
    spinner = Spinner("Scanning host...")
    with open("sslyze_results.txt", "w+") as sslyze_results:
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
                        ciphersuites.add(ciphersuite)
                    sslyze_results.write(line)
    # as calling each flag individually for order instead of sorting out file after,
    # need to remove lines that are prepended and appended for each scan called
    subprocess.call("sed -i 's/-*//g;/Plugin\|PLUGIN\|SCAN\|HOST\|=>/s/^.*$//;/^[[:space:]]*$/d' sslyze_results.txt", shell=True)
    
    highlight = get_weak_insecure_ciphers(ciphersuites)
    
    to_highlight = []
    border_section = False
    print("\n\nPrinting out results...\n")
    with open("sslyze_results.txt", "r") as sslyze_results:
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
                    print(line.strip())
            elif re.search(r'VULNERABLE', line):
                to_highlight.append(line.strip())
            else:
                if len(to_highlight) >= 1:
                    draw_border(to_highlight, highlight, True)
                    to_highlight.clear()
                print(line, end="")
    os.remove("sslyze_results.txt")


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
    with open(re.compile(r'://').sub('-', host)+".txt", "w+") as file:
        nikto = subprocess.call(["nikto", "-host", host], stdout=file)
    if "80" in open_ports and re.search(r'https://', host):
        with open("http-"+host+".txt", "w+") as file:
            nikto = subprocess.call(["nikto", "-host", host, "-port", "80"], stdout=file)
    if "443" in open_ports and re.search(r'http://', host):
        with open("https-"+host+".txt", "w+") as file:
            nikto = subprocess.call(["nikto", "-host", host, "-port", "443"], stdout=file)  


if __name__ == "__main__":
    print(title)
    order = input("What would you like to order?:\n\n+{dash}+\n|{space_one}MENU{space_one}|\n+{dash}+\n| nmap portalicious sandwich (1) |\n| sslyze spicy fries (2){space_two}|\n| nikto cola (3){space_three}|\n+{dash}+\n\nOrder me: ".format(dash="-"*32,space_one=" "*14,space_two=" "*9,space_three=" "*17))
    options = order.split(" ")
    
    host = input("Host? (e.g. https://www.example.com): ")
    nmap_flags = []
    sslyze_flags = []
    open_ports = []
    if '1' in options:
        nmap_flags = input("NMAP: What flags you want otherwise it's -Pn -sS -v: ")
    if '2' in options:
        sslyze_flag = input("SSLSCAN: Do you wanna use sslyze or nah - choose if you need to proxy (y/n)? ") 
        if sslyze_flag == "y":
            proxy_url = input("         Format http://USER:PW@HOST:PORT/: ")
            sslyze_flags.append("https_tunnel={proxy}".format(proxy=proxy_url))
    if '1' in options:
        open_ports = nmap(host, nmap_flags)
    if '2' in options:
        if sslyze_flags:
            sslyze(host, sslyze_flags)
        else:
            sslscan(host)
    if '3' in options:
        nikto(host, open_ports)


# to do or not to do
def help_menu():
    print("Wow, there's a help menu. How helpful.")
    print("When choosing what to order, you can choose any combo of the menu, separated by a space e.g. 1 3, 3 2 1")
    print("-h     This is the only flag to bring up this menu.")


