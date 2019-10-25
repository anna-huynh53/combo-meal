#!/usr/bin/python3

import os, re, subprocess
import requests, json
from time import sleep
import pyfiglet
from pyfiglet import Figlet
from progress.spinner import Spinner

red = "\033[1;31;49m"
yellow = "\033[1;33;49m"
black = "\033[1;30;49m"
white ="\033[1;37;49m"
ansi_escape_seq = re.compile(r'\x1b[^m]*m')

def nmap(host):
    print("nmap")


def sslscan(host, proxy):
    sslscan = subprocess.Popen(["sslscan", host], stdout=subprocess.PIPE, universal_newlines=True)
    
    sslscan_results = open("sslscan_results.txt", "w+")
    ciphers = set()
    spinner = Spinner("Scanning host...")
    while True:
        sleep(0.1)
        spinner.next()
        line = sslscan.stdout.readline()
        if line == "" and sslscan.poll() is not None:
            break
        if line:
            if re.search(r'TLS.+bits', line):
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
                    draw_border(to_highlight)
                    to_highlight.clear()
                print("  " + line, end="")
        elif ssl_weakness_check(line):
            to_highlight.append(line.strip())
        else:
            if len(to_highlight) >= 1:
                draw_border(to_highlight)
                to_highlight.clear()
            print(line, end="")
    sslscan_results.close()
    os.remove("sslscan_results.txt")


# checks for weak and insecure ciphers against ciphersuite.info api
def weak_insecure_ciphers(ciphers):
    weak_ciphers_response = requests.get("https://ciphersuite.info/api/cs/security/weak")
    insecure_ciphers_response = requests.get("https://ciphersuite.info/api/cs/security/insecure")
    weak_ciphers = json.loads(weak_ciphers_response.text)
    insecure_ciphers = json.loads(insecure_ciphers_response.text)

    highlight = []
    found = False
    print("\n")
    spinner = Spinner("Checking for weak and insecure ciphers...")
    for cipher in ciphers:
        sleep(0.1)
        spinner.next()
        for i in weak_ciphers['ciphersuites']:
            if re.search(r'\b' + cipher + r'\b', json.dumps(i)):
                highlight.append(cipher)
                found = True
                break
        if not found:
            for i in insecure_ciphers['ciphersuites']:
                if re.search(r'\b' + cipher + r'\b', json.dumps(i)):
                    highlight.append(cipher)
                    break
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
    tls = split_line[1]
    bits = split_line[2]
    cipher = split_line[4]
    key_exchange = ""
    if len(split_line) >= 6:
        key_exchange = split_line[5]
    if re.search(r'(TLSv1.0|TLSv1.1|SSL)', line) or (int(bits) < 128) or (cipher in highlight) or (key_exchange == "DHE 1024 bits"):
        return True
    return False


def sslyze(host, proxy):
    sslyze = ["sslyze", "--regular", host]
    proxy = input("Proxy?(y/n): ")
    if proxy == "y":
         proxy_url = input("Format http://USER:PW@HOST:PORT/: ")
         sslyze.append("https_tunnel={}".format(proxy_url))
    sslyze = subprocess.Popen(sslyze, stdout=subprocess.PIPE, universal_newlines=True)
    
    sslyze_results = open("sslyze_results.txt", "w+")
    ciphers = set()
    spinner = Spinner("Scanning host...")
    while True:
        sleep(0.1)
        spinner.next()
        line = sslyze.stdout.readline()
        if line == "" and sslyze.poll() is not None:
            break
        if line:
            if re.search(r'TLS.+bits', line):
                ciphersuite = line.split()[0].strip()
                ciphers.add(ciphersuite)
            sslyze_results.write(line)
    sslyze_results.close()
    
    highlight = weak_insecure_ciphers(ciphers)

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
                draw_border(to_highlight, True)
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
                    draw_border(to_highlight, True)
                    to_highlight.clear()
                print(line.rstrip())
        else:
            if len(to_highlight) >= 1:
                draw_border(to_highlight, True)
                to_highlight.clear()
            print(line, end="")
    sslyze_results.close()
    os.remove("sslyze_results.txt")


def draw_border(lines, sslyze_flag=False):
    draw = ""
    prepend_space = ""
    dash = ""
    space = ""
    if sslyze_flag:
        prepend_space = " " * 6
        dash = "-" * (len(lines[0])+2)
        if re.search(r'\*', lines[0]):
            dash = "-" * (len(lines[5])+2)
    else:
        dash = "-" * 80
    
    if len(lines) == 1:
        line = lines[0]
        if not sslyze_flag:
            length = len(ansi_escape_seq.sub('', line))
            space = " " * (78-length)
        if re.search(r'TLS.*bits', line):
            line = colour_keywords(line, sslyze_flag)
        draw += "{prepend_space}{colour}+{dash}+\n{prepend_space}| {default_colour}{line}{colour}{space} |\n{prepend_space}+{dash}+\n{default_colour}".format(prepend_space=prepend_space,dash=dash,space=space,line=line,colour=red,default_colour=white)
        print(draw, end="")
    else:
        draw += "{prepend_space}{colour}+{dash}+\n{default_colour}".format(prepend_space=prepend_space,dash=dash,colour=red,default_colour=white)
        for i in lines:
            if not sslyze_flag:
                space = " " * (78-len(i))
                i = colour_keywords(i, sslyze_flag)
            else:
                if not re.search(r'TLS.*bits', i):
                    space = " " * (len(dash)-len(i)-2)
                else:
                    space = ""
                    i = colour_keywords(i, sslyze_flag)
            draw += "{prepend_space}{colour}| {default_colour}{line}{colour}{space} |\n{default_colour}".format(prepend_space=prepend_space,colour=red,default_colour=white,line=i,space=space)
        draw += "{prepend_space}{colour}+{dash}+{default_colour}".format(prepend_space=prepend_space,colour=red,default_colour=white,dash=dash)
        print(draw)


def colour_keywords(line, sslyze_flag):
    if re.search(r'(TLSv1.0|TLSv1.1|SSL)', line):
        index = line.find('TLS')
        if not index:
            index = line.find('SSL')
        line = colour_keyword(line, index, 7)
        
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
    line = colour_keyword(line, line.find(cipher), len(cipher))
    
    return line


def colour_keyword(line, index, length):
    return line[:index] + yellow + line[index:index+length] + white + line[index+length:]


def nikto(host):
    nikto = subprocess.Popen(["nikto", "-host", host, "-o", "nikto.txt"], stdout=subprocess.PIPE, universal_newlines=True)


if __name__ == "__main__":
    title = Figlet(font="slant")
    print(title.renderText("combo meal"))
    order = input("What would you like to order?:\n\n+{dash}+\n|{space_one}MENU{space_one}|\n+{dash}+\n| nmap portalicious sandwich (1) |\n| ssl spicy fries (2){space_two}|\n| nikto cola (3){space_three}|\n+{dash}+\n\nOrder me: ".format(dash="-"*32,space_one=" "*14,space_two=" "*12,space_three=" "*17))
    options = order.split(" ")
    host = input("Host?: ")
    proxy = input("If you need a proxy to access external sites on this network, enter it now: ")
    if '1' in options:
        nmap(host)
    if '2' in options:
        sslyze_flag = input("Do you wanna use sslyze or nah (y/n)? ")
        if sslyze_flag == "y":
            sslyze(host, proxy)
        else:
            sslscan(host, proxy)
    if '3' in options:
        nikto(host)



