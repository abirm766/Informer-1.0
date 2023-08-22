### Module Import Section ###
import argparse
import sys
import whois
import dns.resolver
import requests
import shodan
import socket
from datetime import datetime
#############################

# using argparse module to take inline arguments
argparse = argparse.ArgumentParser(prog='INFORMER', description="INFORMER 1.0, python3 based basic Information gathering tool",
                                   usage="python3 {} [Search Type(s)] [Options] Target Domain/IP(s)".format(sys.argv[0]))

argparse.add_argument("-v", "--version", action="version", version="%(prog)s 1.0")   # version info

argparse.add_argument("target", nargs='+', help="Enter the domain name or IP.")   # positional argument

# search types
argparse.add_argument("-s", "--shodan", action="store_true", help="Shodan search for given IP.")
argparse.add_argument("-w", "--whois", action="store_true", help="Gather whois info for given domain.")
argparse.add_argument("-r", "--records", action="store_true", help="Gather DNS records for given domain.")
argparse.add_argument("-g", "--geolocation", action="store_true", help="Gather Geolocation info for given domain.")

# options
argparse.add_argument("-u", action="store_true", help="Use the IP of the given domain for Shodan search.")
argparse.add_argument("-p", "--path", nargs=1, help="Specify file to save output.")


def validIPAddress(IP):
    """
    checks if a given string is IP
    :type IP: str
    :rtype: str
    """
    def isIPv4(s):
        try: return str(int(s)) == s and 0 <= int(s) <= 255
        except: return False
    if IP.count(".") == 3 and all(isIPv4(i) for i in IP.split(".")):
        return True
    return False


# namespace object
args = argparse.parse_args()
targets = args.target
sho = args.shodan
who = args.whois
rec = args.records
geo = args.geolocation
use = args.u
output = args.path


# checks if no search option is given
check = set([sho, who, rec, geo])
if len(check) == 1:
    if list(check)[0] == False:
        print("Search Type(s) needed to initiate.")
        print("See the output of {} -h for a summary of options.".format(sys.argv[0]))
        sys.exit()
    else:
        pass
else:
    pass


for target in targets:   # for loop to handle multiple targets
   
   
    whois_result = ''
    dns_result = ''
    geo_result = ''
    shodan_result = ''
   
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
   
   
    if validIPAddress(target) == False:   # consider only target domains
        # whois module
        if who == True:
            print("[+] Getting whois info for {}...".format(target))
            # using whois library, creating instances
            try:
                dom = whois.query(target)
            except:
                print("[-] Error occured. No whois info found!")
            else:   
                print("[+] whois info found.")

                try:
                    print("Name: {}".format(dom.name))
                    whois_result += "Name: {}".format(dom.name) + '\n'
                except:
                    print("Domain name not found!")
                try:
                    print("Registrar: {}".format(dom.registrar))
                    whois_result += "Registrar: {}".format(dom.registrar) + '\n'
                except:
                    print("Registrar info not found!")
                try:
                    print("Creation Date: {}".format(dom.creation_date))
                    whois_result += "Creation Date: {}".format(dom.creation_date) + '\n'
                except:
                    print("Creation date not found!")
                try:
                    print("Expiration Date: {}".format(dom.expiration_date))
                    whois_result += "Expiration Date: {}".format(dom.expiration_date) + '\n'
                except:
                    print("Expiration date not found!")
                try:
                    print("Registrant: {}".format(dom.registrant))
                    whois_result += "Registrant: {}".format(dom.registrant) + '\n'
                except:
                    print("Registrant info not found!")
                try:
                    print("Registrant Country: {}".format(dom.registrant_country))
                    whois_result += "Registrant Country: {}".format(dom.registrant_country) + '\n'
                except:
                    print("Registrant country not found!")


        # DNS module
        if rec == True:
            print("[+] Getting DNS info for {}...".format(target))
            # implementing dns.resolver from dnspython
            try:
                for a in dns.resolver.resolve(target, 'A'):
                    print("[+] A Record: {}".format(str(a)))
                    dns_result += "[+] A Record: {}".format(str(a)) + '\n'
            except:
                print("No A records found!")
            try:
                for ns in dns.resolver.resolve(target, 'NS'):
                    print("[+] NS Record: {}".format(str(ns)))
                    dns_result += "[+] NS Record: {}".format(str(ns)) + '\n'
            except:
                print("No NS records found!")
            try:
                for mx in dns.resolver.resolve(target, 'MX'):
                    print("[+] MX Record: {}".format(str(mx)))
                    dns_result += "[+] MX Record: {}".format(str(mx)) + '\n'
            except:
                print("No MX records found!")
            try:
                for txt in dns.resolver.resolve(target, 'TXT'):
                    print("[+] TXT Record: {}".format(str(txt)))
                    dns_result += "[+] TXT Record: {}".format(str(txt)) + '\n'
            except:
                print("No TXT records found!")


        # Geolocation module
        if geo == True:
            print("[+] Getting Geolocation info for {}...".format(target))

            # implementing requests for web requests
            try:
                response = requests.request('GET', "https://geolocation-db.com/json/" + socket.gethostbyname(target)).json()
            except:
                print("[-] Geolocation info not found!")
            else:
                try:
                    print("[+] Country: {}".format(response['country_name']))
                    geo_result += "[+] Country: {}".format(response['country_name']) + '\n'
                except:
                    print("[-] Country name not found!")
                try:
                    print("[+] State: {}".format(response['state']))
                    geo_result += "[+] State: {}".format(response['state']) + '\n'
                except:
                    print("[-] State not found!")
                try:
                    print("[+] City: {}".format(response['city']))
                    geo_result += "[+] City: {}".format(response['city']) + '\n'
                except:
                    print("[-] City not found!")
                try:
                    print("[+] Latitude: {}".format(response['latitude']))
                    geo_result += "[+] Latitude: {}".format(response['latitude']) + '\n'
                except:
                    print("[-] Latitude not found!")
                try:
                    print("[+] Longitude: {}".format(response['longitude']))
                    geo_result += "[+] Longitude: {}".format(response['longitude']) + '\n'
                except:
                    print("[-] Longitude not found!")
                try:
                    print("[+] IPv4: {}".format(response['IPv4']))
                    geo_result += "[+] IPv4: {}".format(response['IPv4']) + '\n'
                except:
                    print("[-] IP info not found!")


        # shodan module
        if sho == True:
            if use == True:
                print("Getting Shodan info for {}...".format(target))
                ip = socket.gethostbyname(target)

                # shodan api
                api = shodan.Shodan("<shodan api key>")
                try:
                    results = api.search(ip)
                    print("[+] Results found: {}".format(results['total']))
                    for result in results['matches']:
                        print("[+] IP: {}".format(result['ip_str']))
                        shodan_result += "[+] IP: {}".format(result['ip_str']) + '\n'
                        print("[+] Data: \n{}".format(result['data']))
                        shodan_result += "[+] Data: \n{}".format(result['data']) + '\n\n'
                        print()

                except:
                    print("[-] Shodan search error.")
                   
            else:
                pass
               
               
               
    if validIPAddress(target) == True:   # consider only target IPs
        # whois module
        if who == True:
            pass
           
           
        # DNS module
        if rec == True:
            pass
           
           
        # Geolocation module   
        if geo == True:
            pass
           
           
            # shodan module
        if sho == True:
            print("Getting Shodan info for {}...".format(target))

            # shodan api
            api = shodan.Shodan("<shodan api key>")
            try:
                results = api.search(target)
                print("[+] Results found: {}".format(results['total']))
                for result in results['matches']:
                    print("[+] IP: {}".format(result['ip_str']))
                    shodan_result += "[+] IP: {}".format(result['ip_str']) + '\n'
                    print("[+] Data: \n{}".format(result['data']))
                    shodan_result += "[+] Data: \n{}".format(result['data']) + '\n\n'
                    print()

            except:
                print("[-] Shodan search error.")
               
               
       
    if output:   # to write outputs on a file if specified
        with open(output[0], 'a') as file:
            file.write("Search Result for target {}, {}".format(target, current_time) + '\n\n\n')   # headers {target + time stamp}
            file.write(whois_result + '\n\n')
            file.write(dns_result + '\n\n')
            file.write(geo_result + '\n\n')
            file.write(shodan_result + '\n\n')


    print('\n\n\n')