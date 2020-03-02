#!/usr/bin/python
# coding=utf-8
import datetime
import logging
import MySQLdb
import math
import sys
import time
import os
import urllib
import urllib2
import smtplib

import thread
from dashSniffer_functions import *
from multiprocessing import Process
from threading import Thread
sys.path.append('/home/pi//Libraries')
from sendmail import send_mail
from database import Database
from readconfig import read_config
from mqtt_publisher import MQTT

import requests,json

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

dashButton_1  = 'ac:63:be:ad:5b:c5' # Dash zum Holzscheit zaehlen
dashButton_2  = 'b4:7c:9c:cb:6e:e2' # Licht dash in der kueche (Ariel)
dashButton_3  = '50:f5:da:42:e2:fd' # Licht dash hinter Sofa im Wohnzimmer
dashButton_4  = 'ac:63:be:31:ec:80' # Schlafzimmer (SOMAT)
dashButton_5  = 'ac:63:be:3b:e3:fa' # Licht dash im Flur für alle Lichter
dashButton_6  = 'b4:7c:9c:6d:ad:80' # Rolladenfernbedienung im 1. OG für ROllo AUF (Mea Vita)
dashButton_7  = '34:d2:70:bc:c9:7c' # Gardena Rasenmäher goes home for end of day
dashButton_8  = 'fc:a6:67:3c:cb:1b' # Global Shutdown all ClimaStation devices and Smart Metering (Mentos)
dashButton_9  = '44:65:0d:0c:dc:91' # Going to be the button for opening garage door (Nivea MEN DASH)
dashButton_10 = 'ac:63:be:42:af:3f' # Gardena Rasenmäher goes manuel mode (Nivea DASH)
dashButton_11 = 'ac:63:be:32:6f:ae' # Help Button for calling help in emilias room (Diadermine)
dashButton_12 = '68:37:e9:ba:0c:b8' # Counting Baby feeding (Play-Doh)
dashButton_13 = 'b4:7c:9c:c4:7d:4a' # Ambilight TV ON/OFF (Playboy)
dashButton_14 = '68:37:e9:f7:e0:66' # Oberlicht Tür Flur (Energizer)
dashButton_15 = '18:74:2e:c4:c1:89'
dashButton_16 = 'ac:63:be:bd:d0:40' #Available -> EUKANUBA
dashButton_17 = 'b4:7c:9c:aa:25:66' #Available ->
dashButton_18 = 'b4:7c:9c:aa:25:66' #Available ->
dashButton_19 = 'fc:a6:67:37:eb:a7' #Available -> Mentos
dashButton_20 = '68:37:e9:1b:1c:f6' # Stehlampe Esszimmer (Schmükli)
dashButton_21 = 'b4:7c:9c:49:48:39'
dashButton_22 = '78:e1:03:c1:9c:50' #Terrassenbeleuchtung (Nescafe)
dashButton_23 = '18:74:2e:c4:c1:89'



###### Important: MAC Adresse not with capital letters!

debugLevel = 0

def udp_filter(pkt):
  options = pkt[DHCP].options
  for option in options:
    if isinstance(option, tuple):
     if 'requested_addr' in option:
       # we've found the IP address, which means its the second and final UDP request, so we can trigger our action
       test2(pkt.src)
       break

def manualTrigger():
    while True:
        try:
            input = raw_input("Bitte Nummer des Dashbuttons zum Test wählen. Für eine Auflistung einfach 'list' eingeben")
            mac_to_action[input]()
        except KeyboardInterrupt:
            print ('Interrupted')
            sys.exit(0)

mac_to_action = {dashButton_1 : button_pressed_dash_1, dashButton_2 : button_pressed_dash_2, dashButton_3 : button_pressed_dash_3, dashButton_4 : button_pressed_dash_4, dashButton_5 : button_pressed_dash_5, dashButton_6 : button_pressed_dash_6, dashButton_7 : button_pressed_dash_7, dashButton_8 : button_pressed_dash_8, dashButton_9 : button_pressed_dash_9, dashButton_10 : button_pressed_dash_10, dashButton_11 : button_pressed_dash_11, dashButton_12 : button_pressed_dash_12, dashButton_13 : button_pressed_dash_13 ,dashButton_14 : button_pressed_dash_14,dashButton_15 : button_pressed_dash_15,dashButton_16 : button_pressed_dash_16,dashButton_17 : button_pressed_dash_17,dashButton_18 : button_pressed_dash_18,dashButton_19 : button_pressed_dash_19, dashButton_20 : button_pressed_dash_20, dashButton_21 : button_pressed_dash_21,dashButton_22 : button_pressed_dash_22,dashButton_23 : button_pressed_dash_23}
mac_id_list = list(mac_to_action.keys())
if debugLevel > 1:
    print "Waiting for a button press..."
#processmanualTrigger = Thread(target=manualTrigger)
#processmanualTrigger.start()
sniff(prn=udp_filter, store=0, filter="udp", lfilter=lambda d: d.src in mac_id_list)
if __name__ == "__main__":
    try:
        pass
    except KeyboardInterrupt:
        print ('Interrupted')
        sys.exit(0)
    except SystemExit:
        print ('Interrupted with System Exit')
        sys.exit(0)
    except Warning:
        send_Mail(text = 'Python Script generated a warning.', subject = 'Python Script dashSniffer with Warning')
        pass
    except Exception as error:
        print (error.message)
        print (error.args)
        send_mail(text = 'Python Script dashSniffer generated an error with ' + str(error.message) + '    ' +str(error.args), subject = 'Python Script dashSniffer with error')
        pass
