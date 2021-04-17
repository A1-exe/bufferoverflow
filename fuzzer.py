#!/bin/python3

#####################
#      IMPORTS      #
#####################
import sys
import socket
import argparse
import subprocess
import time

#####################
#    CONNECTIONS    #
#####################
HOST = 'localhost'
PORT = 1337
timeout = 5

#####################
#       MISC        #
#####################
# Payload modifiers
lengthsize = 100
length = 1

# Banner
paintBanner = True

#####################
#     FUNCTIONS     #
#####################
payload = ''

def generatePayload(sending):
    return (sending * (length * lengthsize))

def main():
    parser = argparse.ArgumentParser(description='A generic fuzzer.')
    parser.add_argument('host', help='The target host')
    parser.add_argument('port', help='The target port')
    parser.add_argument('prefix', help='The fuzzing prefix')
    parser.add_argument('-f', help='Fuzzing character', metavar='char', dest='sending', default='A')
    parser.add_argument('-t', help='Timeout in seconds', metavar='number', dest='timeout', default=5)
    parser.add_argument('-l', help='Send the prefix <number> times before the data', metavar='number', dest='preloop', default=0)
    parser.add_argument('-d', help='Eat <number> responses between sending data', metavar='number', dest='digest', default=0)

    # Globals
    global payload
    global timeout
    global length
    global lengthsize

    args = parser.parse_args()
    HOST = str(args.host)
    PORT = abs(int(args.port))
    timeout = abs(int(args.timeout))
    prefix = args.prefix.encode('utf-8')
    sending = args.sending.encode('utf-8')
    preloop = abs(int(args.preloop))
    digest = abs(int(args.digest))
    
    while True:
        try: # Detect crash
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT)) # Establish connection
                s.settimeout(timeout)   # Set timeout
                banner = s.recv(1024)   # Get the banner
                
                if (length == 1): # Output banner
                    print(banner.decode('utf-8') if paintBanner else banner)
                
                counter = 0
                while True:
                    if (counter > (digest + preloop)):
                        break  
                    
                    if (counter < preloop):
                        s.sendall(prefix)

                    if (counter < digest):
                        s.recv(1024)

                    counter += 1

                payload = generatePayload(sending)
                print('[+] Sending %s bytes...' % len(payload))
                s.sendall(prefix + payload + b'\n')
                s.recv(1024)
                print('[+] Done...')
                length += 1    

        except Exception as e: # Handle crash
            print('[-] Fuzzer crashed at %s bytes!' % len(payload))
            print(e)
            sys.exit(0) # Terminate program

        time.sleep(1)

if __name__ == "__main__":
	main()