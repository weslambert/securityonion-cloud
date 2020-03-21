# Pre-reqs:
# pip3 install scapy
# Example VXLAN PCAP: https://github.com/the-tcpdump-group/tcpdump/raw/master/tests/vxlan.pcap
import sys, getopt
from scapy.all import *

def write(pkt):
    wrpcap(outputfile, pkt, append=True)

def main(argv):
    global outputfile
    inputfile = ''
    outputfile = ''
    try:
        opts, args = getopt.getopt(argv,"hi:o:",["ifile=","ofile="])
    except getopt.GetoptError:
        print ('vxlan2pcap.py -i <inputfile> -o <outputfile>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print ('vxlan2pcap.py -i <inputfile> -o <outputfile>')
            sys.exit()
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofile"):
            outputfile = arg

    print("\nConverting packets from " + inputfile + " into " + outputfile + "...\n")

    # Read in packets (use PcapReader so we don't have to load large PCAPs in memory)
    with PcapReader(inputfile) as pkts:
        for pkt in pkts:
            # Write VXLAN payload if match
            if pkt.haslayer(VXLAN):
                try:
                    write(pkt[VXLAN].payload)
                 except:
                    print("VXLAN encapsulated packet not found.")
            # Otherwise, just write the packet
            else:
                print("No VXLAN packet to convert...writing original packet.")
                try:
                    write(pkt)
                except:
                    print("Couldn't write packet!")

    print("Done!")
if __name__ == "__main__":
   main(sys.argv[1:])
