#/usr/bin/env python
import struct
import binascii
from en_nabcc_encoding import *

# Most of the functions we base our code on resides in this repo:
# https://github.com/google/brailleback
# The important one are under 'EuroBraille' directory, specifically 'eu_esysiris.c' file.

# Constants
STX = chr(0x02)
ETX = chr(0x03)
PAD = chr(0x55)
NUM_COLS = 0x50

def print_braille_row(data):
    """
    Print braille data visually.
    (We don't use it in the final solution)
    Notice that extended braille dots are organized this way:
    1  4
    2  5
    3  6
    7  8
    """
    assert len(data) == NUM_COLS
    text = ""
    rows = ["", "", "", ""]
    
    for byte in data:
        byte = ord(byte)
        rows[0] += "O" if byte & (1 << 0) else "."
        rows[1] += "O" if byte & (1 << 1) else "."
        rows[2] += "O" if byte & (1 << 2) else "."
        rows[3] += "O" if byte & (1 << 6) else "."
        rows[0] += "O" if byte & (1 << 3) else "."
        rows[1] += "O" if byte & (1 << 4) else "."
        rows[2] += "O" if byte & (1 << 5) else "."
        rows[3] += "O" if byte & (1 << 7) else "."

        rows[0] += " "
        rows[1] += " "
        rows[2] += " "
        rows[3] += " "
    
    # Print all the rows
    print rows[0]
    print rows[1]
    print rows[2]
    print rows[3]
    print ""

def parse_braille_row(data):
    """
    We get a braille data, and parse it as english.
    We use the 'en_nabcc' encoding from the BRLTTY project.
    """
    assert len(data) == NUM_COLS
    text = ""

    for byte in data:
        byte = ord(byte)
        brl_chr = 0
        brl_chr |= BRL_DOT1 if byte & (1 << 0) else 0
        brl_chr |= BRL_DOT2 if byte & (1 << 1) else 0
        brl_chr |= BRL_DOT3 if byte & (1 << 2) else 0
        brl_chr |= BRL_DOT4 if byte & (1 << 3) else 0
        brl_chr |= BRL_DOT5 if byte & (1 << 4) else 0
        brl_chr |= BRL_DOT6 if byte & (1 << 5) else 0
        brl_chr |= BRL_DOT7 if byte & (1 << 6) else 0
        brl_chr |= BRL_DOT8 if byte & (1 << 7) else 0

        try:
            text += chr(brl_encoding[brl_chr])
        except:
            text += "?"

    print text

def parse_txt(pkt, i):
    """
    Parse data generated by the 'writePacket' function,
    and by 'writeWindow' and 'initializeDevice' functions.
    """
    # Assert text start & end
    assert pkt[0] == STX
    data_length = struct.unpack(">H",pkt[1:3])[0]
    assert pkt[data_length+1] == ETX
    
    # Extract packet data
    packet_data = pkt[3:data_length+1]
    assert len(packet_data) == data_length - 2

    # Validate initiliaze device
    if i == 0:
        assert packet_data == "SI"
        return

    # Validate we are writing window
    assert packet_data[0:2] == "BS"
    translated_data = packet_data[2:]

    # Print as braille
    parse_braille_row(translated_data)
    #print_braille_row(translated_data)

# Leftover data from interrupt
def parse_interrupt(data):
    """
    Parse URB_INTERRUPT packet with the EuroBraille device.
    Adapted from the 'handleSystemInformation' function.
    """

    # Extract the data
    seqnum = struct.unpack("<B", data[0])[0]
    STX_index = 1
    if data[1] == PAD:
        STX_index = 2
    assert data[STX_index] == STX
    data_length = struct.unpack(">H",data[STX_index+1:STX_index+3])[0]
    assert data[data_length+STX_index+1] == ETX
    packet_data = data[STX_index+3:data_length+STX_index+1]
    assert len(packet_data) == data_length - 2
    
    # Maybe force-write
    if packet_data[0] == 'R' and packet_data[1] == 'P':
        print "seq {} - force-write".format(seqnum)
        return

    # Make sure it is system information
    assert packet_data[0] == 'S'
    subtype = packet_data[1]

    # Print its meaning
    if subtype == 'H':
        print "seq {} - short name: {}".format(seqnum, packet_data[2:])
    elif subtype == 'I':
        print "seq {} - End".format(seqnum)
    elif subtype == 'G':
        cols = struct.unpack("<B", packet_data[2])[0]
        print "seq {} - text columns = {}".format(seqnum, cols)
    elif subtype == 'S':
        print "seq {} - string".format(seqnum)   
    elif subtype == 'T':
        identifier = struct.unpack("<B", packet_data[2])[0]
        print "seq {} - identifier {}".format(seqnum, identifier)
        if 0x0c == identifier:
            print "model info:"
            print """  { .modelIdentifier = EU_ESYS_80,
    .modelName = "Esys 80",
    .cellCount = 80,
    .hasBrailleKeyboard = 1,
    .isEsys = 1,
    .keyTable = &KEY_TABLE_DEFINITION(esys_large)
  },"""
    else:
        print "seq {} - unknown subtype {}".format(seqnum, subtype)

def main():
    """
    Parse data from the 'feel-it' pcap-ng capture.
    Assume we ran the following commands earlier:
    $ tshark -r feel-it  -T fields -e usb.capdata | grep ":" > urb_interrupt_data.txt
    $ tshark -r feel-it -T fields -e usb.data_fragment | grep ":" > set_report_data.txt
    (Because we are lazy and don't want to parse the pcap here)
    """
    # Parse data of URB_INTERRUPT
    with open("urb_interrupt_data.txt", "r") as f:
        for line in f.readlines():
            hexdata = line.replace(":", "").rstrip().decode("hex")
            parse_interrupt(hexdata)
    
    # Read data of SET_REPORT
    with open("set_report_data.txt", "r") as f:
        # Aggregate reports splitted by writeData_USB
        packets = []
        current_packet = ""
        for line in f.readlines():
            hexdata = line.replace(":","").rstrip().decode("hex")
            current_packet += hexdata
            # Check if should end aggregation
            if ord(hexdata[-1]) == 0x55:
                packets.append(current_packet)
                current_packet = ""
        
        # Parse packets
        for i, pkt in enumerate(packets):
            parse_txt(pkt, i)

if __name__ == "__main__":
    main()

