#!/usr/bin/env python3
eeprom_bytes = open("eeprom.bin", "rb").read()

# Because we can only flip bits one way (1->0),
# We need to find a location which can be patched to "12 0A ??",
# Which is a branch to 0x0A??.
for i in range(len(eeprom_bytes)-3):
    byte1 = eeprom_bytes[i]
    byte2 = eeprom_bytes[i+1]

    if byte1 & 0x12 == 0x12 and byte2 & 0xA == 0xA:
        print(hex(i))
