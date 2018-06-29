
# Feel It
This task was part of the 'MISC' category at the 2018 Google CTF Quals round (during 23-24 June 2018).

It was solved by [or523](https://github.com/or523), in [The Maccabees](https://ctftime.org/team/60231) team.

## The challenge
The only hint given in the website is:
```
I have a feeling there is a flag there somewhere
```
Downloading and extracting the attached zip, we get a single pcap capture file:
```
feel-it: pcap-ng capture file - version 1.0
```
Popping it into wireshark, we see a few packets of USB communication.
I don't know a thing about the USB protocol, but I started to play around with the capture and see what information I can deduce. At start, one type of packets which gets sent all the time pops into my eye, of type ```URB_INTERRUPT```.
In some of these packets (the few first), in addition to the regular data in these packets, there was some 'Leftover Capture Data' (```usb.capdata```), which seems in first sight like additional payload data in these packets. After extracting the data with ```tshark -r feel-it -T fields -e usb.capdata``` and playing with it a bit - we couldn't find anything interesting (most of these packets doesn't carry any leftover data at alll).

Another type of packets that seem to contain data are packets of type ```SET_REPORT``` above the ```USBHID``` layer. Inside the packet, under ```URB_SETUP```, there seem to be a "Data Fragment" field which contains some data, always of length 64 bytes. Again, extracting the data with ```tshark```, it doesn't make much sense by itself; the only thing noticeable here is that some of the packets are padded with ```0x00```, and the other ones are padded with ```0x55``` (```'U'```). A sample of some of these data frgaments:
```
02:00:04:53:49:03:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55
02:00:54:42:53:1d:15:1e:00:01:1d:00:41:5e:24:4e:4f:4a:06:00:1e:11:2d:1e:00:3a:0a:19:1b:11:1e:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:03:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55
02:00:54:42:53:43:57:47:5e:5e:7d:00:22:28:16:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:03:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55:55
```
In this stage, we understood that we must have a better understanding of the two communicating sides - otherwise, deducing what is going on will be super-hard. It is easy to see that the first 32 packets in the capture are some sort of initilization of the communication - a lof of ```GET DESCRIPTOR``` requests and responses, and some ```SET_CONFIGURATION``` packets as well. This could be very useful - especially because we see that the payload at the ```GET_DESCRIPTOR``` responses is a string - but when reading the actual data, all we get is:
```
'Manufacturer is confidential'
'and so is product string'
'not to mention serial number'
```
Google censored the strings... But we still have some hope - after the very first ```GET DESCRIPTOR``` request, which seems to have a descriptor type of ```DEVICE``` (```0x0```), we get in response the following data:
```
Frame 2: 82 bytes on wire (656 bits), 82 bytes captured (656 bits) on interface 0
USB URB
...
DEVICE DESCRIPTOR
    bLength: 18
    bDescriptorType: 0x01 (DEVICE)
...
    idVendor: Keil Software, Inc. (0xc251)
    idProduct: Unknown (0x1126)
   ```
We have a vendor ID and a product ID! Although googling "Keil Software" doesn't yield any interesting results, searching for the actual values (```0xc251```, ```0x1126```) we find [the following file](https://github.com/google/brailleback/blob/master/third_party/brltty/Drivers/Braille/EuroBraille/eu_braille.c), under a github repository by google, called **[brailleback](https://github.com/google/brailleback)**. Looking at the first line of the file, and in the relevant lines for our product & vendor ID:
```c
/*
* BRLTTY - A background process providing access to the console screen (when in
* text mode) for a blind person using a refreshable braille display.
*
```
```c
static const UsbChannelDefinition usbChannelDefinitions[] = {
...
	{ /* Esys (version >= 3.0, no SD card) */
	  .vendor=0XC251, .product=0X1126,
	  .configuration=1, .interface=0, .alternative=0,
	  .inputEndpoint=1, .outputEndpoint=0
	}
...
}
```
And reading briefly into the file, we find some more interesting functions such as ```writeData_USB```.

It seems now that we got a better understanding of what exactly is going on: this device is some sort of [refreshable braille display](https://en.wikipedia.org/wiki/Refreshable_braille_display), connected to the computer in order to help blind pepole read text.
For whom of you who doesn't know, [braille](https://en.wikipedia.org/wiki/Braille) is a writing system for blind pepole, who relies on touching the paper and feeling the characters, making reading possible for the visually impaired. The refreshable braille displays are the new generation of braille reading - a devices that can dynamically raise and lower pins on the device. Braille chracters are usually a 3x2 (or, in the extended version, 4x2) matrix of dots, in which each dot can be on (raised) or off (not there). For example, some braille characters might look like this:

![A sentence written in braille characters](https://upload.wikimedia.org/wikipedia/commons/4/48/LouisBraille.png)

While the rereshable braille display could look something like that (and this model is actually the one used here - from [EuroBraille](http://www.eurobraille.fr/en/esys)) - notice the little dynamic braille characters on the device:
![esys series](http://www.eurobraille.fr/images/esys-series-EN.png)

One last hint that we are on the right track was the task name - **Feel It**, which now makes much more sense - as the purpose of this device is to feel the characters it's displaying.

Great! After we understand what are the devices that are communicating, it seems obvious that what we have here is some sort of activation and usage of a refreshable braille display, and that our goal is to extract the actual braille chracters from the packet capture. My immeidate guess was that this capture actually abuses the braille display, and using the display shows some image (which isn't actually braille characters), but I was later proven wrong.

So let's start exploring! We already have the exact source file, which seems to contain the driver that is actually responsible for communication with the device. As we saw earlier, the ```writeData_USB``` function seems interesting, so let's look what it does:
```c
static ssize_t
writeData_USB (BrailleDisplay *brl, const void *data, size_t length) {
  size_t offset = 0;

  while (offset < length) {
    unsigned char report[64];
    size_t count = length - offset;

    if (count > sizeof(report)) {
      count = sizeof(report);
    } else {
      memset(&report[count], 0X55, (sizeof(report) - count));
    }
    memcpy(report, data+offset, count);

    updateWriteDelay(brl, sizeof(report));
    if (gioSetHidReport(brl->gioEndpoint, 0, report, sizeof(report)) < 0) return -1;

    offset += count;
  }

  return length;
}
```
It seems that this function just get a buffer of data (and its length), split it into 64-bytes chunks ('reports'), and send them in order. In the last chunk, the remaining bytes in the chunk are padded with a value of 0x55 (```'U'```).  The functions called are ```updateWriteDelay```, which does nothing too interesting (updating some internal value), and ```gioSetHidReport``` - which does the actual USB communication - a ```SET_REPORT``` packet over the USBHID layer. That's great! This is just the pattern we saw at the ```SET_REPORT``` packets in the capture - 64-bytes packets, some padded with 0x55.

We can now easily conclude that the packets were eventually sent with this function, and we can also write a simple (yet ugly) python script that will aggregate the reports into complete data packet (meaning - the original buffer that the ```writeData_USB ``` function was called with) using the 0x55 padding (for simplicity - we assume that if a data fragment ends with 0x55, it is the last fragment of the current report).
```python
# Read data of SET_REPORT
with open("report_fragments.txt", "r") as f:
    packets = []
    current_packet = ""
    for line in f.readlines():
        hexdata = line.replace(":","").rstrip().decode("hex")
        current_packet += hexdata
        # Check if end of packet
        if ord(hexdata[-1]) == 0x55:
            packets.append(current_packet)
            current_packet = ""
            
# Parse packets
for i, pkt in enumerate(packets):
    parse_packet(pkt, i)
```
Great! But the packets still contains a lot of data we do not know how to parse. If we print the actual data (```0x55``` padding stripped), we see an interesting pattern: the data always starts with ```0x02``` byte and ends with ```0x03``` byte. 
Let's get back to the code, and try to find who calls the ```writeData_USB``` function. The ```eu_braille.c``` itself doesn't contain any calls, but let's look at all the file in the directory ```brltty/Drivers/Braille/EuroBraille```. There are a few call sites (all using the function pointer ```io->writeData```), but one intersting one - in the file ```eu_esysiris.c```:
```c
static ssize_t
writePacket (BrailleDisplay *brl, const void *packet, size_t size) {
  int packetSize = size + 2;
  unsigned char buf[packetSize + 2];
  if (!io || !packet || !size)
    return (-1);
  buf[0] = STX;
  buf[1] = (packetSize >> 8) & 0x00FF;
  buf[2] = packetSize & 0x00FF;
  memcpy(buf + 3, packet, size);
  buf[sizeof(buf)-1] = ETX;
  logOutputPacket(buf, sizeof(buf));
  return io->writeData(brl, buf, sizeof(buf));
}
```
After some grepping we also discover that (in ASCII) ```STX = 0x02``` and ```ETX = 0x03``` - and it seems we found the correct function. These characters indicate the start and end of the text, and the second and third bytes indicate the length of the text. So we can easily parse this as well:
```python
def parse_packet(pkt, i):
    # Assert text start & end
    assert pkt[0] == STX
    data_length = struct.unpack(">H",pkt[1:3])[0]
    assert pkt[data_length+1] == ETX

    # Extract packet data
    packet_data = pkt[3:data_length+1]
    assert len(packet_data) == data_length - 2
```
Okay, let's continue xrefing! Now, when we extracted the data from the packets, we see another interesting pattern: the first packets starts with the bytes ```"SI"``` (and only them), while all the other packets start with the bytes ```"SB"```, and ```0x50``` bytes of data afterwards. But we easily can understand why by looking at the callers of ```writePacket```:
```c
initializeDevice (BrailleDisplay *brl) {
  ...
      static const unsigned char packet[] = {LP_SYSTEM, LP_SYSTEM_IDENTITY}; // {'S', 'I'}
      if (writePacket(brl, packet, sizeof(packet)) == -1) return 0;
  ...
    }
```
So it's obvious the ```"SI"``` packet is some part of the initilization device. Another interesting function:
```c
static int
writeWindow (BrailleDisplay *brl) {
  static unsigned char previousCells[MAXIMUM_DISPLAY_SIZE];
  unsigned int size = brl->textColumns * brl->textRows;

  if (cellsHaveChanged(previousCells, brl->buffer, size, NULL, NULL, &forceWindowRewrite)) {
    unsigned char data[size + 2];
    unsigned char *byte = data;

    *byte++ = LP_BRAILLE_DISPLAY; // 'S'
    *byte++ = LP_BRAILLE_DISPLAY_STATIC; // 'B'
    byte = translateOutputCells(byte, brl->buffer, size);

    if (writePacket(brl, data, byte-data) == -1) return 0;
  }

  return 1;
}
```
This seems to be the function we needed - the one who actually writes the data to the screen. We see the ```"SB"``` prefix as a good indication that our location is correct; and we can conclude that ```size == 0x50``` (because the length of the actual data). Our assumption at this stage is that each byte sent here represents a single braille character written on the device (because we see that the number of bytes is a multiply of the text columns and rows).
Looking at ```translateOutputCells``` function, it seems to translate the output bytes to different encoding, in which it transforms each bit of the output byte to another bit in the input byte. From the code, it is obvious that each bit represents one braille dot, because we can see the translation table creation (in the file ```Programs/brl_base.c```):
```c
const DotsTable dotsTable_ISO11548_1 = {
  BRL_DOT_1, BRL_DOT_2, BRL_DOT_3, BRL_DOT_4,
  BRL_DOT_5, BRL_DOT_6, BRL_DOT_7, BRL_DOT_8
};
...
void
makeTranslationTable (const DotsTable dots, TranslationTable table) {
  int byte;

  for (byte=0; byte<TRANSLATION_TABLE_SIZE; byte+=1) {
    unsigned char cell = 0;
    int dot;

    for (dot=0; dot<DOTS_TABLE_SIZE; dot+=1) {
      if (byte & dotsTable_ISO11548_1[dot]) {
        cell |= dots[dot];
      }
    }

    table[byte] = cell;
  }
}
```
And the actual definitions of the dots as bitfields (in ```Headers/brl_dots.h```):
```c
#define BRL_DOT_COUNT 8

#define BRL_DOT(number) (BrlDots)(1 << ((number) - 1))
#define BRL_DOT_1 BRL_DOT(1) /* upper-left dot of standard braille cell */
#define BRL_DOT_2 BRL_DOT(2) /* middle-left dot of standard braille cell */
#define BRL_DOT_3 BRL_DOT(3) /* lower-left dot of standard braille cell */
#define BRL_DOT_4 BRL_DOT(4) /* upper-right dot of standard braille cell */
#define BRL_DOT_5 BRL_DOT(5) /* middle-right dot of standard braille cell */
#define BRL_DOT_6 BRL_DOT(6) /* lower-right dot of standard braille cell */
#define BRL_DOT_7 BRL_DOT(7) /* lower-left dot of computer braille cell */
#define BRL_DOT_8 BRL_DOT(8) /* lower-right dot of computer braille cell */
```
Cool! So each byte represents a braille character, and each bit in it represnts a different braille dot. Notice that we can know now that we are using the extended braille format, which have 8 dots instead of 6, because there are clearly some bytes with the 7th and 8th bits on (also - notice the suprising locations of the 7th and 8th dots on the 4x2 grid).

(Another thing we did was to understand the data passing in the ```USB_URB``` packets - but we will not talk about that anymore. The only important conclusion we got is that the display is a single row of ```0x50``` braille characters. If you want to discover more - refer to the attached script and read the ```handleSystemInformation``` function in the mentioned file).

We can now complete the python script, and make it print our braille characters (in hope of finding some sort of image there). Here is a sample of the output (```O``` for dot that is on; ```.``` for a dot that is off):
```
.O O. O. OO .O .O .O .O O. O. O. O. .. .O OO OO .. OO .O OO .O O. .. OO O. .O O. OO OO .O .O .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 
O. O. .O OO O. OO .. O. OO .O O. O. .. .O OO O. .. .. OO O. O. OO O. .O .O .O .. .O .O .O O. OO .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 
.O O. .. .. .. O. .. O. .. .. O. O. .. .. .O .O .. .. O. .. .O .. .. .. .. .O .. O. .. .O O. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 
O. .. .. .. .. .. O. .. .. .. .. .. .. .. O. .. .. O. O. O. .. .. .. .. .. .. .. .. .. .. .. .. OO .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 

.O O. O. OO .O .O .O .O O. O. O. O. .. .O OO OO .. OO .O OO .O O. .. OO O. .O O. OO OO .O .O .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 
O. O. .O OO O. OO .. O. OO .O O. O. .. .O OO O. .. .. OO O. O. OO O. .O .O .O .. .O .O .O O. OO OO .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 
.O O. .. .. .. O. .. O. .. .. O. O. .. .. .O .O .. .. O. .. .O .. .. .. .. .O .. O. .. .O O. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 
O. .. .. .. .. .. O. .. .. .. .. .. .. .. O. .. .. O. O. O. .. .. .. .. .. .. .. .. .. .. .. .. .. OO .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 

.O O. O. OO .O .O .O .O O. O. O. O. .. .O OO OO .. OO .O OO .O O. .. OO O. .O O. OO OO .O .O .. .. O. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 
O. O. .O OO O. OO .. O. OO .O O. O. .. .O OO O. .. .. OO O. O. OO O. .O .O .O .. .O .O .O O. OO OO .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 
.O O. .. .. .. O. .. O. .. .. O. O. .. .. .O .O .. .. O. .. .O .. .. .. .. .O .. O. .. .O O. .. .. O. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 
O. .. .. .. .. .. O. .. .. .. .. .. .. .. O. .. .. O. O. O. .. .. .. .. .. .. .. .. .. .. .. .. .. .. OO .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 

.O O. O. OO .O .O .O .O O. O. O. O. .. .O OO OO .. OO .O OO .O O. .. OO O. .O O. OO OO .O .O .. .. O. OO .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 
O. O. .O OO O. OO .. O. OO .O O. O. .. .O OO O. .. .. OO O. O. OO O. .O .O .O .. .O .O .O O. OO OO .. OO .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 
.O O. .. .. .. O. .. O. .. .. O. O. .. .. .O .O .. .. O. .. .O .. .. .. .. .O .. O. .. .O O. .. .. O. .O .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 
O. .. .. .. .. .. O. .. .. .. .. .. .. .. O. .. .. O. O. O. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. OO .. .. .. .. .. .. .. .. .. .. .. .. .. .. 

OO O. .O .. O. OO .. O. .O .. .O OO .O .. .. .O O. OO .O .. .O .O OO OO O. .O .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 
.O .O OO .. .. .O .. .. OO .. O. O. O. O. .. OO .O .. OO .. OO O. .O OO .O OO .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 
O. O. O. .. .. O. .. .. O. OO O. O. .. O. .. O. .. OO O. .. .O .. .. .. .. O. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 
.. .. .. .. .. .. .. O. O. .. O. O. O. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. .. 
```
Looks cool, but doesn't make much sense... we were probably wrong; these braille characters are probably actually meant for blind people to read as English. 
In order to do so, we will use the [BRLTTY](http://mielke.cc/brltty/) project source - which is used to handle such braille displays. The code we were looking was already part of the BRLTTY project, but wasn't the complete source tree.
Inside the BRLTTY source tree, we find ```en-nabcc.ttb``` file - which is exactly what we wanted: a translation table from extended (8-dot) braille characters into english characters. It looks something like this:
```
...
     #Hex    Dots       Dec Char Description
char \X20 (        )  #  32      space
char \X61 (1       )  #  97   a  latin small letter a
char \X62 (12      )  #  98   b  latin small letter b
char \X63 (1  4    )  #  99   c  latin small letter c
char \X64 (1  45   )  # 100   d  latin small letter d
char \X65 (1   5   )  # 101   e  latin small letter e
char \X66 (12 4    )  # 102   f  latin small letter f
char \X67 (12 45   )  # 103   g  latin small letter g
char \X68 (12  5   )  # 104   h  latin small letter h
...
```
So we easily integrated this translation to the python script (this was, of course, after several other encodings we tried - that just outputted garbage instead of actual text), and the output we get:
```
not an AT-SPI2 text widget                                                      
BRLTTY 5.6                                                                      
?                                                                               
[legit@shell ~]$?                                                               
[legit@shell ~]$C?                                                              
[legit@shell ~]$CT?                                                             
[legit@shell ~]$CTF?                                                            
[legit@shell ~]$CTF{?                                                           
[legit@shell ~]$CTF                                                            
[legit@shell ~]$CT{                                                            
[legit@shell ~]$CF{                                                            
[legit@shell ~]$TF{                                                            
[legit@shell ~]$ TF{                                                           
[legit@shell ~]$ CF{                                                           
[legit@shell ~]$ CT{                                                           
[legit@shell ~]$ CTF                                                           
[legit@shell ~]$ CTF{?                                                          
[legit@shell ~]$ CTF{h?                                                         
[legit@shell ~]$ CTF{h!?                                                        
[legit@shell ~]$ CTF{h!d?                                                       
[legit@shell ~]$ CTF{h!de?                                                      
[legit@shell ~]$ CTF{h!d                                                       
[legit@shell ~]$ CTF{h!e                                                       
[legit@shell ~]$ CTF{he                                                        
[legit@shell ~]$ CTF{h!e                                                       
[legit@shell ~]$ CTF{he                                                        
[legit@shell ~]$ CTF{h1e                                                       
[legit@shell ~]$ CTF{h1d                                                       
[legit@shell ~]$ CTF{h1de?                                                      
[legit@shell ~]$ CTF{h1de_?                                                     
[legit@shell ~]$ CTF{h1de_a?                                                    
[legit@shell ~]$ CTF{h1de_an?                                                   
[legit@shell ~]$ CTF{h1de_and?                                                  
[legit@shell ~]$ CTF{h1de_and_?                                                 
[legit@shell ~]$ CTF{h1de_and_s?                                                
[legit@shell ~]$ CTF{h1de_and_s#?                                               
[legit@shell ~]$ CTF{h1de_and_s##?                                              
[legit@shell ~]$ CTF{h1de_and_s#?                                               
[legit@shell ~]$ CTF{h1de_and_s?                                                
[legit@shell ~]$ CTF{h1de_and_s3?                                               
[legit@shell ~]$ CTF{h1de_and_s33?                                              
[legit@shell ~]$ CTF{h1de_and_s33k?                                             
[legit@shell ~]$ CTF{h1de_and_s33k}?                                            
not an AT-SPI2 text widget                                                      
```
Yay! the flag is ```CTF{h1de_and_s33k}```; and we assume all the other lines are used to create some sort of moving text on the refreshable braille display itself.

## Conclusion
The challenge was really fun. This writeup ended up longer than I thought, although I still hid some details from you, such as the format of the ```USB_URB``` message, or the various struggles with different encodings of braille.

See you next CTF!
\~ or523


> Written with [StackEdit](https://stackedit.io/).
