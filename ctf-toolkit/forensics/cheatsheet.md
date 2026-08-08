# forensics cheatsheet

## first steps (any forensics chall)
```bash
file chall.*                           # identify file type
xxd chall.* | head -20                 # hex dump header
strings -n 6 chall.* | grep -iE "flag|ctf|inctf|key|secret"
exiftool chall.*                       # metadata
binwalk chall.*                        # embedded files
```

---

## steganography

### steghide (jpeg, bmp, wav, au)
```bash
steghide info image.jpg                     # check if data is embedded
steghide extract -sf image.jpg              # extract (asks for password)
steghide extract -sf image.jpg -p ""        # try empty password
steghide extract -sf image.jpg -p "password" # known password
```

### stegseek (bruteforce steghide)
```bash
stegseek image.jpg                          # auto brute with rockyou.txt
stegseek image.jpg wordlist.txt             # custom wordlist
stegseek --crack image.jpg rockyou.txt      # explicit crack mode
```

### zsteg (png, bmp - bit planes)
```bash
zsteg image.png                              # try all methods
zsteg -a image.png                           # all options
zsteg image.png -b 1                         # specific bit plane
zsteg -E "b1,rgb,lsb" image.png             # extract specific channel
```

### stegsolve (gui, java)
```bash
java -jar stegsolve.jar                      # launch GUI
# Navigate through:
#   - Bit planes (Red/Green/Blue plane 0-7)
#   - XOR / AND / OR between frames
#   - Data extract -> select channels, bit order
```
when to use: When zsteg doesn't find anything. Manually flip through bit planes looking for hidden text/images.

### lsb manual extraction
```python
from PIL import Image

img = Image.open('image.png')
pixels = img.load()
bits = ''
for y in range(img.height):
    for x in range(img.width):
        r, g, b = pixels[x, y][:3]
        bits += str(r & 1)
        bits += str(g & 1)
        bits += str(b & 1)

# Convert bits to bytes
flag = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
print(flag[:200])
```

### steg in specific channels
```bash
# Extract specific color channel
convert image.png -channel R -separate red.png
convert image.png -channel G -separate green.png
convert image.png -channel B -separate blue.png
convert image.png -channel A -separate alpha.png  # alpha channel!
```

---

## image forensics

### exiftool
```bash
exiftool image.jpg                           # all metadata
exiftool -GPS* image.jpg                     # GPS coordinates
exiftool -Comment image.jpg                  # comment field
exiftool -all= image.jpg                     # strip all metadata (for submission)
```

### file header analysis
```bash
xxd image.png | head -5                      # check magic bytes
file image.png                               # verify file type
```

common magic bytes:
| Type | Hex | ASCII |
|------|-----|-------|
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `.PNG....` |
| JPEG | `FF D8 FF` | `ÿØÿ` |
| GIF | `47 49 46 38` | `GIF8` |
| BMP | `42 4D` | `BM` |
| PDF | `25 50 44 46` | `%PDF` |
| ZIP | `50 4B 03 04` | `PK..` |
| RAR | `52 61 72 21` | `Rar!` |
| ELF | `7F 45 4C 46` | `.ELF` |
| PCAP | `D4 C3 B2 A1` | `Ô÷²¡` |

### fix corrupted headers
```bash
# PNG: fix IHDR CRC
python3 -c "
import struct, zlib
with open('broken.png','rb') as f: data = bytearray(f.read())
# Fix PNG signature
data[0:8] = b'\x89PNG\r\n\x1a\n'
with open('fixed.png','wb') as f: f.write(data)
"

# JPEG: fix header
printf '\xff\xd8\xff\xe0' | dd of=broken.jpg bs=1 conv=notrunc
```

### detect appended data
```bash
binwalk image.png                            # scan for embedded files
binwalk -e image.png                         # extract embedded files
foremost image.png -o output/               # carve files by header
strings image.png | tail -50                 # check end of file for appended text
```

### png dimension tricks
```python
# PNG width/height might be wrong — brute-force correct dimensions
import struct, zlib

with open('image.png', 'rb') as f:
    data = bytearray(f.read())

for h in range(1, 2000):
    data[0x14:0x18] = struct.pack('>I', h)  # modify height in IHDR
    crc = zlib.crc32(data[0x0C:0x1D]) & 0xffffffff
    data[0x1D:0x21] = struct.pack('>I', crc)
    # Try each height, save and view
```

---

## network forensics (pcap)

### wireshark
key filters:
```
http                                  # HTTP traffic
tcp.stream eq 0                       # follow specific TCP stream
dns                                   # DNS queries
ftp || ftp-data                       # FTP traffic
smtp || pop || imap                   # email protocols
tcp contains "flag"                   # search for flag in TCP
frame contains "inctf"               # search in all frames
http.request.method == "POST"         # HTTP POST requests
ip.src == 192.168.1.1                # filter by source IP
tcp.port == 4444                      # specific port
tls.handshake                        # TLS handshakes
```

right-click -> Follow -> TCP/HTTP Stream to reconstruct convo

### tshark (cli)
```bash
tshark -r capture.pcap                       # read pcap
tshark -r capture.pcap -Y "http"             # filter HTTP
tshark -r capture.pcap -Y "dns"              # filter DNS
tshark -r capture.pcap -Y "tcp contains flag" # search for flag
tshark -r capture.pcap -z "follow,tcp,ascii,0" # follow stream 0
tshark -r capture.pcap -T fields -e http.request.uri # extract URIs
tshark -r capture.pcap -T fields -e dns.qry.name     # extract DNS queries
tshark -r capture.pcap -Y "http.response" -T fields -e http.file_data # HTTP response bodies
tshark -r capture.pcap --export-objects http,exported/ # export HTTP files
```

### extract files from pcap
```bash
# Wireshark: File -> Export Objects -> HTTP / SMB / TFTP
# CLI:
tshark -r capture.pcap --export-objects http,output_dir/
tshark -r capture.pcap --export-objects smb,output_dir/

# Foremost on raw TCP:
tcpflow -r capture.pcap -o flow_output/
foremost -i flow_output/* -o carved/

# NetworkMiner (GUI): auto-extracts files, credentials, images
```

### common pcap patterns
| Pattern | What to check |
|---------|--------------|
| DNS exfiltration | `tshark -r cap.pcap -T fields -e dns.qry.name` -> decode subdomains |
| HTTP file upload | Filter `http.request.method == POST` -> check multipart data |
| FTP transfer | Follow FTP-DATA streams -> files transferred |
| Telnet/SSH creds | Follow TCP streams -> plaintext credentials |
| ICMP tunnel | Check ICMP data payload for hidden data |
| USB HID | Keyboard/mouse data in USB captures |

### usb keyboard pcap
```python
# For USB keyboard HID data captures
KEY_MAP = {4:'a',5:'b',6:'c',7:'d',8:'e',9:'f',10:'g',11:'h',12:'i',13:'j',
           14:'k',15:'l',16:'m',17:'n',18:'o',19:'p',20:'q',21:'r',22:'s',
           23:'t',24:'u',25:'v',26:'w',27:'x',28:'y',29:'z',30:'1',31:'2',
           32:'3',33:'4',34:'5',35:'6',36:'7',37:'8',38:'9',39:'0',
           40:'\n',44:' ',45:'-',46:'=',47:'[',48:']'}

# Extract with tshark:
# tshark -r usb.pcap -Y "usb.transfer_type==1" -T fields -e usb.capdata
```

---

## audio forensics

### audacity spectrograms
```
1. Open audio file in Audacity
2. Click track name -> Spectrogram
3. Look for text/images in the spectrogram view
4. Zoom in on specific frequency ranges
```

### sstv (image in audio)
```bash
# Decode SSTV signal to image
pip install sstv
sstv -d audio.wav -o output.png

# Or use qsstv (GUI): sudo apt install qsstv
```

### dtmf
```bash
# Install: pip install dtmf-decoder
# Or use: http://dialabc.com/sound/detect/
multimon-ng -t wav -a DTMF audio.wav
```

### morse code
```bash
# Listen and decode manually, or:
# Online: https://morsecode.world/international/decoder/audio-decoder-adaptive.html
```

### hidden data in audio
```bash
strings audio.wav | grep -i flag              # check for appended text
binwalk audio.wav                             # embedded files
steghide extract -sf audio.wav                # steghide works on WAV
sonic-visualiser audio.wav                    # advanced spectrogram analysis
# Check: different channels (L/R), spectrogram, waveform
```

---

## file carving

### binwalk
```bash
binwalk file.bin                              # scan for signatures
binwalk -e file.bin                           # extract embedded files
binwalk -D '.*' file.bin                      # extract everything
binwalk --dd='zip:zip' file.bin               # extract only zips
```

### foremost
```bash
foremost -i file.bin -o output/               # carve by file headers
foremost -t jpg,png,pdf -i file.bin -o out/   # specific types only
```

### scalpel
```bash
# Edit /etc/scalpel/scalpel.conf to enable file types
scalpel -c /etc/scalpel/scalpel.conf -o output/ file.bin
```

### dd — manual extraction
```bash
# Extract bytes from offset to end
dd if=file.bin of=extracted.zip bs=1 skip=12345

# Extract specific number of bytes
dd if=file.bin of=chunk.bin bs=1 skip=100 count=500
```

---

## decision tree
```
Got a file?
├- Image? -> exiftool -> steghide/stegseek -> zsteg -> stegsolve -> binwalk
├- Audio? -> Audacity spectrogram -> SSTV? -> DTMF? -> steghide
├- PCAP?  -> Wireshark -> follow streams -> export objects -> DNS/ICMP check
├- Binary blob? -> file -> binwalk -e -> foremost -> strings
├- Corrupted? -> xxd -> fix magic bytes -> fix dimensions
└- ZIP/archive? -> unzip -> check for password -> fcrackzip
```
