# hardware / embedded cheatsheet

## first steps
```bash
file firmware.bin                            # identify type
binwalk firmware.bin                         # scan for filesystems, compressed data
strings -n 8 firmware.bin | grep -iE "password|root|admin|flag|key|secret"
entropy firmware.bin                         # packed/encrypted sections?
```

---

## uart / serial

### what is uart?
- Universal Asynchronous Receiver/Transmitter
- 2 data lines: **TX** (transmit), **RX** (receive) + **GND**
- Common in embedded devices for debug consoles
- Usually gives you a root shell!

### finding uart on a board
1. Look for 3-4 pin headers labeled **J1, JP1, DEBUG, CONSOLE**
2. Use a multimeter:
   - **GND**: continuity to ground plane
   - **VCC**: 3.3V or 5V (don't connect this)
   - **TX**: fluctuates when device boots (it's transmitting)
   - **RX**: steady state (waiting for input)
3. Or use a logic analyzer to identify active pins

### connecting via usb-uart adapter
```bash
# Common adapters: FTDI FT232, CP2102, CH340
# Connect: Adapter TX -> Device RX, Adapter RX -> Device TX, GND -> GND

# Find serial device
ls /dev/ttyUSB* /dev/ttyACM*

# Connect with screen (most common)
screen /dev/ttyUSB0 115200

# Or minicom
minicom -D /dev/ttyUSB0 -b 115200

# Or picocom
picocom /dev/ttyUSB0 -b 115200
```

### baud rate detection
```bash
# Common baud rates: 9600, 19200, 38400, 57600, 115200
# If garbage output -> wrong baud rate

# Auto-detect with baudrate.py:
# https://github.com/devttys0/baudrate
python3 baudrate.py -p /dev/ttyUSB0

# Or use sigrok / PulseView logic analyzer
```

### common baud rates
| Device type | Typical baud |
|------------|-------------|
| Most embedded Linux | 115200 |
| Arduino | 9600 or 115200 |
| ESP8266/ESP32 | 115200 or 74880 (boot) |
| Routers | 115200 |
| Old devices | 9600 |

---

## spi / i2c / jtag

### spi
```
Signals: MOSI, MISO, CLK, CS (Chip Select)
Used for: Flash memory (EEPROM), SD cards
```

reading spi flash:
```bash
# With flashrom + SPI programmer (e.g., Bus Pirate, CH341A)
flashrom -p ch341a_spi -r flash_dump.bin

# With a Bus Pirate:
flashrom -p buspirate_spi:dev=/dev/ttyUSB0 -r dump.bin
```

### i2c
```
Signals: SDA (data), SCL (clock)
Used for: sensors, EEPROMs, RTCs
```

scanning i2c bus:
```bash
# Linux i2c-tools
i2cdetect -y 1                    # scan bus 1
i2cdump -y 1 0x50                 # dump device at address 0x50
i2cget -y 1 0x50 0x00             # read byte
```

### jtag
```
Signals: TDI, TDO, TMS, TCK, TRST (optional)
Used for: debugging, firmware extraction, boundary scan
```

jtag tools:
```bash
# OpenOCD
openocd -f interface/ftdi.cfg -f target/stm32f1x.cfg
# Then connect with GDB:
arm-none-eabi-gdb
target remote :3333

# JTAGulator — auto-detect JTAG pins
# https://github.com/grandideastudio/jtagulator
```

### logic analyzer
```bash
# sigrok / PulseView — open source logic analyzer
pulseview                          # GUI
sigrok-cli -d fx2lafw -o capture.sr -C D0,D1,D2 --time 5s

# Decode protocols in PulseView:
# Add decoder -> UART / SPI / I2C -> set parameters
```

---

## embedded linux

### firmware extraction (binwalk)
```bash
binwalk firmware.bin                         # identify contents
binwalk -e firmware.bin                      # extract
cd _firmware.bin.extracted/

# Look for filesystem:
ls                                           # squashfs, cramfs, jffs2
find . -name "*.conf" -o -name "passwd" -o -name "shadow"
cat etc/passwd                               # hardcoded credentials?
cat etc/shadow                               # password hashes?
find . -name "flag*"                         # flag files
grep -r "flag{" .                            # search for flag
grep -r "password" etc/                      # hardcoded passwords
```

### squashfs
```bash
# Extract SquashFS filesystem
unsquashfs filesystem.squashfs
cd squashfs-root/

# If unsquashfs fails (wrong version):
# Try: sasquatch (handles vendor-modified squashfs)
# https://github.com/devttys0/sasquatch
sasquatch filesystem.squashfs
```

### cramfs
```bash
# Extract CramFS
cramfsck -x extracted/ filesystem.cramfs
# Or: uncramfs extracted/ filesystem.cramfs
```

### jffs2
```bash
# Extract JFFS2
jefferson -d extracted/ filesystem.jffs2
# https://github.com/sviehb/jefferson
```

### u-boot
```bash
# U-Boot bootloader analysis
strings firmware.bin | grep -i "u-boot"
strings firmware.bin | grep "bootargs"       # kernel boot arguments
strings firmware.bin | grep "console="       # serial console config

# If you have U-Boot shell access:
# Common commands:
printenv                                     # show environment variables
md 0x80000000 100                           # memory dump
nand read 0x80000000 0x0 0x100000           # read NAND flash
bootm 0x80000000                            # boot from memory
```

### firmware-mod-kit
```bash
# https://github.com/rampageX/firmware-mod-kit
./extract-firmware.sh firmware.bin
# Modify files in fmk/rootfs/
./build-firmware.sh
```

---

## arduino / microcontroller

### arduino sketch analysis
```bash
# .ino files are C/C++ — read directly
# .hex files — flash dumps, can disassemble:
avr-objdump -m avr -D firmware.hex

# If you have a .elf:
avr-objdump -d firmware.elf
```

### common mcus
| MCU | Architecture | Tools |
|-----|-------------|-------|
| ATmega328 (Arduino Uno) | AVR | avr-gdb, avr-objdump |
| STM32 | ARM Cortex-M | arm-none-eabi-gdb, OpenOCD |
| ESP8266/ESP32 | Xtensa | esptool, xtensa-esp32-elf-objdump |
| PIC | PIC | gputils, MPLAB |

### esptool
```bash
# Read flash
esptool.py --port /dev/ttyUSB0 read_flash 0 0x400000 flash.bin

# Write flash
esptool.py --port /dev/ttyUSB0 write_flash 0 firmware.bin

# Chip info
esptool.py --port /dev/ttyUSB0 chip_id
```

---

## decision tree
```
Hardware challenge?
├- Given a firmware blob -> binwalk -e -> explore filesystem -> grep flag
├- Given serial/logic data -> decode UART (find baud) -> read console
├- Given I2C/SPI capture -> PulseView -> decode protocol -> extract data
├- Given JTAG access -> OpenOCD -> dump flash -> analyze
├- Given .hex/.elf -> disassemble with arch-specific objdump
└- Given PCB photo -> identify chips -> find datasheets -> find debug ports
```
