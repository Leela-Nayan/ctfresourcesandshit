# automotive & OT cheatsheet

---

## can bus

### what is can?
- Controller Area Network — vehicle communication bus
- All ECUs (Electronic Control Units) share the same bus
- Messages have: **Arbitration ID** (11 or 29 bit) + **Data** (0-8 bytes)
- No authentication by default -> replay attacks work!

### can-utils
```bash
# Setup virtual CAN (for testing)
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

# Setup real CAN interface (e.g., SocketCAN adapter)
sudo ip link set can0 type can bitrate 500000
sudo ip link set up can0
```

### candump
```bash
candump vcan0                                # dump all traffic
candump vcan0 -L                             # log format (for replay)
candump vcan0 -l                             # log to file (candump-*.log)
candump can0,123:7FF                         # filter by ID 0x123
candump can0 -t a                            # absolute timestamps
```

### cansend
```bash
cansend vcan0 123#DEADBEEF                   # send ID=0x123, data=DEADBEEF
cansend vcan0 123#R                          # Remote Transmission Request
cansend vcan0 7DF#0201050000000000           # OBD-II query (PID 0x05 = coolant temp)
```

### canplayer (replay)
```bash
canplayer -I candump.log                     # replay log file
canplayer -I candump.log vcan0=can0          # replay to different interface
```

### cansniffer
```bash
cansniffer vcan0                             # real-time view, highlights changes
# Colors show changing data — helps identify what controls what
```

### cangen
```bash
cangen vcan0 -g 100 -I 123 -L 8 -D i       # generate ID=0x123, incrementing data
```

### savvycan (gui)
```bash
# https://github.com/collin80/SavvyCAN
# Open .csv or capture live
# Features: DBC file support, graphing, fuzzing, scripting
```

---

## can analysis techniques

### identify interesting ids
```bash
# Step 1: Record baseline (car idle)
candump can0 -l &
sleep 30
kill %1

# Step 2: Perform action (turn steering, press brake, etc.)
# Step 3: Record during action
# Step 4: Diff the captures
```

### find specific signals
```python
#!/usr/bin/env python3
"""Analyze CAN log for changing values."""
import sys
from collections import defaultdict

messages = defaultdict(set)

with open(sys.argv[1]) as f:
    for line in f:
        parts = line.strip().split()
        if len(parts) >= 3 and '#' in parts[2]:
            can_id, data = parts[2].split('#')
            messages[can_id].add(data)

# Show IDs with changing data (likely interesting)
for can_id, data_set in sorted(messages.items()):
    if len(data_set) > 1:
        print(f"ID 0x{can_id}: {len(data_set)} unique values")
        for d in sorted(data_set)[:5]:
            print(f"  {d}")
```

### replay attack
```bash
# 1. Capture the action (e.g., unlock door)
candump can0 -l                              # logs to candump-*.log

# 2. Filter to the relevant time window
# 3. Replay
canplayer -I candump-2024-01-01_120000.log
```

### can fuzzing
```bash
# Fuzz all IDs:
for id in $(seq 0 2047); do
    cansend vcan0 $(printf "%03X" $id)#FFFFFFFFFFFFFFFF
    sleep 0.01
done

# Fuzz specific ID data:
for i in $(seq 0 255); do
    cansend vcan0 123#$(printf "%02X" $i)00000000000000
    sleep 0.01
done
```

---

## vin

### vin via obd-ii
```bash
# OBD-II request for VIN (Mode 09, PID 02)
cansend can0 7DF#0902000000000000

# Response comes on 7E8 (or 7E0-7E7)
# VIN is 17 ASCII characters spread across multiple frames
```

### vin decode
```python
# VIN structure (17 chars):
# [1-3] WMI (World Manufacturer Identifier)
# [4-8] VDS (Vehicle Descriptor Section)  
# [9]   Check digit
# [10]  Model year
# [11]  Plant code
# [12-17] Sequential number

# Online decoder: https://vpic.nhtsa.dot.gov/decoder/
```

---

## modbus

### what is modbus?
- Industrial communication protocol (1979, still everywhere)
- Master-slave architecture
- **Modbus TCP**: port 502 (modern)
- **Modbus RTU**: serial (RS-485)
- No authentication! Read/write any register!

### modbus function codes
| Code | Function | Description |
|------|----------|-------------|
| 0x01 | Read Coils | Read digital outputs (ON/OFF) |
| 0x02 | Read Discrete Inputs | Read digital inputs |
| 0x03 | Read Holding Registers | Read analog values (16-bit) |
| 0x04 | Read Input Registers | Read input registers |
| 0x05 | Write Single Coil | Write single digital output |
| 0x06 | Write Single Register | Write single 16-bit value |
| 0x0F | Write Multiple Coils | Write multiple outputs |
| 0x10 | Write Multiple Registers | Write multiple values |

### modbus tcp (python)
```python
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('192.168.1.100', port=502)
client.connect()

# Read holding registers (address 0, count 10, unit/slave 1)
result = client.read_holding_registers(0, 10, slave=1)
print(result.registers)

# Read coils
result = client.read_coils(0, 10, slave=1)
print(result.bits)

# Write single register
client.write_register(0, 1234, slave=1)

# Write single coil (ON/OFF)
client.write_coil(0, True, slave=1)

# Scan all registers
for addr in range(0, 1000):
    try:
        result = client.read_holding_registers(addr, 1, slave=1)
        if not result.isError():
            print(f"Register {addr}: {result.registers[0]}")
    except:
        pass

client.close()
```

### modbus in wireshark
```
# Filter: modbus
# Look for:
#   - Function code in packet
#   - Register addresses being read/written
#   - Values being sent
modbus                                       # all Modbus traffic
modbus.func_code == 3                        # Read Holding Registers
modbus.func_code == 6                        # Write Single Register
modbus.func_code == 16                       # Write Multiple Registers
modbus.regval_uint16                         # register values
```

### modbus pcap analysis
```bash
tshark -r capture.pcap -Y "modbus" -T fields \
    -e modbus.func_code \
    -e modbus.reference_num \
    -e modbus.regval_uint16
```

### modbus-cli
```bash
# npm install -g modbus-cli
modbus read 192.168.1.100 0 10              # read 10 registers from 0
modbus write 192.168.1.100 0 1234           # write value to register 0
```

---

## other ot protocols

### dnp3
```
Wireshark filter: dnp3
# Common in power grid SCADA
# Look for: data objects, control commands
```

### s7comm (siemens)
```
Wireshark filter: s7comm
# Siemens PLC communication
# Look for: read/write variables, PLC program uploads
```

### ethernet/ip
```
Wireshark filter: enip || cip
# Rockwell/Allen-Bradley PLCs
```

### bacnet
```
Wireshark filter: bacnet
# HVAC, lighting, access control
```

---

## tools

| Tool | What | Install/URL |
|------|------|------------|
| **can-utils** | CAN bus tools | `apt install can-utils` |
| **SavvyCAN** | CAN GUI analyzer | https://github.com/collin80/SavvyCAN |
| **caringcaribou** | CAN security tool | https://github.com/CaringCaribou/caringcaribou |
| **pymodbus** | Modbus Python client | `pip install pymodbus` |
| **modbus-cli** | Modbus CLI tool | `npm install -g modbus-cli` |
| **Wireshark** | Protocol analyzer | Built-in Modbus, CAN, DNP3, S7comm decoders |
| **scapy** | Packet crafting | `pip install scapy` (has CAN layer) |

## decision tree
```
OT/Auto challenge?
├- CAN log file -> parse IDs -> find changing data -> replay/decode
├- Modbus PCAP -> filter modbus -> extract register reads/writes
├- Modbus service -> connect with pymodbus -> scan registers
├- VIN question -> decode VIN structure or read via OBD-II
├- Unknown protocol -> Wireshark -> check protocol decoders
└- PLC challenge -> identify protocol (S7/Modbus/EIP) -> read/write values
```
