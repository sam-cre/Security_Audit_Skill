# Vulnerability Reference: Embedded Systems, IoT & Firmware

_Load this during Phase 1 when auditing embedded firmware, IoT devices, real-time operating systems (RTOS), hardware interfaces, or connected device ecosystems._

---

## 1. Firmware Security

### Update Mechanism
- Missing firmware signature verification (unsigned OTA updates allow malicious firmware)
- No rollback protection (downgrade attacks to vulnerable versions)
- Update channel over unencrypted HTTP (man-in-the-middle firmware injection)
- Missing version validation (accepting older firmware as "update")

### Firmware Composition
- Hardcoded credentials in firmware binary (WiFi passwords, API keys, default admin passwords)
- Debug symbols and verbose logging left in production firmware
- Embedded private keys or certificates in firmware images
- Sensitive strings extractable via `strings` or `binwalk`

### Secure Boot
- Missing secure boot chain (unsigned bootloader allows arbitrary code execution)
- Bootloader unlocking without proper authorization
- Missing chain-of-trust verification from bootloader → kernel → application

---

## 2. Hardware Debug Interface Exposure

### JTAG / SWD
- JTAG pins accessible on production hardware (allows full memory read/write, firmware extraction)
- Missing JTAG fuse / debug lock bits in production firmware
- SWD (Serial Wire Debug) interface not disabled

### UART / Serial Console
- UART console accessible on production hardware (often provides root shell)
- Boot log leaking sensitive information (kernel addresses, mount points, credentials)
- Interactive root shell available without authentication via serial console

### Other Interfaces
- I2C/SPI bus accessible for EEPROM dumping (credential extraction)
- USB debug modes (ADB, DFU) enabled in production
- Test points on PCB providing access to internal buses

---

## 3. Communication Protocol Security

### Wireless Protocols
- **BLE (Bluetooth Low Energy):** Missing pairing authentication, static passkeys, unencrypted GATT characteristics containing sensitive data
- **Zigbee:** Default trust center link keys, unencrypted network traffic, insecure OTA key provisioning
- **Z-Wave:** Missing S2 security framework, unauthenticated commands
- **WiFi:** WPA2 with weak PSK, WPS enabled, credential stored in plaintext in flash

### MQTT
- MQTT broker without authentication (anonymous publish/subscribe)
- Missing TLS on MQTT connections (plaintext sensor data / commands)
- Overly broad topic ACLs (device can subscribe to all topics)
- No message integrity verification

### CoAP / HTTP
- CoAP endpoints without DTLS encryption
- REST APIs on device without authentication
- Missing rate limiting on device API endpoints

---

## 4. Memory & Runtime Safety

### Buffer Overflows
- Stack buffer overflows in C/C++ firmware (string handling, network parsers)
- Heap overflows in dynamic memory allocation
- Missing bounds checking on input buffers (network packets, serial input, sensor data)

### Memory Protection
- Missing stack canaries in compiled firmware
- No ASLR (Address Space Layout Randomization) — often unavailable on microcontrollers
- Executable stack / heap (NX bit not set)
- Missing MPU (Memory Protection Unit) configuration on Cortex-M devices

### Integer Safety
- Integer overflow in sensor value calculations
- Signed/unsigned confusion in size parameters
- Missing bounds validation on length fields in network protocols

---

## 5. Physical Security

### Tamper Resistance
- No tamper detection mechanisms (tamper switches, mesh sensors)
- Secrets stored in external EEPROM/flash (extractable with chip-off attacks)
- Missing secure element (TPM, ATECC608) for key storage
- PCB traces carrying sensitive signals accessible for probing

### Side-Channel Attacks
- Timing-based attacks on cryptographic operations (non-constant-time comparisons)
- Power analysis vulnerability on crypto operations (SPA/DPA)
- Electromagnetic emanation leaking information

---

## 6. Device Identity & Authentication

### Device Provisioning
- All devices sharing the same credentials/certificates (compromise one → compromise all)
- Device identity derived from predictable values (MAC address, serial number)
- Missing device attestation mechanism

### Fleet Management
- No certificate revocation mechanism for compromised devices
- Missing device decommissioning procedure (factory reset doesn't clear all secrets)
- Over-the-air provisioning without mutual authentication

---

## 7. Data Storage & Privacy

### On-Device Storage
- Sensitive data stored in unencrypted flash/EEPROM
- Credentials persisting after factory reset (incomplete wipe)
- Log files accumulating sensitive sensor/user data without rotation

### Data Transmission
- Sensor data transmitted without encryption
- Location/usage data sent to cloud without user consent
- Missing data minimization (sending more data than necessary)

---

## Tooling

Check for availability of:
```bash
binwalk firmware.bin          # Firmware extraction/analysis
firmwalker firmware_root/     # Firmware filesystem analysis
strings firmware.bin          # String extraction from binary
checksec --file=binary        # Binary hardening checks (NX, PIE, canaries)
openocd                       # JTAG/SWD interface tool
minicom / screen              # UART serial console access
```
