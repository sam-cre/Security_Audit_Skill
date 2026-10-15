# Vulnerability Reference: Embedded Systems, IoT & Firmware

_Load in Phase 1 for firmware, IoT devices, RTOS, hardware interfaces, or connected-device ecosystems._

---

## 1. Firmware

**Update mechanism**
- Unsigned OTA updates
- No rollback or anti-downgrade protection; older firmware accepted as an "update"
- Update channel over HTTP (MITM firmware injection)

**Composition**
- Hardcoded credentials (WiFi passwords, API keys, default admin passwords); embedded private keys or certs
- Debug symbols and verbose logging in production
- Secrets extractable with `strings` or `binwalk`

**Secure boot**
- Unsigned bootloader allows arbitrary code; bootloader unlock without authorization
- No chain of trust from bootloader to kernel to application

## 2. Hardware Debug Interfaces

- **JTAG/SWD:** pins accessible in production (full memory access, firmware extraction); fuse/debug-lock bits unset; SWD not disabled
- **UART/serial:** console on production hardware (often a root shell); boot logs leaking addresses, mounts, credentials; unauthenticated interactive shell
- **Other:** I2C/SPI EEPROM dumping; USB debug modes (ADB, DFU) on; PCB test points exposing internal buses

## 3. Communication Protocols

- **BLE:** no pairing authentication, static passkeys, unencrypted GATT characteristics with sensitive data
- **Zigbee:** default trust center link keys, unencrypted traffic, insecure OTA key provisioning
- **Z-Wave:** no S2 security, unauthenticated commands
- **WiFi:** weak WPA2 PSK, WPS on, plaintext credentials in flash
- **MQTT:** anonymous broker access; no TLS; topic ACLs so broad a device can subscribe to everything; no message integrity
- **CoAP/HTTP:** no DTLS; unauthenticated device REST APIs; no rate limiting

## 4. Memory & Runtime Safety

- Stack and heap overflows in C/C++ (string handling, network parsers); no bounds checks on packets, serial, or sensor input
- No stack canaries; no ASLR (often unavailable on MCUs); executable stack/heap (NX unset); MPU unconfigured on Cortex-M
- Integer overflow in sensor math; signed/unsigned confusion in sizes; unvalidated length fields in protocols

## 5. Physical Security

- No tamper detection; secrets in external EEPROM/flash (chip-off extraction); no secure element (TPM, ATECC608); probeable PCB traces
- Side channels: non-constant-time comparisons, power analysis (SPA/DPA), EM emanation

## 6. Device Identity & Fleet

- All devices share credentials or certs (one compromise is all)
- Identity from predictable values (MAC, serial); no device attestation
- No certificate revocation for compromised devices
- Factory reset leaves secrets; no decommissioning procedure
- OTA provisioning without mutual authentication

## 7. Data Storage & Privacy

- Sensitive data in unencrypted flash/EEPROM; credentials surviving factory reset; unrotated logs accumulating sensor or user data
- Sensor data sent unencrypted; location or usage sent to cloud without consent; over-collection

---

## Tooling

```bash
binwalk firmware.bin          # firmware extraction
firmwalker firmware_root/     # filesystem analysis
strings firmware.bin          # string extraction
checksec --file=binary        # NX, PIE, canaries
openocd                       # JTAG/SWD
minicom / screen              # UART console
```
