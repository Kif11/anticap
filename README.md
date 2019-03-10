# Anti Captive Portals

Bypass captive portals and get free WiFi easy 😝

To build
```
./build.sh
```

To run
```
cd build
./anticap
```

Use `-h` flag to get more help on different options. Use `-v` to show log output.

## What does this tool do exactly?

1. Capture packets in monitor mode for a given WiFi network
2. Go through the list of discover devices and try to access internet
3. Derive some connection rating based on the previous step
4. Pick a device with the best connection and set your mac address to this device

This tool is tested on Mojave 10.14.2 with
Card Type:	AirPort Extreme  (0x14E4, 0x133)
Firmware Version:	Broadcom BCM43xx 1.0 (7.77.61.1 AirPortDriverBrcmNIC-1305.2)

Special thanks for people developing following tools

- https://github.com/feross/SpoofMAC
- https://github.com/unixpickle/JamWiFi
