# Anti Captive Portals

Bypass captive portals and get free WiFi easy 😝
With great power comes great responsobility! Please use it wisely.

To build
```
./build.sh
```

To run
```
./build/anticap
```

Use `-h` flag to get more help on different options.

## What does this tool do exactly?

1. Capture packets in monitor mode for a given WiFi network to discover connected devices
2. Spoof your mac to every discovered address and try to ping google.com
4. If mac address has a positive connection keep it as your current one

This tool is tested on Mojave 10.14.2 with
Card Type:	AirPort Extreme  (0x14E4, 0x133)
Firmware Version:	Broadcom BCM43xx 1.0 (7.77.61.1 AirPortDriverBrcmNIC-1305.2)

Special thanks for people developing following tools

- https://github.com/feross/SpoofMAC
- https://github.com/unixpickle/JamWiFi
