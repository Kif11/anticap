# Anti Captive Portals

![coffee](https://user-images.githubusercontent.com/8003487/57241899-122a0280-706d-11e9-9241-626895bf4eae.png)

Bypass captive portals and get free WiFi easy 😝 With great power comes great responsibility! Please use it wisely.

You can download latest ready to use [anticap 1.0.1 here](https://github.com/Kif11/anticap/releases/download/v1.0.1/anticap). Other versions are available under Releases.

## Usage

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

This tool sets your WiFi card to monitor mode in order to listen for network packets from all of the devices nearby. Each of these packets contain a MAC address which is unique to every device. Since captive portals use MAC addresses to identify users, if you spoof your MAC address to a logged in user, you can access the internet on their behalf. Keep in mind that this situation will lead to packet collision if the other person is using the Internet actively. In this case, both of you will have a bad browsing experience ￼🙁

The general pipeline consist of three steps.

### Discovery

Capture packets in monitor mode for a given WiFi network to discover connected devices. All captured MACs are stored as JSON text files in `<cwd>/store` directory.

### Connection rating

Spoof your mac to every discovered address and try to ping `google.com`. For each MAC anticap will try to perform five ping and save it to the local `store`.

### Spoofing

If mac address has an Internet connection set it as your current one.

## Additional Info

This tool was tested on Mojave 10.14.2 with
WiFI Card:	AirPort Extreme  (0x14E4, 0x133)
Firmware Version:	Broadcom BCM43xx 1.0 (7.77.61.1 AirPortDriverBrcmNIC-1305.2)

Special thanks for people developed the following tools

- https://github.com/feross/SpoofMAC
- https://github.com/unixpickle/JamWiFi
