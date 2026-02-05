# Anti Captive Portals

![coffee](https://user-images.githubusercontent.com/8003487/60137709-a3a81d80-975c-11e9-8596-896390227c4e.png)

Bypass captive portals and get free WiFi easy 😝

## Motivation

Today people have forgotten that Internet access is a basic human right. Admins who "just do their job" place captive portals with ads, phone number verification, and other abominations on otherwise open WiFi networks. This tool is made to overcome that inconvenience.

## What does this tool do exactly?

This tool leverages 802.11 wireless protocol monitor mode to passively capture frames (packets) from all devices operating within range of the target access point (WiFi router). Each captured frame contains the client source MAC address. Captive portal implementations typically rely on MAC address-based authentication to maintain session state and enforce access control policies. By cloning the MAC address of an authenticated client, it becomes possible to inherit their existing authorization context and bypass the captive portal authentication mechanism.

It should be noted that simultaneous usage of a spoofed MAC address while the legitimate client remains active will result in address conflicts and subsequent packet collisions. This will degrades network performance for both parties as the access point cannot deterministically send frames to the correct physical device. (the person who is closer to WiFi router will have much better time)

The general workflow consists of several steps:

### Discovery

Capture packets in monitor mode for a given WiFi network to discover connected devices. All captured MACs are stored as JSON text files in `store` directory for later access.

Note that anticap also maintains a cache of discovered networks in `store/networks/{bssid}.json`. This cache maps BSSIDs to their SSIDs and channels.

### Connection rating

Spoof your MAC to every discovered address and try to ping external server to find if internet access is available. For each address N pings will be performed to determine a rating score. The higher the number of successful ping the higher the score.

### Spoofing

If tester MAC address has an Internet connection set it as your current one.

## Build

```
./build.sh
```

### Commands

anticap uses a subcommand-based interface. Use `-h` flag with any command to get more help on available options.

#### bypass
Full process: packet capture, MAC spoof, and connection testing
```
sudo ./build/anticap bypass -t <BSSID> [-ch <channel>] [-s <SSID>] [-i <interface>] [-n <num_packets>] [-v]
```
- `-t`: Target BSSID
- `-ch`: Target channel
- `-s`: Manually specify SSID
- `-i`: Interface name
- `-n`: Number of packets to capture
- `-v`: Verbose output

#### scan
Scan available WiFi networks and populate cache
```
sudo ./build/anticap scan [-5g] [-t <milliseconds>] [-s] [-i <interface>] [-v]
```
- `-5g`: Include 5GHz channels
- `-t`: Scan time per channel in milliseconds
- `-s`: Save discovered networks to cache
- `-i`: Interface name
- `-v`: Verbose output

#### capture
Run packet capture only (no MAC spoofing)
```
sudo ./build/anticap capture -t <BSSID> [-ch <channel>] [-i <interface>] [-n <num_packets>] [-v]
```

#### handshake
Capture WPA/WPA2 4-way handshake for password cracking with aircrack-ng
```
sudo ./build/anticap handshake -t <BSSID> [-ch <channel>] [-i <interface>] [-timeout <seconds>] [-o <output_file>] [-v]
```
- `-t`: Target BSSID (required)
- `-ch`: Target channel (auto-detected from cache if available)
- `-i`: Interface name (default: en0)
- `-timeout`: Capture timeout in seconds (default: 120)
- `-o`: Output PCAP file path (default: handshakes/<BSSID>_<timestamp>.pcap)
- `-v`: Verbose output

**Note**: To capture a handshake, a client device must connect (or reconnect) to the target network while anticap is monitoring. You can trigger this by:
1. Deauthenticating a connected client (using tools like aireplay-ng)
2. Waiting for a new device to connect naturally
3. Having someone disconnect and reconnect to the network

Once captured, use the PCAP file with aircrack-ng:
```
aircrack-ng -w wordlist.txt handshakes/xx:xx:xx:xx:xx:xx_*.pcap
```

#### join
Join a specified WiFi network
```
sudo ./build/anticap join <SSID> [-p <password>] [-v]
```

#### reset
Reset interface to original MAC address
```
sudo ./build/anticap reset [-i <interface>] [-v]
```

#### setmac
Set interface MAC address
```
sudo ./build/anticap setmac <MAC_ADDRESS> [-i <interface>] [-v]
```

#### list
List stored captures for target MAC (works without root)
```
./build/anticap list -t <BSSID> [-v]
```
