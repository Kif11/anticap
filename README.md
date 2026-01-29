# Anti Captive Portals

![coffee](https://user-images.githubusercontent.com/8003487/60137709-a3a81d80-975c-11e9-8596-896390227c4e.png)

Bypass captive portals and get free WiFi easy 😝

## What does this tool do exactly?

This tool sets your WiFi card to monitor mode in order to listen for network packets from all of the devices nearby. Each of these packets contain a MAC address which is unique to every device. Since captive portals use MAC addresses to identify users, it is possible to spoof your MAC to a "logged in" user to be able to access the internet on their behalf. Keep in mind that this situation will lead to packet collision if the other person is using the Internet actively. In this case, both of you will have a bad browsing experience.

The general workflow consists of several steps:

### Discovery

Capture packets in monitor mode for a given WiFi network to discover connected devices. All captured MACs are stored as JSON text files in `store` directory.

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
sudo ./build/anticap scan [-5g] [-dwell <seconds>] [-s] [-i <interface>] [-v]
```
- `-5g`: Include 5GHz channels
- `-dwell`: Dwell time per channel in seconds
- `-s`: Save discovered networks to cache
- `-i`: Interface name
- `-v`: Verbose output

#### capture
Run packet capture only (no MAC spoofing)
```
sudo ./build/anticap capture -t <BSSID> [-ch <channel>] [-i <interface>] [-n <num_packets>] [-v]
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
