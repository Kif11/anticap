Currently there are several modes that anticap can operate which all jumbled together into one command. Which looks like this:

```bash
anticap -h
-5g
    also scan 5GHz channels during network scan (slower)
-c    run packet capture and exit
-ch int
    target radio channels (1-14). use sudo airport -s to determine active channel (default 11)
-t int
    time in milliseconds to monitor each channel during scan (default 200)
-i string
    name of wifi interface, use ifconfig to find out (default "en0")
-join string
    connect to WiFi network by SSID
-l    list stored captures for target mac
-n int
    number of packets to capture before stop (default 300)
-pass string
    password for WiFi network (use with -join)
-r    reset to original mac address and exit
-s string
    set target interface mac to this one and exit
-scan
    scan for wifi networks using monitor mode to get actual BSSIDs (disconnects from WiFi)
-t string
    mac address of target wifi network (default "9c:e9:1c:20:e1:5e")
-v    output more information
-weak
    sort scan results by security (weakest first) instead of signal strength
```

That doesn't seem very elegant. I make sense to me to use sub-command to separate different run modes of anticap. Here are the specs of desired interface:

```bash
anticap bypass -n 300 -i <interface> -t <TARGET_MAC> // main uber mode that runs as default mode right now. This mode include full process of packet capture, mac spoof and internet connection testing 
anticap scan -5g -t 300 -s "weak" // Scan available wifi networks
anticap capture -i <interface> -n 300 -t <TARGET_MAC>
anticap join -p <PASS> <SSID> // Join specified wifi network
anticap reset // reset to original mac address and exit
anticap setmac -i <interface> <MAC_ADDRESS> -t <TARGET_MAC> // set target interface mac to this one and exit
anticap list // list stored captures for target mac
```

Note that some sub-command like bypass, scan, setmac share options. This is because bypass runs scan and set mac internally.

All sub-command accept verbose flag (-v).