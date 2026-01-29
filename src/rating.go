package main

import (
	"fmt"
	"time"

	ping "github.com/go-ping/ping"
	scribble "github.com/nanobox-io/golang-scribble"
)

func rateConnection(pingCount int) (int, error) {
	pinger, err := ping.NewPinger("www.google.com")
	if err != nil {
		return 0, err
	}

	pinger.OnRecv = func(pkt *ping.Packet) {
		fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v\n",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
	}
	pinger.OnFinish = func(stats *ping.Statistics) {
		fmt.Printf("Ping statistics for %s\n", stats.Addr)
		fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
			stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
	}

	// pinger.Run() will stop after this time
	duration, err := time.ParseDuration("15s")
	if err != nil {
		return 0, err
	}

	pinger.Timeout = duration

	pinger.Count = 10
	pinger.Run() // blocks until finished
	stats := pinger.Statistics()

	return stats.PacketsRecv, nil
}

func rateConnections(
	db *scribble.Driver,
	iface string,
	targetDevice string,
	targetSSID string,
	devices []device) ([]device, error) {

	var rated []device
	var devicesLen = len(devices)
	for i, d := range devices {

		fmt.Printf("Testing device %d of %d\n", i+1, devicesLen)
		fmt.Println("Setting mac to", d.Address)

		if err := setMac(iface, d.Address); err != nil {
			return nil, err
		}

		// Associate with the target network
		_, err := associateWiFi(targetSSID, "")
		if err != nil {
			return nil, err
		}

		// Wait until WiFi interface is connected
		for {
			fmt.Println("Waiting until wifi is connected...")

			iface, err := getDefaultAirportInterfaceInfo()
			if err != nil {
				return nil, err
			}

			if iface.CurrentNetworkInfo != (NetworkInfo{}) {
				fmt.Printf("Connected to %s\n", iface.CurrentNetworkInfo.Name)
				time.Sleep(5 * time.Second)
				break
			}
			time.Sleep(1 * time.Second)
		}

		fmt.Println("Testing connection...")
		connectionScore, err := rateConnection(5)
		if err != nil {
			fmt.Println(err)
			connectionScore = 0
		}

		fmt.Printf("Connection rated %d out of 10\n", connectionScore)

		d.Rating = connectionScore

		db.Write(targetDevice, d.Address, d)

		rated = append(rated, d)

		if connectionScore > 0 {
			break
		}
	}
	return rated, nil
}

func getBestDevice(devices []device) device {
	bestIndex := 0
	bestRating := 0

	for i, d := range devices {
		if d.Rating > bestRating {
			bestRating = d.Rating
			bestIndex = i
		}
	}

	return devices[bestIndex]
}
