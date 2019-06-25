package main

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
	"time"

	scribble "github.com/nanobox-io/golang-scribble"
	ping "github.com/sparrc/go-ping"
)

func rateConnection(pingCount int) (int, error) {
	pinger, err := ping.NewPinger("www.google.com")
	if err != nil {
		return 0, err
	}

	if !*quiet {
		pinger.OnRecv = func(pkt *ping.Packet) {
			fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v\n",
				pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
		}
		pinger.OnFinish = func(stats *ping.Statistics) {
			fmt.Printf("Ping statistics for %s\n", stats.Addr)
			fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
				stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
		}
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
	intrfc string,
	targetDevice string,
	devices []device) ([]device, error) {

	var rated []device
	var devicesLen = len(devices)
	for i, d := range devices {
		if !*quiet {
			fmt.Printf("Testing device %d of %d\n", i+1, devicesLen)
			fmt.Println("Setting mac to", d.Address)
		}

		if err := setMac(intrfc, d.Address); err != nil {
			return nil, err
		}

		// Wait until WiFi interface is connected
		for {
			out, err := exec.Command("networksetup", "-getairportnetwork", "en0").Output()
			if err != nil {
				return nil, err
			}

			s := string(out[:])
			scanner := bufio.NewScanner(strings.NewReader(s))

			scanner.Scan()
			text := scanner.Text()

			if strings.HasPrefix(text, "Current Wi-Fi Network:") {
				time.Sleep(8 * time.Second)
				break
			}
			time.Sleep(1 * time.Second)
		}

		if !*quiet {
			fmt.Println("Testing connection...")
		}
		connectionScore, err := rateConnection(5)
		if err != nil {
			fmt.Println(err)
			connectionScore = 0
		}
		if !*quiet {
			fmt.Printf("Connection rated %d out of 10\n", connectionScore)
		}

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
