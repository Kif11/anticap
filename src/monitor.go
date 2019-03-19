package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	scribble "github.com/nanobox-io/golang-scribble"
)

func handlePacket(p gopacket.Packet) *layers.Dot11 {
	linkLayer := p.Layer(layers.LayerTypeDot11)
	if linkLayer != nil {
		// Get actual dot11 data from this layer
		dot11, _ := linkLayer.(*layers.Dot11)
		return dot11
	}
	return nil
}

func monitor(db *scribble.Driver, intrfc string, targetDevice string, maxNumPackets int) (map[string]device, error) {
	handle, err := pcap.OpenLive(intrfc, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	// Set to capture IEEE802.11 radio packets (Monitor Mode)
	if err := handle.SetLinkType(layers.LinkTypeIEEE80211Radio); err != nil {
		return nil, err
	}

	currentMac, err := getMac(intrfc)
	if err != nil {
		return nil, err
	}

	bpfFilter := fmt.Sprintf("ether src %s and not ether host ff:ff:ff:ff:ff:ff and not ether host %s", targetDevice, currentMac)

	if *debug {
		fmt.Println("BPF Filter: ", bpfFilter)
	}

	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	devices := make(map[string]device)
	packetCount := 0

	for packet := range packetSource.Packets() {
		if packetCount > maxNumPackets {
			handle.Close()
			break
		}

		chunk := handlePacket(packet)
		packetCount++

		if chunk == nil {
			continue
		}

		dstAddr := chunk.Address1
		srcAddr := chunk.Address2

		if dstAddr == nil {
			continue
		}

		devicePair := fmt.Sprintf("%s %s\n", dstAddr, srcAddr)

		if *debug {
			fmt.Printf(devicePair)
		}

		var newDevice device

		if val, ok := devices[dstAddr.String()]; ok {
			val.PCount++
			newDevice = val
		} else {
			newDevice = device{
				Address: dstAddr.String(),
				PCount:  0,
				Rating:  0,
			}
		}

		devices[dstAddr.String()] = newDevice

		db.Write(srcAddr.String(), dstAddr.String(), newDevice)

		// // If the file doesn't exist, create it, or append to the file
		// f, err := os.OpenFile(*outFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		// if err != nil {
		// 	log.Fatal(err)
		// }
		// defer f.Close()

		// if _, err := f.Write([]byte(devicePair)); err != nil {
		// 	log.Fatal(err)
		// }

		// devices = append(devices, devicePair)
	}

	if *debug {
		fmt.Printf("Total %d devices discovered\n", len(devices))
	}

	return devices, nil
}
