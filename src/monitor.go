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

func monitor(db *scribble.Driver, intrfc string, targetDevice string, maxNumPackets int) ([]device, error) {
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

	if !*quite {
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

		var newDevice device

		if val, ok := devices[dstAddr.String()]; ok {
			val.PCount++
			newDevice = val
		} else {
			newDevice = device{
				Address: dstAddr.String(),
				PCount:  1,
				Rating:  0,
			}
		}

		if !*quite {
			fmt.Printf("%s %d\n", dstAddr, newDevice.PCount)
		}

		devices[dstAddr.String()] = newDevice

		db.Write(srcAddr.String(), dstAddr.String(), newDevice)
	}

	sortedDevices := sortDevices(devices)
	if !*quite {
		fmt.Printf("\nTotal %d devices discovered\n\n", len(devices))

		for _, d := range sortedDevices {
			fmt.Printf("%s: %d\n", d.Address, d.PCount)
		}
	}

	return sortedDevices, nil
}
