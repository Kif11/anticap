package main

import (
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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

func monitor(intrfc string, targetDevice string, maxNumPackets int) (map[string]int, error) {
	if !isSudo() {
		return nil, errors.New("This program needs to be run as sudo")
	}

	handle, err := pcap.OpenLive(intrfc, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	// Set to capture IEEE802.11 radio packets (Monitor Mode)
	if err := handle.SetLinkType(layers.LinkTypeIEEE80211Radio); err != nil {
		return nil, err
	}

	bpfFilter := fmt.Sprintf("ether src %s and not ether host ff:ff:ff:ff:ff:ff and not ether host %s", targetDevice, getMac(intrfc))

	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		return nil, err
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	devices := make(map[string]int)
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

		// if *printAddresses {
		srcAddr := chunk.Address2
		fmt.Println(dstAddr, srcAddr)
		// }

		if dstAddr == nil {
			continue
		}

		devices[dstAddr.String()]++

		// if *debug {
		// for k, v := range devices {
		// 	fmt.Println(k, v)
		// }
		// }
	}

	return devices, nil
}
