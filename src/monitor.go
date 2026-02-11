package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	scribble "github.com/nanobox-io/golang-scribble"
)

// openMonitorHandle opens a pcap handle configured for monitor mode
func openMonitorHandle(iface string, targetDevice string, currentMac string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	// Set to capture IEEE802.11 radio packets (Monitor Mode)
	if err := handle.SetLinkType(layers.LinkTypeIEEE80211Radio); err != nil {
		handle.Close()
		return nil, err
	}

	bpfFilter := fmt.Sprintf("ether src %s and not ether host ff:ff:ff:ff:ff:ff and not ether host %s", targetDevice, currentMac)
	fmt.Println("BPF Filter:", bpfFilter)

	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		handle.Close()
		return nil, err
	}

	return handle, nil
}

func monitor(db *scribble.Driver, iface string, targetDevice string, channel int, maxNumPackets int) ([]device, error) {
	if err := setChannel(iface, channel); err != nil {
		return nil, err
	}

	currentMac, err := getMac(iface)
	if err != nil {
		return nil, err
	}

	handle, err := openMonitorHandle(iface, targetDevice, currentMac)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	devices := make(map[string]device)
	packetCount := 0

	for packet := range packetSource.Packets() {
		if packetCount > maxNumPackets {
			break
		}

		dot11, radioTap := handlePacket(packet)
		packetCount++

		if dot11 == nil || dot11.Address1 == nil {
			continue
		}

		info := extractPacketInfo(dot11, radioTap)
		if info.dstAddr == "" {
			continue
		}

		dev := updateDevice(devices, info)
		devices[info.dstAddr] = dev

		printPacketInfo(info, dev)

		if info.srcAddr != "" {
			db.Write(info.srcAddr, info.dstAddr, dev)
		}
	}

	printDeviceSummary(devices)

	return sortDevices(devices), nil
}
