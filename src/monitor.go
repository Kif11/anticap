package main

import (
	"fmt"
	"os"
	"os/exec"
	"text/tabwriter"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	scribble "github.com/nanobox-io/golang-scribble"
)

// SetChannel changes the channel of the network interface.
func setChannel(iface string, channel int) error {
	// Command to change the channel
	cmd := exec.Command("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", iface, "--channel="+fmt.Sprintf("%d", channel))

	// Run the command
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to set channel: %w", err)
	}

	return nil
}

func handlePacket(p gopacket.Packet) *layers.Dot11 {
	linkLayer := p.Layer(layers.LayerTypeDot11)
	if linkLayer != nil {
		// Get actual dot11 data from this layer
		dot11, _ := linkLayer.(*layers.Dot11)
		return dot11
	}
	return nil
}

func monitor(db *scribble.Driver, iface string, targetDevice string, channel int, maxNumPackets int) ([]device, error) {
	err := setChannel(iface, channel)
	if err != nil {
		return nil, err
	}

	handle, err := pcap.OpenLive(iface, 65536, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	// Set to capture IEEE802.11 radio packets (Monitor Mode)
	if err := handle.SetLinkType(layers.LinkTypeIEEE80211Radio); err != nil {
		return nil, err
	}

	currentMac, err := getMac(iface)
	if err != nil {
		return nil, err
	}

	bpfFilter := fmt.Sprintf("ether src %s and not ether host ff:ff:ff:ff:ff:ff and not ether host %s", targetDevice, currentMac)
	// bpfFilter := ""

	if !*quiet {
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

		if !*quiet {
			fmt.Printf("%s %d\n", dstAddr, newDevice.PCount)
		}

		devices[dstAddr.String()] = newDevice

		db.Write(srcAddr.String(), dstAddr.String(), newDevice)
	}

	sortedDevices := sortDevices(devices)
	if !*quiet {
		fmt.Printf("\nTotal %d devices discovered\n\n", len(devices))

		const padding = 4
		w := tabwriter.NewWriter(os.Stdout, 0, 0, padding, ' ', tabwriter.AlignRight)

		fmt.Fprintln(w, "Address\tPackets\t")
		fmt.Fprintln(w, "\t")
		for _, d := range sortedDevices {
			fmt.Fprintf(w, "%s\t%d\t\n", d.Address, d.PCount)
		}
		fmt.Fprintln(w, "\t")
		w.Flush()
	}

	return sortedDevices, nil
}
