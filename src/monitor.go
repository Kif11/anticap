package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

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

// printPacketInfo prints real-time packet information as it arrives
func printPacketInfo(info packetInfo, dev device) {
	retryFlag := " "
	if info.isRetry {
		retryFlag = "R"
	}
	dataRateMbps := float64(info.dataRate) * 0.5
	fmt.Printf("[%s%s] %s -> %s | RSSI: %d dBm | SNR: %d | Rate: %.1f Mbps | Pkts: %d\n",
		info.frameType, retryFlag, info.srcAddr, info.dstAddr,
		info.rssi, info.snr, dataRateMbps, dev.PCount)
}

// extractPacketInfo extracts all relevant information from Dot11 and RadioTap layers
func extractPacketInfo(dot11 *layers.Dot11, radioTap *layers.RadioTap) packetInfo {
	info := packetInfo{
		rssi:     -100,
		noise:    -100,
		dataRate: 0,
	}

	if dot11.Address1 != nil {
		info.dstAddr = dot11.Address1.String()
	}
	if dot11.Address2 != nil {
		info.srcAddr = dot11.Address2.String()
	}

	// Extract frame type information
	info.isDataFrame = dot11.Type.MainType() == layers.Dot11TypeData
	info.isRetry = dot11.Flags.Retry()

	// Determine frame type string
	// see https://en.wikipedia.org/wiki/802.11_frame_types#Types_and_subtypes
	info.frameType = dot11.Type.MainType()
	info.frameSubType = dot11.Type

	// Extract RadioTap information
	if radioTap != nil {
		info.rssi = radioTap.DBMAntennaSignal
		info.noise = radioTap.DBMAntennaNoise
		info.dataRate = uint8(radioTap.Rate)
	}
	info.snr = info.rssi - info.noise

	return info
}

// updateDevice updates or creates a device entry based on packet info
func updateDevice(devices map[string]device, info packetInfo) device {
	var dev device

	if existing, ok := devices[info.dstAddr]; ok {
		dev = existing
		dev.PCount++
		// Update RSSI with running average
		dev.AvgRSSI = int8((int(dev.AvgRSSI)*(dev.PCount-1) + int(info.rssi)) / dev.PCount)
		dev.LastRSSI = info.rssi
		dev.LastSeen = time.Now().Unix()
		if info.isRetry {
			dev.RetryCount++
		}
		if info.isDataFrame {
			dev.DataFrameCount++
		}
		if info.dataRate > dev.MaxDataRate {
			dev.MaxDataRate = info.dataRate
		}
		dev.SNR = info.snr
	} else {
		retryCount := 0
		if info.isRetry {
			retryCount = 1
		}
		dataFrameCount := 0
		if info.isDataFrame {
			dataFrameCount = 1
		}
		dev = device{
			Address:        info.dstAddr,
			PCount:         1,
			Rating:         0,
			AvgRSSI:        info.rssi,
			LastRSSI:       info.rssi,
			LastSeen:       time.Now().Unix(),
			RetryCount:     retryCount,
			DataFrameCount: dataFrameCount,
			MaxDataRate:    info.dataRate,
			SNR:            info.snr,
		}
	}

	return dev
}

// printDeviceSummary prints a summary table of all discovered devices
func printDeviceSummary(devices map[string]device) {
	sortedDevices := sortDevices(devices)

	fmt.Printf("\n%s\n", strings.Repeat("-", 80))
	fmt.Printf("Total %d devices discovered\n\n", len(devices))

	const padding = 2
	w := tabwriter.NewWriter(os.Stdout, 0, 0, padding, ' ', tabwriter.AlignRight)

	fmt.Fprintln(w, "Address\tPackets\tRSSI\tSNR\tDataRate\tRetry%\tData%\t")
	fmt.Fprintln(w, "\t\t\t\t\t\t\t")
	for _, d := range sortedDevices {
		retryPct := float64(0)
		if d.PCount > 0 {
			retryPct = float64(d.RetryCount) / float64(d.PCount) * 100
		}
		dataPct := float64(0)
		if d.PCount > 0 {
			dataPct = float64(d.DataFrameCount) / float64(d.PCount) * 100
		}
		// RadioTap Rate is in units of 500 Kbps, so multiply by 0.5 to get Mbps
		dataRateMbps := float64(d.MaxDataRate) * 0.5
		fmt.Fprintf(w, "%s\t%d\t%d dBm\t%d\t%.1f Mbps\t%.1f%%\t%.1f%%\t\n",
			d.Address, d.PCount, d.AvgRSSI, d.SNR, dataRateMbps, retryPct, dataPct)
	}
	fmt.Fprintln(w, "\t\t\t\t\t\t\t")
	w.Flush()
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
