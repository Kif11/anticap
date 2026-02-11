package main

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Styles
var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			PaddingTop(1)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF6B6B")).
			Padding(1, 0, 1, 0)

	tableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#FAFAFA")).
				Background(lipgloss.Color("#7D56F4")).
				PaddingLeft(1).
				PaddingRight(1)

	goodRSSIStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575"))
	okRSSIStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700"))
	weakRSSIStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6B6B"))

	secureStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#8f8f8f"))
	mediumStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffd900"))
	insecureStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575"))
)

// AccessPoint represents a WiFi access point
type AccessPoint struct {
	BSSID    string `json:"bssid"`
	SSID     string `json:"ssid"`
	Channels []int  `json:"channels"`
	RSSI     int8   `json:"rssi"`
	Security string `json:"security"`
	SeenAt   int64  `json:"seen_at"`
}

// APUpdateMsg is a message sent when an access point is updated
type APUpdateMsg struct {
	BSSID string
	AP    AccessPoint
}

// ChannelUpdateMsg is sent when starting to scan a new channel
type ChannelUpdateMsg struct {
	Channel int
}

// ScanCompleteMsg is sent when scanning is finished
type ScanCompleteMsg struct{}

// model represents the Bubble Tea model for the scanning UI
type model struct {
	accessPoints   map[string]AccessPoint
	sortBy         string
	scanning       bool
	total          int
	currentChannel int
	viewport       viewport.Model
	err            error
	ready          bool
}

// packetInfo holds extracted information from a single packet
type packetInfo struct {
	srcAddr      string
	dstAddr      string
	rssi         int8
	noise        int8
	snr          int8
	dataRate     uint8
	isDataFrame  bool
	isRetry      bool
	frameType    layers.Dot11Type
	frameSubType layers.Dot11Type
}

// scanForAccessPoints scans for WiFi access points by capturing beacon/probe response frames
// This method can get actual BSSIDs even on modern macOS where airport utility is deprecated
// and Swift Core WiFi utils require geo location permission to see BSSIDs
// channels: list of channels to scan (e.g., []int{1,6,11} for 2.4GHz)
// scanTime: time to spend on each channel (e.g., 500ms)
// updateChan: channel to send real-time updates to the UI
// channelChan: channel to send current channel updates
// Returns a map of BSSID -> AccessPoint
func scanForAccessPoints(iface string, channels []int, scanTime time.Duration, verbose bool, updateCh chan<- APUpdateMsg, channelCh chan<- ChannelUpdateMsg, errCh chan<- error) (map[string]AccessPoint, error) {
	accessPoints := make(map[string]AccessPoint)

	handle, err := pcap.OpenLive(iface, 65536, true, scanTime)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %w", iface, err)
	}
	defer handle.Close()

	// Set to capture IEEE802.11 radio packets (Monitor Mode)
	if err := handle.SetLinkType(layers.LinkTypeIEEE80211Radio); err != nil {
		return nil, fmt.Errorf("failed to set link type to monitor mode: %w", err)
	}

	// BPF filter for beacon and probe response frames
	// Type 0, Subtype 8 = Beacon
	// Type 0, Subtype 5 = Probe Response
	if err := handle.SetBPFFilter("type mgt subtype beacon"); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	for _, channel := range channels {
		if err := setChannel(iface, channel); err != nil {
			errCh <- fmt.Errorf("failed to set channel %d: %v", channel, err)
			continue
		}

		// Send channel update
		if channelCh != nil {
			channelCh <- ChannelUpdateMsg{Channel: channel}
		}

		// Capture packets for scanTime on this channel
		deadline := time.Now().Add(scanTime)

		for time.Now().Before(deadline) {
			data, ci, err := handle.ReadPacketData()
			if err != nil {
				errCh <- fmt.Errorf("error reading packet on channel %d: %v", channel, err)
				continue
			}

			packet := gopacket.NewPacket(data, layers.LayerTypeRadioTap, gopacket.Default)

			rTap := getRadioTapLayer(packet)
			if rTap == nil {
				continue
			}

			dot11 := getDot11Layer(packet)
			if dot11 == nil {
				continue
			}

			// Address3 is BSSID in beacon/probe frames
			bssid := dot11.Address3.String()
			ssid := extractSSIDFromBeacon(packet)
			_, enc, cipher, auth := dot11ParseEncryption(packet, dot11)

			signal := rTap.DBMAntennaSignal
			if rTap.DBMAntennaSignal == 0 {
				signal = -100
			}

			if existing, ok := accessPoints[bssid]; ok {
				// Use last captured signal strength
				existing.RSSI = signal

				if !slices.Contains(existing.Channels, channel) {
					existing.Channels = append(existing.Channels, channel)
				}

				existing.SeenAt = ci.Timestamp.Unix()

				accessPoints[bssid] = existing
				// Send update
				if updateCh != nil {
					updateCh <- APUpdateMsg{BSSID: bssid, AP: existing}
				}
			} else {
				ap := AccessPoint{
					BSSID:    bssid,
					SSID:     ssid,
					Channels: []int{channel},
					RSSI:     signal,
					Security: fmt.Sprintf("%s %s %s", enc, cipher, auth),
					SeenAt:   ci.Timestamp.Unix(),
				}

				accessPoints[bssid] = ap
				// Send update
				if updateCh != nil {
					updateCh <- APUpdateMsg{BSSID: bssid, AP: ap}
				}
			}
		}
	}

	return accessPoints, nil
}

func getDot11Layer(packet gopacket.Packet) *layers.Dot11 {
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return nil
	}

	dot11, ok := dot11Layer.(*layers.Dot11)
	if !ok {
		return nil
	}

	return dot11
}

func getRadioTapLayer(packet gopacket.Packet) *layers.RadioTap {
	rtLayer := packet.Layer(layers.LayerTypeRadioTap)
	if rtLayer == nil {
		return nil
	}

	radioTap, ok := rtLayer.(*layers.RadioTap)
	if !ok {
		return nil
	}

	return radioTap
}

// handlePacket extracts Dot11 and RadioTap layers from a packet
func handlePacket(p gopacket.Packet) (*layers.Dot11, *layers.RadioTap) {
	var dot11 *layers.Dot11
	var radioTap *layers.RadioTap

	if rtLayer := p.Layer(layers.LayerTypeRadioTap); rtLayer != nil {
		radioTap, _ = rtLayer.(*layers.RadioTap)
	}

	if d11Layer := p.Layer(layers.LayerTypeDot11); d11Layer != nil {
		dot11, _ = d11Layer.(*layers.Dot11)
	}

	return dot11, radioTap
}

// extractSSIDFromBeacon extracts SSID from 802.11 Information Elements
func extractSSIDFromBeacon(packet gopacket.Packet) string {
	dot11InfoLayer := packet.Layer(layers.LayerTypeDot11InformationElement)
	if dot11InfoLayer == nil {
		return ""
	}

	// Iterate through all information elements
	for _, layer := range packet.Layers() {
		if infoElem, ok := layer.(*layers.Dot11InformationElement); ok {
			if infoElem.ID == layers.Dot11InformationElementIDSSID {
				return string(infoElem.Info)
			}
		}
	}
	return ""
}

// sortAccessPoints converts map to slice and sorts by specified criteria
func sortAccessPoints(aps map[string]AccessPoint, sortType string) []AccessPoint {
	// Convert map to slice
	apList := make([]AccessPoint, 0, len(aps))
	for _, ap := range aps {
		apList = append(apList, ap)
	}

	if sortType == "security" {
		// Sort by security strength (weakest first), then by RSSI (strongest first) for ties
		sort.Slice(apList, func(i, j int) bool {
			strengthI := getSecurityStrength(apList[i].Security)
			strengthJ := getSecurityStrength(apList[j].Security)
			if strengthI != strengthJ {
				return strengthI < strengthJ // Weakest first
			}
			return apList[i].RSSI > apList[j].RSSI // Stronger signal first for ties
		})
	} else {
		// Sort by signal strength (strongest RSSI first - less negative = stronger)
		sort.Slice(apList, func(i, j int) bool {
			return apList[i].RSSI > apList[j].RSSI
		})
	}

	return apList
}

func joinInts(ints []int) string {
	str := ""
	for _, i := range ints {
		str += " " + strconv.Itoa(i)
	}
	return str
}

// Init initializes the model
func (m model) Init() tea.Cmd {
	return nil
}

// Update handles messages
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "q" || msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		// Handle viewport keys
		m.viewport, cmd = m.viewport.Update(msg)
		cmds = append(cmds, cmd)
	case tea.WindowSizeMsg:
		if !m.ready {
			// Initialize viewport
			m.viewport = viewport.New(msg.Width, msg.Height-6) // Leave space for header
			m.viewport.SetContent(m.generateTableContent())
			m.ready = true
		} else {
			m.viewport.Width = msg.Width
			m.viewport.Height = msg.Height - 3
		}
	case APUpdateMsg:
		if m.accessPoints == nil {
			m.accessPoints = make(map[string]AccessPoint)
		}
		m.accessPoints[msg.BSSID] = msg.AP
		m.total = len(m.accessPoints)
		// Update viewport content
		if m.ready {
			m.viewport.SetContent(m.generateTableContent())
		}
	case ChannelUpdateMsg:
		m.currentChannel = msg.Channel
	case ScanCompleteMsg:
		m.scanning = false
	case error:
		m.err = msg
	}

	return m, tea.Batch(cmds...)
}

// generateTableContent generates the table content for the viewport
func (m model) generateTableContent() string {
	if len(m.accessPoints) == 0 {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("No access points found yet...")
	}

	apList := sortAccessPoints(m.accessPoints, m.sortBy)

	var content strings.Builder

	// Table header with styling - use fixed widths
	bssidHeader := lipgloss.NewStyle().Width(17).Align(lipgloss.Left).Render(tableHeaderStyle.Render("BSSID"))
	ssidHeader := lipgloss.NewStyle().Width(32).Align(lipgloss.Left).Render(tableHeaderStyle.Render("SSID"))
	channelHeader := lipgloss.NewStyle().Width(48).Align(lipgloss.Left).Render(tableHeaderStyle.Render("Channel"))
	rssiHeader := lipgloss.NewStyle().Width(12).Align(lipgloss.Left).Render(tableHeaderStyle.Render("RSSI"))
	securityHeader := tableHeaderStyle.Render("Security")

	content.WriteString(lipgloss.JoinHorizontal(lipgloss.Left,
		bssidHeader, "  ",
		ssidHeader, "  ",
		channelHeader, "  ",
		rssiHeader, "  ",
		securityHeader) + "\n")
	content.WriteString(strings.Repeat("─", 120) + "\n")

	// Table rows
	for _, ap := range apList {
		ssid := ap.SSID
		if ssid == "" {
			ssid = "<hidden>"
		}
		if len(ssid) > 32 {
			ssid = ssid[:29] + "..."
		}

		security := ap.Security
		if security == "" {
			security = "Unknown"
		}

		// Color code RSSI
		rssiStr := fmt.Sprintf("%d dBm", ap.RSSI)
		var styledRSSI string
		if ap.RSSI >= -60 {
			styledRSSI = goodRSSIStyle.Render(rssiStr)
		} else if ap.RSSI >= -70 {
			styledRSSI = okRSSIStyle.Render(rssiStr)
		} else {
			styledRSSI = weakRSSIStyle.Render(rssiStr)
		}

		// Color code security
		var styledSecurity string
		if strings.Contains(security, "WPA3") || strings.Contains(security, "SAE") {
			styledSecurity = secureStyle.Render(security)
		} else if strings.Contains(security, "WPA2") {
			styledSecurity = secureStyle.Render(security)
		} else if strings.Contains(security, "WPA") {
			styledSecurity = mediumStyle.Render(security)
		} else if strings.Contains(security, "WEP") || strings.Contains(security, "OPEN") {
			styledSecurity = insecureStyle.Render(security)
		} else {
			styledSecurity = security
		}

		// Build row
		bssidCol := lipgloss.NewStyle().Width(17).Align(lipgloss.Left).Render(ap.BSSID)
		ssidCol := lipgloss.NewStyle().Width(32).Align(lipgloss.Left).Render(ssid)
		channelCol := lipgloss.NewStyle().Width(48).Align(lipgloss.Left).Render(joinInts(ap.Channels))
		rssiCol := lipgloss.NewStyle().Width(12).Align(lipgloss.Left).Render(styledRSSI)

		row := lipgloss.JoinHorizontal(lipgloss.Left,
			bssidCol, "  ",
			ssidCol, "  ",
			channelCol, "  ",
			rssiCol, "  ",
			styledSecurity)
		content.WriteString(row + "\n")
	}

	return content.String()
}

// View renders the UI
func (m model) View() string {
	if !m.ready {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4")).Render("Initializing...")
	}

	// Header
	var header string
	if m.scanning {
		header = headerStyle.Render(fmt.Sprintf("📡 Scanning channel: %d, 📊 Total APs: %d ... 'q' to quit", m.currentChannel, m.total))
	} else {
		header = headerStyle.Render(fmt.Sprintf("📡 Scan Complete!, 📊 Total APs: %d ... 'q' to quit", m.total))
	}

	var errorLine string = ""
	if m.err != nil {
		errorLine = errorStyle.Render(fmt.Sprintf("⚠️  %s", m.err.Error()))
	}

	// Combine header and viewport with a table
	return lipgloss.JoinVertical(lipgloss.Left, header, errorLine, m.viewport.View())
}
