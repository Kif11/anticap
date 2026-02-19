package main

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// APUpdateMsg is a message sent when an access point is updated
type APUpdateMsg struct {
	BSSID string
	AP    AccessPoint
}

// ChannelUpdateMsg is sent when starting to scan a new channel
type ChannelUpdateMsg struct {
	Channel int
}

// HandshakeUpdateMsg is sent when a handshake frame is captured
type HandshakeUpdateMsg struct {
	BSSID string
	Frame HandshakeFrame
}

// ScanCompleteMsg is sent when scanning is finished
type ScanCompleteMsg struct{}

// scanModel represents the Bubble Tea scanModel for the scanning UI
type scanModel struct {
	accessPoints   map[string]AccessPoint
	handshakes     map[string][]HandshakeFrame
	sortBy         string
	scanning       bool
	total          int
	currentChannel int
	busyChannel    int
	viewport       viewport.Model
	err            error
	ready          bool
}

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
				PaddingLeft(1).
				PaddingRight(1)

	goodRSSIStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575"))
	okRSSIStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700"))
	weakRSSIStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#8f8f8f"))

	secureStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#8f8f8f"))
	mediumStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffd900"))
	insecureStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575"))

	textAccent = lipgloss.NewStyle().Foreground(lipgloss.Color("#9804b5"))
)

// Init initializes the model
func (m scanModel) Init() tea.Cmd {
	return nil
}

// Update handles messages
func (m scanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
		headerHeight := 6
		if !m.ready {
			// Initialize viewport
			m.viewport = viewport.New(msg.Width, msg.Height-headerHeight)
			m.viewport.SetContent(makeAPTable(m))
			m.ready = true
		} else {
			m.viewport.Width = msg.Width
			m.viewport.Height = msg.Height - headerHeight
		}
	case APUpdateMsg:
		if m.accessPoints == nil {
			m.accessPoints = make(map[string]AccessPoint)
		}

		m.accessPoints[msg.BSSID] = msg.AP
		m.total = len(m.accessPoints)
		// Update viewport content
		if m.ready {
			m.viewport.SetContent(makeAPTable(m))
		}

		m.busyChannel = getBusyChannel(m.accessPoints)

	case HandshakeUpdateMsg:

		fmt.Printf("got handshake msg %d\n", msg.Frame.Num)
		os.Exit(0)

		if m.handshakes == nil {
			m.handshakes = make(map[string][]HandshakeFrame)
		}
		m.handshakes[msg.BSSID] = append(m.handshakes[msg.BSSID], msg.Frame)
		// Update viewport content
		if m.ready {
			m.viewport.SetContent(makeAPTable(m))
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

func ta(i int) string {
	return textAccent.Render(strconv.Itoa(i))
}

// View renders the UI
func (m scanModel) View() string {
	if !m.ready {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4")).Render("Initializing...")
	}

	// Header
	var header string
	if m.scanning {
		header = headerStyle.Render(fmt.Sprintf("📡 Scanning channel: %s, Total APs: %s, Busiest channel: %s ... 'q' to quit", ta(m.currentChannel), ta(m.total), ta(m.busyChannel)))
	} else {
		header = headerStyle.Render(fmt.Sprintf("📡 Scan Complete!, Total APs: %s, Busiest channel: %s ... 'q' to quit", ta(m.total), ta(m.busyChannel)))
	}

	var errorLine string = ""
	if m.err != nil {
		errorLine = errorStyle.Render(fmt.Sprintf("⚠️  %s", m.err.Error()))
	}

	// Combine header and viewport with a table
	return lipgloss.JoinVertical(lipgloss.Left, header, errorLine, m.viewport.View())
}

// Get top N channels with most amount of packets
func getActiveChannels(chs map[int]channelStats, n int) []int {
	pairs := [][]int{}
	for ch, st := range chs {
		pairs = append(pairs, []int{ch, st.numPackets})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i][1] > pairs[j][1]
	})
	best := []int{}
	num := int(math.Min(float64(n), float64(len(pairs))))
	for i := range num {
		best = append(best, pairs[i][0])
	}
	return best
}

// Determine the busiest channel or channel with the most amount of traffic
func getBusyChannel(aps map[string]AccessPoint) int {
	chans := make(map[int]int)
	for _, ap := range aps {
		for ch, inf := range ap.ChannelStats {
			numPack, ok := chans[ch]
			if ok {
				chans[ch] = numPack + inf.numPackets
			} else {
				chans[ch] = inf.numPackets
			}
		}
	}
	busyChan := 0
	maxPackets := 0
	for ch, numPacket := range chans {
		if numPacket > maxPackets {
			maxPackets = numPacket
			busyChan = ch
		}
	}
	return busyChan
}

func joinInts(ints []int) string {
	str := ""
	for i, num := range ints {
		if i > 0 {
			str += " "
		}
		str += strconv.Itoa(num)
	}
	return str
}

// sortAccessPoints converts map to slice and sorts by specified criteria
func sortAccessPoints(aps map[string]AccessPoint, sortType string) []AccessPoint {
	// Convert map to slice
	apList := make([]AccessPoint, 0, len(aps))
	for _, ap := range aps {
		apList = append(apList, ap)
	}

	switch sortType {
	case "security":
		// Sort by security strength (weakest first), then by RSSI (strongest first) for ties
		sort.Slice(apList, func(i, j int) bool {
			strengthI := getSecurityStrength(apList[i].Security)
			strengthJ := getSecurityStrength(apList[j].Security)
			if strengthI != strengthJ {
				return strengthI < strengthJ // Weakest first
			}
			return apList[i].RSSI > apList[j].RSSI // Stronger signal first for ties
		})
	case "bssid":
		// Sort by BSSID alphabetically
		sort.Slice(apList, func(i, j int) bool {
			return apList[i].BSSID < apList[j].BSSID
		})
	case "clients":
		// Sort by number of clients (most clients first)
		sort.Slice(apList, func(i, j int) bool {
			return len(apList[i].Clients) > len(apList[j].Clients)
		})
	default:
		// Sort by signal strength (strongest RSSI first - less negative = stronger)
		sort.Slice(apList, func(i, j int) bool {
			return apList[i].RSSI > apList[j].RSSI
		})
	}

	return apList
}

// formatHandshakeStatus creates a visual representation of captured handshake frames
// Returns a string like "۰✔️۰۰" where ✔️ indicates a captured frame
func formatHandshakeStatus(frames []HandshakeFrame) string {
	captured := make(map[int]bool)
	for _, frame := range frames {
		captured[frame.Num] = true
	}

	result := ""
	for i := 1; i <= 4; i++ {
		if captured[i] {
			result += "✔️"
		} else {
			result += "۰"
		}
	}
	return result
}

// generates the table content for the viewport
func makeAPTable(m scanModel) string {
	if len(m.accessPoints) == 0 {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#888888")).Render("No access points found yet...")
	}

	apList := sortAccessPoints(m.accessPoints, m.sortBy)

	var content strings.Builder

	// Table header with styling - use fixed widths
	bssidHeader := lipgloss.NewStyle().Width(17).Align(lipgloss.Left).Render(tableHeaderStyle.Render("BSSID"))
	ssidHeader := lipgloss.NewStyle().Width(32).Align(lipgloss.Left).Render(tableHeaderStyle.Render("SSID"))
	channelHeader := lipgloss.NewStyle().Width(12).Align(lipgloss.Left).Render(tableHeaderStyle.Render("Channel"))
	rssiHeader := lipgloss.NewStyle().Width(12).Align(lipgloss.Left).Render(tableHeaderStyle.Render("RSSI"))
	clientsHeader := lipgloss.NewStyle().Width(8).Align(lipgloss.Left).Render(tableHeaderStyle.Render("Clients"))
	handshakeHeader := lipgloss.NewStyle().Width(6).Align(lipgloss.Left).Render(tableHeaderStyle.Render("HS"))
	securityHeader := tableHeaderStyle.Render("Security")

	content.WriteString(lipgloss.JoinHorizontal(lipgloss.Left,
		bssidHeader, "  ",
		ssidHeader, "  ",
		channelHeader, "  ",
		rssiHeader, "  ",
		clientsHeader, "  ",
		handshakeHeader, "  ",
		securityHeader) + "\n")
	content.WriteString(strings.Repeat("─", 135) + "\n")

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

		activeChannels := getActiveChannels(ap.ChannelStats, 3)

		// Get handshake status
		handshakeStatus := "۰۰۰۰"
		if frames, ok := m.handshakes[ap.BSSID]; ok && len(frames) > 0 {
			handshakeStatus = formatHandshakeStatus(frames)
		}

		// Build row
		bssidCol := lipgloss.NewStyle().Width(17).Align(lipgloss.Left).Render(ap.BSSID)
		ssidCol := lipgloss.NewStyle().Width(32).Align(lipgloss.Left).Render(ssid)
		channelCol := lipgloss.NewStyle().Width(12).Align(lipgloss.Left).Render(joinInts(activeChannels))
		clientsCol := lipgloss.NewStyle().Width(8).Align(lipgloss.Left).Render(strconv.Itoa(len(ap.Clients)))
		rssiCol := lipgloss.NewStyle().Width(12).Align(lipgloss.Left).Render(styledRSSI)
		handshakeCol := lipgloss.NewStyle().Width(6).Align(lipgloss.Left).Render(handshakeStatus)

		row := lipgloss.JoinHorizontal(lipgloss.Left,
			bssidCol, "  ",
			ssidCol, "  ",
			channelCol, "  ",
			rssiCol, "  ",
			clientsCol, "  ",
			handshakeCol, "  ",
			styledSecurity)
		content.WriteString(row + "\n")
	}

	return content.String()
}
