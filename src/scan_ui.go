package main

import (
	"fmt"
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

// ScanCompleteMsg is sent when scanning is finished
type ScanCompleteMsg struct{}

// scanModel represents the Bubble Tea scanModel for the scanning UI
type scanModel struct {
	accessPoints   map[string]AccessPoint
	sortBy         string
	scanning       bool
	total          int
	currentChannel int
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
				Foreground(lipgloss.Color("#FAFAFA")).
				PaddingLeft(1).
				PaddingRight(1)

	goodRSSIStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575"))
	okRSSIStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700"))
	weakRSSIStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6B6B"))

	secureStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#8f8f8f"))
	mediumStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#ffd900"))
	insecureStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575"))
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
		if !m.ready {
			// Initialize viewport
			m.viewport = viewport.New(msg.Width, msg.Height-6) // Leave space for header
			m.viewport.SetContent(makeAPTable(m))
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

// View renders the UI
func (m scanModel) View() string {
	if !m.ready {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#7D56F4")).Render("Initializing...")
	}

	// Header
	var header string
	if m.scanning {
		header = headerStyle.Render(fmt.Sprintf("📡 Scanning channel: %d, Total APs: %d ... 'q' to quit", m.currentChannel, m.total))
	} else {
		header = headerStyle.Render(fmt.Sprintf("📡 Scan Complete!, Total APs: %d ... 'q' to quit", m.total))
	}

	var errorLine string = ""
	if m.err != nil {
		errorLine = errorStyle.Render(fmt.Sprintf("⚠️  %s", m.err.Error()))
	}

	// Combine header and viewport with a table
	return lipgloss.JoinVertical(lipgloss.Left, header, errorLine, m.viewport.View())
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
