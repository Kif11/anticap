package main

import (
	"bufio"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
)

func getMac(interfc string) (string, error) {
	netInterface, err := net.InterfaceByName(interfc)
	if err != nil {
		return "", err
	}
	return netInterface.HardwareAddr.String(), nil
}

func getRouterAddress() (string, error) {
	airportBin := "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport"

	out, err := exec.Command(airportBin, "-I").Output()

	if err != nil {
		return "", err
	}

	s := string(out[:])
	scanner := bufio.NewScanner(strings.NewReader(s))

	for scanner.Scan() {
		text := scanner.Text()
		if !strings.Contains(text, "BSSID") {
			continue
		}
		text = strings.TrimSpace(text)
		text = strings.Replace(text, "BSSID: ", "", 1)
		return text, nil
	}
	return "", errors.New("can not find BSSID in airport output")
}

func setMac(interfc string, mac string) error {
	airportBin := "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/A/Resources/airport"

	// Dissociate from WiFi network
	if err := exec.Command(airportBin, "-z").Run(); err != nil {
		return err
	}

	// Spoof mac
	if err := exec.Command("ifconfig", interfc, "ether", mac).Run(); err != nil {
		return err
	}

	// Detect new network hardware and create a default network service on the hardware
	if err := exec.Command("networksetup", "-detectnewhardware").Run(); err != nil {
		return err
	}

	// Restart WiFi interface to connect back
	if err := exec.Command("networksetup", "-setairportpower", interfc, "off").Run(); err != nil {
		return err
	}
	if err := exec.Command("networksetup", "-setairportpower", interfc, "on").Run(); err != nil {
		return err
	}

	return nil
}

func isSudo() bool {
	if os.Getenv("SUDO_USER") != "" {
		return true
	}
	return false
}
