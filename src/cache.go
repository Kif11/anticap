package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// getCachedNetwork retrieves SSID for given BSSID from cache
func getCachedNetwork(bssid string) (CachedNetwork, error) {
	cacheFile := filepath.Join("store", "networks", bssid+".json")

	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		return CachedNetwork{}, fmt.Errorf("no cache entry for BSSID %s", bssid)
	}

	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return CachedNetwork{}, fmt.Errorf("failed to read cache file: %w", err)
	}

	var info CachedNetwork
	if err := json.Unmarshal(data, &info); err != nil {
		return CachedNetwork{}, fmt.Errorf("failed to parse cache file: %w", err)
	}

	return info, nil
}

// populateNetworkCache stores discovered networks in individual cache files
func populateNetworkCache(aps map[string]AccessPoint, verbose bool) error {
	cacheDir := filepath.Join("store", "networks")
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	count := 0
	for bssid, ap := range aps {
		// Skip networks without SSID
		if ap.SSID == "" {
			continue
		}

		info := CachedNetwork{
			BSSID:    bssid,
			SSID:     ap.SSID,
			Channels: ap.Channels,
		}

		data, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			if verbose {
				fmt.Printf("Warning: failed to marshal network info for %s: %v\n", bssid, err)
			}
			continue
		}

		cacheFile := filepath.Join(cacheDir, bssid+".json")
		if err := os.WriteFile(cacheFile, data, 0644); err != nil {
			if verbose {
				fmt.Printf("Warning: failed to write cache file for %s: %v\n", bssid, err)
			}
			continue
		}
		count++
	}

	if verbose {
		fmt.Printf("Cached %d networks in %s\n", count, cacheDir)
	}

	return nil
}
