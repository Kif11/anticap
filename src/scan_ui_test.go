package main

import (
	"reflect"
	"testing"
)

func TestGetActiveChannels(t *testing.T) {
	tests := []struct {
		name     string
		chs      map[int]channelStats
		n        int
		expected []int
	}{
		{
			name:     "empty map",
			chs:      map[int]channelStats{},
			n:        1,
			expected: []int{},
		},
		{
			name: "single channel",
			chs: map[int]channelStats{
				1: {numPackets: 10},
			},
			n:        1,
			expected: []int{1},
		},
		{
			name: "multiple channels, n=2",
			chs: map[int]channelStats{
				1: {numPackets: 5},
				2: {numPackets: 10},
				3: {numPackets: 8},
			},
			n:        2,
			expected: []int{2, 3},
		},
		{
			name: "n larger than available",
			chs: map[int]channelStats{
				1: {numPackets: 5},
				2: {numPackets: 10},
			},
			n:        5,
			expected: []int{2, 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getActiveChannels(tt.chs, tt.n)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("getActiveChannels() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestJoinInts(t *testing.T) {
	tests := []struct {
		name     string
		ints     []int
		expected string
	}{
		{
			name:     "empty slice",
			ints:     []int{},
			expected: "",
		},
		{
			name:     "single int",
			ints:     []int{1},
			expected: "1",
		},
		{
			name:     "multiple ints",
			ints:     []int{1, 2, 3},
			expected: "1 2 3",
		},
		{
			name:     "negative ints",
			ints:     []int{-1, 0, 42},
			expected: "-1 0 42",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := joinInts(tt.ints)
			if result != tt.expected {
				t.Errorf("joinInts() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestSortAccessPoints(t *testing.T) {
	tests := []struct {
		name     string
		aps      map[string]AccessPoint
		sortType string
		expected []AccessPoint
	}{
		{
			name: "sort by security",
			aps: map[string]AccessPoint{
				"bssid1": {BSSID: "bssid1", Security: "OPEN", RSSI: -50},
				"bssid2": {BSSID: "bssid2", Security: "WEP", RSSI: -60},
				"bssid3": {BSSID: "bssid3", Security: "WPA2", RSSI: -70},
				"bssid4": {BSSID: "bssid4", Security: "WPA3", RSSI: -40},
			},
			sortType: "security",
			expected: []AccessPoint{
				{BSSID: "bssid1", Security: "OPEN", RSSI: -50},
				{BSSID: "bssid2", Security: "WEP", RSSI: -60},
				{BSSID: "bssid3", Security: "WPA2", RSSI: -70},
				{BSSID: "bssid4", Security: "WPA3", RSSI: -40},
			},
		},
		{
			name: "sort by security with RSSI tie",
			aps: map[string]AccessPoint{
				"bssid1": {BSSID: "bssid1", Security: "WPA2", RSSI: -50},
				"bssid2": {BSSID: "bssid2", Security: "WPA2", RSSI: -60},
			},
			sortType: "security",
			expected: []AccessPoint{
				{BSSID: "bssid1", Security: "WPA2", RSSI: -50}, // stronger RSSI first
				{BSSID: "bssid2", Security: "WPA2", RSSI: -60},
			},
		},
		{
			name: "sort by RSSI",
			aps: map[string]AccessPoint{
				"bssid1": {BSSID: "bssid1", RSSI: -70},
				"bssid2": {BSSID: "bssid2", RSSI: -50},
				"bssid3": {BSSID: "bssid3", RSSI: -60},
			},
			sortType: "",
			expected: []AccessPoint{
				{BSSID: "bssid2", RSSI: -50},
				{BSSID: "bssid3", RSSI: -60},
				{BSSID: "bssid1", RSSI: -70},
			},
		},
		{
			name:     "empty map",
			aps:      map[string]AccessPoint{},
			sortType: "security",
			expected: []AccessPoint{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sortAccessPoints(tt.aps, tt.sortType)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("sortAccessPoints() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGetBusyChannel(t *testing.T) {
	tests := []struct {
		name     string
		aps      map[string]AccessPoint
		expected int
	}{
		{
			name:     "empty map",
			aps:      map[string]AccessPoint{},
			expected: 0,
		},
		{
			name: "single AP single channel",
			aps: map[string]AccessPoint{
				"bssid1": {
					BSSID: "bssid1",
					ChannelStats: map[int]channelStats{
						1: {numPackets: 10},
					},
				},
			},
			expected: 1,
		},
		{
			name: "multiple APs same channel",
			aps: map[string]AccessPoint{
				"bssid1": {
					BSSID: "bssid1",
					ChannelStats: map[int]channelStats{
						1: {numPackets: 5},
					},
				},
				"bssid2": {
					BSSID: "bssid2",
					ChannelStats: map[int]channelStats{
						1: {numPackets: 15},
					},
				},
			},
			expected: 1,
		},
		{
			name: "multiple channels, channel 2 busiest",
			aps: map[string]AccessPoint{
				"bssid1": {
					BSSID: "bssid1",
					ChannelStats: map[int]channelStats{
						1: {numPackets: 10},
						2: {numPackets: 20},
					},
				},
				"bssid2": {
					BSSID: "bssid2",
					ChannelStats: map[int]channelStats{
						2: {numPackets: 5},
						3: {numPackets: 8},
					},
				},
			},
			expected: 2, // channel 2: 20+5=25, channel 1:10, channel 3:8
		},
		{
			name: "AP with multiple channels",
			aps: map[string]AccessPoint{
				"bssid1": {
					BSSID: "bssid1",
					ChannelStats: map[int]channelStats{
						1:  {numPackets: 5},
						6:  {numPackets: 15},
						11: {numPackets: 10},
					},
				},
			},
			expected: 6,
		},
		{
			name: "tie, returns first encountered",
			aps: map[string]AccessPoint{
				"bssid1": {
					BSSID: "bssid1",
					ChannelStats: map[int]channelStats{
						1: {numPackets: 15},
					},
				},
				"bssid2": {
					BSSID: "bssid2",
					ChannelStats: map[int]channelStats{
						2: {numPackets: 10},
					},
				},
			},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getBusyChannel(tt.aps)
			if result != tt.expected {
				t.Errorf("getBusyChannel() = %v, want %v", result, tt.expected)
			}
		})
	}
}
