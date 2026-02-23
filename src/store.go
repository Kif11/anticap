package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type store struct {
	items map[string]int
}

func (s *store) init() {
	s.items = make(map[string]int)
}

func (s *store) add(key string, value int) bool {
	s.items[key] = value
	return true
}

func (s *store) save(outFile string) bool {
	// If the file doesn't exist, create it, or append to the file
	f, err := os.OpenFile(outFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
		return false
	}
	defer f.Close()

	for k, v := range s.items {
		data := fmt.Sprintf("%s %d\n", k, v)
		if _, err := f.Write([]byte(data)); err != nil {
			log.Fatal(err)
			return false
		}
	}
	return true
}

type PacketStore struct {
	File   *os.File
	Writer *pcapgo.Writer
}

func (ps *PacketStore) Init(path string) error {
	if path == "" {
		// If user doesn't provide output path the packing saving to the file is disabled
		return nil
	}

	// Create output directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Open output file in append mode
	var err error
	ps.File, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open output file: %w", err)
	}

	// Check if file is empty (new file) to write pcap header
	fileInfo, err := ps.File.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat output file: %w", err)
	}

	// Initialize pcap writer
	ps.Writer = pcapgo.NewWriter(ps.File)

	// Write pcap header only if file is new/empty
	if fileInfo.Size() == 0 {
		if err := ps.Writer.WriteFileHeader(65536, layers.LinkTypeIEEE80211Radio); err != nil {
			return fmt.Errorf("failed to write pcap header: %w", err)
		}
	}

	return nil
}

func (ps *PacketStore) Close() {
	ps.File.Close()
}

// Write packet to pcap file
func (ps *PacketStore) Write(ci gopacket.CaptureInfo, data []byte) error {
	if ps.Writer == nil {
		return nil
	}
	if err := ps.Writer.WritePacket(ci, data); err != nil {
		return err
	}

	return nil
}
