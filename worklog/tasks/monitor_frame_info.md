# Enhanced 802.11 Frame Data Extraction

## Overview

Currently only extracting MAC addresses and packet counts from captured frames. The gopacket library exposes significantly more data that would help identify devices with active, high-quality connections (useful for captive portal bypass).

## Tasks

### 1. Extend the `device` struct

**File:** `src/store.go`

Add additional metrics to track per device:

```go
type device struct {
    Address        string  `json:"address"`
    PCount         int     `json:"pcount"`          // Total packet count
    Rating         int     `json:"rating"`
    AvgRSSI        int8    `json:"avg_rssi"`        // Average signal strength
    LastRSSI       int8    `json:"last_rssi"`       // Most recent reading
    LastSeen       int64   `json:"last_seen"`       // Unix timestamp
    RetryCount     int     `json:"retry_count"`     // Frames with Retry flag set
    DataFrameCount int     `json:"data_frame_count"`// Data frames (vs mgmt/ctrl)
    MaxDataRate    uint8   `json:"max_data_rate"`   // Highest observed rate
    SNR            int8    `json:"snr"`             // Signal-to-noise ratio
}
```

---

### 2. Modify `handlePacket` to return RadioTap layer

**File:** `src/monitor.go` (lines 598-605)

Change signature to also return `*layers.RadioTap`:

```go
func handlePacket(packet gopacket.Packet) (*layers.Dot11, *layers.RadioTap) {
    var dot11 *layers.Dot11
    var radioTap *layers.RadioTap

    if rtLayer := packet.Layer(layers.LayerTypeRadioTap); rtLayer != nil {
        radioTap, _ = rtLayer.(*layers.RadioTap)
    }

    if d11Layer := packet.Layer(layers.LayerTypeDot11); d11Layer != nil {
        dot11, _ = d11Layer.(*layers.Dot11)
    }

    return dot11, radioTap
}
```

---

### 3. Update packet processing loop

**File:** `src/monitor.go` (lines 662-700)

Extract additional fields from each packet:

| Field | Source | Description |
|-------|--------|-------------|
| RSSI | `radioTap.DBMAntennaSignal` | Signal strength per device |
| Noise | `radioTap.DBMAntennaNoise` | Ambient noise floor |
| SNR | `Signal - Noise` | Connection quality metric |
| Data Rate | `radioTap.Rate` | Throughput capability |
| Frame Type | `dot11.Type.MainType()` | Data vs Mgmt vs Ctrl |
| Retry Flag | `dot11.Flags.Retry()` | Poor link quality indicator |
| ToDS/FromDS | `dot11.Flags.ToDS()` / `FromDS()` | Traffic direction |

Example processing:

```go
dot11, radioTap := handlePacket(packet)
if dot11 != nil {
    isDataFrame := dot11.Type.MainType() == layers.Dot11TypeData
    isRetry := dot11.Flags.Retry()
    toDS := dot11.Flags.ToDS()

    rssi := int8(-100)
    noise := int8(-100)
    dataRate := uint8(0)
    if radioTap != nil {
        rssi = radioTap.DBMAntennaSignal
        noise = radioTap.DBMAntennaNoise
        dataRate = uint8(radioTap.Rate)
    }
    snr := rssi - noise

    // Update device metrics...
}
```

### 4. Enhance output table

**File:** `src/monitor.go` (lines 710-725)

Add new columns to the report:

```
Address              Packets  RSSI   SNR   DataRate  Retry%  Data%
-----------------------------------------------------------------
aa:bb:cc:dd:ee:ff       42    -45    25     54Mbps    5.2%   85.7%
```

## RadioTap Fields Reference

| Field | Type | Description |
|-------|------|-------------|
| `TSFT` | `uint64` | MAC timestamp (μs) |
| `Rate` | `RadioTapRate` | Data rate (Mbps/2) |
| `ChannelFrequency` | `uint16` | Tx/Rx frequency (MHz) |
| `ChannelFlags` | `RadioTapChannelFlags` | CCK, OFDM, 2.4/5GHz |
| `DBMAntennaSignal` | `int8` | Signal strength (dBm) |
| `DBMAntennaNoise` | `int8` | Noise floor (dBm) |
| `Antenna` | `uint8` | Receiving antenna index |
| `Flags` | `RadioTapFlags` | WEP, Short preamble, FCS |
| `MCS` | `RadioTapMCS` | 802.11n modulation info |
| `VHT` | `RadioTapVHT` | 802.11ac info |
| `DataRetries` | `uint8` | Number of retries |

## Dot11 Flags Reference

| Method | Description |
|--------|-------------|
| `ToDS()` | Frame going to distribution system (client→AP) |
| `FromDS()` | Frame from distribution system (AP→client) |
| `Retry()` | Retransmission flag |
| `PowerManagement()` | Device in power save mode |
| `WEP()` | Protected frame |
| `MF()` | More fragments |
| `Order()` | Strict ordering required |

## Dot11 Frame Types

| Constant | Value | Description |
|----------|-------|-------------|
| `Dot11TypeMgmt` | 0x00 | Management frames |
| `Dot11TypeCtrl` | 0x01 | Control frames |
| `Dot11TypeData` | 0x02 | Data frames |
