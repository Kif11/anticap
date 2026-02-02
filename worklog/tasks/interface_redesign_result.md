# CLI Refactoring Complete

The command-line interface has been refactored from a single command with flags to a subcommand-based structure as specified in [interface_redesign.md](interface_redesign.md).

## Changes Made

### New Subcommand Structure

| Command | Options | Description |
|---------|---------|-------------|
| `anticap bypass` | `-i`, `-t`, `-ch`, `-n`, `-v` | Full process: packet capture, mac spoof, connection testing |
| `anticap scan` | `-5g`, `-t`, `-s`, `-i`, `-v` | Scan available WiFi networks |
| `anticap capture` | `-i`, `-t`, `-ch`, `-n`, `-v` | Run packet capture only |
| `anticap join` | `-p`, `-v` `<SSID>` | Join specified WiFi network |
| `anticap reset` | `-i`, `-v` | Reset to original MAC address |
| `anticap setmac` | `-i`, `-v` `<MAC_ADDRESS>` | Set interface MAC address |
| `anticap list` | `-t`, `-v` | List stored captures for target MAC |

### Files Modified

- `src/main.go` - Replaced global flags with subcommand-based parsing using `flag.NewFlagSet`
- `src/monitor.go` - Updated `monitor()` and `ScanForAccessPoints()` to accept `verbose` parameter
- `src/rating.go` - Updated `rateConnection()` and `rateConnections()` to accept `verbose` parameter  
- `src/utils.go` - Updated `resetOriginalMac()` to accept `verbose` parameter

### Additional Improvements

- Help (`-h`, `--help`) works without root for all commands
- `list` command works without root (only reads from local store)
- Commands requiring root privileges check before execution but allow help display without root
