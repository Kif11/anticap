## Problem

I need to supply ssid to the rateConnection function so that it is able to associate with the target network internally using associateWiFi function.
At the moment my program only receives BSSID (aka MAC address) of the target router. 

## Plan: Add BSSID-to-SSID Resolution with Individual File Cache and Manual Override

The easiest way to determine SSID from BSSID is to leverage existing scanning functionality with persistent caching and manual override capabilities.

### Steps
1. Add manual SSID override flag to cmdBypass by adding `-s` flag that completely bypasses automatic resolution when provided
2. Create NetworkInfo struct and cache functions by adding `NetworkInfo{BSSID, SSID, Channel}` type and helper functions for individual file storage as `store/networks/{bssid}.json`
3. Implement SSID resolution with cache-first logic before monitoring: check manual override first, then cache lookup, then full scan if needed, exit with detailed error if all fail
4. Fix undefined ssid variable by replacing with resolved SSID from the resolution logic before calling `rateConnections`
5. Update cmdScan to populate cache only by storing all discovered networks individually in `store/networks/` after scanning completes
6. Add error message that includes example usage with `-s` flag and suggests running `anticap scan` to populate cache when automatic resolution fails
