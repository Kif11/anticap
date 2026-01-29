import CoreWLAN

let ifaceName = CommandLine.arguments[1]
let channelNumStr = CommandLine.arguments[2]

guard let channelNum = Int(channelNumStr) else {
    print("Invalid channel number")
    exit(1)
}

let client = CWWiFiClient.shared
guard let interface = client().interface(withName: ifaceName) else {
    print("Interface not found")
    exit(1)
}

interface.disassociate()

var band: CWChannelBand
if channelNum >= 1 && channelNum <= 14 {
    band = .band2GHz
} else if channelNum >= 36 {
    band = .band5GHz
} else {
    print("Unsupported channel number")
    exit(1)
}

// Get supported channels
guard let supportedChannels = interface.supportedWLANChannels() else {
    print("Unable to retrieve supported channels")
    exit(1)
}

// Find the matching channel
guard let cwChannel = supportedChannels.first(where: { $0.channelNumber == channelNum && $0.channelBand == band }) else {
    print("Channel \(channelNum) on \(band == .band2GHz ? "2.4GHz" : "5GHz") band is not supported")
    exit(1)
}

print("Setting interface \(ifaceName) to channel \(channelNum) on \(band == .band2GHz ? "2.4GHz" : "5GHz") band")

do {
    try interface.setWLANChannel(cwChannel)
} catch let error {
    print("Error setting channel: \(error)")
    exit(1)
}