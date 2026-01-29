import CoreWLAN

let client = CWWiFiClient.shared
guard let interface = client().interface() else {
    print("No WiFi interface found")
    exit(1)
}

interface.disassociate()
