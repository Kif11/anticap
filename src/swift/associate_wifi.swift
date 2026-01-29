#!/usr/bin/swift

import Foundation
import CoreWLAN

// Usage: swift associate_wifi.swift <SSID> [password]
// Password is optional for open networks

guard CommandLine.arguments.count >= 2 else {
    print("{\"success\": false, \"error\": \"Usage: associate_wifi.swift <SSID> [password]\"}")
    exit(1)
}

let targetSSID = CommandLine.arguments[1]
let password: String? = CommandLine.arguments.count >= 3 ? CommandLine.arguments[2] : nil

struct AssociateResult: Codable {
    let success: Bool
    let error: String?
    let ssid: String?
    let bssid: String?
}

func outputResult(_ result: AssociateResult) {
    let encoder = JSONEncoder()
    if let jsonData = try? encoder.encode(result),
       let jsonString = String(data: jsonData, encoding: .utf8) {
        print(jsonString)
    } else {
        print("{\"success\": false, \"error\": \"Failed to encode result\"}")
    }
}

let client = CWWiFiClient.shared()

guard let interface = client.interface() else {
    outputResult(AssociateResult(success: false, error: "No WiFi interface found", ssid: nil, bssid: nil))
    exit(1)
}

// Scan for networks to find the target by SSID
do {
    let networks = try interface.scanForNetworks(withSSID: nil)
    
    var targetNetwork: CWNetwork? = nil
    for network in networks {
        if let ssid = network.ssid, ssid == targetSSID {
            targetNetwork = network
            break
        }
    }
    
    guard let network = targetNetwork else {
        var availableNetworks: [String] = []
        for network in networks {
            if let ssid = network.ssid, !ssid.isEmpty {
                availableNetworks.append(ssid)
            }
        }
        let suggestion = availableNetworks.isEmpty ? 
            "No networks found." :
            "Available: \(availableNetworks.prefix(5).joined(separator: ", "))\(availableNetworks.count > 5 ? "..." : "")"
        
        outputResult(AssociateResult(
            success: false, 
            error: "Network '\(targetSSID)' not found. \(suggestion)",
            ssid: nil,
            bssid: nil
        ))
        exit(1)
    }
    
    // Attempt to associate
    do {
        try interface.associate(to: network, password: password)
        
        // Wait for connection to establish
        Thread.sleep(forTimeInterval: 2.0)
        
        let connectedSSID = interface.ssid() ?? network.ssid ?? "Unknown"
        let connectedBSSID = interface.bssid() ?? "Unknown"
        
        outputResult(AssociateResult(
            success: true,
            error: nil,
            ssid: connectedSSID,
            bssid: connectedBSSID
        ))
        
    } catch let associateError as NSError {
        var errorMsg: String
        switch associateError.code {
        case -3924: errorMsg = "Invalid password"
        case -3925: errorMsg = "Network requires a password"
        case -3905: errorMsg = "Operation timed out"
        case -3906: errorMsg = "Association failed - network may be out of range"
        case -3907: errorMsg = "Authentication failed - wrong password?"
        default: errorMsg = "Association failed (code \(associateError.code)): \(associateError.localizedDescription)"
        }
        
        outputResult(AssociateResult(success: false, error: errorMsg, ssid: network.ssid, bssid: nil))
        exit(1)
    }
    
} catch let scanError as NSError {
    outputResult(AssociateResult(
        success: false,
        error: "Failed to scan: \(scanError.localizedDescription)",
        ssid: nil,
        bssid: nil
    ))
    exit(1)
}
