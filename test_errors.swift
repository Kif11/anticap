#!/usr/bin/swift

import CoreWLAN
import Foundation

print("=== All CWErr properties and methods ===")

// Create a sample error
if let err = CWErr(rawValue: -3905) {
    print("Sample error: \(err)")
    print("Raw value: \(err.rawValue)")
    
    // Try to see if it has a description
    let mirror = Mirror(reflecting: err)
    print("Mirror display style: \(String(describing: mirror.displayStyle))")
    print("Mirror children count: \(mirror.children.count)")
    for child in mirror.children {
        print("  \(child.label ?? "?"): \(child.value)")
    }
}

print("\n=== Checking if CWErr conforms to CaseIterable ===")
// Try to access .allCases if it exists
if let allCases = (CWErr.self as? any CaseIterable.Type) {
    print("CWErr conforms to CaseIterable!")
} else {
    print("CWErr does NOT conform to CaseIterable")
}

print("\n=== Complete scan of error codes ===")
for code in -4000 ... -3800 {
    if let cwErr = CWErr(rawValue: code) {
        print(code, terminator: " ")
    }
}
print("\n")
