//! CVE Case Studies - Real-world vulnerability analysis
//!
//! This example demonstrates how Rust's memory safety prevents vulnerabilities
//! that have been exploited in real-world CVEs affecting C/C++ software.

/// CVE-2014-0160 - Heartbleed (OpenSSL Buffer Over-read)
///
/// In C, a missing bounds check allowed attackers to read arbitrary memory.
/// Rust's slice bounds checking prevents this category of vulnerability.
mod heartbleed_prevention {
    /// Demonstrates how Rust prevents buffer over-read vulnerabilities
    ///
    /// In the real Heartbleed bug:
    /// - Client could request a "heartbeat" echo with a specified length
    /// - Server would copy `length` bytes without checking actual data size
    /// - Attacker could read beyond buffer into sensitive memory (keys, passwords)
    pub fn demonstrate_bounds_checking() {
        println!("\n=== CVE-2014-0160 Heartbleed Prevention ===");

        // Simulated heartbeat payload
        let actual_data = b"Hello";
        let claimed_length = 65535; // Attacker claims much larger size

        // C code (VULNERABLE):
        // memcpy(response, request_data, claimed_length);
        // Would copy 65535 bytes, reading far beyond actual 5-byte buffer

        // Rust equivalent (SAFE):
        let safe_response: Vec<u8> = actual_data
            .iter()
            .take(claimed_length.min(actual_data.len()))
            .copied()
            .collect();

        println!("Claimed length: {} bytes", claimed_length);
        println!("Actual length: {} bytes", actual_data.len());
        println!("Safe response length: {} bytes", safe_response.len());
        println!("Rust prevented reading beyond buffer bounds!");

        // Alternative: explicit bounds check
        let response = if claimed_length <= actual_data.len() {
            actual_data[..claimed_length].to_vec()
        } else {
            println!("Warning: Length mismatch detected, using actual length");
            actual_data.to_vec()
        };

        println!("Response: {:?}", String::from_utf8_lossy(&response));
    }

    /// Safe heartbeat implementation
    pub fn safe_heartbeat(payload: &[u8], claimed_length: usize) -> Vec<u8> {
        // Rust enforces bounds checking automatically
        let actual_length = payload.len().min(claimed_length);
        payload[..actual_length].to_vec()
    }
}

/// CVE-2021-3156 - Sudo Baron Samedit (Heap Buffer Overflow)
///
/// A heap-based buffer overflow in sudo's argument parsing.
/// Rust's ownership and bounds checking prevent this vulnerability class.
mod baron_samedit_prevention {
    /// Demonstrates how Rust prevents heap buffer overflows
    pub fn demonstrate_heap_safety() {
        println!("\n=== CVE-2021-3156 Baron Samedit Prevention ===");

        // The vulnerability: backslash processing with off-by-one error
        // In C: writing beyond allocated heap buffer

        let input = r"test\ argument\ with\ escapes";

        // C code (VULNERABLE):
        // char* buf = malloc(strlen(input));  // Off-by-one: no space for null
        // for (char* p = input; *p; p++) {
        //     if (*p == '\\') { ... }  // Could write beyond buf
        // }

        // Rust equivalent (SAFE):
        let processed: String = input
            .chars()
            .filter(|&c| c != '\\')
            .collect();

        println!("Input: {}", input);
        println!("Processed: {}", processed);
        println!("Rust's String automatically manages heap allocation!");

        // Vec demonstration - automatic growth
        let mut buffer: Vec<char> = Vec::new();
        for c in input.chars() {
            if c != '\\' {
                buffer.push(c); // Automatically grows, no overflow possible
            }
        }
        println!("Buffer safely grew to {} chars", buffer.len());
    }

    /// Safe argument parsing
    pub fn parse_arguments(args: &[&str]) -> Vec<String> {
        args.iter()
            .map(|arg| {
                arg.chars()
                    .filter(|&c| c != '\\')
                    .collect()
            })
            .collect()
    }
}

/// CVE-2019-14287 - Sudo User ID Bypass (Integer Overflow)
///
/// An integer overflow/underflow allowed privilege escalation.
/// Rust's checked arithmetic and Option types prevent this.
mod sudo_uid_bypass_prevention {
    /// Demonstrates how Rust prevents integer overflow exploits
    pub fn demonstrate_integer_safety() {
        println!("\n=== CVE-2019-14287 Sudo UID Bypass Prevention ===");

        // The vulnerability: -1 as UID was converted to MAX_UINT, then to 0 (root)
        // sudo -u#-1 command -> became root!

        // C code (VULNERABLE):
        // uid_t uid = (uid_t) -1;  // Becomes 4294967295
        // if (uid != 0) { ... }    // Check passes
        // setuid(uid);             // Wraps to 0 (root)!

        // Rust with explicit handling:
        let user_input = -1i32;

        // Checked conversion (SAFE):
        match u32::try_from(user_input) {
            Ok(uid) => println!("Valid UID: {}", uid),
            Err(_) => println!("Invalid UID: negative values not allowed!"),
        }

        // Demonstrate wrapping behavior awareness
        let wrapped = user_input as u32; // 4294967295
        println!("If we forced wrapping: {}", wrapped);
        println!("Rust makes this explicit - no silent overflow!");

        // Safe UID handling
        let safe_uid = validate_uid(user_input);
        match safe_uid {
            Some(uid) => println!("Safe UID: {}", uid),
            None => println!("Rejected: Invalid UID input"),
        }
    }

    /// Safe UID validation
    pub fn validate_uid(input: i32) -> Option<u32> {
        if input < 0 {
            None // Reject negative values
        } else {
            Some(input as u32)
        }
    }

    /// Even safer with explicit bounds
    pub fn validate_uid_strict(input: i64) -> Option<u32> {
        if input >= 0 && input <= u32::MAX as i64 {
            Some(input as u32)
        } else {
            None
        }
    }
}

/// CVE-2020-8597 - pppd Buffer Overflow (EAP Packet Handling)
///
/// A stack buffer overflow in PPP daemon's EAP packet handling.
/// Rust's slice safety and bounds checking prevent this.
mod pppd_buffer_overflow_prevention {
    /// Demonstrates how Rust prevents stack buffer overflows
    pub fn demonstrate_stack_safety() {
        println!("\n=== CVE-2020-8597 pppd Buffer Overflow Prevention ===");

        // The vulnerability: copying EAP packet data without size validation
        // Stack buffer overflow -> Remote Code Execution

        // C code (VULNERABLE):
        // char buffer[256];
        // memcpy(buffer, packet_data, packet_length);  // No bounds check!

        // Rust equivalent (SAFE):
        let packet_data = vec![0u8; 1024]; // Attacker sends oversized packet
        let mut buffer = [0u8; 256]; // Fixed-size stack buffer

        // Safe copy with bounds checking
        let bytes_to_copy = packet_data.len().min(buffer.len());
        buffer[..bytes_to_copy].copy_from_slice(&packet_data[..bytes_to_copy]);

        println!("Packet size: {} bytes", packet_data.len());
        println!("Buffer size: {} bytes", buffer.len());
        println!("Safely copied: {} bytes", bytes_to_copy);
        println!("Stack buffer overflow prevented!");

        // Even safer: reject oversized packets
        if packet_data.len() > buffer.len() {
            println!("Warning: Oversized packet rejected!");
        }
    }

    /// Safe packet processing
    pub fn process_eap_packet(packet: &[u8], max_size: usize) -> Result<Vec<u8>, &'static str> {
        if packet.len() > max_size {
            return Err("Packet exceeds maximum allowed size");
        }
        Ok(packet.to_vec())
    }
}

/// CVE-2018-1000001 - glibc getcwd() Buffer Underflow
///
/// A buffer underflow in glibc's realpath() function.
/// Rust's ownership model and bounds checking prevent this.
mod glibc_buffer_underflow_prevention {
    use std::path::PathBuf;

    /// Demonstrates how Rust prevents buffer underflows
    pub fn demonstrate_path_safety() {
        println!("\n=== CVE-2018-1000001 glibc getcwd() Prevention ===");

        // The vulnerability: getcwd() could return relative path starting with '('
        // realpath() didn't handle this, causing buffer underflow

        // C code (VULNERABLE):
        // char buf[PATH_MAX];
        // realpath("../../../etc/passwd", buf);  // Potential underflow

        // Rust equivalent (SAFE):
        let malicious_path = "../../../etc/passwd";

        // PathBuf handles path manipulation safely
        let path = PathBuf::from(malicious_path);

        // Canonicalize safely handles path resolution
        match std::fs::canonicalize(&path) {
            Ok(canonical) => println!("Resolved path: {:?}", canonical),
            Err(e) => println!("Path resolution failed safely: {}", e),
        }

        // No buffer underflow possible - Rust manages memory safely
        println!("Rust's PathBuf prevents buffer underflows in path handling");

        // Demonstrate safe path joining
        let base = PathBuf::from("/home/user");
        let relative = "../../../etc/passwd";
        let combined = base.join(relative);
        println!("Combined path (not canonicalized): {:?}", combined);
        println!("No memory corruption possible!");
    }

    /// Safe path resolution
    pub fn safe_resolve_path(path: &str) -> Option<PathBuf> {
        let p = PathBuf::from(path);
        std::fs::canonicalize(&p).ok()
    }
}

/// CVE-2017-5753 - Spectre Variant 1 (Bounds Check Bypass)
///
/// While Rust can't fully prevent Spectre, it provides safer patterns
/// and the constant_time_eq crate for timing-safe comparisons.
mod spectre_mitigation_patterns {
    /// Demonstrates safer patterns for sensitive comparisons
    pub fn demonstrate_timing_safe_patterns() {
        println!("\n=== CVE-2017-5753 Spectre Mitigation Patterns ===");

        // Spectre exploits speculative execution of bounds checks
        // Rust's bounds checks are still vulnerable to speculation
        // but we can use safer patterns for sensitive operations

        let secret = b"secret_password";
        let guess = b"secret_password";

        // Naive comparison (potentially vulnerable to timing attacks):
        // if secret == guess { ... }

        // Constant-time comparison pattern
        let result = constant_time_compare(secret, guess);
        println!("Constant-time comparison result: {}", result);

        // For cryptographic operations, use dedicated libraries
        // that implement constant-time operations
        println!("Use dedicated crypto libraries for sensitive comparisons");
        println!("Examples: subtle, constant_time_eq crates");
    }

    /// Constant-time byte comparison (simplified)
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }
}

/// Summary: Vulnerability classes prevented by Rust
mod vulnerability_summary {
    /// Print summary of prevented vulnerability classes
    pub fn print_summary() {
        println!("\n=== Rust Memory Safety Summary ===");
        println!("Vulnerability classes prevented by Rust's design:\n");

        let prevented = [
            ("Buffer Overflow", "Bounds checking on all array/slice access"),
            ("Buffer Over-read", "Slice length tracked, can't read beyond bounds"),
            ("Use-After-Free", "Ownership system tracks all references"),
            ("Double-Free", "Single owner, dropped exactly once"),
            ("Null Pointer Deref", "Option<T> forces explicit handling"),
            ("Data Races", "Send/Sync traits + borrow checker"),
            ("Integer Overflow", "Checked arithmetic in debug, wrapping explicit"),
            ("Format String", "Type-safe formatting macros"),
            ("Uninitialized Memory", "All variables must be initialized"),
        ];

        for (vuln, prevention) in &prevented {
            println!("  {} -> {}", vuln, prevention);
        }

        println!("\nThese protections eliminate ~70% of CVEs according to");
        println!("Microsoft and Google security research (2019-2024).");
    }
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║     Rust Memory Safety: CVE Case Studies v2.0                ║");
    println!("║     Demonstrating Real-World Vulnerability Prevention        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    heartbleed_prevention::demonstrate_bounds_checking();
    baron_samedit_prevention::demonstrate_heap_safety();
    sudo_uid_bypass_prevention::demonstrate_integer_safety();
    pppd_buffer_overflow_prevention::demonstrate_stack_safety();
    glibc_buffer_underflow_prevention::demonstrate_path_safety();
    spectre_mitigation_patterns::demonstrate_timing_safe_patterns();
    vulnerability_summary::print_summary();

    println!("\n=== Case Studies Complete ===");
    println!("All examples demonstrate how Rust's design prevents");
    println!("vulnerability classes that have caused major security incidents.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heartbleed_prevention() {
        let data = b"test";
        let result = heartbleed_prevention::safe_heartbeat(data, 1000);
        assert_eq!(result.len(), data.len());
    }

    #[test]
    fn test_argument_parsing() {
        let args = &["test\\arg", "normal"];
        let parsed = baron_samedit_prevention::parse_arguments(args);
        assert_eq!(parsed[0], "testarg");
        assert_eq!(parsed[1], "normal");
    }

    #[test]
    fn test_uid_validation() {
        assert!(sudo_uid_bypass_prevention::validate_uid(-1).is_none());
        assert_eq!(sudo_uid_bypass_prevention::validate_uid(1000), Some(1000));
    }

    #[test]
    fn test_packet_processing() {
        let packet = vec![0u8; 100];
        assert!(pppd_buffer_overflow_prevention::process_eap_packet(&packet, 256).is_ok());

        let large_packet = vec![0u8; 1000];
        assert!(pppd_buffer_overflow_prevention::process_eap_packet(&large_packet, 256).is_err());
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(spectre_mitigation_patterns::constant_time_compare(b"test", b"test"));
        assert!(!spectre_mitigation_patterns::constant_time_compare(b"test", b"tset"));
        assert!(!spectre_mitigation_patterns::constant_time_compare(b"short", b"longer"));
    }
}
