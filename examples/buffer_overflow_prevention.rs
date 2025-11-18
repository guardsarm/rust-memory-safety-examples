//! Buffer overflow prevention example

use rust_memory_safety_examples::buffer_overflow;

fn main() {
    println!("=== Buffer Overflow Prevention in Rust ===\n");

    println!("1. Safe Array Access");
    buffer_overflow::safe_array_access();

    println!("\n2. Safe String Handling");
    buffer_overflow::safe_string_handling();

    println!("\n3. C vs Rust Comparison");
    buffer_overflow::compare_c_vs_rust();

    println!("\n=== Key Takeaways ===");
    println!("✓ Rust prevents buffer overflows at compile time and runtime");
    println!("✓ Bounds checking is automatic and cannot be bypassed");
    println!("✓ No undefined behavior - panics are safe and recoverable");
    println!("✓ Strings automatically resize - no fixed buffer vulnerabilities");
}
