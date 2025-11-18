//! Data race prevention example

use rust_memory_safety_examples::data_race;

fn main() {
    println!("=== Data Race Prevention in Rust ===\n");

    println!("1. Safe Concurrent Access with Arc and Mutex");
    data_race::safe_concurrent_access();

    println!("\n2. Type System Prevents Races");
    data_race::type_system_prevents_races();

    println!("\n3. C vs Rust Comparison");
    data_race::compare_c_vs_rust();

    println!("\n=== Key Takeaways ===");
    println!("✓ Rust prevents data races at compile time");
    println!("✓ Send and Sync traits enforce thread safety");
    println!("✓ Arc and Mutex provide safe concurrent access");
    println!("✓ No undefined behavior in concurrent code");
}
