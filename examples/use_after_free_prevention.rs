//! Use-after-free prevention example

use rust_memory_safety_examples::use_after_free;

fn main() {
    println!("=== Use-After-Free Prevention in Rust ===\n");

    println!("1. Ownership Prevents Use-After-Free");
    use_after_free::ownership_prevents_uaf();

    println!("\n2. Borrowing Prevents Dangling References");
    use_after_free::borrowing_prevents_dangling();

    println!("\n3. C vs Rust Comparison");
    use_after_free::compare_c_vs_rust();

    println!("\n=== Key Takeaways ===");
    println!("✓ Rust's ownership system makes use-after-free impossible");
    println!("✓ Compile-time prevention - errors caught before execution");
    println!("✓ Lifetimes ensure references are always valid");
    println!("✓ No runtime overhead - zero-cost abstraction");
}
