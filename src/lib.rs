//! # Rust Memory Safety Examples
//!
//! Educational examples demonstrating memory-safe programming patterns in Rust
//! for financial systems and critical infrastructure.
//!
//! ## Purpose
//!
//! This library provides clear, documented examples of how Rust's ownership system
//! prevents common memory safety vulnerabilities that affect C/C++ systems.
//!
//! ## Comparative Examples
//!
//! Each module includes:
//! - Vulnerable C/C++ code patterns (commented examples)
//! - Safe Rust equivalents
//! - Explanations of how Rust prevents the vulnerability
//! - Real-world CVE references
//!
//! ## Alignment with Federal Guidance
//!
//! These examples align with 2024 CISA/FBI guidance recommending memory-safe
//! languages for critical infrastructure to eliminate 70% of security vulnerabilities.

#![allow(clippy::empty_line_after_doc_comments)]
#![allow(clippy::mixed_attributes_style)]
#![allow(dead_code)]
#![allow(clippy::vec_init_then_push)]
#![allow(clippy::approx_constant)]
#![allow(clippy::useless_vec)]

pub mod buffer_overflow_prevention;
pub mod data_race_prevention;
pub mod use_after_free_prevention;

/// Module demonstrating buffer overflow prevention
pub mod buffer_overflow {
    //! Buffer overflow prevention through bounds checking
    //!
    //! In C/C++, buffer overflows are a major security vulnerability.
    //! Rust prevents these at compile time and runtime.

    /// Safe array access - Rust prevents buffer overflows
    pub fn safe_array_access() {
        let data = vec![1, 2, 3, 4, 5];

        // Safe access with bounds checking
        if let Some(&value) = data.get(10) {
            println!("Value: {}", value);
        } else {
            println!("Index out of bounds - safely handled!");
        }

        // Panics instead of undefined behavior (can be caught)
        // let value = data[10]; // Would panic with clear error message
    }

    /// Safe string handling - no buffer overflows
    pub fn safe_string_handling() {
        let mut buffer = String::new();

        // Rust automatically resizes, no fixed buffer overflow
        for i in 0..1000 {
            buffer.push_str(&format!("Item {}, ", i));
        }

        println!("Buffer safely holds {} bytes", buffer.len());
    }

    /// Comparing C vs Rust buffer handling
    pub fn compare_c_vs_rust() {
        // C code (UNSAFE):
        // char buffer[10];
        // strcpy(buffer, "This is way too long"); // Buffer overflow!

        // Rust equivalent (SAFE):
        let buffer = "This is way too long".to_string();
        let truncated: String = buffer.chars().take(10).collect();

        println!("C: Buffer overflow vulnerability");
        println!("Rust: Safe truncation - {}", truncated);
    }
}

/// Module demonstrating use-after-free prevention
pub mod use_after_free {
    //! Use-after-free prevention through ownership
    //!
    //! Use-after-free is impossible in safe Rust due to the ownership system.

    /// Ownership prevents use-after-free
    pub fn ownership_prevents_uaf() {
        let data = vec![1, 2, 3, 4, 5];

        // Transfer ownership
        let owned_data = data;
        // data is now invalid

        // This would not compile:
        // println!("{:?}", data); // ERROR: value used after move

        println!("Rust prevents use-after-free at compile time");
        println!("Data safely owned: {:?}", owned_data);
    }

    /// Borrowing prevents dangling references
    pub fn borrowing_prevents_dangling() {
        let data = vec![1, 2, 3, 4, 5];

        // Borrow the data
        let reference = &data;

        // Can't drop data while reference exists
        // drop(data); // ERROR: cannot move out of `data` because it is borrowed

        println!("Reference is valid: {:?}", reference);
        // data dropped here, after reference is done
    }

    /// Comparing C vs Rust lifetime management
    pub fn compare_c_vs_rust() {
        // C code (UNSAFE):
        // int* ptr;
        // {
        //     int x = 42;
        //     ptr = &x;
        // }
        // printf("%d", *ptr); // Use-after-free!

        // Rust equivalent (SAFE - won't compile):
        /*
        let ptr: &i32;
        {
            let x = 42;
            ptr = &x; // ERROR: `x` does not live long enough
        }
        */

        println!("C: Use-after-free vulnerability");
        println!("Rust: Compile-time prevention of dangling pointers");
    }
}

/// Module demonstrating data race prevention
///
/// Data race prevention through ownership and type system
///
/// Rust prevents data races at compile time through the type system.
pub mod data_race {
    use std::sync::{Arc, Mutex};
    use std::thread;

    /// Arc and Mutex for safe concurrent access
    pub fn safe_concurrent_access() {
        let counter = Arc::new(Mutex::new(0));
        let mut handles = vec![];

        for _ in 0..10 {
            let counter_clone = Arc::clone(&counter);
            let handle = thread::spawn(move || {
                let mut num = counter_clone.lock().unwrap();
                *num += 1;
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        println!("Final count (safe): {}", *counter.lock().unwrap());
        println!("No data races possible!");
    }

    /// Send and Sync traits prevent data races
    pub fn type_system_prevents_races() {
        // This would not compile (Rc is not Send):
        // use std::rc::Rc;
        // let data = Rc::new(vec![1, 2, 3]);
        // thread::spawn(move || {
        //     println!("{:?}", data); // ERROR: Rc cannot be sent between threads
        // });

        println!("Rust's type system prevents data races at compile time");
    }

    /// Comparing C vs Rust concurrency
    pub fn compare_c_vs_rust() {
        // C code (UNSAFE):
        // int counter = 0;
        // // Multiple threads incrementing counter without synchronization
        // // Result: Data race, undefined behavior

        // Rust equivalent (SAFE):
        safe_concurrent_access();

        println!("\nC: Data races cause undefined behavior");
        println!("Rust: Compile-time prevention of data races");
    }
}

/// Module demonstrating integer overflow protection
pub mod integer_overflow {
    //! Integer overflow detection and prevention

    /// Checked arithmetic prevents silent overflows
    pub fn checked_arithmetic() {
        let a: u32 = 4_000_000_000;
        let b: u32 = 1_000_000_000;

        // Silent overflow in C (undefined behavior)
        // In Rust debug mode: panics
        // In Rust release mode with checked_add: returns None

        match a.checked_add(b) {
            Some(result) => println!("Result: {}", result),
            None => println!("Overflow detected and handled safely!"),
        }
    }

    /// Saturating arithmetic for financial calculations
    pub fn saturating_arithmetic() {
        let balance: u32 = 1000;
        let withdrawal: u32 = 2000;

        // Saturating subtraction (clamps at 0)
        let new_balance = balance.saturating_sub(withdrawal);

        println!("Balance after withdrawal: {} (saturated)", new_balance);
    }
}

/// Module demonstrating null pointer dereference prevention
pub mod null_pointer {
    //! Null pointer prevention through Option<T>

    /// Option<T> eliminates null pointer dereferences
    pub fn option_prevents_null() {
        fn find_user(id: u32) -> Option<String> {
            if id == 1 {
                Some("Alice".to_string())
            } else {
                None
            }
        }

        // Must explicitly handle None case
        match find_user(1) {
            Some(name) => println!("Found user: {}", name),
            None => println!("User not found"),
        }

        // Can't accidentally dereference null
        // let name = find_user(99); // Type is Option<String>
        // println!("{}", name); // ERROR: can't print Option directly
    }

    /// Comparing C vs Rust null handling
    pub fn compare_c_vs_rust() {
        // C code (UNSAFE):
        // char* ptr = find_user(99); // Returns NULL
        // printf("%s", ptr); // Null pointer dereference!

        // Rust equivalent (SAFE):
        option_prevents_null();

        println!("\nC: Null pointer dereferences cause crashes");
        println!("Rust: Option<T> forces handling of null cases");
    }
}

/// Module demonstrating double-free prevention
pub mod double_free {
    //! Double-free prevention through ownership
    //!
    //! Double-free errors (freeing the same memory twice) are impossible in Rust
    //! because the ownership system ensures memory is freed exactly once.

    /// Ownership ensures single free
    pub fn ownership_prevents_double_free() {
        let data = vec![1, 2, 3, 4, 5];

        // Data is automatically freed when it goes out of scope
        // Trying to manually free twice would not compile:
        // drop(data);
        // drop(data); // ERROR: use of moved value

        println!("Rust prevents double-free through ownership");
        println!("Data will be freed exactly once: {:?}", data);
    } // data freed here automatically

    /// Box demonstrates single ownership
    pub fn box_single_ownership() {
        let boxed_value = Box::new(42);

        // Transfer ownership
        let moved_box = boxed_value;

        // This would not compile:
        // drop(boxed_value); // ERROR: value used after move

        println!("Boxed value freed exactly once: {}", moved_box);
    } // moved_box freed here

    /// Comparing C vs Rust memory management
    pub fn compare_c_vs_rust() {
        // C code (UNSAFE):
        // int* ptr = malloc(sizeof(int));
        // free(ptr);
        // free(ptr); // Double-free!

        // Rust equivalent (SAFE - won't compile):
        ownership_prevents_double_free();

        println!("\nC: Double-free vulnerabilities");
        println!("Rust: Compile-time prevention of double-free");
    }
}

/// Module demonstrating uninitialized memory prevention
pub mod uninitialized_memory {
    //! Uninitialized memory prevention through initialization requirements

    /// All variables must be initialized
    pub fn initialization_required() {
        // This would not compile:
        // let x: i32;
        // println!("{}", x); // ERROR: use of possibly uninitialized variable

        // Must initialize
        let x: i32 = 42;
        println!("Value is always initialized: {}", x);
    }

    /// Uninitialized array prevention
    pub fn array_initialization() {
        // C code (UNSAFE):
        // int arr[100];
        // printf("%d", arr[0]); // Reading uninitialized memory!

        // Rust equivalent (SAFE):
        let arr = vec![0; 100]; // Initialized to zero
        println!("Array element (initialized): {}", arr[0]);

        // Or must explicitly initialize each element
        let arr2: Vec<i32> = (0..100).map(|i| i * 2).collect();
        println!("Array with values: {} elements", arr2.len());
    }

    /// Struct initialization must be complete
    pub fn struct_initialization() {
        struct User {
            id: u32,
            name: String,
            email: String,
        }

        // This would not compile:
        // let user = User {
        //     id: 1,
        //     name: "Alice".to_string(),
        //     // ERROR: missing field `email`
        // };

        // Must initialize all fields
        let user = User {
            id: 1,
            name: "Alice".to_string(),
            email: "alice@example.com".to_string(),
        };

        println!("User struct fully initialized: {}", user.name);
    }

    /// Comparing C vs Rust initialization
    pub fn compare_c_vs_rust() {
        println!("C: Uninitialized memory contains garbage values");
        println!("Rust: Compiler enforces initialization before use");

        initialization_required();
        array_initialization();
        struct_initialization();
    }
}

/// Module demonstrating memory leak prevention with RAII
///
/// Memory leak prevention through RAII (Resource Acquisition Is Initialization)
pub mod memory_leak {
    use std::fs::File;
    use std::io::Write;

    /// RAII ensures resources are cleaned up
    pub fn raii_file_handling() {
        // File automatically closed when it goes out of scope
        {
            let mut file = File::create("/tmp/test.txt").ok();
            if let Some(ref mut f) = file {
                let _ = f.write_all(b"Hello, RAII!");
            }
            // File automatically closed here
        }

        println!("File handle automatically closed (RAII)");
    }

    /// Drop trait for custom cleanup
    pub fn drop_trait_cleanup() {
        struct DatabaseConnection {
            id: u32,
        }

        impl Drop for DatabaseConnection {
            fn drop(&mut self) {
                println!("Closing database connection: {}", self.id);
            }
        }

        {
            let _conn = DatabaseConnection { id: 1 };
            println!("Database connection open");
            // Automatically cleaned up at end of scope
        }

        println!("Connection automatically closed via Drop trait");
    }

    /// Comparing C vs Rust resource management
    pub fn compare_c_vs_rust() {
        // C code (RISK):
        // FILE* f = fopen("test.txt", "w");
        // // Forgot to call fclose(f) - memory/resource leak!

        // Rust equivalent (SAFE):
        raii_file_handling();

        println!("\nC: Easy to forget resource cleanup (leaks)");
        println!("Rust: RAII ensures automatic cleanup");
    }
}

/// Module demonstrating type confusion prevention
pub mod type_confusion {
    //! Type confusion prevention through strong typing

    /// Strong typing prevents type confusion
    pub fn strong_typing_prevents_confusion() {
        let integer: i32 = 42;
        let float: f64 = 3.14;

        // This would not compile:
        // let result = integer + float; // ERROR: mismatched types

        // Must explicitly convert
        let result = integer as f64 + float;
        println!("Explicit conversion required: {}", result);
    }

    /// Newtype pattern for type safety
    pub fn newtype_pattern() {
        struct UserId(u32);
        struct ProductId(u32);

        let user = UserId(123);
        let product = ProductId(456);

        // This would not compile:
        // if user == product { } // ERROR: mismatched types

        println!("NewType pattern prevents mixing different ID types");
        println!("User ID: {}, Product ID: {}", user.0, product.0);
    }

    /// Enum prevents invalid states
    pub fn enum_prevents_invalid_states() {
        enum ConnectionState {
            Disconnected,
            Connecting,
            Connected { session_id: String },
            Error { message: String },
        }

        let state = ConnectionState::Connected {
            session_id: "abc123".to_string(),
        };

        // Can't access session_id unless in Connected state
        match state {
            ConnectionState::Connected { session_id } => {
                println!("Connected with session: {}", session_id);
            }
            _ => println!("Not connected"),
        }
    }

    /// Comparing C vs Rust type safety
    pub fn compare_c_vs_rust() {
        println!("C: Type confusion through casting and unions");
        println!("Rust: Strong type system prevents confusion at compile time");

        strong_typing_prevents_confusion();
        newtype_pattern();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_overflow_examples() {
        buffer_overflow::safe_array_access();
        buffer_overflow::safe_string_handling();
        buffer_overflow::compare_c_vs_rust();
    }

    #[test]
    fn test_use_after_free_examples() {
        use_after_free::ownership_prevents_uaf();
        use_after_free::borrowing_prevents_dangling();
        use_after_free::compare_c_vs_rust();
    }

    #[test]
    fn test_data_race_examples() {
        data_race::safe_concurrent_access();
        data_race::type_system_prevents_races();
        data_race::compare_c_vs_rust();
    }

    #[test]
    fn test_integer_overflow_examples() {
        integer_overflow::checked_arithmetic();
        integer_overflow::saturating_arithmetic();
    }

    #[test]
    fn test_null_pointer_examples() {
        null_pointer::option_prevents_null();
        null_pointer::compare_c_vs_rust();
    }

    #[test]
    fn test_double_free_examples() {
        double_free::ownership_prevents_double_free();
        double_free::box_single_ownership();
        double_free::compare_c_vs_rust();
    }

    #[test]
    fn test_uninitialized_memory_examples() {
        uninitialized_memory::initialization_required();
        uninitialized_memory::array_initialization();
        uninitialized_memory::struct_initialization();
        uninitialized_memory::compare_c_vs_rust();
    }

    #[test]
    fn test_memory_leak_examples() {
        memory_leak::raii_file_handling();
        memory_leak::drop_trait_cleanup();
        memory_leak::compare_c_vs_rust();
    }

    #[test]
    fn test_type_confusion_examples() {
        type_confusion::strong_typing_prevents_confusion();
        type_confusion::newtype_pattern();
        type_confusion::enum_prevents_invalid_states();
        type_confusion::compare_c_vs_rust();
    }
}
