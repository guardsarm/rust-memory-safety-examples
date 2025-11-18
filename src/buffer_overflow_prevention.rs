//! Buffer overflow prevention examples

/// VULNERABLE C CODE (for comparison):
/// ```c
/// #include <string.h>
///
/// void vulnerable_copy(char* dest, const char* src) {
///     strcpy(dest, src);  // NO BOUNDS CHECKING!
/// }
///
/// int main() {
///     char buffer[10];
///     char* long_string = "This is a very long string that will overflow";
///     vulnerable_copy(buffer, long_string);  // BUFFER OVERFLOW!
///     return 0;
/// }
/// ```
///
/// **Vulnerability:** strcpy doesn't check destination buffer size,
/// causing stack corruption, potential code execution, crashes.
///
/// **CVE Examples:**
/// - CVE-2021-3156 (sudo): Heap buffer overflow
/// - CVE-2014-0160 (Heartbleed): Buffer over-read
///

/// SAFE RUST EQUIVALENT:
/// Rust prevents buffer overflows at compile time through bounds checking
pub fn safe_copy(dest: &mut [u8], src: &[u8]) -> Result<(), &'static str> {
    if dest.len() < src.len() {
        return Err("Destination buffer too small");
    }

    dest[..src.len()].copy_from_slice(src);
    Ok(())
}

/// Example: Array access with bounds checking
pub fn safe_array_access() {
    let array = [1, 2, 3, 4, 5];

    // Compile-time known indices are checked
    let _first = array[0]; // OK

    // Runtime bounds checking (panics on out-of-bounds)
    // let _invalid = array[10];  // Would panic!

    // Safe alternative: get() returns Option
    match array.get(10) {
        Some(value) => println!("Value: {}", value),
        None => println!("Index out of bounds (safely handled)"),
    }
}

/// Example: Vector with automatic bounds checking
pub fn safe_vector_usage() {
    let mut vec = Vec::new();
    vec.push(1);
    vec.push(2);
    vec.push(3);

    // Safe iteration (no overflow possible)
    for item in &vec {
        println!("{}", item);
    }

    // Safe indexed access
    if let Some(value) = vec.get(5) {
        println!("Value at index 5: {}", value);
    } else {
        println!("Index 5 doesn't exist");
    }
}

/// Example: String handling (always safe in Rust)
pub fn safe_string_operations() {
    let mut dest = String::with_capacity(10);
    let src = "This is a very long string that would overflow a fixed buffer";

    // String automatically grows - no overflow possible
    dest.push_str(src);

    println!("String length: {} (automatically managed)", dest.len());
}

/// Demonstration: Why Rust prevents overflows
pub fn demonstration_bounds_checking() {
    let buffer: [u8; 10] = [0; 10];
    let data: [u8; 20] = [1; 20];

    // This would NOT compile:
    // buffer.copy_from_slice(&data);  // Compile error: size mismatch!

    // Safe alternative:
    let safe_copy = &data[..buffer.len()];
    let mut mutable_buffer = buffer;
    mutable_buffer.copy_from_slice(safe_copy);

    println!("Safe copy completed: {:?}", mutable_buffer);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_copy_success() {
        let mut dest = [0u8; 10];
        let src = [1, 2, 3, 4, 5];

        assert!(safe_copy(&mut dest, &src).is_ok());
        assert_eq!(&dest[..5], &src);
    }

    #[test]
    fn test_safe_copy_overflow_prevented() {
        let mut dest = [0u8; 5];
        let src = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Overflow is caught and returned as error
        assert!(safe_copy(&mut dest, &src).is_err());
    }

    #[test]
    #[should_panic]
    #[allow(unconditional_panic, clippy::out_of_bounds_indexing)]
    fn test_out_of_bounds_panic() {
        let array = [1, 2, 3];
        let _ = array[10]; // Panics (controlled failure, not undefined behavior)
    }

    #[test]
    fn test_safe_get() {
        let array = [1, 2, 3];
        assert_eq!(array.get(1), Some(&2));
        assert_eq!(array.get(10), None); // Safe handling
    }
}
