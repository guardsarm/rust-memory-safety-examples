//! Use-after-free prevention through ownership and lifetimes

/// VULNERABLE C CODE (for comparison):
/// ```c
/// #include <stdlib.h>
/// #include <stdio.h>
///
/// int* vulnerable_use_after_free() {
///     int* ptr = malloc(sizeof(int));
///     *ptr = 42;
///     free(ptr);           // Memory freed
///     return ptr;          // DANGLING POINTER!
/// }
///
/// void exploit() {
///     int* p = vulnerable_use_after_free();
///     printf("%d\n", *p);  // USE-AFTER-FREE!
/// }
/// ```
///
/// **Vulnerability:** Accessing memory after it's been freed causes:
/// - Undefined behavior
/// - Potential code execution (if attacker controls freed memory)
/// - Crashes
///
/// **CVE Examples:**
/// - CVE-2020-0796 (SMBGhost): Use-after-free in Windows SMB
/// - CVE-2019-5786 (Chrome): Use-after-free in FileReader
///

/// SAFE RUST EQUIVALENT:
/// Rust's ownership system prevents use-after-free at compile time

/// Example 1: Ownership prevents use-after-free
pub fn ownership_prevents_uaf() {
    let data = Box::new(42);  // Heap allocation
    let value = *data;        // Copy the value

    drop(data);               // Explicitly free memory

    // This would NOT compile:
    // println!("{}", *data); // Compile error: value moved!

    println!("Copied value: {}", value);  // Safe: we copied the value
}

/// Example 2: References have lifetimes
pub fn lifetime_prevents_dangling_ref() {
    let reference;

    {
        let data = String::from("temporary");
        // This would NOT compile:
        // reference = &data;  // Compile error: `data` doesn't live long enough
    }

    // Cannot use reference here - compiler prevents it
}

/// Example 3: Borrowing rules prevent use-after-free
pub fn borrowing_prevents_uaf() {
    let mut data = vec![1, 2, 3];

    let reference = &data[0];  // Immutable borrow

    // This would NOT compile:
    // data.clear();  // Compile error: cannot mutate while borrowed!

    println!("First element: {}", reference);
    // reference is no longer used, borrow ends

    data.clear();  // Now we can mutate
    println!("Vector cleared");
}

/// Example 4: Smart pointers provide safe resource management
use std::rc::Rc;

pub fn shared_ownership_safe() {
    let data = Rc::new(vec![1, 2, 3]);
    let clone1 = Rc::clone(&data);
    let clone2 = Rc::clone(&data);

    println!("Data from clone1: {:?}", clone1);
    println!("Data from clone2: {:?}", clone2);

    // Memory is freed only when ALL Rc references are dropped
    drop(clone1);
    drop(clone2);
    drop(data);  // Now memory is freed
}

/// Example 5: Real-world pattern - safe object lifecycle
pub struct SafeObject {
    data: Vec<i32>,
}

impl SafeObject {
    pub fn new(data: Vec<i32>) -> Self {
        Self { data }
    }

    pub fn get_data(&self) -> &[i32] {
        &self.data
    }

    // Ownership rules prevent use-after-free:
    // Once this consumes self, the object cannot be used again
    pub fn consume(self) -> Vec<i32> {
        self.data
    }
}

pub fn safe_object_usage() {
    let obj = SafeObject::new(vec![1, 2, 3]);
    let data_ref = obj.get_data();
    println!("Data: {:?}", data_ref);

    let owned_data = obj.consume();  // obj is moved here

    // This would NOT compile:
    // obj.get_data();  // Compile error: value used after move!

    println!("Owned data: {:?}", owned_data);
}

/// Example 6: Demonstration of Rust's compile-time safety
pub fn compile_time_safety_demo() {
    struct Resource {
        id: i32,
    }

    impl Drop for Resource {
        fn drop(&mut self) {
            println!("Resource {} freed", self.id);
        }
    }

    let res = Resource { id: 1 };
    println!("Resource created: {}", res.id);

    // Resource is automatically freed at end of scope
    // No possibility of use-after-free
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ownership_transfer() {
        let data = Box::new(42);
        let moved_data = data;

        // data cannot be used here - ownership transferred
        assert_eq!(*moved_data, 42);
    }

    #[test]
    fn test_reference_lifetime() {
        let data = String::from("test");
        let reference = &data;

        assert_eq!(reference, "test");
        // reference lifetime ends here, data can be used again
    }

    #[test]
    fn test_rc_shared_ownership() {
        let data = Rc::new(vec![1, 2, 3]);
        let clone = Rc::clone(&data);

        assert_eq!(Rc::strong_count(&data), 2);
        drop(clone);
        assert_eq!(Rc::strong_count(&data), 1);
    }

    #[test]
    fn test_safe_object() {
        let obj = SafeObject::new(vec![1, 2, 3]);
        assert_eq!(obj.get_data(), &[1, 2, 3]);

        let data = obj.consume();
        assert_eq!(data, vec![1, 2, 3]);
    }
}
