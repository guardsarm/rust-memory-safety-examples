//! Data race prevention through Send/Sync traits

use std::sync::{Arc, Mutex, RwLock};
use std::thread;

/// VULNERABLE C CODE (for comparison):
/// ```c
/// #include <pthread.h>
/// #include <stdio.h>
///
/// int counter = 0;  // Shared mutable state
///
/// void* increment(void* arg) {
///     for (int i = 0; i < 100000; i++) {
///         counter++;  // DATA RACE!
///     }
///     return NULL;
/// }
///
/// int main() {
///     pthread_t t1, t2;
///     pthread_create(&t1, NULL, increment, NULL);
///     pthread_create(&t2, NULL, increment, NULL);
///     pthread_join(t1, NULL);
///     pthread_join(t2, NULL);
///     printf("Counter: %d\n", counter);  // Undefined result!
///     return 0;
/// }
/// ```
///
/// **Vulnerability:** Concurrent access to shared mutable data causes:
/// - Data corruption
/// - Undefined behavior
/// - Non-deterministic bugs
/// - Security vulnerabilities
///

/// SAFE RUST EQUIVALENT:
/// Rust prevents data races at compile time through the type system

/// Example 1: Mutex protects shared mutable state
pub fn safe_concurrent_counter() {
    let counter = Arc::new(Mutex::new(0));
    let mut handles = vec![];

    for _ in 0..10 {
        let counter_clone = Arc::clone(&counter);
        let handle = thread::spawn(move || {
            for _ in 0..1000 {
                let mut num = counter_clone.lock().unwrap();
                *num += 1;
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    println!("Final counter value: {}", *counter.lock().unwrap());
    // Always produces correct result: 10,000
}

/// Example 2: RwLock for read-heavy workloads
pub fn safe_read_write_access() {
    let data = Arc::new(RwLock::new(vec![1, 2, 3]));
    let mut handles = vec![];

    // Multiple readers (allowed concurrently)
    for i in 0..5 {
        let data_clone = Arc::clone(&data);
        let handle = thread::spawn(move || {
            let read_guard = data_clone.read().unwrap();
            println!("Reader {}: {:?}", i, *read_guard);
        });
        handles.push(handle);
    }

    // Single writer (exclusive access)
    let data_clone = Arc::clone(&data);
    let writer_handle = thread::spawn(move || {
        let mut write_guard = data_clone.write().unwrap();
        write_guard.push(4);
        println!("Writer added element");
    });
    handles.push(writer_handle);

    for handle in handles {
        handle.join().unwrap();
    }
}

/// Example 3: Demonstrating Send and Sync traits
/// Send: Safe to transfer ownership between threads
/// Sync: Safe to share references between threads

/// This type is Send (can be moved to another thread)
struct SendableData {
    value: i32,
}

/// This type is NOT Send due to raw pointer
struct NotSendable {
    ptr: *mut i32, // Raw pointers are not Send
}

/// Compiler enforces thread safety
pub fn thread_safety_enforced() {
    let sendable = SendableData { value: 42 };

    // This works: SendableData is Send
    thread::spawn(move || {
        println!("Value in thread: {}", sendable.value);
    });

    // This would NOT compile:
    // let not_sendable = NotSendable { ptr: std::ptr::null_mut() };
    // thread::spawn(move || {
    //     // Compile error: NotSendable is not Send!
    // });
}

/// Example 4: Message passing (alternative to shared state)
use std::sync::mpsc;

pub fn safe_message_passing() {
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        for i in 0..5 {
            tx.send(i).unwrap();
        }
    });

    for received in rx {
        println!("Received: {}", received);
    }
}

/// Example 5: Atomic types for lock-free programming
use std::sync::atomic::{AtomicUsize, Ordering};

pub fn safe_atomic_operations() {
    let counter = Arc::new(AtomicUsize::new(0));
    let mut handles = vec![];

    for _ in 0..10 {
        let counter_clone = Arc::clone(&counter);
        let handle = thread::spawn(move || {
            for _ in 0..1000 {
                counter_clone.fetch_add(1, Ordering::SeqCst);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    println!("Atomic counter: {}", counter.load(Ordering::SeqCst));
}

/// Example 6: Scoped threads for guaranteed lifetime
pub fn scoped_threads_safe() {
    let mut data = vec![1, 2, 3];

    thread::scope(|s| {
        s.spawn(|| {
            // Can borrow data because scope guarantees lifetime
            println!("Data length: {}", data.len());
        });

        s.spawn(|| {
            println!("Data: {:?}", data);
        });
    });

    // All spawned threads are joined before scope ends
    data.push(4); // Safe to modify again
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn test_mutex_correctness() {
        let counter = Arc::new(Mutex::new(0));
        let mut handles = vec![];

        for _ in 0..10 {
            let counter_clone = Arc::clone(&counter);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    *counter_clone.lock().unwrap() += 1;
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(*counter.lock().unwrap(), 1000);
    }

    #[test]
    fn test_atomic_correctness() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];

        for _ in 0..10 {
            let counter_clone = Arc::clone(&counter);
            let handle = thread::spawn(move || {
                for _ in 0..100 {
                    counter_clone.fetch_add(1, Ordering::SeqCst);
                }
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(counter.load(Ordering::SeqCst), 1000);
    }

    #[test]
    fn test_message_passing() {
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            tx.send(42).unwrap();
        });

        let received = rx.recv().unwrap();
        assert_eq!(received, 42);
    }

    #[test]
    fn test_rwlock() {
        let data = Arc::new(RwLock::new(vec![1, 2, 3]));
        let data_clone = Arc::clone(&data);

        let handle = thread::spawn(move || {
            let read = data_clone.read().unwrap();
            read.len()
        });

        let len = handle.join().unwrap();
        assert_eq!(len, 3);
    }
}
