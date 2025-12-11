//! Benchmarks measuring the performance overhead of Rust's safety features
//!
//! This benchmark suite demonstrates that Rust's memory safety comes with
//! minimal to zero runtime overhead in most cases.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::collections::HashMap;

/// Benchmark: Bounds-checked array access vs unchecked
fn benchmark_bounds_checking(c: &mut Criterion) {
    let mut group = c.benchmark_group("Bounds Checking");

    let data: Vec<i32> = (0..10000).collect();
    let indices: Vec<usize> = (0..1000).map(|i| i % data.len()).collect();

    // Safe bounds-checked access
    group.bench_function("safe_access", |b| {
        b.iter(|| {
            let mut sum = 0i64;
            for &idx in &indices {
                sum += data[idx] as i64;
            }
            black_box(sum)
        })
    });

    // Using get() with explicit check
    group.bench_function("get_checked", |b| {
        b.iter(|| {
            let mut sum = 0i64;
            for &idx in &indices {
                if let Some(&val) = data.get(idx) {
                    sum += val as i64;
                }
            }
            black_box(sum)
        })
    });

    // Unsafe unchecked access (for comparison only)
    group.bench_function("unsafe_unchecked", |b| {
        b.iter(|| {
            let mut sum = 0i64;
            for &idx in &indices {
                // SAFETY: indices are pre-validated to be within bounds
                sum += unsafe { *data.get_unchecked(idx) as i64 };
            }
            black_box(sum)
        })
    });

    // Iterator (compiler can often elide bounds checks)
    group.bench_function("iterator", |b| {
        b.iter(|| {
            let sum: i64 = data.iter().map(|&x| x as i64).sum();
            black_box(sum)
        })
    });

    group.finish();
}

/// Benchmark: Reference counting overhead (Arc vs raw pointers)
fn benchmark_reference_counting(c: &mut Criterion) {
    use std::sync::Arc;

    let mut group = c.benchmark_group("Reference Counting");

    // Arc clone and drop
    group.bench_function("arc_clone_drop", |b| {
        let data = Arc::new(vec![1, 2, 3, 4, 5]);
        b.iter(|| {
            let cloned = Arc::clone(&data);
            black_box(&cloned);
            // cloned dropped here
        })
    });

    // Raw reference (no overhead, but no safety)
    group.bench_function("raw_reference", |b| {
        let data = vec![1, 2, 3, 4, 5];
        let ptr = &data;
        b.iter(|| {
            black_box(ptr);
        })
    });

    // Box allocation and deallocation
    group.bench_function("box_alloc_dealloc", |b| {
        b.iter(|| {
            let boxed = Box::new(vec![1, 2, 3, 4, 5]);
            black_box(&boxed);
        })
    });

    group.finish();
}

/// Benchmark: Mutex locking overhead
fn benchmark_mutex_overhead(c: &mut Criterion) {
    use std::sync::Mutex;

    let mut group = c.benchmark_group("Mutex Overhead");

    // Mutex lock/unlock
    group.bench_function("mutex_lock_unlock", |b| {
        let data = Mutex::new(0i32);
        b.iter(|| {
            let mut guard = data.lock().unwrap();
            *guard += 1;
            black_box(*guard);
        })
    });

    // Atomic operations
    group.bench_function("atomic_add", |b| {
        use std::sync::atomic::{AtomicI32, Ordering};
        let counter = AtomicI32::new(0);
        b.iter(|| {
            let val = counter.fetch_add(1, Ordering::SeqCst);
            black_box(val);
        })
    });

    // Unsynchronized (single-threaded baseline)
    group.bench_function("unsynchronized", |b| {
        let mut counter = 0i32;
        b.iter(|| {
            counter += 1;
            black_box(counter);
        })
    });

    group.finish();
}

/// Benchmark: Option vs null pointer checking
fn benchmark_option_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("Option Overhead");

    let some_values: Vec<Option<i32>> = (0..1000).map(|i| {
        if i % 10 == 0 { None } else { Some(i) }
    }).collect();

    // Option with match
    group.bench_function("option_match", |b| {
        b.iter(|| {
            let mut sum = 0i64;
            for opt in &some_values {
                match opt {
                    Some(val) => sum += *val as i64,
                    None => {}
                }
            }
            black_box(sum)
        })
    });

    // Option with if let
    group.bench_function("option_if_let", |b| {
        b.iter(|| {
            let mut sum = 0i64;
            for opt in &some_values {
                if let Some(val) = opt {
                    sum += *val as i64;
                }
            }
            black_box(sum)
        })
    });

    // Option with unwrap_or
    group.bench_function("option_unwrap_or", |b| {
        b.iter(|| {
            let sum: i64 = some_values.iter()
                .map(|opt| opt.unwrap_or(0) as i64)
                .sum();
            black_box(sum)
        })
    });

    // Filter and map (idiomatic)
    group.bench_function("option_filter_map", |b| {
        b.iter(|| {
            let sum: i64 = some_values.iter()
                .filter_map(|opt| opt.map(|v| v as i64))
                .sum();
            black_box(sum)
        })
    });

    group.finish();
}

/// Benchmark: String handling safety overhead
fn benchmark_string_safety(c: &mut Criterion) {
    let mut group = c.benchmark_group("String Safety");

    let test_string = "Hello, World! This is a test string for benchmarking.";

    // String concatenation (safe, allocating)
    group.bench_function("string_concat", |b| {
        b.iter(|| {
            let mut s = String::new();
            for _ in 0..100 {
                s.push_str(test_string);
            }
            black_box(s.len())
        })
    });

    // Pre-allocated string
    group.bench_function("string_preallocated", |b| {
        b.iter(|| {
            let mut s = String::with_capacity(test_string.len() * 100);
            for _ in 0..100 {
                s.push_str(test_string);
            }
            black_box(s.len())
        })
    });

    // Byte slice operations
    group.bench_function("byte_slice_copy", |b| {
        let bytes = test_string.as_bytes();
        let mut buffer = vec![0u8; bytes.len() * 100];
        b.iter(|| {
            for i in 0..100 {
                let start = i * bytes.len();
                buffer[start..start + bytes.len()].copy_from_slice(bytes);
            }
            black_box(buffer.len())
        })
    });

    group.finish();
}

/// Benchmark: Checked arithmetic overhead
fn benchmark_checked_arithmetic(c: &mut Criterion) {
    let mut group = c.benchmark_group("Checked Arithmetic");

    let values: Vec<i32> = (1..1000).collect();

    // Regular arithmetic (wrapping in release)
    group.bench_function("regular_add", |b| {
        b.iter(|| {
            let mut sum = 0i32;
            for &v in &values {
                sum = sum.wrapping_add(v);
            }
            black_box(sum)
        })
    });

    // Checked arithmetic
    group.bench_function("checked_add", |b| {
        b.iter(|| {
            let mut sum = 0i32;
            for &v in &values {
                sum = sum.checked_add(v).unwrap_or(sum);
            }
            black_box(sum)
        })
    });

    // Saturating arithmetic
    group.bench_function("saturating_add", |b| {
        b.iter(|| {
            let mut sum = 0i32;
            for &v in &values {
                sum = sum.saturating_add(v);
            }
            black_box(sum)
        })
    });

    // Overflow-checked (for financial applications)
    group.bench_function("overflowing_add", |b| {
        b.iter(|| {
            let mut sum = 0i32;
            let mut overflow_count = 0;
            for &v in &values {
                let (new_sum, overflow) = sum.overflowing_add(v);
                if overflow {
                    overflow_count += 1;
                }
                sum = new_sum;
            }
            black_box((sum, overflow_count))
        })
    });

    group.finish();
}

/// Benchmark: HashMap with safe vs unsafe patterns
fn benchmark_hashmap_safety(c: &mut Criterion) {
    let mut group = c.benchmark_group("HashMap Safety");

    let mut map: HashMap<i32, i32> = HashMap::new();
    for i in 0..1000 {
        map.insert(i, i * 2);
    }

    let keys: Vec<i32> = (0..500).chain(1000..1500).collect();

    // Safe get with Option handling
    group.bench_function("safe_get", |b| {
        b.iter(|| {
            let mut sum = 0i64;
            for &key in &keys {
                if let Some(&val) = map.get(&key) {
                    sum += val as i64;
                }
            }
            black_box(sum)
        })
    });

    // Entry API (safe mutation)
    group.bench_function("entry_api", |b| {
        let mut map_clone = map.clone();
        b.iter(|| {
            for &key in &keys {
                map_clone.entry(key).or_insert(0);
            }
            black_box(map_clone.len())
        })
    });

    // Get with unwrap_or
    group.bench_function("get_unwrap_or", |b| {
        b.iter(|| {
            let mut sum = 0i64;
            for &key in &keys {
                sum += *map.get(&key).unwrap_or(&0) as i64;
            }
            black_box(sum)
        })
    });

    group.finish();
}

/// Benchmark: Vector operations with bounds checking
fn benchmark_vector_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Vector Operations");

    let size = 10000;

    // Vector push (with automatic reallocation)
    group.bench_function("vec_push", |b| {
        b.iter(|| {
            let mut v = Vec::new();
            for i in 0..size {
                v.push(i);
            }
            black_box(v.len())
        })
    });

    // Pre-allocated vector push
    group.bench_function("vec_push_preallocated", |b| {
        b.iter(|| {
            let mut v = Vec::with_capacity(size);
            for i in 0..size {
                v.push(i);
            }
            black_box(v.len())
        })
    });

    // Vector extend
    group.bench_function("vec_extend", |b| {
        b.iter(|| {
            let mut v = Vec::new();
            v.extend(0..size);
            black_box(v.len())
        })
    });

    // Collect from iterator
    group.bench_function("vec_collect", |b| {
        b.iter(|| {
            let v: Vec<usize> = (0..size).collect();
            black_box(v.len())
        })
    });

    group.finish();
}

/// Benchmark: Result vs exceptions (simulated)
fn benchmark_error_handling(c: &mut Criterion) {
    let mut group = c.benchmark_group("Error Handling");

    let inputs: Vec<i32> = (0..1000).collect();

    // Result with no errors
    group.bench_function("result_ok_path", |b| {
        b.iter(|| {
            let mut sum = 0i64;
            for &input in &inputs {
                match safe_divide(input, 2) {
                    Ok(val) => sum += val as i64,
                    Err(_) => {}
                }
            }
            black_box(sum)
        })
    });

    // Result with some errors
    group.bench_function("result_mixed", |b| {
        b.iter(|| {
            let mut sum = 0i64;
            let mut errors = 0;
            for &input in &inputs {
                match safe_divide(input, input % 10) {
                    Ok(val) => sum += val as i64,
                    Err(_) => errors += 1,
                }
            }
            black_box((sum, errors))
        })
    });

    // Using ? operator (simulated with closure)
    group.bench_function("result_question_mark", |b| {
        b.iter(|| {
            let result: Result<i64, &str> = (|| {
                let mut sum = 0i64;
                for &input in &inputs {
                    sum += safe_divide(input, 2)? as i64;
                }
                Ok(sum)
            })();
            black_box(result)
        })
    });

    group.finish();
}

fn safe_divide(a: i32, b: i32) -> Result<i32, &'static str> {
    if b == 0 {
        Err("Division by zero")
    } else {
        Ok(a / b)
    }
}

criterion_group!(
    benches,
    benchmark_bounds_checking,
    benchmark_reference_counting,
    benchmark_mutex_overhead,
    benchmark_option_overhead,
    benchmark_string_safety,
    benchmark_checked_arithmetic,
    benchmark_hashmap_safety,
    benchmark_vector_operations,
    benchmark_error_handling,
);

criterion_main!(benches);
