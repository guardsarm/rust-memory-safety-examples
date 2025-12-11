//! Secure Programming Patterns in Rust v2.0
//!
//! This example demonstrates secure coding patterns that leverage Rust's
//! type system and ownership model for building robust, secure systems.

use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, RwLock};

/// Pattern 1: Type-State Pattern for Protocol Safety
///
/// Ensures operations occur in the correct order at compile time.
mod type_state_pattern {
    use std::marker::PhantomData;

    /// Connection states
    pub struct Disconnected;
    pub struct Connected;
    pub struct Authenticated;

    /// Type-safe connection that enforces state transitions
    pub struct Connection<State> {
        host: String,
        _state: PhantomData<State>,
    }

    impl Connection<Disconnected> {
        pub fn new(host: &str) -> Self {
            Connection {
                host: host.to_string(),
                _state: PhantomData,
            }
        }

        pub fn connect(self) -> Result<Connection<Connected>, &'static str> {
            println!("Connecting to {}...", self.host);
            // In real code: perform actual connection
            Ok(Connection {
                host: self.host,
                _state: PhantomData,
            })
        }
    }

    impl Connection<Connected> {
        pub fn authenticate(self, _username: &str, _password: &str) -> Result<Connection<Authenticated>, &'static str> {
            println!("Authenticating...");
            // In real code: perform authentication
            Ok(Connection {
                host: self.host,
                _state: PhantomData,
            })
        }

        pub fn disconnect(self) -> Connection<Disconnected> {
            println!("Disconnecting...");
            Connection {
                host: self.host,
                _state: PhantomData,
            }
        }
    }

    impl Connection<Authenticated> {
        pub fn execute_query(&self, query: &str) -> Result<String, &'static str> {
            println!("Executing query: {}", query);
            Ok(format!("Results for: {}", query))
        }

        pub fn disconnect(self) -> Connection<Disconnected> {
            println!("Disconnecting authenticated session...");
            Connection {
                host: self.host,
                _state: PhantomData,
            }
        }
    }

    pub fn demonstrate() {
        println!("\n=== Type-State Pattern for Protocol Safety ===");

        let conn = Connection::<Disconnected>::new("database.example.com");

        // These operations must occur in order - enforced at compile time!
        // conn.execute_query("SELECT *"); // Won't compile - not connected!

        let connected = conn.connect().unwrap();
        // connected.execute_query("SELECT *"); // Won't compile - not authenticated!

        let authenticated = connected.authenticate("user", "pass").unwrap();
        let result = authenticated.execute_query("SELECT * FROM users").unwrap();
        println!("Query result: {}", result);

        let _disconnected = authenticated.disconnect();
        println!("Type-state pattern ensures correct operation order!");
    }
}

/// Pattern 2: Builder Pattern with Validation
///
/// Ensures all required fields are set before construction.
mod validated_builder {
    pub struct User {
        username: String,
        email: String,
        role: Role,
    }

    #[derive(Clone)]
    pub enum Role {
        Admin,
        User,
        Guest,
    }

    /// Builder states
    pub struct NoUsername;
    pub struct HasUsername;
    pub struct NoEmail;
    pub struct HasEmail;
    pub struct NoRole;
    pub struct HasRole;

    pub struct UserBuilder<U, E, R> {
        username: Option<String>,
        email: Option<String>,
        role: Option<Role>,
        _u: std::marker::PhantomData<U>,
        _e: std::marker::PhantomData<E>,
        _r: std::marker::PhantomData<R>,
    }

    impl UserBuilder<NoUsername, NoEmail, NoRole> {
        pub fn new() -> Self {
            UserBuilder {
                username: None,
                email: None,
                role: None,
                _u: std::marker::PhantomData,
                _e: std::marker::PhantomData,
                _r: std::marker::PhantomData,
            }
        }
    }

    impl Default for UserBuilder<NoUsername, NoEmail, NoRole> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<E, R> UserBuilder<NoUsername, E, R> {
        pub fn username(self, username: &str) -> Result<UserBuilder<HasUsername, E, R>, &'static str> {
            if username.len() < 3 {
                return Err("Username must be at least 3 characters");
            }
            Ok(UserBuilder {
                username: Some(username.to_string()),
                email: self.email,
                role: self.role,
                _u: std::marker::PhantomData,
                _e: std::marker::PhantomData,
                _r: std::marker::PhantomData,
            })
        }
    }

    impl<U, R> UserBuilder<U, NoEmail, R> {
        pub fn email(self, email: &str) -> Result<UserBuilder<U, HasEmail, R>, &'static str> {
            if !email.contains('@') {
                return Err("Invalid email address");
            }
            Ok(UserBuilder {
                username: self.username,
                email: Some(email.to_string()),
                role: self.role,
                _u: std::marker::PhantomData,
                _e: std::marker::PhantomData,
                _r: std::marker::PhantomData,
            })
        }
    }

    impl<U, E> UserBuilder<U, E, NoRole> {
        pub fn role(self, role: Role) -> UserBuilder<U, E, HasRole> {
            UserBuilder {
                username: self.username,
                email: self.email,
                role: Some(role),
                _u: std::marker::PhantomData,
                _e: std::marker::PhantomData,
                _r: std::marker::PhantomData,
            }
        }
    }

    impl UserBuilder<HasUsername, HasEmail, HasRole> {
        pub fn build(self) -> User {
            User {
                username: self.username.unwrap(),
                email: self.email.unwrap(),
                role: self.role.unwrap(),
            }
        }
    }

    pub fn demonstrate() {
        println!("\n=== Validated Builder Pattern ===");

        // All required fields must be set - compile-time guarantee!
        let user = UserBuilder::new()
            .username("alice").unwrap()
            .email("alice@example.com").unwrap()
            .role(Role::Admin)
            .build();

        println!("Created user: {}", user.username);

        // This won't compile - missing email:
        // UserBuilder::new().username("bob").unwrap().role(Role::User).build();

        // This will fail at runtime due to validation:
        let result = UserBuilder::new().username("ab"); // Too short
        match result {
            Ok(_) => println!("Username accepted"),
            Err(e) => println!("Validation error: {}", e),
        }

        println!("Builder pattern ensures complete and valid construction!");
    }
}

/// Pattern 3: Secret/Sensitive Data Wrapper
///
/// Prevents accidental logging or display of sensitive data.
mod secret_wrapper {
    use std::fmt;

    /// Wrapper that prevents accidental exposure of sensitive data
    pub struct Secret<T>(T);

    impl<T> Secret<T> {
        pub fn new(value: T) -> Self {
            Secret(value)
        }

        /// Explicitly expose the secret (intentional access)
        pub fn expose(&self) -> &T {
            &self.0
        }

        /// Consume and expose the secret
        pub fn into_inner(self) -> T {
            self.0
        }
    }

    impl<T> fmt::Debug for Secret<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Secret([REDACTED])")
        }
    }

    impl<T> fmt::Display for Secret<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "[REDACTED]")
        }
    }

    // Prevent Clone to avoid accidental duplication
    // Secret doesn't implement Clone by default

    /// Zeroize on drop for extra security
    impl<T: Default> Drop for Secret<T> {
        fn drop(&mut self) {
            // In real code: use zeroize crate for secure zeroing
            self.0 = T::default();
        }
    }

    pub fn demonstrate() {
        println!("\n=== Secret Data Wrapper Pattern ===");

        let api_key = Secret::new("super_secret_api_key_12345".to_string());
        let password = Secret::new("my_password".to_string());

        // Safe to log - won't expose secret
        println!("API Key (debug): {:?}", api_key);
        println!("Password (display): {}", password);

        // Intentional exposure requires explicit method call
        println!("Exposed key length: {}", api_key.expose().len());

        // The secret is automatically zeroed when dropped
        println!("Secret wrapper prevents accidental exposure!");
    }
}

/// Pattern 4: Capability-Based Security
///
/// Use types to represent and enforce capabilities/permissions.
mod capability_pattern {
    use std::marker::PhantomData;

    /// Capability markers
    pub struct CanRead;
    pub struct CanWrite;
    pub struct CanDelete;

    /// File handle with capabilities encoded in the type
    pub struct FileHandle<Caps> {
        path: String,
        _caps: PhantomData<Caps>,
    }

    impl FileHandle<()> {
        pub fn open_readonly(path: &str) -> FileHandle<CanRead> {
            println!("Opening {} in read-only mode", path);
            FileHandle {
                path: path.to_string(),
                _caps: PhantomData,
            }
        }

        pub fn open_readwrite(path: &str) -> FileHandle<(CanRead, CanWrite)> {
            println!("Opening {} in read-write mode", path);
            FileHandle {
                path: path.to_string(),
                _caps: PhantomData,
            }
        }

        pub fn open_full(path: &str) -> FileHandle<(CanRead, CanWrite, CanDelete)> {
            println!("Opening {} with full permissions", path);
            FileHandle {
                path: path.to_string(),
                _caps: PhantomData,
            }
        }
    }

    /// Trait for types that include read capability
    pub trait HasRead {}
    impl HasRead for CanRead {}
    impl HasRead for (CanRead, CanWrite) {}
    impl HasRead for (CanRead, CanWrite, CanDelete) {}

    /// Trait for types that include write capability
    pub trait HasWrite {}
    impl HasWrite for CanWrite {}
    impl HasWrite for (CanRead, CanWrite) {}
    impl HasWrite for (CanRead, CanWrite, CanDelete) {}

    /// Trait for types that include delete capability
    pub trait HasDelete {}
    impl HasDelete for CanDelete {}
    impl HasDelete for (CanRead, CanWrite, CanDelete) {}

    impl<Caps: HasRead> FileHandle<Caps> {
        pub fn read(&self) -> String {
            format!("Reading from {}", self.path)
        }
    }

    impl<Caps: HasWrite> FileHandle<Caps> {
        pub fn write(&self, _data: &str) {
            println!("Writing to {}", self.path);
        }
    }

    impl<Caps: HasDelete> FileHandle<Caps> {
        pub fn delete(self) {
            println!("Deleting {}", self.path);
        }
    }

    pub fn demonstrate() {
        println!("\n=== Capability-Based Security Pattern ===");

        let readonly = FileHandle::open_readonly("/tmp/readonly.txt");
        println!("{}", readonly.read());
        // readonly.write("data"); // Won't compile - no write capability!
        // readonly.delete(); // Won't compile - no delete capability!

        let readwrite = FileHandle::open_readwrite("/tmp/readwrite.txt");
        println!("{}", readwrite.read());
        readwrite.write("some data");
        // readwrite.delete(); // Won't compile - no delete capability!

        let full = FileHandle::open_full("/tmp/deleteme.txt");
        println!("{}", full.read());
        full.write("temporary data");
        full.delete();

        println!("Capabilities enforced at compile time!");
    }
}

/// Pattern 5: Parse, Don't Validate
///
/// Convert unvalidated data into validated types immediately.
mod parse_dont_validate {
    /// Validated email address - can only be constructed through parsing
    pub struct Email(String);

    impl Email {
        pub fn parse(input: &str) -> Result<Self, &'static str> {
            // Validation happens once, at parse time
            if input.is_empty() {
                return Err("Email cannot be empty");
            }
            if !input.contains('@') {
                return Err("Email must contain @");
            }
            if input.len() > 254 {
                return Err("Email too long");
            }

            // Additional validation could include:
            // - Check for valid domain
            // - Check local part length
            // - Check for valid characters

            Ok(Email(input.to_lowercase()))
        }

        pub fn as_str(&self) -> &str {
            &self.0
        }

        pub fn domain(&self) -> &str {
            self.0.split('@').nth(1).unwrap_or("")
        }
    }

    /// Validated port number
    pub struct Port(u16);

    impl Port {
        pub fn parse(input: u16) -> Result<Self, &'static str> {
            if input == 0 {
                return Err("Port 0 is reserved");
            }
            Ok(Port(input))
        }

        pub fn value(&self) -> u16 {
            self.0
        }

        pub fn is_privileged(&self) -> bool {
            self.0 < 1024
        }
    }

    /// Validated URL with protocol
    pub struct ValidUrl {
        protocol: String,
        host: String,
        port: Option<u16>,
        path: String,
    }

    impl ValidUrl {
        pub fn parse(input: &str) -> Result<Self, &'static str> {
            if !input.starts_with("http://") && !input.starts_with("https://") {
                return Err("URL must start with http:// or https://");
            }

            let protocol = if input.starts_with("https://") {
                "https"
            } else {
                "http"
            };

            let without_protocol = input.trim_start_matches("https://").trim_start_matches("http://");

            let (host_port, path) = match without_protocol.find('/') {
                Some(idx) => (&without_protocol[..idx], &without_protocol[idx..]),
                None => (without_protocol, "/"),
            };

            let (host, port) = match host_port.find(':') {
                Some(idx) => {
                    let port_str = &host_port[idx + 1..];
                    let port = port_str.parse::<u16>().map_err(|_| "Invalid port")?;
                    (&host_port[..idx], Some(port))
                }
                None => (host_port, None),
            };

            Ok(ValidUrl {
                protocol: protocol.to_string(),
                host: host.to_string(),
                port,
                path: path.to_string(),
            })
        }

        pub fn host(&self) -> &str {
            &self.host
        }

        pub fn is_secure(&self) -> bool {
            self.protocol == "https"
        }
    }

    pub fn demonstrate() {
        println!("\n=== Parse, Don't Validate Pattern ===");

        // Parse immediately at system boundary
        match Email::parse("user@example.com") {
            Ok(email) => {
                // email is guaranteed valid throughout its lifetime
                println!("Valid email: {}", email.as_str());
                println!("Domain: {}", email.domain());
            }
            Err(e) => println!("Invalid email: {}", e),
        }

        match Email::parse("invalid-email") {
            Ok(_) => println!("Unexpectedly valid"),
            Err(e) => println!("Correctly rejected: {}", e),
        }

        match Port::parse(8080) {
            Ok(port) => {
                println!("Valid port: {}", port.value());
                println!("Is privileged: {}", port.is_privileged());
            }
            Err(e) => println!("Invalid port: {}", e),
        }

        match ValidUrl::parse("https://example.com:443/api/users") {
            Ok(url) => {
                println!("Valid URL host: {}", url.host());
                println!("Is secure: {}", url.is_secure());
            }
            Err(e) => println!("Invalid URL: {}", e),
        }

        println!("Parse once, use validated types everywhere!");
    }
}

/// Pattern 6: Interior Mutability with Safety Guarantees
///
/// Safe shared mutation using RefCell, Mutex, and RwLock.
mod interior_mutability {
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex, RwLock};
    use std::thread;

    /// Thread-local mutable state with RefCell
    pub fn refcell_pattern() {
        println!("\n--- RefCell for Single-Threaded Mutability ---");

        let data = RefCell::new(vec![1, 2, 3]);

        // Borrow checking happens at runtime
        {
            let borrowed = data.borrow();
            println!("Read: {:?}", *borrowed);
        }

        {
            let mut borrowed_mut = data.borrow_mut();
            borrowed_mut.push(4);
            println!("After mutation: {:?}", *borrowed_mut);
        }

        // This would panic at runtime (double mutable borrow):
        // let mut a = data.borrow_mut();
        // let mut b = data.borrow_mut(); // Panic!

        println!("RefCell enforces borrow rules at runtime");
    }

    /// Thread-safe mutable state with Mutex
    pub fn mutex_pattern() {
        println!("\n--- Mutex for Thread-Safe Mutability ---");

        let counter = Arc::new(Mutex::new(0));
        let mut handles = vec![];

        for i in 0..5 {
            let counter_clone = Arc::clone(&counter);
            let handle = thread::spawn(move || {
                let mut num = counter_clone.lock().unwrap();
                *num += 1;
                println!("Thread {} incremented counter to {}", i, *num);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        println!("Final counter value: {}", *counter.lock().unwrap());
        println!("Mutex ensures exclusive access across threads");
    }

    /// Reader-writer lock for read-heavy workloads
    pub fn rwlock_pattern() {
        println!("\n--- RwLock for Read-Heavy Workloads ---");

        let data = Arc::new(RwLock::new(vec![1, 2, 3]));
        let mut handles = vec![];

        // Multiple readers can access simultaneously
        for i in 0..3 {
            let data_clone = Arc::clone(&data);
            let handle = thread::spawn(move || {
                let read_guard = data_clone.read().unwrap();
                println!("Reader {}: {:?}", i, *read_guard);
            });
            handles.push(handle);
        }

        // Writer gets exclusive access
        {
            let data_clone = Arc::clone(&data);
            let handle = thread::spawn(move || {
                let mut write_guard = data_clone.write().unwrap();
                write_guard.push(4);
                println!("Writer: Added element");
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        println!("Final data: {:?}", *data.read().unwrap());
        println!("RwLock allows concurrent reads, exclusive writes");
    }

    pub fn demonstrate() {
        println!("\n=== Interior Mutability Patterns ===");
        refcell_pattern();
        mutex_pattern();
        rwlock_pattern();
    }
}

/// Pattern 7: Error Handling with Type Safety
///
/// Using Result and custom error types for robust error handling.
mod error_handling {
    use std::fmt;

    /// Custom error type with variants for different error conditions
    #[derive(Debug)]
    pub enum ServiceError {
        NotFound { resource: String },
        Unauthorized { reason: String },
        ValidationFailed { field: String, message: String },
        RateLimited { retry_after: u64 },
        Internal { message: String },
    }

    impl fmt::Display for ServiceError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ServiceError::NotFound { resource } => {
                    write!(f, "Resource not found: {}", resource)
                }
                ServiceError::Unauthorized { reason } => {
                    write!(f, "Unauthorized: {}", reason)
                }
                ServiceError::ValidationFailed { field, message } => {
                    write!(f, "Validation failed for {}: {}", field, message)
                }
                ServiceError::RateLimited { retry_after } => {
                    write!(f, "Rate limited. Retry after {} seconds", retry_after)
                }
                ServiceError::Internal { message } => {
                    write!(f, "Internal error: {}", message)
                }
            }
        }
    }

    impl std::error::Error for ServiceError {}

    /// Service using Result for error handling
    pub struct UserService;

    impl UserService {
        pub fn get_user(id: u64) -> Result<String, ServiceError> {
            if id == 0 {
                return Err(ServiceError::ValidationFailed {
                    field: "id".to_string(),
                    message: "ID cannot be zero".to_string(),
                });
            }

            if id == 999 {
                return Err(ServiceError::NotFound {
                    resource: format!("User with ID {}", id),
                });
            }

            Ok(format!("User_{}", id))
        }

        pub fn delete_user(id: u64, auth_token: Option<&str>) -> Result<(), ServiceError> {
            if auth_token.is_none() {
                return Err(ServiceError::Unauthorized {
                    reason: "Authentication required".to_string(),
                });
            }

            if id == 1 {
                return Err(ServiceError::Unauthorized {
                    reason: "Cannot delete admin user".to_string(),
                });
            }

            Ok(())
        }
    }

    pub fn demonstrate() {
        println!("\n=== Type-Safe Error Handling Pattern ===");

        // Using Result with match
        match UserService::get_user(42) {
            Ok(user) => println!("Found user: {}", user),
            Err(e) => println!("Error: {}", e),
        }

        // Using Result with if let
        if let Err(e) = UserService::get_user(999) {
            println!("Expected error: {}", e);
        }

        // Using ? operator (would need Result return type)
        let result = UserService::delete_user(1, Some("token"));
        match result {
            Ok(()) => println!("User deleted"),
            Err(ServiceError::Unauthorized { reason }) => {
                println!("Authorization failed: {}", reason);
            }
            Err(e) => println!("Other error: {}", e),
        }

        println!("Type-safe errors enable exhaustive handling!");
    }
}

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║     Rust Secure Programming Patterns v2.0                    ║");
    println!("║     Type-Safe Security Through Rust's Type System            ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    type_state_pattern::demonstrate();
    validated_builder::demonstrate();
    secret_wrapper::demonstrate();
    capability_pattern::demonstrate();
    parse_dont_validate::demonstrate();
    interior_mutability::demonstrate();
    error_handling::demonstrate();

    println!("\n=== Secure Patterns Summary ===");
    println!("1. Type-State: Enforce protocol order at compile time");
    println!("2. Validated Builder: Ensure complete construction");
    println!("3. Secret Wrapper: Prevent accidental exposure");
    println!("4. Capability-Based: Encode permissions in types");
    println!("5. Parse, Don't Validate: Validate once at boundaries");
    println!("6. Interior Mutability: Safe shared mutation");
    println!("7. Type-Safe Errors: Exhaustive error handling");
    println!("\nAll patterns leverage Rust's type system for security!");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_validation() {
        assert!(parse_dont_validate::Email::parse("valid@example.com").is_ok());
        assert!(parse_dont_validate::Email::parse("invalid").is_err());
        assert!(parse_dont_validate::Email::parse("").is_err());
    }

    #[test]
    fn test_port_validation() {
        assert!(parse_dont_validate::Port::parse(8080).is_ok());
        assert!(parse_dont_validate::Port::parse(0).is_err());

        let port = parse_dont_validate::Port::parse(22).unwrap();
        assert!(port.is_privileged());

        let high_port = parse_dont_validate::Port::parse(8080).unwrap();
        assert!(!high_port.is_privileged());
    }

    #[test]
    fn test_url_parsing() {
        let url = parse_dont_validate::ValidUrl::parse("https://example.com/api").unwrap();
        assert!(url.is_secure());
        assert_eq!(url.host(), "example.com");

        assert!(parse_dont_validate::ValidUrl::parse("ftp://example.com").is_err());
    }

    #[test]
    fn test_service_errors() {
        assert!(error_handling::UserService::get_user(42).is_ok());
        assert!(error_handling::UserService::get_user(999).is_err());
        assert!(error_handling::UserService::get_user(0).is_err());
    }

    #[test]
    fn test_secret_redaction() {
        let secret = secret_wrapper::Secret::new("password".to_string());
        let debug_str = format!("{:?}", secret);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains("password"));
    }
}
