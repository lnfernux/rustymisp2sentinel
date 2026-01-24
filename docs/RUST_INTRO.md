# Introduction to Rust: Learning Through MISP2Sentinel

This guide introduces Rust programming concepts using the MISP2Sentinel project as a practical example. You'll learn how Rust works by understanding real code that solves a real problem: syncing threat intelligence from MISP to Microsoft Sentinel.

## What is Rust?

Rust is a systems programming language focused on three goals: **safety**, **speed**, and **concurrency**. It achieves memory safety without garbage collection, making it as fast as C/C++ but much safer.

## Project Structure: Workspaces and Crates

Rust organizes code into **crates** (like Python packages). Multiple crates form a **workspace**.

```
rustymisp2sentinel/
├── Cargo.toml              # Workspace configuration
├── Cargo.lock              # Lock file for reproducible builds
├── config.toml             # Configuration file
├── config.toml.example     # Configuration template
├── misp2sentinel-core/     # Shared library crate
└── misp2sentinel-cli/      # Binary crate (command-line tool)
```

### The Root Cargo.toml

```toml
[workspace]
resolver = "2"
members = [
    "misp2sentinel-core",    # Library with shared code
    "misp2sentinel-cli",     # CLI application
]

[workspace.package]
version = "0.1.0"
edition = "2021"

[workspace.dependencies]
tokio = { version = "1.49", features = ["full"] }  # Async runtime
reqwest = { version = "0.13", features = ["json", "form", "rustls"] }  # HTTP client
serde = { version = "1.0", features = ["derive"] }   # Serialization
chrono = { version = "0.4", features = ["serde"] }  # Date/time handling
thiserror = "2.0"  # Error handling
```

**Key concept:** Dependencies are declared in `Cargo.toml`. Running `cargo build` downloads and compiles them automatically—like `pip install` but with exact version locking.

## Modules and Visibility

Rust uses a module system to organize code. Look at [misp2sentinel-core/src/lib.rs](../misp2sentinel-core/src/lib.rs):

```rust
//! Core library for MISP to Microsoft Sentinel threat intelligence synchronization

pub mod config;    // pub = public, accessible from outside
pub mod error;
pub mod misp;
pub mod progress;
pub mod sentinel;
pub mod stix;
pub mod sync;

// Re-export commonly used types for convenience
pub use config::Config;
pub use error::Error;
pub use sync::Syncer;
```

- `mod` declares a module (maps to a file: `config.rs`, `error.rs`, etc.)
- `pub` makes it public (visible to other crates)
- `pub use` re-exports types so users can write `misp2sentinel_core::Config` instead of `misp2sentinel_core::config::Config`

## Structs: Rust's Data Structures

Structs are like Python classes but without inheritance. Here's our configuration:

```rust
/// Main configuration struct
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub misp: MispConfig,
    pub sentinel: SentinelConfig,
    pub sync: SyncConfig,
}

/// MISP server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispConfig {
    pub url: String,
    pub api_key: String,
    
    #[serde(default = "default_true")]
    pub verify_tls: bool,
    
    #[serde(default)]
    pub max_events: Option<u32>,  // Option = nullable
}
```

### What are those `#[derive(...)]` things?

These are **derive macros** that auto-generate code:

| Derive | What it does | Python equivalent |
|--------|--------------|-------------------|
| `Debug` | Enables `{:?}` formatting | `__repr__` |
| `Clone` | Enables `.clone()` to copy | `copy.deepcopy()` |
| `Serialize` | Enables JSON/TOML output | `json.dumps()` |
| `Deserialize` | Enables JSON/TOML parsing | `json.loads()` |

### Option<T>: Rust's Null Safety

Rust has no `null`. Instead, optional values use `Option<T>`:

```rust
pub max_events: Option<u32>,  // Either Some(100) or None
```

Usage:
```rust
// Check if it has a value
if let Some(max) = config.max_events {
    println!("Limiting to {} events", max);
}

// Or provide a default
let max = config.max_events.unwrap_or(1000);
```

This eliminates null pointer exceptions at compile time!

## Error Handling: Result<T, E>

Rust doesn't have exceptions. Functions that can fail return `Result<T, E>`:

```rust
// From error.rs - define error types
#[derive(Error, Debug)]
pub enum Error {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("MISP API error: {0}")]
    MispApi(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),  // Auto-convert from reqwest errors
}

pub type Result<T> = std::result::Result<T, Error>;
```

### Using Results

```rust
// Function that can fail
pub fn from_file(path: &str) -> Result<Config> {
    let content = std::fs::read_to_string(path)?;  // ? propagates errors
    let config: Config = toml::from_str(&content)?;
    Ok(config)  // Wrap success in Ok()
}

// Calling it
fn main() {
    match Config::from_file("config.toml") {
        Ok(config) => println!("Loaded config"),
        Err(e) => eprintln!("Failed: {}", e),
    }
    
    // Or use ? in functions that return Result
    let config = Config::from_file("config.toml")?;
}
```

The `?` operator is like Python's `raise` but automatic—if the result is `Err`, it returns early.

## Ownership: Rust's Superpower

This is what makes Rust unique. Every value has exactly one **owner**.

```rust
fn main() {
    let events = fetch_events();  // events owns the data
    process(events);              // ownership moves to process()
    // println!("{:?}", events);  // ERROR! events was moved
}
```

### Borrowing: References

Instead of moving, you can **borrow**:

```rust
fn main() {
    let events = fetch_events();
    process(&events);            // &events = borrow (read-only)
    println!("{:?}", events);    // OK! we still own events
}

fn process(events: &Vec<MispEvent>) {  // borrows, doesn't own
    for event in events {
        // read-only access
    }
}
```

### Real Example from misp.rs

```rust
impl MispClient {
    pub fn new(config: &MispConfig) -> Result<Self> {  // Borrows config
        let client = Client::builder()
            .danger_accept_invalid_certs(!config.verify_tls)
            .build()?;

        Ok(Self {
            client,
            base_url: config.url.clone(),  // Clone to own a copy
            api_key: config.api_key.clone(),
        })
    }
}
```

- `&MispConfig` = we borrow the config (don't take ownership)
- `.clone()` = make a copy we can own
- `Self` = refers to the struct type (`MispClient`)

## Async/Await: Concurrent Programming

Rust's async is similar to Python's, but more explicit:

```rust
// Declare an async function
pub async fn fetch_events(&self, config: &MispConfig) -> Result<Vec<MispEvent>> {
    let response = self.client
        .post(&url)
        .header("Authorization", &self.api_key)
        .json(&request_body)
        .send()
        .await?;  // .await waits for the future, ? propagates errors
    
    let events: Vec<MispEvent> = response.json().await?;
    Ok(events)
}
```

### Concurrent Execution

Our Sentinel upload uses concurrent batch processing:

```rust
use futures::stream::{self, StreamExt};

// Upload batches concurrently (4 at a time)
let results: Vec<Result<()>> = stream::iter(batches)
    .map(|batch| self.upload_batch(batch))  // Create futures
    .buffer_unordered(4)                     // Run 4 concurrently
    .collect()
    .await;
```

This is why Rust uploads 5x faster than Python's sequential approach!

## Traits: Rust's Interfaces

Traits define shared behavior (like Python's abstract base classes):

```rust
// Standard library trait
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Config(msg) => write!(f, "Config error: {}", msg),
            Error::MispApi(msg) => write!(f, "MISP error: {}", msg),
            // ...
        }
    }
}
```

The `#[derive(Debug, Clone, Serialize)]` macros auto-implement common traits.

## Pattern Matching

Rust's `match` is like Python's `match` but more powerful:

```rust
// From stix.rs - convert MISP attributes to STIX patterns
fn create_pattern_for_attribute(&self, attr: &MispAttribute) -> Option<String> {
    match attr.attr_type.as_str() {
        // Simple network indicators
        "ip-src" | "ip-dst" => {
            if attr.value.contains(':') {
                Some(create_pattern(ObservableType::IPv6Addr, &attr.value))
            } else {
                Some(create_pattern(ObservableType::IPv4Addr, &attr.value))
            }
        }
        
        // Composite types
        "ip-src|port" | "ip-dst|port" => {
            let ip = attr.value.split('|').next()?;  // ? returns None if split fails
            Some(create_pattern(ObservableType::IPv4Addr, ip))
        }
        
        "domain" | "hostname" => {
            Some(create_pattern(ObservableType::DomainName, &attr.value))
        }
        
        // Unknown type
        _ => None,
    }
}
```

## Iterators and Functional Style

Rust iterators are zero-cost abstractions—as fast as manual loops:

```rust
// Convert events to indicators with filtering and mapping
let indicators: Vec<StixIndicator> = events
    .iter()                                    // Create iterator
    .flat_map(|event| &event.attributes)       // Flatten nested attributes
    .filter(|attr| attr.to_ids)                // Only IDS-flagged
    .filter(|attr| ACTIONABLE_TYPES.contains(&attr.attr_type))
    .filter_map(|attr| self.convert_attribute(attr))  // Convert, skip None
    .collect();                                // Collect into Vec
```

Compare to Python:
```python
indicators = [
    self.convert_attribute(attr)
    for event in events
    for attr in event.attributes
    if attr.to_ids and attr.type in ACTIONABLE_TYPES
]
```

## Lifetimes: Advanced Borrowing

When structs hold references, you need **lifetimes**:

```rust
// This struct borrows data with lifetime 'a
struct Parser<'a> {
    data: &'a str,  // Reference valid for lifetime 'a
}

impl<'a> Parser<'a> {
    fn new(data: &'a str) -> Self {
        Parser { data }
    }
}
```

Most of the time, Rust infers lifetimes automatically. You'll see them in function signatures:

```rust
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}
```

This says: "the returned reference lives as long as both inputs."

## Building and Running

```bash
# Development build (fast compile, slow run)
cargo build

# Release build (slow compile, fast run) - 5-10x faster!
cargo build --release

# Run CLI
cargo run --release

# Run specific binary in workspace
cargo run -p misp2sentinel-cli --release

# Run tests
cargo test

# Build just the core library
cargo build -p misp2sentinel-core
```

## Common Patterns in This Project

### Builder Pattern

```rust
let client = Client::builder()
    .danger_accept_invalid_certs(!config.verify_tls)
    .timeout(Duration::from_secs(300))
    .pool_max_idle_per_host(10)
    .build()?;
```

### The `impl` Block

```rust
impl MispClient {
    // Constructor (not special, just convention to name it `new`)
    pub fn new(config: &MispConfig) -> Result<Self> { ... }
    
    // Instance method (&self = borrows self)
    pub async fn fetch_events(&self) -> Result<Vec<MispEvent>> { ... }
    
    // Mutable method (&mut self = mutable borrow)
    pub fn clear_cache(&mut self) { ... }
}
```

### Serialization with Serde

```rust
#[derive(Serialize, Deserialize)]
pub struct StixIndicator {
    #[serde(rename = "type")]  // JSON field name
    pub object_type: String,
    
    #[serde(skip_serializing_if = "Option::is_none")]  // Omit if None
    pub description: Option<String>,
    
    #[serde(default)]  // Use Default if missing
    pub labels: Vec<String>,
}

// Usage
let json = serde_json::to_string(&indicator)?;
let indicator: StixIndicator = serde_json::from_str(&json)?;
```

## Summary: Rust vs Python

| Concept | Python | Rust |
|---------|--------|------|
| Null | `None` | `Option<T>` |
| Exceptions | `try/except` | `Result<T, E>` + `?` |
| Classes | `class Foo:` | `struct Foo` + `impl Foo` |
| Inheritance | `class Bar(Foo):` | Traits (composition) |
| Memory | Garbage collected | Ownership system |
| Async | `async def` | `async fn` |
| Package manager | pip | cargo |
| Type hints | Optional (`def f(x: int)`) | Required (`fn f(x: i32)`) |

## Next Steps

1. **Read the code**: Start with `misp2sentinel-core/src/sync.rs` to see the main workflow
2. **Run examples**: `cargo run --example test_sentinel_api`
3. **Modify something**: Try adding a new MISP attribute type in `stix.rs`
4. **Official resources**:
   - [The Rust Book](https://doc.rust-lang.org/book/) - comprehensive tutorial
   - [Rust by Example](https://doc.rust-lang.org/rust-by-example/) - learn by doing
   - [Rustlings](https://github.com/rust-lang/rustlings) - small exercises

## Quick Reference

```rust
// Variables (immutable by default)
let x = 5;
let mut y = 10;  // mutable

// Functions
fn add(a: i32, b: i32) -> i32 {
    a + b  // No semicolon = return value
}

// Strings
let s: &str = "string slice";     // Borrowed, immutable
let s: String = String::from("owned");  // Owned, growable

// Collections
let v: Vec<i32> = vec![1, 2, 3];
let m: HashMap<String, i32> = HashMap::new();

// Control flow
if condition { } else { }
for item in collection { }
while condition { }
loop { break; }

// Error handling
fn might_fail() -> Result<i32, Error> {
    Ok(42)    // Success
    Err(e)    // Failure
}
let value = might_fail()?;  // Propagate error
```

Welcome to Rust! 🦀
