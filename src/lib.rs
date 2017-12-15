//! sec
//! ===
//!
//! The `sec` crate prevent secrets from accidentally leaking through `Debug`
//! or `Display` implementations. It does so by wrapping any kind of
//! confidential information in a zero-overhead type:
//!
//! ```rust
//! use sec::Secret;
//!
//! #[derive(Debug)]
//! struct User {
//!     id: usize,
//!     username: String,
//!     session_token: Secret<String>,
//! }
//!
//! let alice = User{
//!     id: 1,
//!     username: "alice".to_owned(),
//!     session_token: Secret::new("no one should see this".to_owned()),
//! };
//!
//! println!("Now talking to: {:?}", alice);
//! ```
//!
//! This will yield the following output:
//!
//! ```raw
//! Now talking to: User{ id = 1, username: String("alice"), session_token: "..." }
//! ```
//!
//! This functionality is very useful when dealing with data that should always
//! be prevented from accidentally leaking through panics, log files.
//!
//! The contained data can be accessed by any of the `reaveal` methods:
//!
//! ```rust
//! #  use sec::Secret;
//! #
//! #  #[derive(Debug)]
//! #  struct User {
//! #      id: usize,
//! #      username: String,
//! #      session_token: Secret<String>,
//! #  }
//! #
//! #  let alice = User{
//! #      id: 1,
//! #      username: "alice".to_owned(),
//! #      session_token: Secret::new("no one should see this".to_owned()),
//! #  };
//! #
//! println!("Don't tell anyone, but Alice's token is: {}",
//!          alice.session_token.reveal());
//! ```
//!
//! ## Serde support (`deserialize`/`serialize` features)
//!
//! If the `deserialize` feature is enabled, any `Secret<T>` will automatically
//! implement `Deserialize`:
//!
//! ```norun
//! #[derive(Deserialize)]
//! struct AuthRequest{
//!     username: String,
//!     password: Secret<String>,
//! }
//! ```
//!
//! `AuthRequest` will be deserialized as if `password` was a regular `String`,
//! the result will be stored as a `Secret<String>`.
//!
//! Serialization can be enabled through the `serialize` feature.
//!
//! **IMPORTANT**: Serializing data to a readable format is still a way to leak
//! secrets. Only enable this feature if you need it.
//!
//!
//! ## `no_std` support
//!
//! By disabling the default features, `no_std` is supported. It can be
//! re-enabled through the `std` feature.
//!
//!
//! ## Security
//!
//! While `sec` usually does a good job from preventing accidentally leaks
//! through logging mistakes, it currently does not protect the actual memory
//! (while not impossible, this requires a lot of extra effort due to heap
//! allocations).
//!
//! If protecting cryptographic secrets in-memory from stackdumps and similar
//! is a concern, have a look at the [secrets](https://crates.io/crates/secrets)
//! crate or similar crates.

#![no_std]

#[macro_use]
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "serialize")]
extern crate serde;

#[cfg(test)]
mod tests;

use core::fmt;

#[cfg(feature = "std")]
use std::string::String;

#[cfg(feature = "serialize")]
use serde::Serializer;

#[cfg(feature = "deserialize")]
use serde::Deserializer;

/// Wraps a type `T`, preventing it from being accidentally revealed.
pub struct Secret<T>(T);

#[cfg(feature = "std")]
impl Secret<String> {
    #[inline]
    pub fn as_str(&self) -> Secret<&str> {
        Secret(self.0.as_str())
    }

    #[inline]
    pub fn reveal_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<T> Secret<T> {
    #[inline]
    pub fn new(val: T) -> Secret<T> {
        Secret(val)
    }

    #[inline]
    pub fn as_ref(&self) -> Secret<&T> {
        Secret(&self.0)
    }

    #[inline]
    pub fn as_mut(&mut self) -> Secret<&mut T> {
        Secret(&mut self.0)
    }

    #[inline]
    pub fn reveal(&self) -> &T {
        &self.0
    }

    #[inline]
    pub fn reveal_into(self) -> T {
        self.0
    }

    #[inline]
    pub fn map_revealed<V, F: FnOnce(T) -> V>(self, f: F) -> Secret<V> {
        Secret(f(self.0))
    }
}

impl<T> fmt::Debug for Secret<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "...")
    }
}

impl<T: fmt::Display> fmt::Display for Secret<T> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "...")
    }
}

impl<T: Clone> Clone for Secret<T> {
    #[inline]
    fn clone(&self) -> Self {
        Secret(self.0.clone())
    }
}

impl<T: Copy> Copy for Secret<T> {}
unsafe impl<T: Sync> Sync for Secret<T> {}
unsafe impl<T: Send> Send for Secret<T> {}

impl<T> From<T> for Secret<T> {
    #[inline]
    fn from(v: T) -> Secret<T> {
        Secret(v)
    }
}

#[cfg(feature = "serialize")]
impl<T: serde::Serialize> serde::Serialize for Secret<T> {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[cfg(feature = "deserialize")]
impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Secret<T> {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Secret)
    }
}
