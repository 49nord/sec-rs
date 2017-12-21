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
//! Only methods that contain `reveal` in their name actually allow accessing
//! the secret value.
//!
//!
//! ## Serde support (`deserialize`/`serialize` features)
//!
//! If the `deserialize` feature is enabled, any `Secret<T>` will automatically
//! implement `Deserialize` from [Serde](https://crates.io/crates/serde):
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
//! the result will be stored as a `Secret<String>`. Additionally, if any
//! deserialization errors occur, the resulting serde error will be replaced
//! to avoid leaking the unparsed value.
//!
//! Serialization can be enabled through the `serialize` feature.
//!
//! **IMPORTANT**: Serializing data to a readable format is still a way to leak
//! secrets. Only enable this feature if you need it.
//!
//!
//! ## Diesel support (`diesel_sql` feature)
//!
//! Limited support for inserting and loading `Secret<T>` values through
//! [Diesel](https://crates.io/crates/diesel) can be enabled by the `diesel_sql`
//! feature.
//!
//! **IMPORTANT**: The database may log and echo back (on error) any query that
//! fails, takes to long or is otherwise deemed interesting. Using `Secret`
//! values in expressions should be avoided.
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

#[cfg(feature = "diesel_sql")]
extern crate diesel;

#[macro_use]
#[cfg(feature = "std")]
extern crate std;

#[cfg(any(feature = "serialize", feature = "deserialize"))]
extern crate serde;

#[cfg(test)]
mod tests;

use core::fmt;
use core::hash::{Hash, Hasher};
use core::cmp::Ordering;

#[cfg(feature = "diesel_sql")]
use std::io::Write;

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
    /// Returns a `str` reference, wrapped in a secret
    #[inline]
    pub fn as_str(&self) -> Secret<&str> {
        Secret(self.0.as_str())
    }

    /// Return and **reveal** a `str` reference.
    #[inline]
    pub fn reveal_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<T> Secret<T> {
    /// Creates a new secret
    #[inline]
    pub fn new(val: T) -> Secret<T> {
        Secret(val)
    }

    /// Create a secret immutable reference
    #[inline]
    pub fn as_ref(&self) -> Secret<&T> {
        Secret(&self.0)
    }

    /// Create a secret mutable reference
    #[inline]
    pub fn as_mut(&mut self) -> Secret<&mut T> {
        Secret(&mut self.0)
    }

    /// **Reveal** the held value by returning a reference
    #[inline]
    pub fn reveal(&self) -> &T {
        &self.0
    }

    /// **Reveal** the held value by unwrapping
    #[inline]
    pub fn reveal_into(self) -> T {
        self.0
    }

    /// **Reveals** the held value by applying a function to it
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

impl<T: PartialEq> PartialEq for Secret<T> {
    #[inline]
    fn eq(&self, other: &Secret<T>) -> bool {
        self.0.eq(&other.0)
    }
}

impl<T: PartialOrd> PartialOrd for Secret<T> {
    #[inline]
    fn partial_cmp(&self, other: &Secret<T>) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl<T: Ord> Ord for Secret<T> {
    #[inline]
    fn cmp(&self, other: &Secret<T>) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl<T: Hash> Hash for Secret<T> {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl<T: Default> Default for Secret<T> {
    #[inline]
    fn default() -> Secret<T> {
        Secret(T::default())
    }
}

impl<T: Copy> Copy for Secret<T> {}
impl<T: Eq> Eq for Secret<T> {}
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
use serde::de::Error;

#[cfg(feature = "deserialize")]
impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Secret<T> {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // we need to intercept the exception, as it might contain the actual
        // raw value being deserialized
        match T::deserialize(deserializer).map(Secret) {
            Err(_) => Err(D::Error::custom(
                "a confidential value could not be deserialized",
            )),
            Ok(v) => Ok(v),
        }
    }
}

#[cfg(all(feature = "diesel_sql", feature = "std"))]
impl<A, DB, T> diesel::types::ToSql<A, DB> for Secret<T>
where
    T: diesel::types::ToSql<A, DB> + fmt::Debug,
    DB: diesel::backend::Backend
        + diesel::types::HasSqlType<A>,
{
    #[inline]
    fn to_sql<W: Write>(
        &self,
        out: &mut diesel::types::ToSqlOutput<W, DB>,
    ) -> Result<diesel::types::IsNull, std::boxed::Box<std::error::Error + Send + Sync>> {
        self.0.to_sql(out)
    }
}

#[cfg(all(feature = "diesel_sql", feature = "std"))]
impl<'a, E, T> diesel::expression::AsExpression<E> for &'a Secret<T>
where
    T: diesel::expression::AsExpression<E>,
    &'a T: diesel::expression::AsExpression<E>,
{
    type Expression = <&'a T as diesel::expression::AsExpression<E>>::Expression;

    #[inline]
    fn as_expression(self) -> Self::Expression {
        (&self.0).as_expression()
    }
}


#[cfg(all(feature = "diesel_sql", feature = "std"))]
impl<T, ST, DB> diesel::query_source::Queryable<ST, DB> for Secret<T>
where
    DB: diesel::backend::Backend + diesel::types::HasSqlType<ST>,
    T: diesel::query_source::Queryable<ST, DB>,
{
    type Row = T::Row;

    #[inline]
    fn build(row: Self::Row) -> Self {
        Secret(T::build(row))
    }
}
