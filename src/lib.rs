//! # sec
//!
//! The `sec` crate prevent secrets from accidentally leaking through `Debug` or `Display`
//! implementations. It does so by wrapping any kind of confidential information in a zero-overhead
//! type:
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
//! Now talking to: User { id = 1, username: String("alice"), session_token: "..." }
//! ```
//!
//! This functionality is very useful when dealing with data that should always be prevented from
//! accidentally leaking through panics, log files.
//!
//! The contained data can be accessed by any of the `reveal` methods:
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
//! Only methods that contain `reveal` in their name actually allow accessing the secret value.
//!
//!
//! ## Serde support (`deserialize`/`serialize` features)
//!
//! If the `deserialize` feature is enabled, any `Secret<T>` will automatically implement
//! `Deserialize` from [Serde](https://crates.io/crates/serde):
//!
//! ```ignore
//! #[derive(Deserialize)]
//! struct AuthRequest{
//!     username: String,
//!     password: Secret<String>,
//! }
//! ```
//!
//! `AuthRequest` will be deserialized as if `password` was a regular `String`, the result will be
//! stored as a `Secret<String>`. Additionally, if any deserialization errors occur, the resulting
//! serde error will be replaced to avoid leaking the unparsed value.
//!
//! Serialization can be enabled through the `serialize` feature.
//!
//! **IMPORTANT**: Serializing data to a readable format is still a way to leak secrets. Only enable
//! this feature if you need it.
//!
//!
//! ## Diesel support (`diesel` feature)
//!
//! Limited support for inserting and loading `Secret<T>` values through
//! [Diesel](https://crates.io/crates/diesel) can be enabled by the `diesel` feature.
//!
//! **IMPORTANT**: The database may log and echo back (on error) any query that fails, takes too
//! long or is otherwise deemed interesting. Using `Secret` values in expressions should be avoided.
//!
//! ## Rocket support (`rocket` feature)
//!
//! Experimental support is available for `rocket`, specifically rocket's
//! [`rocket::form::FromFormField`] trait, which is implemented for all `Secret<T>` whose underlying
//! `T`s implemented it.
//!
//! Note that the only supported rocket version is a pinned dev version of rocket 0.5.
//!
//!
//! ## `no_std` support
//!
//! By disabling the default features, `no_std` is supported. It can be re-enabled through the `std`
//! feature.
//!
//!
//! ## Additional traits
//!
//! The traits `PartialEq`, `Eq` and `Hash` are implemented for `Secret`, by simply passing through
//! the operation to the underlying type. These traits should be safe in a way that they will not
//! accidentally leak the enclosed secret.
//!
//! Additional, by enabling the `ord` feature, the `PartialOrd` and `Ord` traits will be
//! implemented. Since ordering could potentially leak information when a collection order by a
//! Secret is printed in-order, these are opt-in by default.
//!
//!
//! ## Security
//!
//! While `sec` usually does a good job from preventing accidentally leaks through logging mistakes,
//! it currently does not protect the actual memory (while not impossible, this requires a lot of
//! extra effort due to heap allocations). The data protected by sec is usually sent across the
//! network and passed around among different applications (e.g. a token authorizing a client) or
//! could reasonably be used as a key for a HashMap.
//!
//! To prevent copies inside an application, data is usually allocated on the heap only and scrubbed
//! afer deallocation. `sec` makes a trade-off in favor of performance and generality here by not
//! supporting this pattern. It is not written to protect your GPG private key from core dumps, but
//! rather login tokens from accidental disclosure.
//!
//! If protecting cryptographic secrets in-memory from stackdumps and similar is a concern, have a
//! look at the [secrets] (https://crates.io/crates/secrets), [secstr]
//! (https://crates.io/crates/secstr) or similar crates.

#![no_std]

#[cfg(feature = "diesel")]
extern crate diesel;

#[macro_use]
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "serde")]
extern crate serde;

#[cfg(test)]
mod tests;

use core::fmt;
use core::hash::{Hash, Hasher};

#[cfg(feature = "ord")]
use core::cmp::Ordering;

#[cfg(feature = "diesel")]
use std::io::Write;

#[cfg(feature = "std")]
use std::string::String;

#[cfg(feature = "serde")]
use serde::{de::Error, Deserializer, Serializer};

#[cfg(feature = "rocket")]
use rocket::form::FromFormField;
#[cfg(feature = "rocket")]
use std::{boxed::Box, future::Future, pin::Pin};

/// Wraps a type `T`, preventing it from being accidentally revealed.
pub struct Secret<T>(T);

#[cfg(feature = "std")]
impl Secret<String> {
    /// Returns a `str` reference, wrapped in a secret
    #[inline]
    pub fn as_str(&self) -> Secret<&str> {
        Secret(self.0.as_str())
    }

    /// Returns and **reveal** a `str` reference.
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

    /// Creates a secret immutable reference
    #[inline]
    pub fn as_ref(&self) -> Secret<&T> {
        Secret(&self.0)
    }

    /// Creates a secret mutable reference
    #[inline]
    pub fn as_mut(&mut self) -> Secret<&mut T> {
        Secret(&mut self.0)
    }

    /// **Reveals** the held value by returning a reference
    #[inline]
    pub fn reveal(&self) -> &T {
        &self.0
    }

    /// **Reveals** the held value by unwrapping
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

#[cfg(feature = "ord")]
impl<T: PartialOrd> PartialOrd for Secret<T> {
    #[inline]
    fn partial_cmp(&self, other: &Secret<T>) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

#[cfg(feature = "ord")]
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

#[cfg(feature = "serde")]
impl<T: serde::Serialize> serde::Serialize for Secret<T> {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[cfg(feature = "serde")]
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

#[cfg(all(feature = "diesel", feature = "std"))]
impl<A, DB, T> diesel::types::ToSql<A, DB> for Secret<T>
where
    T: diesel::types::ToSql<A, DB> + fmt::Debug,
    DB: diesel::backend::Backend + diesel::types::HasSqlType<A>,
{
    #[inline]
    fn to_sql<W: Write>(
        &self,
        out: &mut diesel::serialize::Output<W, DB>,
    ) -> Result<diesel::types::IsNull, std::boxed::Box<dyn std::error::Error + Send + Sync>> {
        self.0.to_sql(out)
    }
}

#[cfg(all(feature = "diesel", feature = "std"))]
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

#[cfg(all(feature = "diesel", feature = "std"))]
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

#[cfg(all(feature = "std", feature = "rocket"))]
impl<'v, T> FromFormField<'v> for Secret<T>
where
    T: FromFormField<'v>,
{
    #[inline]
    fn from_value(field: rocket::form::ValueField<'v>) -> rocket::form::Result<'v, Self> {
        <T as FromFormField>::from_value(field).map(Secret)
    }

    #[inline]
    fn from_data<'life0, 'async_trait>(
        field: rocket::form::DataField<'v, 'life0>,
    ) -> Pin<Box<dyn Future<Output = rocket::form::Result<'v, Self>> + Send + 'async_trait>>
    where
        'v: 'async_trait,
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move { <T as FromFormField>::from_data(field).await.map(Secret) })
    }

    #[inline]
    fn default() -> Option<Self> {
        <T as FromFormField>::default().map(Secret)
    }
}
