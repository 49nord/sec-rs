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
use serde::{Deserializer, Serializer};

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

#[cfg(feature = "serialize")]
impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Secret<T> {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Secret)
    }
}
