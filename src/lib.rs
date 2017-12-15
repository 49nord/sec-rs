extern crate serde;

#[cfg(test)]
mod tests;

use std::fmt;
use serde::{Deserializer, Serializer};

pub struct Secret<T>(T);

impl Secret<String> {
    #[inline]
    pub fn as_str(&self) -> Secret<&str> {
        Secret(self.0.as_str())
    }
}

impl<T> Secret<T> {
    #[inline]
    pub fn as_ref(&self) -> Secret<&T> {
        Secret(&self.0)
    }

    #[inline]
    pub fn inner(&self) -> &T {
        &self.0
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.0
    }

    #[inline]
    pub fn map<V, F: FnOnce(T) -> V>(self, f: F) -> Secret<V> {
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

impl<T: serde::Serialize> serde::Serialize for Secret<T> {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Secret<T> {
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Secret)
    }
}
