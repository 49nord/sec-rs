use super::Secret;

use std::string::String;
use std::borrow::ToOwned;

#[cfg(feature = "serialize")]
use serde;

#[derive(Debug)]
struct PublicStruct {
    pub secret_field: Secret<String>,
}

#[test]
fn test_new() {
    let _: Secret<String> = Secret::new("THIS-SHOULD-BE-SECRET".into());
}

#[test]
fn test_hidden_debug_composite() {
    let data = PublicStruct { secret_field: "THIS-SHOULD-BE-SECRET".to_owned().into() };

    assert_eq!("PublicStruct { secret_field: ... }", format!("{:?}", data));
}

#[test]
fn test_hidden_display() {
    let data = PublicStruct { secret_field: "THIS-SHOULD-BE-SECRET".to_owned().into() };

    assert_eq!("...", format!("{}", data.secret_field));
}

#[test]
fn test_non_str_type() {
    let data: Secret<usize> = Secret::new(42);
    let data_ref: Secret<&usize> = data.as_ref();

    assert_eq!("...", format!("{}", data));
    assert_eq!("...", format!("{:?}", data));
    assert_eq!("...", format!("{}", data_ref));
    assert_eq!("...", format!("{:?}", data_ref));
}

#[test]
fn test_hidden_debug() {
    let data = Secret::new("THIS-SHOULD-BE-SECRET");

    assert_eq!("...", format!("{}", data));
}

#[test]
fn test_as_str() {
    let data: Secret<String> = Secret::new("THIS-SHOULD-BE-SECRET".into());
    let data_str: Secret<&str> = data.as_str();

    assert_eq!("...", format!("{}", data_str));
    assert_eq!("...", format!("{:?}", data_str));
}

#[test]
fn test_static_strings() {
    // test static strings as well
    let data: Secret<&'static str> = Secret::new("THIS-SHOULD-BE-SECRET");

    assert_eq!("...", format!("{}", data));
    assert_eq!("...", format!("{:?}", data));
}

#[test]
fn test_reveal_str() {
    let data: Secret<String> = Secret::new("THIS-SHOULD-BE-SECRET".into());
    let revealed: &str = data.reveal_str();

    assert_eq!("THIS-SHOULD-BE-SECRET", revealed);
}

#[test]
fn test_as_ref() {
    let data: Secret<String> = Secret::new("THIS-SHOULD-BE-SECRET".into());
    let data_str: Secret<&String> = data.as_ref();

    assert_eq!("...", format!("{}", data_str));
    assert_eq!("...", format!("{:?}", data_str));
}

#[test]
fn test_as_mut() {
    let mut data: Secret<String> = Secret::new("THIS-SHOULD-BE-SECRET".into());
    let data_str: Secret<&mut String> = data.as_mut();

    assert_eq!("...", format!("{}", data_str));
    assert_eq!("...", format!("{:?}", data_str));
}

#[test]
fn test_reveal() {
    let data_42: Secret<usize> = Secret::new(42);
    let data_s: Secret<String> = Secret::new("THIS-SHOULD-BE-SECRET".into());

    let revealed_42: &usize = data_42.reveal();
    let revealed_s: &String = data_s.reveal();

    assert_eq!(revealed_42, &42);
    assert_eq!(revealed_s, "THIS-SHOULD-BE-SECRET");
}

#[test]
fn test_reveal_into() {
    let data_42: Secret<usize> = Secret::new(42);
    let data_s: Secret<String> = Secret::new("THIS-SHOULD-BE-SECRET".into());

    let revealed_42: usize = data_42.reveal_into();
    let revealed_s: String = data_s.reveal_into();

    assert_eq!(revealed_42, 42);
    assert_eq!(revealed_s, "THIS-SHOULD-BE-SECRET");
}

#[test]
fn test_map_revealed() {
    let data_42: Secret<usize> = Secret::new(42);

    let data_84 = data_42.map_revealed(|v| v * 2);

    assert_eq!(84, data_84.reveal_into());
}

#[cfg(feature = "serialize")]
#[test]
fn test_serde_serialize() {
    let a: Secret<u32> = Secret::new(42);

    fn requires_serde<'de, T: serde::Serialize>(_: T) {}
    requires_serde(a);
}

#[cfg(feature = "deserialize")]
#[test]
fn test_serde_deserialize() {
    let a: Secret<u32> = Secret::new(42);

    fn requires_serde<'de, T: serde::Deserialize<'de>>(_: T) {}
    requires_serde(a);
}

#[test]
fn test_copy() {
    let a: Secret<usize> = Secret::new(42);
    let c: Secret<usize> = a;

    assert_eq!(a.reveal(), c.reveal());
}

#[test]
fn test_clone() {
    let a: Secret<String> = Secret::new("AA".to_owned());
    let c: Secret<String> = a.clone();

    assert_eq!(a.reveal(), c.reveal());
}

#[test]
fn test_sync() {
    fn requires_sync<T: Sync>(_: T) {}
    requires_sync(Secret::new(123));
}

#[test]
fn test_send() {
    fn requires_send<T: Send>(_: T) {}
    requires_send(Secret::new(123));
}

#[test]
fn test_partial_eq() {
    let data_42: Secret<usize> = Secret::new(42);
    let data_33: Secret<usize> = Secret::new(33);
    let data_42_2: Secret<usize> = Secret::new(42);

    // reflective
    assert_eq!(data_42, data_42);

    // equality
    assert_eq!(data_42, data_42_2);

    // inequality
    assert_ne!(data_33, data_42_2);
}

#[cfg(feature = "ord")]
#[test]
fn test_partial_ord() {
    let data_42: Secret<usize> = Secret::new(42);
    let data_33: Secret<usize> = Secret::new(33);

    assert!(data_42 > data_33);
    assert!(data_33 < data_42);
}

#[test]
fn test_default() {
    let data_def: Secret<usize> = Secret::default();
    assert_eq!(data_def.reveal_into(), 0);
}

#[test]
fn test_hash() {
    use std::collections::HashMap;

    let mut items = HashMap::new();
    items.insert(Secret::new(0), 0);
}

// FIXME: add test for the following case
//
// #[macro_use]
// extern crate serde_derive;
// extern crate serde;
// extern crate serde_json;
// extern crate sec;
//
// #[derive(Deserialize, Debug)]
// struct AuthRequest {
//     username: String,
//     key_code: sec::Secret<usize>,
// }
//
// fn main() {
//     let data = r#"{
//         "username": "Alice",
//         "key_code": "123"
//     }"#;
//
//     let res: AuthRequest = serde_json::from_str(data).unwrap();
//     println!("Result: {:?}", res);
// }
//
// the resulting panic should not leak the secret code `123`.
