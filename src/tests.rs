use super::Secret;

#[derive(Debug)]
struct PublicStruct {
    pub secret_field: Secret<String>,
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
fn test_hidden_debug() {
    let data = Secret::new("THIS-SHOULD-BE-SECRET");

    assert_eq!("...", format!("{}", data));
}

#[test]
fn test_as_str() {
    unimplemented!()
}

#[test]
fn test_reveal_str() {
    unimplemented!()
}

#[test]
fn test_new() {
    unimplemented!()
}

#[test]
fn test_as_ref() {
    unimplemented!()
}

#[test]
fn test_reveal() {
    unimplemented!()
}

#[test]
fn test_reveal_into() {
    unimplemented!()
}

#[test]
fn test_map_revealed() {
    unimplemented!()
}

#[test]
fn test_serde() {
    unimplemented!()
}

#[test]
fn test_copy() {
    unimplemented!()
}

#[test]
fn test_clone() {
    unimplemented!()
}

#[test]
fn test_eq() {
    unimplemented!()
}

#[test]
fn test_partial_eq() {
    unimplemented!()
}

#[test]
fn test_ord() {
    unimplemented!()
}

#[test]
fn test_partial_ord() {
    unimplemented!()
}

#[test]
fn test_sync() {
    unimplemented!()
}

#[test]
fn test_send() {
    unimplemented!()
}
