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
