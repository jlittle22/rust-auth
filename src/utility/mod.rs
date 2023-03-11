pub fn env(key: &'static str, placeholder: Option<&'static str>) -> String {
    let result = std::env::var(key);

    if let Err(_) = result {
        if placeholder.is_none() {
            panic!("{key} missing from .env file...");
        }

        return String::from(placeholder.unwrap());
    }

    return String::from(result.unwrap());
}
