use mongodb::bson::{doc, Document};

pub struct Config {
    pub jwt_expiration_time: i32,
}

impl Config {
    pub fn from_document(d: Document) -> Self {
        let jwt_expiration_time = d
            .get_i32("jwt_expiration_time")
            .expect("Missing jwt_expiration_time in config document.");
        return Config {
            jwt_expiration_time,
        };
    }
}
