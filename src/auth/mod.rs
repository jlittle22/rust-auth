
mod models;

use super::utility;
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use mongodb::bson::{doc, Document};
use mongodb::options::ClientOptions;
use mongodb::{Client, Database};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt;

pub enum Error {
    UserNotFound,
    IncorrectPassword,
    DatabaseError(String),
    JwtError(String),
    TokenExpired,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UserNotFound => write!(f, "Error::UserNotFound"),
            Error::IncorrectPassword => write!(f, "Error::IncorrectPassword"),
            Error::DatabaseError(s) => write!(f, "Error::DatabaseError: {}", s),
            Error::JwtError(s) => write!(f, "Error::JwtError: {}", s),
            Error::TokenExpired => write!(f, "Error::TokenExpired"),
        }
    }
}

pub struct Auth {
    db: Database,
    secret: String,
}

impl Auth {
    pub async fn new(mongodb_uri: &String) -> Result<Self, String> {
        let result = ClientOptions::parse(mongodb_uri).await;

        if let Err(err) = result {
            return Err(err.to_string());
        }

        let client_options = result.unwrap();
        let result = Client::with_options(client_options);

        if let Err(err) = result {
            return Err(err.to_string());
        }

        let client = result.unwrap();

        let db = utility::env("AUTH_DB_NAME", None);

        let secret = utility::env("AUTH_SIGNING_SECRET", None);

        return Ok(Auth {
            db: client.database(&db),
            secret: secret,
        });
    }

    async fn get_config(&self) -> models::Config {
        let filter = doc! {
            "_id" : "config",
        };

        let config_result = self
            .db
            .collection::<Document>("config")
            .find_one(filter, None)
            .await;
        let config_optional =
            config_result.expect("Database error accesing config collection.");
        let config_doc =
            config_optional.expect("Config document is missing in database.");

        return models::Config::from_document(config_doc);
    }

    pub async fn authorize_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<String, Error> {
        let filter = doc! {
            "username" : username,
        };

        let user_result = self
            .db
            .collection::<Document>("users")
            .find_one(filter, None)
            .await;

        if let Err(err) = user_result {
            return Err(Error::DatabaseError(err.to_string()));
        }

        let user_optional = user_result.unwrap();
        if user_optional.is_none() {
            return Err(Error::UserNotFound);
        }

        let user: Document = user_optional.unwrap();
        let stored_password: &str = user.get_str("password").unwrap();
        if password != stored_password {
            return Err(Error::IncorrectPassword);
        }

        let config = self.get_config().await;

        let key: Result<Hmac<Sha256>, _> =
            Hmac::new_from_slice(self.secret.as_bytes());
        if let Err(err) = key {
            return Err(Error::JwtError(err.to_string()));
        }

        // TODO(jsnl): Modularize claim encoding...
        let mut claims = BTreeMap::new();
        claims.insert("sub", username);

        let token_str = claims.sign_with_key(&key.unwrap());
        if let Err(err) = token_str {
            return Err(Error::JwtError(err.to_string()));
        }

        return Ok(token_str.unwrap());
    }

    pub fn verify(&self, jwt: &String) -> Result<BTreeMap<String, String>, Error> {
        let key: Result<Hmac<Sha256>, _> =
            Hmac::new_from_slice(self.secret.as_bytes());
        if let Err(err) = key {
            return Err(Error::JwtError(err.to_string()));
        }

        let claims: Result<BTreeMap<String, String>, _> = jwt.verify_with_key(&key.unwrap());
        if let Err(err) = claims {
            return Err(Error::JwtError(err.to_string()));
        }

        return Ok(claims.unwrap());
    }
}
