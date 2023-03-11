#[macro_use]
extern crate rocket;

use dotenv::dotenv;
use rocket::State;

mod auth;
use crate::auth::Auth;

mod utility;

struct ServerContext {
    auth: Auth,
}

impl ServerContext {
    async fn new() -> Self {
        let uri: String = utility::env("AUTH_DB_URI", None);

        let auth_result = Auth::new(&uri).await;

        if let Err(err) = auth_result {
            panic!("{}", err);
        }

        return ServerContext {
            auth: auth_result.unwrap(),
        };
    }
}

#[get("/authorize?<username>&<password>")]
async fn authorize(
    username: &str,
    password: &str,
    state: &State<ServerContext>,
) -> String {
    let auth_attempt = state.auth.authorize_user(username, password).await;

    let mut token_result = String::new();
    match auth_attempt {
        Err(err) => token_result.push_str(&err.to_string()),
        Ok(jwt) => token_result.push_str(&jwt),
    }

    let mut claims_result = String::new();
    match state.auth.verify(&token_result) {
        Err(err) => claims_result.push_str(&err.to_string()),
        Ok(claims) => claims_result.push_str(&format!("{:?}", claims)),
    }

    return format!("Username: {} \nResult: {} \nClaims: {}", username, token_result, claims_result);
}

#[launch]
async fn rocket() -> _ {
    dotenv().expect("dotenv failed.");

    rocket::build()
        .mount("/", routes![authorize])
        .manage(ServerContext::new().await)
}
