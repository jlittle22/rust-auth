# Rust JWT Auth Module
Demos a Rust JWT authentication module in a simple HTTP server.

Configure `.env` file with the following fields:
```
AUTH_DB_URI=<required>            <-- MongoDB URI
AUTH_DB_NAME=<required>           <-- MongoDB DB name
AUTH_SIGNING_SECRET=<required>    <-- JWT signing secret
```