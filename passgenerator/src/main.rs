use std::env;

use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use rand_core::OsRng;

fn main() {
    let args: Vec<String> = env::args().collect();

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(&args[1].as_bytes(), &salt)
        .map(|hash| hash.to_string());
    println!("{}", hashed_password.unwrap());
}