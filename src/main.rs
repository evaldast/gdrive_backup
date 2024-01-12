use base64::Engine;
use chrono::{Duration, Utc};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use reqwest::blocking::{multipart, Client};
use serde_json::Value;
use std::{error::Error as StdError, process::Command, str};

mod app;
mod crypto;

use app::App;
use crypto::Crypto;

#[derive(Debug, thiserror::Error)]
enum CryptoError {
    #[error("Failed to base64 decode encryption key")]
    DecodeEncryptionKey(#[from] base64::DecodeError),

    #[error("Failed to create AES key")]
    CreateAesKey(aes_gcm::Error),
}

impl From<aes_gcm::Error> for CryptoError {
    fn from(err: aes_gcm::Error) -> Self {
        CryptoError::CreateAesKey(err)
    }
}

fn main() -> Result<(), Box<dyn StdError>> {
    let app = App::new()?;
    let crypto = Crypto::new(&app.encryption_key)?;

    let mut dump_data = get_dump_data(&app.postgres_url);
    crypto.encrypt_in_place(&mut dump_data)?;

    let form = {
        let now = Utc::now();
        let filename = format!("{}_dump.sql", now.to_rfc3339());
        create_multipart_data(&filename, &app.folder_id, dump_data)
    };

    let response = {
        let jwt_token = generate_jwt_token(&app.google_keyfile, Duration::minutes(15));
        let access_token = get_access_token(&jwt_token);
        let client = Client::new();

        client
            .post("https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart")
            .header("Authorization", format!("Bearer {}", access_token))
            .multipart(form)
            .send()
            .expect("Google Drive API error")
    };

    println!("{}", response.text().unwrap());

    Ok(())
}

fn get_dump_data(postgres_url: &str) -> Vec<u8> {
    let command = format!("pg_dump {}", postgres_url);
    let output = Command::new("sh")
        .arg("-c")
        .arg(command)
        .output()
        .expect("failed to execute pg_dump process");

    output.stdout
}

fn create_multipart_data(filename: &str, folder_id: &str, file_bytes: Vec<u8>) -> multipart::Form {
    let metadata = format!(
        r#"{{
            "name": "{}",
            "parents": ["{}"]
        }}"#,
        filename, folder_id
    );

    let metadata_part = multipart::Part::text(metadata)
        .mime_str("text/plain")
        .unwrap();
    let bytes_part = multipart::Part::bytes(file_bytes).file_name(filename.to_owned());

    multipart::Form::new()
        .part("metadata", metadata_part)
        .part("file", bytes_part)
}

fn get_access_token(jwt_token: &str) -> String {
    let client = Client::new();
    let response = client
        .post("https://www.googleapis.com/oauth2/v4/token")
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &jwt_token),
        ])
        .send()
        .expect("Failed to send access token request");

    if !response.status().is_success() {
        panic!(
            "access token response does not indicate success. {status_code}",
            status_code = response.status().as_str()
        );
    }

    let response_json: Value = response.json().expect("Could not parse response json");
    let accesss_token = response_json
        .get("access_token")
        .expect("Access token not found in response");

    accesss_token.to_string()
}

fn generate_jwt_token(keyfile: &str, valid_for: Duration) -> String {
    let keyfile_string = std::fs::read_to_string(keyfile).unwrap();
    let keyfile_json = serde_json::from_str::<serde_json::Value>(&keyfile_string).unwrap();
    let sa_email = keyfile_json.get("client_email").unwrap().as_str().unwrap();
    let private_key = keyfile_json.get("private_key").unwrap().as_str().unwrap();

    let header = r#"{"alg":"RS256","typ":"JWT"}"#;

    let now = Utc::now();
    let claim = format!(
        r#"{{
                "iss":"{}",
                "scope":"https://www.googleapis.com/auth/drive",
                "aud":"https://www.googleapis.com/oauth2/v4/token",
                "exp":{},
                "iat":{}
            }}"#,
        sa_email,
        now.timestamp() + valid_for.num_seconds(),
        now.timestamp(),
    );

    let request_body = format!(
        "{}.{}",
        base64_stream(header.as_bytes()),
        base64_stream(claim.as_bytes())
    );

    let private_key_pkey = PKey::private_key_from_pem(private_key.as_bytes())
        .expect("Failed to convert private key to PKey");

    let mut signer = Signer::new(MessageDigest::sha256(), &private_key_pkey).unwrap();
    signer.update(request_body.as_bytes()).unwrap();
    let signature = signer.sign_to_vec().expect("Failed to sign");

    let signature_base64 = base64_stream(&signature);

    format!("{}.{}", request_body, signature_base64)
}

fn base64_stream(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}
