use std::{env, fs, io::Write, path::Path};
use stellar_tvc_example::{Config, Error};
use turnkey_api_key_stamper::TurnkeyP256ApiKey;

fn load_key(path: &Path) -> Result<TurnkeyP256ApiKey, Error> {
    if !path.exists() {
        let key = TurnkeyP256ApiKey::generate();
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(hex::encode(key.private_key()).as_bytes())?;
        file.sync_all()?;
        return Ok(key);
    }
    let private = fs::read_to_string(path)?;
    Ok(TurnkeyP256ApiKey::from_strings(private.trim(), None)?)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let config = Config {
        organization_id: env::var("TURNKEY_ORGANIZATION_ID")?,
        network_passphrase: env::var("STELLAR_NETWORK_PASSPHRASE")?,
        allowed_contract: env::var("ALLOWED_CONTRACT")?.parse()?,
        turnkey_api_url: env::var("TURNKEY_API_URL")
            .unwrap_or_else(|_| "https://api.turnkey.com".into()),
    };
    let key_file = env::var("TURNKEY_KEY_FILE").unwrap_or_else(|_| "/keys/voter.hex".into());
    let app = stellar_tvc_example::router(config, load_key(Path::new(&key_file))?)?;
    let address = env::var("LISTEN_ADDRESS").unwrap_or_else(|_| "0.0.0.0:44020".into());
    let listener = tokio::net::TcpListener::bind(&address).await?;
    eprintln!("TVC listening on {address}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_the_voting_key_and_rejects_invalid_existing_keys() -> Result<(), Error> {
        let directory = env::temp_dir().join(format!("stellar-tvc-keys-{}", std::process::id()));
        fs::create_dir(&directory)?;
        let result = (|| -> Result<(), Error> {
            let path = directory.join("voter.hex");
            let first = load_key(&path)?;
            assert_eq!(
                first.compressed_public_key(),
                load_key(&path)?.compressed_public_key()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
            }
            fs::write(&path, "invalid-existing-key")?;
            assert!(load_key(&path).is_err());
            assert_eq!(fs::read_to_string(&path)?, "invalid-existing-key");
            Ok(())
        })();
        fs::remove_dir_all(directory)?;
        result
    }
}
