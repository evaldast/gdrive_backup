use dotenvy::dotenv;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Environment variable {0} is missing")]
    MissingEnvVariable(String),
}

pub struct App {
    pub postgres_url: String,
    pub folder_id: String,
    pub google_keyfile: String,
    pub encryption_key: String,
}

impl App {
    pub fn new() -> Result<Self, AppError> {
        dotenv().ok();

        let postgres_url = get_env_var("POSTGRES_URL")?;
        let encryption_key = get_env_var("ENCRYPTION_KEY")?;
        let folder_id = get_env_var("FOLDER_ID")?;
        let google_keyfile = get_env_var("KEYFILE")?;

        Ok(App {
            postgres_url,
            folder_id,
            google_keyfile,
            encryption_key,
        })
    }
}

fn get_env_var(name: &str) -> Result<String, AppError> {
    std::env::var(name).map_err(|_| AppError::MissingEnvVariable(name.to_string()))
}