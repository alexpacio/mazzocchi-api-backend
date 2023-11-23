#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expires_in: String,
    pub jwt_maxage: i32,
    pub sqlserver_hostname: String,
    pub sqlserver_username: String,
    pub sqlserver_password: String,
    pub cors_origin_value: String
}

impl Config {
    pub fn init() -> Config {
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let jwt_expires_in = std::env::var("JWT_EXPIRED_IN").expect("JWT_EXPIRED_IN must be set");
        let jwt_maxage = std::env::var("JWT_MAXAGE").expect("JWT_MAXAGE must be set");
        let sqlserver_hostname = std::env::var("SQLSERVER_HOSTNAME").expect("SQLSERVER_HOSTNAME must be set");
        let sqlserver_username = std::env::var("SQLSERVER_USERNAME").expect("SQLSERVER_USERNAME must be set");
        let sqlserver_password = std::env::var("SQLSERVER_PASSWORD").expect("SQLSERVER_PASSWORD must be set");
        let cors_origin_value = std::env::var("CORS_ORIGIN_VALUE").expect("CORS_ORIGIN_VALUE must be set");
        Config {
            database_url,
            jwt_secret,
            jwt_expires_in,
            jwt_maxage: jwt_maxage.parse::<i32>().unwrap(),
            sqlserver_hostname,
            sqlserver_username,
            sqlserver_password,
            cors_origin_value
        }
    }
}
