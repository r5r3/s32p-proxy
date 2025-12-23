use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct UserRecord {
    pub access_key: String,
    pub secret_key: String,
    pub username: String,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Debug)]
pub struct UserDb {
    by_access_key: HashMap<String, UserRecord>,
}

impl UserDb {
    pub fn demo() -> Self {
        let mut by_access_key = HashMap::new();
        by_access_key.insert(
            "TESTACCESSKEY123".to_string(),
            UserRecord {
                access_key: "TESTACCESSKEY123".to_string(),
                secret_key: "TESTSECRETKEY456".to_string(),
                username: "alice".to_string(),
                uid: 1001,
                gid: 1001,
            },
        );
        Self { by_access_key }
    }

    pub fn get(&self, access_key: &str) -> Option<&UserRecord> {
        self.by_access_key.get(access_key)
    }
}

