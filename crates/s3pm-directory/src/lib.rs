pub mod directory;
pub mod openbao_client;

// Existing re-exports
pub use directory::{Directory, file, layout, openbao, posix_groups, types, yaml};
pub use directory::types::{UserDoc, BucketDoc, BucketView, AclEntry, Principal, AccessLevel};

// layout.rs API (so admin can import from s3pm_directory::DirectoryLayout etc if you want)
pub use directory::layout::{DirectoryLayout, IndexDoc, normalize_acl, principal_key};

// Shared helpers / DTOs
pub use directory::file::{
    load_directory_yaml_file, parse_directory_yaml_str, render_directory_yaml_string,
    save_directory_yaml_file, DirectoryFileV1,
};

// openbao client API
pub use openbao_client::{OpenBaoAuth, OpenBaoClient};

