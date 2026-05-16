pub mod cache;
pub mod directory;
pub mod openbao_client;

// TTL cache decorator over the Directory trait.
pub use cache::{CacheConfig, CachingDirectory};
// Existing re-exports
// Shared helpers / DTOs
// layout.rs API (so admin can import from s32p_directory::DirectoryLayout etc if you want)
pub use directory::{
    Directory, file,
    file::{
        DirectoryFileV1, load_directory_yaml_file, parse_directory_yaml_str,
        render_directory_yaml_string, save_directory_yaml_file,
    },
    layout,
    layout::{DirectoryLayout, IndexDoc, normalize_acl, principal_key},
    openbao, posix_groups, posix_users, types,
    types::{AccessLevel, AclEntry, BucketDoc, BucketView, Principal, UserDoc},
    yaml,
};
// openbao client API
pub use openbao_client::{OpenBaoAuth, OpenBaoClient};
