use anyhow::Result;
use async_trait::async_trait;

use super::hash::Key;
use super::routing::Contact;
use crate::identity::Identity;

#[async_trait]
pub trait DhtNetwork: Send + Sync + 'static {
    async fn find_node(&self, to: &Contact, target: Identity) -> Result<Vec<Contact>>;

    async fn find_value(&self, to: &Contact, key: Key) -> Result<(Option<Vec<u8>>, Vec<Contact>)>;

    async fn store(&self, to: &Contact, key: Key, value: Vec<u8>) -> Result<()>;

    async fn ping(&self, to: &Contact) -> Result<()>;
}
