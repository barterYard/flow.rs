use otopr::{DecodableMessage, Map, Repeated};

#[derive(DecodableMessage, Default, PartialEq, Eq)]
pub struct Account {
    /// The address of this account.
    /// Since there is no need to push or remove bytes
    /// from this owned buffer, we don't use a growable buffer.
    pub address: Box<[u8]>,
    pub balance: u64,
    pub code: Vec<u8>,
    pub keys: Repeated<Vec<AccountKey>>,
    pub contracts: Map<String, Vec<u8>>,
}

#[derive(DecodableMessage, Default, PartialEq, Eq)]
pub struct AccountKey {
    pub index: u32,
    pub public_key: Vec<u8>,
    pub sign_algo: u32,
    pub hash_algo: u32,
    pub weight: u32,
    pub sequence_number: u32,
    pub revoked: bool,
}