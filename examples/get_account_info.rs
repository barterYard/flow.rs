use std::{
    error::Error,
    io::{stdin, BufRead},
};

use cadence_json::AddressOwned;
use flow_sdk::client::TonicHyperFlowClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let stdin = stdin();
    let mut stdin = stdin.lock();
    let mut buf = String::new();

    println!("Enter the account's address:");

    stdin.read_line(&mut buf)?;

    let addr = buf.trim();

    let address: AddressOwned = addr.parse()?;
    let mut net = TonicHyperFlowClient::mainnet()?;

    let account = net.account_at_latest_block(&address.data).await?.account;

    let latest_block_height = net.latest_block_header(true).await?.0.height;

    let account1 = net
        .account_at_block_height(&address.data, latest_block_height)
        .await?
        .account;

    println!("{:#?}", account);

    assert_eq!(account, account1);

    Ok(())
}