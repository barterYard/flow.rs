use std::error::Error;

use ::cadence_json::{CompositeOwned, ValueOwned};
use flow_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut client = TonicHyperFlowClient::mainnet().await?;
    client.ping().await?;

    let latest_block_height = client.latest_block_header(Seal::Sealed).await?.height;
    let start_height = latest_block_height - 20;

    println!(
        "Searching for accounts created within the last 20 blocks ({}-{})...",
        start_height, latest_block_height
    );

    for events in client
        .events_for_height_range(
            "A.4eb8a10cb9f87357.NFTStorefront.ListingAvailable",
            start_height,
            latest_block_height,
        )
        .await?
        .results
        .iter()
    {
        if events.events.is_empty() {
            continue;
        }
        println!(
            "\nBlock #{} ({}):",
            events.block_height,
            hex::encode(&events.block_id)
        );
        for event in events.events.iter() {
            // let j = "";
            // let r: ValueOwned = serde_json::from_str("{\"type\":\"Event\",\"value\":{\"fields\":[{\"name\":\"storefrontAddress\",\"value\":{\"type\":\"Address\",\"value\":\"0x559aa7e789e3f695\"}},{\"name\":\"listingResourceID\",\"value\":{\"type\":\"UInt64\",\"value\":\"566485303\"}},{\"name\":\"ftVaultType\",\"value\":{\"type\":\"Type\",\"value\":{\"staticType\":{\"fields\":[{\"id\":\"uuid\",\"type\":{\"kind\":\"UInt64\"}},{\"id\":\"balance\",\"type\":{\"kind\":\"UFix64\"}}],\"initializers\":[],\"kind\":\"Resource\",\"type\":\"\",\"typeID\":\"A.ead892083b3e2c6c.DapperUtilityCoin.Vault\"}}}},{\"name\":\"nftID\",\"value\":{\"type\":\"UInt64\",\"value\":\"283949\"}},{\"name\":\"price\",\"value\":{\"type\":\"UFix64\",\"value\":\"10.00000000\"}}],\"id\":\"A.4eb8a10cb9f87357.NFTStorefront.ListingAvailable\"}}").unwrap();
            // println!("{:?}", r);
            let val = event.parse_payload()?;

            println!("  - {:#?}", val);
        }
    }

    Ok(())
}
