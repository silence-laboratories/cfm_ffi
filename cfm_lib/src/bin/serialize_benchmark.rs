use serde::{Serialize, Deserialize};
use bincode;
use serde_cbor;

#[derive(Serialize, Deserialize, Debug)]
struct Example {
    id: u32,
    name: String,
    optional_field: Option<String>,
}

fn main() {
    let data = Example {
        id: 123,
        name: "TestUser".to_string(),
        optional_field: None,
    };

    let bincode_serialized = bincode::serialize(&data).unwrap();
    let cbor_serialized = serde_cbor::to_vec(&data).unwrap();

    println!("Bincode Size: {} bytes", bincode_serialized.len());
    println!("CBOR Size: {} bytes", cbor_serialized.len());
}