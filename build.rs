#![allow(dead_code)]

use std::env;
use std::fs::File;
use std::io::Write;

use schemars::generate::SchemaSettings;

#[path = "src/schema/manifest.rs"]
mod schema;

fn main() {
    println!("cargo:rerun-if-changed=src/schema/manifest.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");

    let full_version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "1.0.0".to_string());
    let major_version = full_version.split('.').next().unwrap_or("1");
    let filename = format!("schema/elaine-v{}.schema.json", major_version);

    let settings = SchemaSettings::default();
    let generator = settings.into_generator();

    let schema = generator.into_root_schema_for::<schema::ElaineManifest>();

    let schema_json = serde_json::to_string_pretty(&schema).unwrap();

    let mut file = File::create(&filename).unwrap_or_else(|e| panic!("Failed to create schema file '{}': {}", filename, e));
    file.write_all(schema_json.as_bytes())
        .unwrap_or_else(|e| panic!("Failed to write schema to '{}': {}", filename, e));

    println!("cargo:warning=Generated JSON Schema: {}", filename);
}
