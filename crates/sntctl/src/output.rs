//! Formatting and output helpers for CLI.

use serde::Serialize;

pub fn print_json<T: Serialize>(val: &T) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(val)?;
    println!("{}", json);
    Ok(())
}

pub fn print_header(title: &str) {
    println!("================================================================================");
    println!(" {}", title);
    println!("================================================================================");
}

pub fn print_row(label: &str, value: &str) {
    println!("  {:<24} {}", label, value);
}
