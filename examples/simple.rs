//! A very basic example program that sends a GET request and prints out the
//! response from the server.

use isahc::prelude::*;

fn main() -> Result<(), isahc::Error> {
    // Send a GET request and wait for the response headers.
    // Must be `mut` so we can read the response body.
    let mut response = isahc::get("https://example.org")?;

    // Print some basic info about the response to standard output.
    println!("Status: {}", response.status());
    println!("Headers: {:#?}", response.headers());

    // Read the response body as text into a string and print it.
    print!("{}", response.text()?);

    Ok(())
}
