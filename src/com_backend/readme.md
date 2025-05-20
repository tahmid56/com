# Auth Canister

An ICP canister for user signup and signin, written in Rust.

## Setup

1. Install `dfx` (DFinity SDK): `sh -ci "$(curl -fsSL https://internetcomputer.org/install.sh)"`
2. Install Rust: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
3. Start local ICP replica: `dfx start --background`
4. Install dependencies: `cargo build`
5. Deploy canister: `dfx deploy`

## Usage

- **Signup**: Call `signup(username, password)` to register a user.
- **Signin**: Call `signin(username, password)` to authenticate.

## Testing

Run tests with: `cargo test`