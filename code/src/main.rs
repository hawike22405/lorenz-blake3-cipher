use clap::Parser;
use lorenz_blake3_cipher::cipher::{self, decrypt, encrypt};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about = "Lorenz-BLAKE3 image cipher reference (research prototype)")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Encrypt a raw image file.
    Encrypt {
        #[arg(short, long)]
        key: PathBuf,
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        width: u32,
        #[arg(long)]
        height: u32,
        #[arg(long)]
        channels: u8,
        #[arg(long, default_value_t = 42)]
        seed: u64,
    },
    /// Decrypt a container file.
    Decrypt {
        #[arg(short, long)]
        key: PathBuf,
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Verify a container's authentication tag without decrypting.
    Verify {
        #[arg(short, long)]
        key: PathBuf,
        #[arg(short, long)]
        input: PathBuf,
    },
}

fn load_key(path: &PathBuf) -> [u8; 32] {
    let bytes = fs::read(path).expect("failed to read key file");
    if bytes.len() != 32 {
        panic!("key file must be exactly 32 bytes");
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    k
}

fn main() {
    let args = Args::parse();

    match args.command {
        Commands::Encrypt {
            key,
            input,
            output,
            width,
            height,
            channels,
            seed,
        } => {
            let master_key = load_key(&key);
            let plaintext = fs::read(&input).expect("failed to read input");
            let mut rng = StdRng::seed_from_u64(seed);
            let container = encrypt(
                &master_key,
                &plaintext,
                width,
                height,
                channels,
                &mut rng,
            );
            fs::write(&output, container.serialize()).expect("failed to write output");
            println!(
                "wrote {} bytes ({} header + {} payload + 32 tag)",
                container.serialize().len(),
                cipher::HEADER_SIZE,
                container.payload.len()
            );
        }
        Commands::Decrypt {
            key,
            input,
            output,
        } => {
            let master_key = load_key(&key);
            let buf = fs::read(&input).expect("failed to read input");
            let container = cipher::CiphertextContainer::deserialize(&buf)
                .expect("failed to parse container");
            let plaintext = decrypt(&master_key, &container)
                .expect("decryption failed (authentication tag mismatch or corrupt container)");
            fs::write(&output, &plaintext).expect("failed to write output");
            println!("wrote {} decrypted bytes", plaintext.len());
        }
        Commands::Verify { key, input } => {
            let master_key = load_key(&key);
            let buf = fs::read(&input).expect("failed to read input");
            let container = cipher::CiphertextContainer::deserialize(&buf)
                .expect("failed to parse container");
            let keys = cipher::derive_keys(&master_key, &container.header.nonce);
            let ok = cipher::verify_tag(
                &keys.auth_key,
                &container.header.serialize(),
                &container.payload,
                &container.tag,
            );
            if ok {
                println!("VERIFIED: authentication tag OK");
            } else {
                println!("INVALID: authentication tag mismatch");
                std::process::exit(1);
            }
        }
    }
}
