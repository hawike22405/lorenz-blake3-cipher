use clap::Parser;
use lorenz_blake3_cipher::cipher::{self, decrypt, encrypt};
use rand::rngs::OsRng;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Lorenz-BLAKE3 image cipher reference (research prototype)"
)]
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

fn load_key(path: &PathBuf) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(33).read_to_end(&mut bytes)?;
    if bytes.len() != 32 {
        return Err("key file must be exactly 32 bytes".into());
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    Ok(k)
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Commands::Encrypt {
            key,
            input,
            output,
            width,
            height,
            channels,
        } => {
            let master_key = load_key(&key)?;
            let plaintext = read_input(&input)?;
            let mut rng = OsRng;
            let container = encrypt(&master_key, &plaintext, width, height, channels, &mut rng)?;
            write_new(&output, &container.serialize())?;
            println!(
                "wrote {} bytes ({} header + {} payload + 32 tag)",
                container.serialize().len(),
                cipher::HEADER_SIZE,
                container.payload.len()
            );
        }
        Commands::Decrypt { key, input, output } => {
            let master_key = load_key(&key)?;
            let buf = read_input(&input)?;
            let container = cipher::CiphertextContainer::deserialize(&buf)
                .ok_or("failed to parse container")?;
            let plaintext = decrypt(&master_key, &container)
                .ok_or("decryption failed (authentication tag mismatch or corrupt container)")?;
            write_new(&output, &plaintext)?;
            println!("wrote {} decrypted bytes", plaintext.len());
        }
        Commands::Verify { key, input } => {
            let master_key = load_key(&key)?;
            let buf = read_input(&input)?;
            let container = cipher::CiphertextContainer::deserialize(&buf)
                .ok_or("failed to parse container")?;
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
    Ok(())
}

fn read_input(path: &PathBuf) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use std::io::Read;
    let mut buf = Vec::new();
    fs::File::open(path)?
        .take((cipher::MAX_PAYLOAD + 114) as u64)
        .read_to_end(&mut buf)?;
    if buf.len() > cipher::MAX_PAYLOAD + 113 {
        return Err("input exceeds 64 MiB policy".into());
    }
    Ok(buf)
}
fn write_new(path: &PathBuf, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)?;
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
