use colored::Colorize;

use crate::{
    cli::args::CertCommand,
    domain::model::DotLockResult,
    storage::{
        self,
        identity::{
            initialize_local_identity, initialize_local_identity_with_options, load_local_identity,
            private_key_path, public_key_path,
        },
    },
};

pub fn run(command: CertCommand) -> DotLockResult<()> {
    match command {
        CertCommand::Init { force, plain } => {
            let identity = if plain {
                initialize_local_identity_with_options(force, true)?
            } else {
                initialize_local_identity(force)?
            };
            if plain {
                println!(
                    "{} local identity ready without passphrase ({})",
                    "ok:".green().bold(),
                    identity.fingerprint.bold()
                );
            } else {
                println!(
                    "{} local identity ready ({})",
                    "ok:".green().bold(),
                    identity.fingerprint.bold()
                );
            }
            println!(
                "     {} {}",
                "private".dimmed(),
                private_key_path()?.display()
            );
            println!(
                "     {} {}",
                "public".dimmed(),
                public_key_path()?.display()
            );
            Ok(())
        }
        CertCommand::Show => {
            let identity = load_local_identity()?;
            println!(
                "{} {}",
                "fingerprint:".cyan().bold(),
                identity.fingerprint.bold()
            );
            println!(
                "{} {}",
                "private:".cyan().bold(),
                private_key_path()?.display()
            );
            println!(
                "{} {}",
                "public:".cyan().bold(),
                public_key_path()?.display()
            );
            Ok(())
        }
        CertCommand::ExportPub { path } => {
            let identity = load_local_identity()?;
            if let Some(path) = path {
                storage::secure_fs::write_string_atomic(
                    &path,
                    &identity.public_key_pem,
                    0o700,
                    0o644,
                )?;
                println!(
                    "{} public key exported to {}",
                    "ok:".green().bold(),
                    path.display().to_string().bold()
                );
            } else {
                print!("{}", identity.public_key_pem);
            }
            Ok(())
        }
    }
}
