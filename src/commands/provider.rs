use crate::{
    cli::{args::ProviderCommand, global::json_output},
    domain::model::DotLockResult,
    providers::{describe_provider, list_providers},
};

pub fn run(command: ProviderCommand) -> DotLockResult<()> {
    match command {
        ProviderCommand::List => {
            let providers = list_providers(None)?;
            if json_output() {
                // FG1 schema: `["<name>", ...]`.
                println!(
                    "{}",
                    serde_json::to_string(&providers)
                        .map_err(|err| crate::domain::error::DotLockError::Io(err.to_string()))?
                );
                return Ok(());
            }
            for provider in providers {
                println!("{provider}");
            }
            Ok(())
        }
        ProviderCommand::Info { name } => {
            print!("{}", describe_provider(&name, None)?);
            Ok(())
        }
    }
}
