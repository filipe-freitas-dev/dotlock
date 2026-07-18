use crate::{
    cli::args::ProviderCommand,
    domain::model::DotLockResult,
    providers::{describe_provider, list_providers},
};

pub fn run(command: ProviderCommand) -> DotLockResult<()> {
    match command {
        ProviderCommand::List => {
            for provider in list_providers(None)? {
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
