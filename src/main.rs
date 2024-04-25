use aws_config::{
    environment::{EnvironmentVariableCredentialsProvider, EnvironmentVariableRegionProvider},
    meta::{
        credentials::CredentialsProviderChain,
        region::{ProvideRegion, RegionProviderChain},
    },
    AppName, BehaviorVersion, Region,
};
use aws_credential_types::provider::{error::CredentialsError, ProvideCredentials};
use aws_sdk_iam::config::SharedCredentialsProvider;
use clap::Parser;

#[derive(Debug, Parser, Clone)]
struct Args {
    #[clap(short, long)]
    region: Option<String>,

    #[clap(short, long)]
    access_key: Option<String>,

    #[clap(short, long)]
    secret_key: Option<String>,
}

impl Args {
    fn cred(&self) -> anyhow::Result<(String, String)> {
        let ak = self
            .access_key
            .clone()
            .ok_or(anyhow::anyhow!("access key not found"))?;
        let sk = self
            .secret_key
            .clone()
            .ok_or(anyhow::anyhow!("secret key not found"))?;
        Ok((ak, sk))
    }
}

impl ProvideRegion for Args {
    fn region(&self) -> aws_config::meta::region::future::ProvideRegion<'_> {
        aws_config::meta::region::future::ProvideRegion::ready(self.region.clone().map(Region::new))
    }
}

impl ProvideCredentials for Args {
    fn provide_credentials<'a>(
        &'a self,
    ) -> aws_credential_types::provider::future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        let cred = self
            .cred()
            .map_err(|_e| {
                CredentialsError::not_loaded("no providers in chain provided credentials")
            })
            .map(|(ak, sk)| aws_credential_types::Credentials::new(ak, sk, None, None, "Args"));
        aws_credential_types::provider::future::ProvideCredentials::ready(cred)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let sdk_config = {
        let region_provider = RegionProviderChain::first_try(args.clone())
            .or_else(EnvironmentVariableRegionProvider::default())
            .or_else(Region::new("us-east-1"));
        let cred_provider = CredentialsProviderChain::first_try("Args", args.clone())
            .or_else("env", EnvironmentVariableCredentialsProvider::default());

        let cred_provider =
            SharedCredentialsProvider::new(cred_provider.provide_credentials().await?);

        let config = aws_config::SdkConfig::builder()
            .region(region_provider.region().await)
            .credentials_provider(cred_provider)
            .app_name(AppName::new("MyUnusedAnalyzer")?)
            .behavior_version(BehaviorVersion::latest())
            .build();

        if let Err(e) = config
            .credentials_provider()
            .unwrap()
            .provide_credentials()
            .await
        {
            panic!("failed to load credentials: {:?}", e);
        }
        config
    };
    let iam_config = aws_sdk_iam::config::Builder::from(&sdk_config).build();

    let iam_client = aws_sdk_iam::Client::from_conf(iam_config);

    let resp = iam_client.list_users().send().await;
    println!("{:#?}", resp);

    Ok(())
}
