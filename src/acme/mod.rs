use acme_client::{
    api::Directory,
    Certificate, DirectoryUrl, Error as AcmeError, Order, Account, AccountBuilder,
    Identifier, Authorization, DnsChallenge, ChallengeType
};
use anyhow::{Context, Result};
use cloudflare::endpoints::dns::{DnsContent, DnsRecord, DnsRecordType};
use cloudflare::framework::{
    auth::Credentials,
    Environment,
    HttpApiClient,
    HttpApiClientConfig,
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;
use std::sync::{Arc, Mutex};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub enabled: bool,
    pub email: String,
    pub directory_url: String,
    pub cloudflare_api_token: String,
    pub certs_dir: String,
    pub renew_before_days: u32,
    pub domains: Vec<String>,
}

pub struct AcmeManager {
    config: AcmeConfig,
    account: Arc<Mutex<Option<Account>>>,
    client: Arc<HttpApiClient>,
}

impl AcmeManager {
    pub async fn new(config: AcmeConfig) -> Result<Self> {
        let credentials = Credentials::UserAuthToken {
            token: config.cloudflare_api_token.clone(),
        };
        
        let client = HttpApiClient::new(
            credentials,
            HttpApiClientConfig::default(),
            Environment::Production,
        )?;

        Ok(Self {
            config,
            account: Arc::new(Mutex::new(None)),
            client: Arc::new(client),
        })
    }

    async fn get_or_create_account(&self) -> Result<Account> {
        let mut account_guard = self.account.lock()?;
        
        if let Some(account) = &*account_guard {
            return Ok(account.clone());
        }

        let directory_url = DirectoryUrl::parse(&self.config.directory_url)?;
        let directory = Directory::fetch(&directory_url).await?;
        
        let account = AccountBuilder::new()
            .email(&self.config.email)
            .terms_of_service_agreed(true)
            .build(&directory)
            .await
            .context("Failed to create ACME account")?;

        *account_guard = Some(account.clone());
        Ok(account)
    }

    pub async fn obtain_or_renew_certificate(&self, domain: &str) -> Result<CertificateInfo> {
        let cert_path = self.get_cert_path(domain);
        let key_path = self.get_key_path(domain);

        if Path::new(&cert_path).exists() && Path::new(&key_path).exists() {
            if let Some(info) = self.check_certificate_expiry(&cert_path).await? {
                if info.days_remaining > self.config.renew_before_days {
                    tracing::info!(
                        "Certificate for {} is still valid for {} days, no renewal needed",
                        domain,
                        info.days_remaining
                    );
                    return Ok(info);
                }
                tracing::info!(
                    "Certificate for {} expires in {} days, renewing...",
                    domain,
                    info.days_remaining
                );
            }
        }

        tracing::info!("Obtaining certificate for domain: {}", domain);
        let cert_info = self.request_certificate(domain).await?;
        
        self.save_certificate(&cert_info, &cert_path, &key_path).await?;
        tracing::info!("Certificate saved to {} and {}", cert_path, key_path);
        
        Ok(cert_info)
    }

    async fn request_certificate(&self, domain: &str) -> Result<CertificateInfo> {
        let directory_url = DirectoryUrl::parse(&self.config.directory_url)?;
        let directory = Directory::fetch(&directory_url).await?;
        let account = self.get_or_create_account().await?;

        let order = Order::new(&directory, &account, &[Identifier::Dns(domain.to_string())])
            .await
            .context("Failed to create ACME order")?;

        let authorizations = order.authorizations().await?;
        
        for auth in authorizations {
            self.solve_dns_challenge(&directory, &account, &auth).await?;
        }

        let order = order.finalize(None).await?;
        let certificate = order.download_certificate().await?;

        Ok(CertificateInfo {
            cert_der: certificate.cert_chain,
            key_der: certificate.private_key,
            expires_at: certificate.expiry,
            days_remaining: self.calculate_days_remaining(certificate.expiry),
        })
    }

    async fn solve_dns_challenge(
        &self,
        directory: &Directory,
        account: &Account,
        auth: &Authorization,
    ) -> Result<()> {
        let challenge = auth
            .challenges()
            .iter()
            .find(|c| c.challenge_type() == ChallengeType::Dns01)
            .ok_or_else(|| anyhow::anyhow!("DNS challenge not found"))?;

        let dns_challenge = DnsChallenge::new(challenge);
        let record_name = dns_challenge.dns_name();
        let record_value = dns_challenge.dns_value();

        tracing::info!(
            "Creating DNS TXT record: {} = {}",
            record_name,
            record_value
        );

        self.create_dns_record(&record_name, &record_value).await?;
        
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

        challenge.validate(directory, account).await?;
        
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        self.delete_dns_record(&record_name, &record_value).await?;
        
        Ok(())
    }

    async fn create_dns_record(&self, name: &str, value: &str) -> Result<()> {
        let zone_id = self.get_zone_id(name).await?;
        
        let record = DnsRecord {
            name: name.to_string(),
            content: DnsContent::TXT { content: value.to_string() },
            ttl: 300,
            proxied: Some(false),
            ..Default::default()
        };

        self.client
            .create_dns_record(&zone_id, &record)
            .map_err(|e| anyhow::anyhow!("Failed to create DNS record: {}", e))?;
        
        Ok(())
    }

    async fn delete_dns_record(&self, name: &str, value: &str) -> Result<()> {
        let zone_id = self.get_zone_id(name).await?;
        let records = self
            .client
            .list_dns_records(&zone_id)
            .map_err(|e| anyhow::anyhow!("Failed to list DNS records: {}", e))?;

        for record in records.result {
            if record.name == name && 
               matches!(record.content, DnsContent::TXT { content } if content == value) 
            {
                self.client
                    .delete_dns_record(&zone_id, record.id)
                    .map_err(|e| anyhow::anyhow!("Failed to delete DNS record: {}", e))?;
                tracing::info!("Deleted DNS TXT record: {}", name);
                return Ok(());
            }
        }

        Ok(())
    }

    async fn get_zone_id(&self, name: &str) -> Result<String> {
        let zones = self
            .client
            .list_zones()
            .map_err(|e| anyhow::anyhow!("Failed to list zones: {}", e))?;

        let domain_parts: Vec<&str> = name.split('.').collect();
        for i in 0..domain_parts.len() {
            let candidate = domain_parts[i..].join(".");
            for zone in &zones.result {
                if zone.name == candidate {
                    return Ok(zone.id.clone());
                }
            }
        }

        Err(anyhow::anyhow!("Could not find zone for domain: {}", name))
    }

    async fn save_certificate(
        &self,
        cert_info: &CertificateInfo,
        cert_path: &str,
        key_path: &str,
    ) -> Result<()> {
        let cert_pem = pem::encode(&pem::Pem {
            tag: "CERTIFICATE".to_string(),
            contents: cert_info.cert_der.clone(),
        });

        let key_pem = pem::encode(&pem::Pem {
            tag: "PRIVATE KEY".to_string(),
            contents: cert_info.key_der.clone(),
        });

        fs::write(cert_path, cert_pem)?;
        fs::write(key_path, key_pem)?;

        Ok(())
    }

    async fn check_certificate_expiry(&self, cert_path: &str) -> Result<Option<CertificateInfo>> {
        let file = File::open(cert_path)?;
        let mut reader = BufReader::new(file);
        
        let cert_der: Vec<CertificateDer> = certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {}", e))?;

        if cert_der.is_empty() {
            return Ok(None);
        }

        let cert = x509_parser::parse_x509_certificate(&cert_der[0].as_ref())?;
        let not_after = cert.tbs_certificate.validity.not_after.to_datetime();
        
        let expires_at = DateTime::from_utc(not_after, Utc);
        let days_remaining = self.calculate_days_remaining(expires_at);

        Ok(Some(CertificateInfo {
            cert_der: cert_der[0].to_vec(),
            key_der: Vec::new(),
            expires_at,
            days_remaining,
        }))
    }

    fn calculate_days_remaining(&self, expires_at: DateTime<Utc>) -> i64 {
        let now = Utc::now();
        (expires_at - now).num_days()
    }

    fn get_cert_path(&self, domain: &str) -> String {
        format!("{}/{}.crt", self.config.certs_dir, domain)
    }

    fn get_key_path(&self, domain: &str) -> String {
        format!("{}/{}.key", self.config.certs_dir, domain)
    }

    pub async fn load_certificate(&self, domain: &str) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let cert_path = self.get_cert_path(domain);
        let key_path = self.get_key_path(domain);

        let cert_file = File::open(&cert_path)?;
        let mut cert_reader = BufReader::new(cert_file);
        let certs: Vec<CertificateDer<'static>> = certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to load certificate: {}", e))?;

        let key_file = File::open(&key_path)?;
        let mut key_reader = BufReader::new(key_file);
        let mut keys: Vec<PrivatePkcs8KeyDer<'static>> = pkcs8_private_keys(&mut key_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Failed to load private key: {}", e))?;

        if keys.is_empty() {
            return Err(anyhow::anyhow!("No private key found"));
        }

        Ok((certs, PrivateKeyDer::Pkcs8(keys.remove(0))))
    }

    pub async fn start_renewal_loop(&self) -> Result<()> {
        let interval = tokio::time::Duration::from_hours(24);
        
        loop {
            for domain in &self.config.domains {
                match self.obtain_or_renew_certificate(domain).await {
                    Ok(info) => {
                        tracing::info!(
                            "Certificate for {} expires in {} days",
                            domain,
                            info.days_remaining
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to obtain/renew certificate for {}: {}",
                            domain,
                            e
                        );
                    }
                }
            }
            
            tokio::time::sleep(interval).await;
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertificateInfo {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
    pub expires_at: DateTime<Utc>,
    pub days_remaining: i64,
}