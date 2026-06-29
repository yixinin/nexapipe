use anyhow::{Context, Result};
use base64::Engine;
use chrono::{DateTime, NaiveDateTime, Utc};
use cloudflare::endpoints::dns::dns::{
    CreateDnsRecord, CreateDnsRecordParams, DnsContent, ListDnsRecords, ListDnsRecordsParams,
};
use cloudflare::endpoints::zones::zone::{ListZones, ListZonesParams};
use cloudflare::framework::{Environment, auth::Credentials, client::async_api::Client};
use instant_acme::{
    Account, AuthorizationHandle, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use rustls_pemfile::{certs, pkcs8_private_keys};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;

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
    client: Arc<Client>,
}

impl AcmeManager {
    pub async fn new(config: AcmeConfig) -> Result<Self> {
        let credentials = Credentials::UserAuthToken {
            token: config.cloudflare_api_token.clone(),
        };

        let client = Client::new(
            credentials,
            cloudflare::framework::client::ClientConfig::default(),
            Environment::Production,
        )?;

        Ok(Self {
            config,
            account: Arc::new(Mutex::new(None)),
            client: Arc::new(client),
        })
    }

    async fn get_or_create_account(&self) -> Result<Account> {
        let mut account_guard = self.account.lock().await;

        if let Some(account) = &*account_guard {
            return Ok(account.clone());
        }

        let builder = Account::builder().context("Failed to create account builder")?;

        let contact = vec![format!("mailto:{}", self.config.email)];
        let contact_refs: Vec<&str> = contact.iter().map(|s| s.as_str()).collect();

        let new_account = NewAccount {
            contact: &contact_refs,
            terms_of_service_agreed: true,
            only_return_existing: false,
        };

        let (account, _credentials) = builder
            .create(&new_account, self.config.directory_url.clone(), None)
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
                if info.days_remaining > self.config.renew_before_days as i64 {
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

        self.save_certificate(&cert_info, &cert_path, &key_path)
            .await?;
        tracing::info!("Certificate saved to {} and {}", cert_path, key_path);

        Ok(cert_info)
    }

    async fn request_certificate(&self, domain: &str) -> Result<CertificateInfo> {
        let account = self.get_or_create_account().await?;

        let identifiers = vec![Identifier::Dns(domain.to_string())];

        let new_order = NewOrder::new(&identifiers);

        let mut order = account
            .new_order(&new_order)
            .await
            .context("Failed to create ACME order")?;

        let mut authorizations = order.authorizations();

        while let Some(auth_result) = authorizations.next().await {
            let mut auth = auth_result.context("Failed to get authorization")?;
            self.solve_dns_challenge(&mut auth).await?;
        }

        let retry_policy = RetryPolicy::default();

        let status = order.poll_ready(&retry_policy).await?;
        if status != OrderStatus::Ready {
            return Err(anyhow::anyhow!("Order not ready, status: {:?}", status));
        }

        let cert_pem = order.finalize().await.context("Failed to finalize order")?;

        let cert_der = pem_to_der(&cert_pem)?;

        let expires_at = self.parse_certificate_expiry(&cert_der).await?;
        let days_remaining = self.calculate_days_remaining(expires_at);

        Ok(CertificateInfo {
            cert_der,
            key_der: cert_pem.as_bytes().to_vec(),
            expires_at,
            days_remaining,
        })
    }

    async fn solve_dns_challenge<'a>(&self, auth: &'a mut AuthorizationHandle<'a>) -> Result<()> {
        let identifier = auth.identifier();
        let dns_name = identifier.to_string();

        let mut challenge = auth
            .challenge(ChallengeType::Dns01)
            .ok_or_else(|| anyhow::anyhow!("DNS challenge not found"))?;

        let record_name = format!("_acme-challenge.{}", dns_name);
        let key_auth = challenge.key_authorization().dns_value();

        tracing::info!("Creating DNS TXT record: {} = {}", record_name, key_auth);

        self.create_dns_record(&record_name, &key_auth).await?;

        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

        challenge.set_ready().await?;

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

        self.delete_dns_record(&record_name, &key_auth).await?;

        Ok(())
    }

    async fn create_dns_record(&self, name: &str, value: &str) -> Result<()> {
        let zone_id = self.get_zone_id(name).await?;

        let params = CreateDnsRecordParams {
            name,
            content: DnsContent::TXT {
                content: value.to_string(),
            },
            ttl: Some(300),
            proxied: Some(false),
            priority: None,
        };

        let endpoint = CreateDnsRecord {
            zone_identifier: &zone_id,
            params,
        };
        self.client
            .request(&endpoint)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create DNS record: {}", e))?;

        Ok(())
    }

    async fn delete_dns_record(&self, name: &str, value: &str) -> Result<()> {
        let zone_id = self.get_zone_id(name).await?;
        let params = ListDnsRecordsParams {
            name: Some(name.to_string()),
            ..Default::default()
        };
        let endpoint = ListDnsRecords {
            zone_identifier: &zone_id,
            params,
        };
        let records = self
            .client
            .request(&endpoint)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to list DNS records: {}", e))?;

        for record in records.result {
            if record.name == name
                && matches!(record.content, DnsContent::TXT { content } if content == value)
            {
                use cloudflare::endpoints::dns::dns::DeleteDnsRecord;
                let endpoint = DeleteDnsRecord {
                    zone_identifier: &zone_id,
                    identifier: &record.id,
                };
                self.client
                    .request(&endpoint)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to delete DNS record: {}", e))?;
                tracing::info!("Deleted DNS TXT record: {}", name);
                return Ok(());
            }
        }

        Ok(())
    }

    async fn get_zone_id(&self, name: &str) -> Result<String> {
        let endpoint = ListZones {
            params: ListZonesParams::default(),
        };
        let zones = self
            .client
            .request(&endpoint)
            .await
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
        let cert_pem = der_to_pem(&cert_info.cert_der, "CERTIFICATE")?;
        fs::write(cert_path, cert_pem)?;
        fs::write(key_path, &cert_info.key_der)?;

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
        let not_after = cert.1.validity.not_after.to_datetime();
        let naive_not_after = NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(
                not_after.year(),
                not_after.month() as u32,
                not_after.day() as u32,
            )
            .unwrap(),
            chrono::NaiveTime::from_hms_opt(
                not_after.hour() as u32,
                not_after.minute() as u32,
                not_after.second() as u32,
            )
            .unwrap(),
        );

        let expires_at = DateTime::from_utc(naive_not_after, Utc);
        let days_remaining = self.calculate_days_remaining(expires_at);

        Ok(Some(CertificateInfo {
            cert_der: cert_der[0].to_vec(),
            key_der: Vec::new(),
            expires_at,
            days_remaining,
        }))
    }

    async fn parse_certificate_expiry(&self, cert_der: &[u8]) -> Result<DateTime<Utc>> {
        let cert = x509_parser::parse_x509_certificate(cert_der)?;
        let not_after = cert.1.validity.not_after.to_datetime();
        let naive_not_after = NaiveDateTime::new(
            chrono::NaiveDate::from_ymd_opt(
                not_after.year(),
                not_after.month() as u32,
                not_after.day() as u32,
            )
            .unwrap(),
            chrono::NaiveTime::from_hms_opt(
                not_after.hour() as u32,
                not_after.minute() as u32,
                not_after.second() as u32,
            )
            .unwrap(),
        );
        Ok(DateTime::from_utc(naive_not_after, Utc))
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

    pub async fn load_certificate(
        &self,
        domain: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
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
                        tracing::error!("Failed to obtain/renew certificate for {}: {}", domain, e);
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

fn pem_to_der(pem_data: &str) -> Result<Vec<u8>> {
    let mut reader = BufReader::new(pem_data.as_bytes());
    let certs: Vec<CertificateDer> = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM: {}", e))?;

    if certs.is_empty() {
        return Err(anyhow::anyhow!("No certificate found in PEM data"));
    }

    Ok(certs[0].to_vec())
}

fn der_to_pem(der_data: &[u8], tag: &str) -> Result<String> {
    use base64::engine::general_purpose::STANDARD;
    let encoded = STANDARD.encode(der_data);
    let lines: Vec<String> = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect();

    Ok(format!(
        "-----BEGIN {}-----\n{}\n-----END {}-----",
        tag,
        lines.join("\n"),
        tag
    ))
}
