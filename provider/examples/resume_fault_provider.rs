use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{Context, Result};
use cocore_provider::{
    advisor::{AdvisorClient, InvocationManager, STREAM_RESUME_VERSION},
    crypto::{EncryptionKey, ProviderKeypair},
    engines::{
        stub::StubEngine, DeltaChannel, Engine, EngineRegistry, GenerateRequest, GenerateResponse,
    },
    oauth::Session,
    pds::{PdsClient, ProBonoPolicy},
    protocol::Register,
    receipt::StrongRef,
    schedule::ModelSchedules,
    secure_enclave::{load_or_create_identity, SigningIdentity},
};
use tokio::sync::RwLock;

struct CountingStub {
    invocations: Arc<AtomicUsize>,
}

impl Engine for CountingStub {
    fn name(&self) -> &'static str {
        "stub"
    }

    fn ready(&self) -> bool {
        true
    }

    fn generate_once(&self, request: &GenerateRequest) -> Result<GenerateResponse> {
        StubEngine.generate_once(request)
    }

    fn generate_stream(
        &self,
        request: &GenerateRequest,
        on_delta: &mut dyn FnMut(DeltaChannel, &str) -> Result<()>,
    ) -> Result<GenerateResponse> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        // Long enough that the expiry scenario's reconnect block (2.5s in
        // provider-resume-e2e.ts) plus reconnect latency comfortably ends
        // BEFORE generation completes — the resume rejection must abort the
        // job pre-receipt, with a wide margin on a loaded CI runner.
        std::thread::sleep(Duration::from_millis(3_600));
        let response = self.generate_once(request)?;
        for chunk in response.text.as_bytes().chunks(24) {
            let text = std::str::from_utf8(chunk)?;
            on_delta(DeltaChannel::Content, text)?;
            std::thread::sleep(Duration::from_millis(40));
        }
        Ok(response)
    }
}

fn write_status(path: &Path, invocations: usize, active: bool) -> Result<()> {
    let temporary = path.with_extension("tmp");
    std::fs::write(
        &temporary,
        serde_json::json!({ "invocations": invocations, "active": active }).to_string(),
    )?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let advisor_url = args.next().context("advisor WebSocket URL")?;
    let pds_base = args.next().context("mock PDS base URL")?;
    let status_path = PathBuf::from(args.next().context("status file path")?);

    let signer: Arc<dyn SigningIdentity> = Arc::from(load_or_create_identity()?);
    let encryption: Arc<dyn EncryptionKey> = Arc::new(ProviderKeypair::generate());
    let invocations = Arc::new(AtomicUsize::new(0));
    let mut engines = EngineRegistry::new();
    engines.register(
        "stub",
        Arc::new(CountingStub {
            invocations: invocations.clone(),
        }),
    );

    let pds = PdsClient::new(Session {
        did: "did:plc:resume-fault-provider".into(),
        handle: "resume-fault-provider.test".into(),
        api_key: "local-fault-test".into(),
        api_base: pds_base,
    });
    let attestation = Arc::new(RwLock::new(Some(StrongRef {
        uri: "at://did:plc:resume-fault-provider/dev.cocore.compute.attestation/test".into(),
        cid: "bafytestattestation".into(),
    })));
    let manager = InvocationManager::new();
    let status_manager = manager.clone();
    let status_invocations = invocations.clone();
    tokio::spawn(async move {
        loop {
            let _ = write_status(
                &status_path,
                status_invocations.load(Ordering::SeqCst),
                status_manager.has_active(),
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let register = Register {
        provider_did: "did:plc:resume-fault-provider".into(),
        auth_jwt: None,
        machine_id: Some("resume-fault-machine".into()),
        machine_label: "resume-fault-machine".into(),
        chip: "CI".into(),
        ram_gb: 8,
        supported_models: vec!["stub".into()],
        encryption_pub_key: encryption.public_key_b64(),
        attestation_pub_key: signer.public_key_b64(),
        attestation_uri: "at://did:plc:resume-fault-provider/dev.cocore.compute.attestation/test"
            .into(),
        engine_fault: None,
        cd_hash: None,
        tier: None,
        region: None,
        apns_device_token: None,
        supports_tool_calls: Some(false),
        tool_call_models: None,
        binary_version: Some(env!("CARGO_PKG_VERSION").into()),
        secure_enclave_available: Some(false),
        enc_scheme: Some("x25519".into()),
        stream_resume_version: Some(STREAM_RESUME_VERSION),
    };
    let schedules = ModelSchedules::default();
    let configured_models = vec!["stub".to_string()];
    let pro_bono = ProBonoPolicy::default();
    let client = AdvisorClient::new(advisor_url);

    loop {
        if let Err(error) = client
            .run(
                register.clone(),
                &signer,
                &encryption,
                &pds,
                attestation.clone(),
                &engines,
                None,
                &configured_models,
                None,
                &schedules,
                &configured_models,
                None,
                &pro_bono,
                false,
                None,
                &manager,
            )
            .await
        {
            eprintln!("provider reconnect: {error}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
