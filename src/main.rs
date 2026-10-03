use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use openab_sb::audit::Audit;
use openab_sb::auth::{generate_secret, Verifier};
use openab_sb::config::Config;
use openab_sb::hub::close_code;
use openab_sb::App;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "openab-sb", version, about = "OpenAB Switchboard")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the switchboard.
    Serve {
        #[arg(short, long, default_value = "openab-sb.toml")]
        config: PathBuf,
    },
    /// Validate a config file and exit.
    Check {
        #[arg(short, long, default_value = "openab-sb.toml")]
        config: PathBuf,
    },
    /// Print a fresh secret and its verifier. The secret goes to the other party;
    /// only the verifier goes into openab-sb.toml.
    GenSecret,
    /// Read a secret on stdin and print its verifier.
    Hash,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::GenSecret => {
            let secret = generate_secret()?;
            println!("secret:   {secret}");
            println!("verifier: {}", Verifier::of_secret(&secret).render());
            Ok(())
        }
        Command::Hash => {
            let mut text = String::new();
            std::io::stdin().read_to_string(&mut text)?;
            println!("{}", Verifier::of_secret(text.trim()).render());
            Ok(())
        }
        Command::Check { config } => {
            let parsed = Config::load(&config)?;
            println!(
                "ok: listen {}, {} client(s), {} pty attach(es)",
                parsed.listen,
                parsed.auth.clients.len(),
                parsed.pty_attach.len()
            );
            Ok(())
        }
        Command::Serve { config } => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "openab_sb=info".into()),
                )
                .with_writer(std::io::stderr)
                .init();
            tokio::runtime::Runtime::new()?.block_on(serve(config))
        }
    }
}

async fn serve(path: PathBuf) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = Config::load(&path)?;
    let audit = Audit::open(config.audit_path.as_deref(), config.audit_args)
        .context("opening the audit log")?;
    let app = App::new(&config, audit);
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;
    tracing::info!(listen = %config.listen, clients = config.auth.clients.len(),
                   pty_attach = config.pty_attach.len(), "openab-sb listening");
    let attachers = app.spawn_pty_attachers(config.pty_attach.clone());

    #[cfg(unix)]
    {
        let app = app.clone();
        let path = path.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let Ok(mut hup) = signal(SignalKind::hangup()) else {
                return;
            };
            while hup.recv().await.is_some() {
                match Config::load(&path) {
                    Ok(fresh) => {
                        app.reload_auth(fresh.auth);
                        tracing::info!(
                            "credentials reloaded (listen, limits and pty_attach need a restart)"
                        );
                    }
                    Err(error) => {
                        tracing::error!(%error, "reload failed; keeping the old credentials")
                    }
                }
            }
        });
    }

    let hub = app.hub();
    axum::serve(
        listener,
        app.router()
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        tracing::info!("shutting down");
        hub.close_all(close_code::GOING_AWAY);
    })
    .await?;
    for attacher in attachers {
        attacher.abort();
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
