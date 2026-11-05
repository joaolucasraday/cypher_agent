use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::net::{ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

// =================================================
// CONFIGURAÇÕES DO SISTEMA
// =================================================

const CANARY_DIR: &str = "C:\\CypherCanary";
const CANARY_FILE: &str = "C:\\CypherCanary\\financeiro_urgente.xlsx";

// URL pública do seu CYPHER ADM na Vercel (sem barra no final)
const ADM_BASE_URL: &str = "https://cypher-adm.vercel.app";

// =================================================
// ESTRUTURAS DE COMUNICAÇÃO COM O CYPHER ADM
// =================================================

#[derive(Serialize)]
struct HeartbeatPayload {
    hostname: String,
    ip: String,
}

#[derive(Serialize)]
struct AlertPayload {
    hostname: String,
    details: String,
}

#[derive(Deserialize)]
struct CommandResponse {
    should_isolate: bool,
}

// =================================================
// INICIALIZAÇÃO DO CYPHER AGENT
// =================================================

fn main() {
    println!("=================================================");
    println!("     CYPHER AGENT - SERVIÇO DE CONTENÇÃO ATIVO   ");
    println!("     Conectado a: {}", ADM_BASE_URL);
    println!("=================================================");

    // 1. Prepara a armadilha (Honeyfile)
    setup_honeyfile();

    let is_isolated = Arc::new(AtomicBool::new(false));
    let is_isolated_worker = is_isolated.clone();

    // 2. Inicia o Heartbeat contínuo com a nuvem em thread separada
    thread::spawn(move || {
        adm_heartbeat_loop(is_isolated_worker);
    });

    // 3. Inicia o monitoramento de ameaças
    if let Err(e) = watch_canary(is_isolated) {
        eprintln!("[ERRO] Falha no motor de monitoramento: {:?}", e);
    }
}

// =================================================
// PREPARAÇÃO DO HONEYFILE
// =================================================

fn setup_honeyfile() {
    if !Path::new(CANARY_DIR).exists() {
        fs::create_dir_all(CANARY_DIR).expect("Falha ao criar pasta Canary");
    }

    if !Path::new(CANARY_FILE).exists() {
        let mut file = File::create(CANARY_FILE).expect("Falha ao criar Honeyfile");
        file.write_all(b"ARQUIVO ISCA - CYPHER SECURITY LABS")
            .expect("Falha ao escrever no Honeyfile");
        println!("[+] Honeyfile criado com sucesso em: {}", CANARY_FILE);
    } else {
        println!("[+] Honeyfile já presente e armado.");
    }
}

// =================================================
// MONITORAMENTO DO HONEYFILE
// =================================================

fn watch_canary(is_isolated: Arc<AtomicBool>) -> notify::Result<()> {
    let (tx, rx) = channel();

    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.send(res);
        },
        Config::default().with_poll_interval(Duration::from_millis(100)),
    )?;

    watcher.watch(Path::new(CANARY_DIR), RecursiveMode::NonRecursive)?;
    println!("[*] Monitorando acessos suspeitos. Aguardando ameaça...");

    for res in rx {
        match res {
            Ok(event) => {
                if is_suspicious_event(&event) {
                    println!("\n🚨 [ALERTA CRÍTICO] HONEYFILE VIOLADO!");
                    println!("Tipo de evento: {:?}", event.kind);

                    // 1. Transmite alerta para a Vercel
                    send_alert_to_adm(format!("Violação de Honeyfile ({:?})", event.kind));

                    // 2. Isola a máquina localmente
                    trigger_host_isolation();

                    // 3. Atualiza estado
                    is_isolated.store(true, Ordering::SeqCst);
                }
            }
            Err(e) => eprintln!("[!] Erro de leitura: {:?}", e),
        }
    }

    Ok(())
}

fn is_suspicious_event(event: &Event) -> bool {
    matches!(event.kind, EventKind::Modify(_) | EventKind::Remove(_))
}

// =================================================
// PROTOCOLO DE AUTO-ISOLAMENTO
// =================================================

fn trigger_host_isolation() {
    println!("[!] EXECUTANDO PROTOCOLO DE AUTO-ISOLAMENTO...");

    let vercel_ip = get_vercel_server_ip();

    // Garante que o firewall esteja ligado
    run_cmd("netsh", &["advfirewall", "set", "allprofiles", "state", "on"]);

    // 1. Bloqueia todo o tráfego de saída e entrada
    run_cmd("netsh", &["advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"]);

    // 2. Libera Loopback interno (127.0.0.1)
    run_cmd("netsh", &[
        "advfirewall", "firewall", "add", "rule",
        "name=CYPHER_LOOPBACK", "dir=out", "action=allow",
        "remoteip=127.0.0.1"
    ]);

    // 3. Libera DNS (UDP 53) para resolver o domínio da Vercel
    run_cmd("netsh", &[
        "advfirewall", "firewall", "add", "rule",
        "name=CYPHER_DNS_LINK", "dir=out", "action=allow", "protocol=UDP",
        "remoteport=53"
    ]);

    // 4. Libera HTTPS (TCP 443) para manter o canal com a Vercel restrito ao IP dela
    run_cmd("netsh", &[
        "advfirewall", "firewall", "add", "rule",
        "name=CYPHER_ADM_HTTPS", "dir=out", "action=allow", "protocol=TCP",
        &format!("remoteip={}", vercel_ip),
        "remoteport=443"
    ]);

    println!("-------------------------------------------------");
    println!("🔒 MÁQUINA TOTALMENTE ISOLADA");
    println!("- Tráfego Local: BLOQUEADO");
    println!("- Internet geral (Google, Navegadores, etc): BLOQUEADA");
    println!("- Cordão Umbilical com a Nuvem ({}): ABERTO", vercel_ip);
    println!("-------------------------------------------------");
}

// =================================================
// RESTAURAÇÃO DA CONECTIVIDADE
// =================================================

fn restore_network() {
    println!("\n🔓 [ORDEM DO ADM] RESTAURANDO CONECTIVIDADE NORMAL...");

    run_cmd("netsh", &["advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"]);
    run_cmd("netsh", &["advfirewall", "firewall", "delete", "rule", "name=CYPHER_LOOPBACK"]);
    run_cmd("netsh", &["advfirewall", "firewall", "delete", "rule", "name=CYPHER_DNS_LINK"]);
    run_cmd("netsh", &["advfirewall", "firewall", "delete", "rule", "name=CYPHER_ADM_HTTPS"]);

    println!("✅ Rede restabelecida com sucesso.");
}

// =================================================
// COMUNICAÇÃO COM O CYPHER ADM (VERCEL)
// =================================================

fn send_alert_to_adm(details: String) {
    let hostname = env::var("COMPUTERNAME").unwrap_or_else(|_| "Desconhecido".into());
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();

    let url = format!("{}/api/alert", ADM_BASE_URL);
    let payload = AlertPayload { hostname, details };

    match client.post(&url).json(&payload).send() {
        Ok(_) => println!("[+] Alerta SOS transmitido com sucesso à nuvem."),
        Err(e) => eprintln!("[!] Falha ao transmitir alerta à nuvem: {:?}", e),
    }
}

// =================================================
// HEARTBEAT E CONTROLE REMOTO
// =================================================

fn adm_heartbeat_loop(is_isolated: Arc<AtomicBool>) {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();

    let hostname = env::var("COMPUTERNAME").unwrap_or_else(|_| "Desconhecido".into());
    let url = format!("{}/api/heartbeat", ADM_BASE_URL);

    loop {
        let payload = HeartbeatPayload {
            hostname: hostname.clone(),
            ip: get_local_ip(),
        };

        if let Ok(res) = client.post(&url).json(&payload).send() {
            if let Ok(cmd) = res.json::<CommandResponse>() {
                let currently_isolated = is_isolated.load(Ordering::SeqCst);

                // Se o ADM mandou isolar pela web
                if cmd.should_isolate && !currently_isolated {
                    trigger_host_isolation();
                    is_isolated.store(true, Ordering::SeqCst);
                }
                // Se o ADM mandou liberar pela web
                else if !cmd.should_isolate && currently_isolated {
                    restore_network();
                    is_isolated.store(false, Ordering::SeqCst);
                }
            }
        }

        thread::sleep(Duration::from_secs(2));
    }
}

// Captura o IP local do usuário na placa de rede ativa
fn get_local_ip() -> String {
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

// Descobre o IP real do servidor da Vercel na nuvem para limitar a regra do firewall
fn get_vercel_server_ip() -> String {
    let domain = "cypher-adm.vercel.app:443";
    if let Ok(mut addrs) = domain.to_socket_addrs() {
        if let Some(addr) = addrs.next() {
            return addr.ip().to_string();
        }
    }
    "76.76.21.21".to_string()
}

// Execução dos comandos do sistema
fn run_cmd(program: &str, args: &[&str]) {
    let _ = Command::new(program).args(args).output();
}