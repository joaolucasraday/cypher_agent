
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::{self, File};
use std::io::Write;
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

// Configure aqui o IP do PC onde o CYPHER ADM está rodando.
// Utilize "127.0.0.1" se estiver na mesma máquina.
// Caso esteja em outra máquina, informe o IP correspondente.
const ADM_SERVER_IP: &str = "127.0.0.1";
const ADM_SERVER_PORT: &str = "8443";

// =================================================
// ESTRUTURAS DE COMUNICAÇÃO COM O CYPHER ADM
// =================================================

/// Dados enviados periodicamente ao servidor ADM
/// para informar que o agente continua ativo.
#[derive(Serialize)]
struct HeartbeatPayload {
    hostname: String,
    ip: String,
}

/// Informações enviadas ao ADM quando uma ameaça
/// é identificada pelo monitoramento do Honeyfile.
#[derive(Serialize)]
struct AlertPayload {
    hostname: String,
    details: String,
}

/// Resposta recebida do ADM durante o heartbeat,
/// indicando se o computador deve permanecer isolado.
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
    println!("=================================================");

    // 1. Prepara a armadilha (Honeyfile)
    setup_honeyfile();

    // Controla o estado de isolamento da máquina,
    // compartilhando essa informação entre as threads.
    let is_isolated = Arc::new(AtomicBool::new(false));
    let is_isolated_worker = is_isolated.clone();

    // 2. Inicia a comunicação contínua com o CYPHER ADM
    // em uma thread independente do monitoramento.
    thread::spawn(move || {
        adm_heartbeat_loop(is_isolated_worker);
    });

    // 3. Inicia a escuta da armadilha
    if let Err(e) = watch_canary(is_isolated) {
        eprintln!("[ERRO] Falha no motor de monitoramento: {:?}", e);
    }
}

// =================================================
// PREPARAÇÃO DO HONEYFILE
// =================================================

/// Cria o diretório e o arquivo isca se eles não existirem.

fn setup_honeyfile() {
    if !Path::new(CANARY_DIR).exists() {
        fs::create_dir_all(CANARY_DIR)
            .expect("Falha ao criar pasta Canary");
    }

    if !Path::new(CANARY_FILE).exists() {
        let mut file = File::create(CANARY_FILE)
            .expect("Falha ao criar Honeyfile");

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

/// Escuta alterações no sistema de arquivos via
/// monitoramento de diretório do Windows.
///
/// Ao identificar uma alteração suspeita:
/// 1. Identifica a violação do Honeyfile.
/// 2. Envia um alerta imediato ao CYPHER ADM.
/// 3. Executa o protocolo de isolamento da máquina.
/// 4. Atualiza o estado de isolamento.
fn watch_canary(is_isolated: Arc<AtomicBool>) -> notify::Result<()> {
    let (tx, rx) = channel();

    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.send(res);
        },
        Config::default().with_poll_interval(Duration::from_millis(100)),
    )?;

    watcher.watch(
        Path::new(CANARY_DIR),
        RecursiveMode::NonRecursive,
    )?;

    println!("[*] Monitorando acessos suspeitos. Aguardando ameaça...");

    // Loop que fica escutando os eventos do sistema de arquivos.
    for res in rx {
        match res {
            Ok(event) => {
                if is_suspicious_event(&event) {
                    println!("\n🚨 [ALERTA CRÍTICO] HONEYFILE VIOLADO!");
                    println!("Tipo de evento: {:?}", event.kind);

                    // 1. Avisa o ADM imediatamente
                    send_alert_to_adm(
                        format!("Violação de Honeyfile ({:?})", event.kind)
                    );

                    // 2. Executa a contenção instantânea
                    trigger_host_isolation();

                    // 3. Atualiza o estado de isolamento
                    is_isolated.store(true, Ordering::SeqCst);
                }
            }

            Err(e) => eprintln!("[!] Erro de leitura: {:?}", e),
        }
    }

    Ok(())
}

/// Filtra se o evento foi de escrita, deleção ou renomeação.
/// Eventos de modificação e remoção são considerados suspeitos.
fn is_suspicious_event(event: &Event) -> bool {
    matches!(
        event.kind,
        EventKind::Modify(_) | EventKind::Remove(_)
    )
}

// =================================================
// PROTOCOLO DE AUTO-ISOLAMENTO
// =================================================

/// Aciona o isolamento de rede do computador.
///
/// 1. Garante que o firewall esteja ativo.
/// 2. Bloqueia todo o tráfego de entrada e saída.
/// 3. Libera o Loopback interno (127.0.0.1).
/// 4. Libera exclusivamente o canal de comunicação
///    com o CYPHER ADM, conforme as regras configuradas.
fn trigger_host_isolation() {
    println!("[!] EXECUTANDO PROTOCOLO DE AUTO-ISOLAMENTO...");

    // Garante que o firewall esteja ativo
    // (caso esteja desligado).
    run_cmd("netsh", &[
        "advfirewall", "set", "allprofiles", "state", "on"
    ]);

    // 1. Bloqueia todo o tráfego de saída e entrada por padrão.
    run_cmd("netsh", &[
        "advfirewall", "set", "allprofiles",
        "firewallpolicy", "blockinbound,blockoutbound"
    ]);

    // 2. Libera o Loopback interno (127.0.0.1)
    // para manter a comunicação local do Windows.
    run_cmd("netsh", &[
        "advfirewall", "firewall", "add", "rule",
        "name=CYPHER_LOOPBACK",
        "dir=out",
        "action=allow",
        "remoteip=127.0.0.1"
    ]);

    // 3. Libera o cordão umbilical apenas para falar
    // com o CYPHER ADM.
    run_cmd("netsh", &[
        "advfirewall", "firewall", "add", "rule",
        "name=CYPHER_ADM_LINK",
        "dir=out",
        "action=allow",
        "protocol=TCP",
        &format!("remoteip={}", ADM_SERVER_IP),
        &format!("remoteport={}", ADM_SERVER_PORT)
    ]);

    println!("-------------------------------------------------");
    println!("🔒 MÁQUINA TOTALMENTE ISOLADA");
    println!("- Tráfego Local: BLOQUEADO");
    println!("- Internet: BLOQUEADA");
    println!(
        "- Canal com ADM ({}:{}): ABERTO",
        ADM_SERVER_IP,
        ADM_SERVER_PORT
    );
    println!("-------------------------------------------------");
}

// =================================================
// RESTAURAÇÃO DA CONECTIVIDADE
// =================================================

/// Restaura a conectividade normal da máquina
/// quando o CYPHER ADM envia uma ordem de liberação.
///
/// Remove as regras específicas criadas pelo agente
/// e restaura a política padrão de conectividade.
fn restore_network() {
    println!("\n🔓 [ORDEM DO ADM] RESTAURANDO CONECTIVIDADE NORMAL...");

    run_cmd("netsh", &[
        "advfirewall", "set", "allprofiles",
        "firewallpolicy", "blockinbound,allowoutbound"
    ]);

    run_cmd("netsh", &[
        "advfirewall", "firewall", "delete", "rule",
        "name=CYPHER_LOOPBACK"
    ]);

    run_cmd("netsh", &[
        "advfirewall", "firewall", "delete", "rule",
        "name=CYPHER_ADM_LINK"
    ]);

    println!("✅ Rede restabelecida com sucesso.");
}

// =================================================
// COMUNICAÇÃO COM O CYPHER ADM
// =================================================

/// Envia um alerta imediato ao CYPHER ADM
/// quando uma violação do Honeyfile é identificada.
///
/// Informa o nome do computador e os detalhes
/// do evento detectado.
fn send_alert_to_adm(details: String) {
    let hostname = env::var("COMPUTERNAME")
        .unwrap_or_else(|_| "Desconhecido".into());

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    let url = format!(
        "http://{}:{}/api/alert",
        ADM_SERVER_IP,
        ADM_SERVER_PORT
    );

    let payload = AlertPayload {
        hostname,
        details,
    };

    let _ = client.post(url).json(&payload).send();
}

// =================================================
// HEARTBEAT E CONTROLE REMOTO
// =================================================

/// Mantém comunicação periódica com o CYPHER ADM.
///
/// A cada 2 segundos:
/// 1. Envia um heartbeat informando que o agente está ativo.
/// 2. Aguarda a resposta do servidor.
/// 3. Verifica se o ADM solicitou isolamento ou liberação.
/// 4. Executa a ação correspondente caso o estado atual
///    da máquina seja diferente do estado solicitado.
///
/// Essa rotina funciona em uma thread independente,
/// permitindo que o monitoramento do Honeyfile continue ativo.
fn adm_heartbeat_loop(is_isolated: Arc<AtomicBool>) {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();

    let hostname = env::var("COMPUTERNAME")
        .unwrap_or_else(|_| "Desconhecido".into());

    let url = format!(
        "http://{}:{}/api/heartbeat",
        ADM_SERVER_IP,
        ADM_SERVER_PORT
    );

    loop {
        let payload = HeartbeatPayload {
            hostname: hostname.clone(),
            ip: "Local".to_string(),
        };

        if let Ok(res) = client.post(&url).json(&payload).send() {
            if let Ok(cmd) = res.json::<CommandResponse>() {
                let currently_isolated = is_isolated.load(Ordering::SeqCst);

                // Se o ADM mandou isolar e a máquina ainda não está isolada.
                if cmd.should_isolate && !currently_isolated {
                    trigger_host_isolation();
                    is_isolated.store(true, Ordering::SeqCst);
                }

                // Se o ADM mandou liberar e a máquina está isolada.
                else if !cmd.should_isolate && currently_isolated {
                    restore_network();
                    is_isolated.store(false, Ordering::SeqCst);
                }
            }
        }

        // Aguarda 2 segundos antes da próxima comunicação.
        thread::sleep(Duration::from_secs(2));
    }
}

// =================================================
// EXECUÇÃO DE COMANDOS DO SISTEMA
// =================================================

/// Executa comandos externos do Windows.
///
/// Utilizado principalmente para configurar o Windows Defender
/// Firewall por meio do utilitário netsh.
fn run_cmd(program: &str, args: &[&str]) {
    let _ = Command::new(program)
        .args(args)
        .output();
}

//netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
//netsh advfirewall firewall delete rule name="CYPHER_LOOPBACK"
//netsh advfirewall firewall delete rule name="CYPHER_ADM_LINK"