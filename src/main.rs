
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc::channel;
use std::time::Duration;

// CONFIGURAÇÕES DO SISTEMA
const CANARY_DIR: &str = "C:\\CypherCanary";
const CANARY_FILE: &str = "C:\\CypherCanary\\financeiro_urgente.xlsx";
const ADM_SERVER_IP: &str = "192.168.1.100"; // IP simulado do painel ADM
const ADM_SERVER_PORT: &str = "8443";

fn main() {
    println!("=================================================");
    println!("     CYPHER AGENT - SERVIÇO DE CONTENÇÃO ATIVO   ");
    println!("=================================================");

    // 1. Prepara a armadilha (Honeyfile)
    setup_honeyfile();

    // 2. Inicia a escuta da armadilha
    if let Err(e) = watch_canary() {
        eprintln!("[ERRO] Falha no motor de monitoramento: {:?}", e);
    }
}

/// Cria o diretório e o arquivo isca se eles não existirem
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

/// Escuta alterações no sistema de arquivos via Win32 ReadDirectoryChangesW
fn watch_canary() -> notify::Result<()> {
    let (tx, rx) = channel();

    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.send(res);
        },
        Config::default().with_poll_interval(Duration::from_millis(100)),
    )?;

    watcher.watch(Path::new(CANARY_DIR), RecursiveMode::NonRecursive)?;
    println!("[*] Monitorando acessos suspeitos. Aguardando ameaça...");

    // Loop que fica escutando os eventos do Windows
    for res in rx {
        match res {
            Ok(event) => {
                if is_suspicious_event(&event) {
                    println!("\n🚨 [ALERTA CRÍTICO] HONEYFILE VIOLADO!");
                    println!("Tipo de evento: {:?}", event.kind);

                    // Executa a contenção instantânea
                    trigger_host_isolation();
                    break; // Interrompe para evitar loop de alertas
                }
            }
            Err(e) => eprintln!("[!] Erro de leitura: {:?}", e),
        }
    }

    Ok(())
}

/// Filtra se o evento foi de escrita, deleção ou renomeação
fn is_suspicious_event(event: &Event) -> bool {
    matches!(
        event.kind,
        EventKind::Modify(_) | EventKind::Remove(_)
    )
}

/// Aciona o isolamento de rede do computador
fn trigger_host_isolation() {
    println!("[!] EXECUTANDO PROTOCOLO DE AUTO-ISOLAMENTO...");

    // 1. Bloqueia todo o tráfego de saída e entrada
    run_cmd("netsh", &["advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"]);

    // 2. Libera o Loopback interno (127.0.0.1) para não travar o Windows
    run_cmd("netsh", &[
        "advfirewall", "firewall", "add", "rule",
        "name=CYPHER_LOOPBACK", "dir=out", "action=allow",
        "remoteip=127.0.0.1"
    ]);

    // 3. Libera o cordão umbilical apenas para falar com o CYPHER ADM
    run_cmd("netsh", &[
        "advfirewall", "firewall", "add", "rule",
        "name=CYPHER_ADM_LINK", "dir=out", "action=allow", "protocol=TCP",
        &format!("remoteip={}", ADM_SERVER_IP),
        &format!("remoteport={}", ADM_SERVER_PORT)
    ]);

    println!("-------------------------------------------------");
    println!("MÁQUINA TOTALMENTE ISOLADA");
    println!("- Tráfego Local: BLOQUEADO");
    println!("- Internet: BLOQUEADA");
    println!("- Canal com ADM ({}:{}): ABERTO", ADM_SERVER_IP, ADM_SERVER_PORT);
    println!("-------------------------------------------------");
}

fn run_cmd(program: &str, args: &[&str]) {
    let _ = Command::new(program)
        .args(args)
        .output();
}

//netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound
//netsh advfirewall firewall delete rule name="CYPHER_LOOPBACK"
//netsh advfirewall firewall delete rule name="CYPHER_ADM_LINK"