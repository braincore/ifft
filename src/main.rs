use chrono::Utc;
use clap::{value_t, App, Arg};
use globset::Glob;
use notify::immediate_watcher;
use notify::{RecursiveMode, Watcher};
use notify_rust::Notification;
use serde_derive::Deserialize;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{exit, Command, Output};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

fn watch(
    watch_path: PathBuf,
    configs: Vec<Config>,
    on_start_name: Option<String>,
    quit_after_on_start: bool,
    show_desktop_notifications: bool,
    verbose: bool,
) -> notify::Result<()> {
    let (event_tx, event_rx) = channel();
    // We don't use the debounce feature because the old one in notify 4.x had
    // a tendency to hang. Haven't tried the one in 5.x.
    let mut watcher = immediate_watcher(move |res| match res {
        Ok(event) => {
            if let Err(e) = event_tx.send(event) {
                println!("send error: {:?}", e);
            }
        }
        Err(e) => println!("watch error: {:?}", e),
    })
    .unwrap();
    if !quit_after_on_start {
        // The recursive mode built into notify has a tendency to go bonkers
        // and consume GBs of RAM and hang the process. It also doesn't support
        // filtering out certain paths. So instead, use our own walker. The
        // downside, is that there is no logic (yet) for watching new folders
        // that are added.
        let walker = ignore::WalkBuilder::new(&watch_path)
            .standard_filters(true)
            .build();
        for entry in walker {
            if let Err(e) = entry {
                println!("error: {}", e);
                continue;
            }
            let entry = entry.unwrap();
            let path = entry.into_path();
            if !path.is_dir() {
                continue;
            } else {
                if verbose {
                    println!("Watching folder: {:?}", &path);
                }
                watcher.watch(&path, RecursiveMode::NonRecursive)?;
            }
        }
    }

    let timer = Instant::now();
    let (then_tx, then_rx) = channel();

    let mut num_iffts = 0;
    for config in &configs {
        num_iffts += config.iffts.len();
    }

    let then_tx_clone = then_tx.clone();
    let configs_clone = configs.clone();
    thread::spawn(move || {
        process_events(
            num_iffts,
            timer,
            then_rx,
            then_tx_clone,
            configs_clone,
            show_desktop_notifications,
        );
    });

    if on_start_name.is_some() {
        let mut all_iffts = vec![];
        for config in &configs {
            for ifft in &config.iffts {
                if ifft.name == on_start_name {
                    if ifft.then_needs_path_sub() {
                        println!(
                            "On-Start: Ignoring ifft b/c it needs a path sub: {:?}",
                            ifft.config_parent_path
                        );
                    } else {
                        all_iffts.push(ifft);
                    }
                }
            }
        }
        let linearized_iffts = linearize_iffts(all_iffts.clone());
        if let Ok(linearized_iffts) = linearized_iffts {
            for ifft in &linearized_iffts {
                if ifft.name == on_start_name {
                    println!(
                        "On-Start: Match ifft name in config: {:?}",
                        ifft.config_parent_path
                    );
                    then_tx
                        .send(Some((timer.elapsed(), ifft.clone(), None)))
                        .unwrap();
                }
            }
        } else {
            eprintln!("`on_start_listen` could not be satisfied (cycle or bad ref)",)
        }
    }
    if quit_after_on_start {
        then_tx.send(None).expect("Failed to send quit signal.");
    }

    loop {
        match event_rx.recv() {
            Ok(event) => {
                let date = Utc::now();
                println!("[{}] Event: {:?}", date.format("%Y-%m-%d %H:%M:%SZ"), event);
                for path in event.paths {
                    assert!(path.is_absolute());
                    let mut paths = vec![path.clone()];
                    let canonical_path = match path.canonicalize() {
                        Ok(p) => p,
                        Err(e) => {
                            match e.kind() {
                                std::io::ErrorKind::NotFound => {
                                    // If the path does not exist, canonicalization will fail.
                                    // Try to rebuild path based on canonicalization of parent
                                    // though even that path may no longer exist.
                                    if let Some(parent_path) = path.parent() {
                                        if let Ok(mut parent_path_canonical) =
                                            parent_path.canonicalize()
                                        {
                                            parent_path_canonical.push(path.file_name().unwrap());
                                            parent_path_canonical
                                        } else {
                                            path.clone()
                                        }
                                    } else {
                                        path.clone()
                                    }
                                }
                                _ => path.clone(),
                            }
                        }
                    };

                    if canonical_path != path {
                        paths.push(canonical_path);
                    }
                    for path in &paths {
                        for config in &configs {
                            let relpath = match path.strip_prefix(&config.root) {
                                Ok(p) => p,
                                Err(_) => {
                                    continue;
                                }
                            };
                            assert!(relpath.is_relative());
                            match config.filter(relpath) {
                                FilterResult::Pass { ifft } => {
                                    println!("  Match from config in: {:?}", config.root);
                                    if let Some(ref name) = ifft.name {
                                        println!("  Matched ifft: {}", name);
                                    }
                                    if let IfCond::Glob(ref if_cond_glob) = ifft.if_cond {
                                        println!("  Matched if-cond: {:?}", if_cond_glob.glob());
                                    }

                                    then_tx
                                        .send(Some((
                                            timer.elapsed(),
                                            ifft.clone(),
                                            Some(path.to_path_buf()),
                                        )))
                                        .unwrap();
                                }
                                FilterResult::Reject { global_not } => {
                                    if let Some(global_not) = global_not {
                                        println!("  Skip: global not: {:?}", global_not.glob());
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("watch error: {:?}", e),
        }
    }
}

/// Linearize iffts.
///
/// Iffts may specify an "on start" dependency on another ifft. This
/// relationship can be modeled as a DAG. The output is a linearization of the
/// DAG.
///
/// If there's a cycle or if a bad ref is made, returns Err.
fn linearize_iffts(mut all_iffts: Vec<&Ifft>) -> Result<Vec<Ifft>, ()> {
    let mut linearized_iffts: Vec<Ifft> = vec![];
    let mut prev_len = all_iffts.len();
    loop {
        if all_iffts.is_empty() {
            break;
        }
        for i in 0..all_iffts.len() {
            let ifft = all_iffts[i];
            if let IfCond::OnStartListen(after) = &ifft.if_cond {
                let mut found = false;
                for linearized_ifft in &linearized_iffts {
                    if linearized_ifft.emit.is_some()
                        && *after
                            == (
                                linearized_ifft.config_parent_path.clone(),
                                linearized_ifft.emit.clone().unwrap(),
                            )
                    {
                        linearized_iffts.push(ifft.clone());
                        found = true;
                        break;
                    }
                }
                if found {
                    all_iffts.remove(i);
                    break;
                }
            } else {
                linearized_iffts.push(ifft.clone());
                all_iffts.remove(i);
                break;
            }
        }
        if prev_len == all_iffts.len() {
            return Err(());
        } else {
            prev_len = all_iffts.len();
        }
    }
    Ok(linearized_iffts)
}

fn process_events(
    num_iffts: usize,
    timer: Instant,
    rx: Receiver<Option<(Duration, Ifft, Option<PathBuf>)>>,
    tx: Sender<Option<(Duration, Ifft, Option<PathBuf>)>>,
    configs: Vec<Config>,
    show_desktop_notifications: bool,
) {
    let mut last_triggered = vec![None; num_iffts];
    loop {
        match rx.recv() {
            Ok(msg) => {
                if msg.is_none() {
                    println!("Exiting...");
                    exit(0);
                }
                let (ts, ifft, path) = msg.unwrap();
                let date = Utc::now();
                println!(
                    "[{}] Execute: {:?} from {:?}",
                    date.format("%Y-%m-%d %H:%M:%SZ"),
                    ifft.then,
                    ifft.working_dir,
                );
                let last_triggered_index = ifft.id as usize;
                if let Some(last_triggered) = last_triggered[last_triggered_index] {
                    if last_triggered > ts {
                        println!(
                            "  Skip: Already executed ifft after event: {:?} > {:?}",
                            last_triggered, ts
                        );
                        continue;
                    }
                }
                if !ifft.then_needs_path_sub() {
                    // Sleep a small fraction of time in anticipation that more events
                    // with the same trigger are coming in. Effectively another
                    // debounce layer. Beware: This sets an upper bound on execution
                    // throughput of 50 execs/sec.
                    thread::sleep(Duration::from_millis(20));
                    // Marking trigger time before we run the command is necessarily
                    // conservative.
                    last_triggered[last_triggered_index] = Some(timer.elapsed());
                }
                let start_time = timer.elapsed();
                let output_res = ifft.then_exec(&path);
                if let Err(e) = output_res {
                    eprintln!("  >Skipping due to error: {}", e);
                    continue;
                }
                let exec_time = timer.elapsed() - start_time;
                let output = output_res.unwrap();
                let mut success = false;
                let exit_msg = if let Some(exit_code) = output.status.code() {
                    println!("  Exit code: {}", exit_code);
                    if exit_code == 0 {
                        success = true;
                        String::from("completed")
                    } else {
                        format!("errored (code={})", exit_code)
                    }
                } else {
                    String::from("unknown")
                };
                if let Ok(stdout) = String::from_utf8(output.stdout) {
                    println!("  Stdout:");
                    for line in stdout.lines() {
                        println!("    {}", line)
                    }
                }
                if let Ok(stderr) = String::from_utf8(output.stderr) {
                    println!("  Stderr:");
                    for line in stderr.lines() {
                        println!("    {}", line)
                    }
                }
                if show_desktop_notifications {
                    let res = Notification::new()
                        .summary(
                            format!(
                                "ifft: {} {}",
                                exit_msg,
                                path_to_string(&ifft.config_parent_path)
                            )
                            .as_str(),
                        )
                        .body(
                            format!("{}s: {}", approx_duration_as_string(exec_time), ifft.then)
                                .as_str(),
                        )
                        .timeout(2000)
                        .show();
                    if let Err(e) = res {
                        eprintln!("Error showing desktop notification: {:?}", e);
                    }
                }
                if success {
                    if let Some(emit_id) = ifft.emit_id() {
                        for config in &configs {
                            for maybe_triggered_ifft in &config.iffts {
                                if let IfCond::Listen(target) = &maybe_triggered_ifft.if_cond {
                                    if target == &emit_id {
                                        // FIXME: An ifft with a listen_cond cannot use {{}} in the `then` clause.
                                        // Catch and report violations of this.
                                        tx.send(Some((
                                            timer.elapsed(),
                                            maybe_triggered_ifft.clone(),
                                            None,
                                        )))
                                        .expect("Failed to enqueue ifft task triggered by emit.");
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("process error: {:?}", e),
        }
    }
}

fn approx_duration_as_string(duration: Duration) -> String {
    return format!("{}", duration.as_millis() as f64 / 1000f64);
}

#[derive(Debug, Deserialize)]
struct ConfigRaw {
    root: Option<String>,
    not: Option<Vec<String>>,
    ifft: Vec<IfftRaw>,
}

#[derive(Debug, Deserialize)]
struct IfftRaw {
    name: Option<String>,
    // Always an absolute path.
    working_dir: Option<String>,
    #[serde(rename = "if")]
    if_cond: Option<String>,
    not: Option<Vec<String>>,
    then: String,
    after: Option<String>,
    emit: Option<String>,
}

#[derive(Clone, Debug)]
struct Config {
    root: PathBuf,
    nots: Vec<Glob>,
    iffts: Vec<Ifft>,
}

impl Config {
    fn filter(&self, relpath: &Path) -> FilterResult {
        assert!(relpath.is_relative());
        for not in &self.nots {
            if not.compile_matcher().is_match(&relpath) {
                return FilterResult::Reject {
                    global_not: Some(not),
                };
            }
        }
        for ifft in &self.iffts {
            if ifft.filter(relpath) {
                return FilterResult::Pass { ifft: &ifft };
            }
        }
        FilterResult::Reject { global_not: None }
    }
}

#[derive(Clone, Debug)]
struct Ifft {
    // At first an ID specific to the config this belongs to, and then later
    // made into a global, unique ID across all configs.
    id: u32,
    config_parent_path: PathBuf,
    name: Option<String>,
    working_dir: PathBuf,
    if_cond: IfCond,
    nots: Vec<Glob>,
    then: String,
    emit: Option<String>,
}

impl Ifft {
    fn filter(&self, relpath: &Path) -> bool {
        assert!(relpath.is_relative());
        if let IfCond::Glob(ref if_cond_glob) = self.if_cond {
            if !if_cond_glob.compile_matcher().is_match(&relpath) {
                return false;
            }
        } else {
            return false;
        }
        for not in &self.nots {
            if not.compile_matcher().is_match(&relpath) {
                return false;
            }
        }
        true
    }

    fn then_needs_path_sub(&self) -> bool {
        // TODO: Cache this.
        self.then.contains("{{}}")
    }

    fn then_exec(&self, path: &Option<PathBuf>) -> io::Result<Output> {
        let mut cmd = Command::new("sh");
        let then = if let Some(path) = path {
            self.then
                .replace("{{}}", path.to_str().expect("Non utf-8 path"))
        } else {
            assert!(!self.then_needs_path_sub());
            self.then.clone()
        };
        cmd.arg("-c").arg(&then);
        cmd.current_dir(&self.working_dir);
        cmd.output()
    }

    fn emit_id(&self) -> Option<ListenTarget> {
        if let Some(ref emit) = self.emit {
            Some((self.config_parent_path.clone(), emit.clone()))
        } else {
            None
        }
    }
}

enum FilterResult<'a> {
    Pass { ifft: &'a Ifft },
    Reject { global_not: Option<&'a Glob> },
}

// Helper for converting ConfigRaw, which is serde's deserialize target.
// Because it results in a "loose" struct with optionals and primitive types,
// we convert it to a Config which is stricter and makes use of more fitting
// types.
fn config_raw_to_config(
    config_raw: ConfigRaw,
    config_parent_path: String,
) -> Result<Config, String> {
    let root_raw = config_raw.root.unwrap_or(config_parent_path);
    let root_shell_expanded = shellexpand::full(&root_raw);
    if let Err(shellexpand::LookupError {
        ref var_name,
        ref cause,
    }) = root_shell_expanded
    {
        return Err(match cause {
            env::VarError::NotPresent => format!("Environment variable ${} not set.", var_name),
            env::VarError::NotUnicode(_) => {
                format!("Environment variable ${} is not valid unicode.", var_name)
            }
        });
    }
    let test_root = PathBuf::from(&*root_shell_expanded.unwrap());
    if !test_root.exists() {
        return Err(format!(
            "Root path is invalid: {}",
            test_root.to_str().unwrap()
        ));
    }
    let root = test_root.canonicalize().unwrap();

    let mut root_nots = vec![];
    if let Some(ref root_not) = config_raw.not {
        for entry in root_not {
            let try_glob = Glob::new(entry);
            if let Err(e) = try_glob {
                return Err(format!("root.not: {}", e));
            }
            root_nots.push(try_glob.unwrap());
        }
    }

    let mut iffts = vec![];
    for (ifft_counter, ifft_raw) in config_raw.ifft.iter().enumerate() {
        let mut nots = vec![];
        if let Some(ref not) = ifft_raw.not {
            for entry in not {
                let try_glob = Glob::new(entry);
                if let Err(e) = try_glob {
                    return Err(format!("ifft.not: {}", e));
                }
                nots.push(try_glob.unwrap());
            }
        }
        let if_cond;
        if let Some(ref if_cond_raw) = ifft_raw.if_cond {
            if_cond = match parse_if_cond(&root, if_cond_raw.clone()) {
                Ok(res) => res,
                Err(e) => {
                    return Err(e);
                }
            }
        } else {
            if_cond = IfCond::None;
        }
        let working_dir = if let Some(ref working_dir_raw) = ifft_raw.working_dir {
            let test_path = PathBuf::from(working_dir_raw);
            if test_path.is_relative() {
                root.join(test_path)
            } else {
                test_path
            }
        } else {
            root.clone()
        };
        iffts.push(Ifft {
            id: ifft_counter as u32,
            config_parent_path: root.clone(),
            name: ifft_raw.name.clone(),
            working_dir,
            if_cond,
            nots,
            then: ifft_raw.then.clone(),
            emit: ifft_raw.emit.clone(),
        });
    }

    Ok(Config {
        root,
        nots: root_nots,
        iffts,
    })
}

fn parse_listen_string(root: &PathBuf, listen: String) -> Result<ListenTarget, ()> {
    let listen_str = listen
        .trim_start_matches("listen:")
        .trim_start_matches("on_start_listen:");
    let mut listen_iter = listen_str.rsplitn(2, ':');
    let listen_trigger = listen_iter.next();
    if listen_trigger.is_none() {
        return Err(());
    }
    let listen_path_str = listen_iter.next();
    if listen_path_str.is_none() {
        return Err(());
    }
    let listen_path = root
        .join(PathBuf::from(listen_path_str.unwrap()))
        .canonicalize()
        .expect("Could not canonicalize path.");
    Ok((listen_path, String::from(listen_trigger.unwrap())))
}

type ListenTarget = (PathBuf, String);

#[derive(Clone, Debug)]
enum IfCond {
    Glob(Glob),
    Listen(ListenTarget),
    OnStartListen(ListenTarget),
    None,
}

fn parse_if_cond(root: &PathBuf, if_cond_raw: String) -> Result<IfCond, String> {
    if if_cond_raw.starts_with("listen:") {
        if let Ok(listen_target) = parse_listen_string(&root, if_cond_raw) {
            Ok(IfCond::Listen(listen_target))
        } else {
            Err(String::from(
                "ifft.if: Bad listen format: \"listen:PATH:TRIGGER\"",
            ))
        }
    } else if if_cond_raw.starts_with("on_start_listen") {
        if let Ok(listen_target) = parse_listen_string(&root, if_cond_raw) {
            Ok(IfCond::OnStartListen(listen_target))
        } else {
            Err(String::from(
                "ifft.if: Bad on_start_listen format: \"on_start_listen:PATH:TRIGGER\"",
            ))
        }
    } else {
        let try_glob = Glob::new(&if_cond_raw);
        if let Err(e) = try_glob {
            return Err(format!("ifft.if: {}", e));
        }
        Ok(IfCond::Glob(try_glob.unwrap()))
    }
}

fn read_and_parse_config(config_path: PathBuf) -> Config {
    let contents = match fs::read_to_string(&config_path) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("error: Cannot read config: {}", e);
            exit(1);
        }
    };
    let config_raw = match toml::from_str(&contents) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("error: Cannot parse config: {}", e);
            exit(1);
        }
    };
    // Safe unwrap since we've successfully opened the config path already.
    // Assume we can safely round trip path: string -> Path -> string.
    let config_parent_path = PathBuf::from(&config_path)
        .parent()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let config = config_raw_to_config(config_raw, config_parent_path);
    match config {
        Ok(config) => config,
        Err(e) => {
            eprintln!("error: {}", e);
            exit(1);
        }
    }
}

fn path_to_string(path: &Path) -> String {
    path.to_str().unwrap().to_string()
}

fn main() {
    let matches = App::new("IFFT")
        .about("IF Filesystem-event Then")
        .arg(
            Arg::with_name("WATCH-PATH")
                .default_value(".")
                .required(true)
                .help("The path to a directory tree containing IFFT config files (.toml).")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("RUN-BEFORE")
                .required(false)
                .short("r")
                .long("run")
                .help("DEPRECATED BY -s: Run all iffts with specified name before watching.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ON-START")
                .required(false)
                .short("s")
                .long("on-start")
                .help("On start, run all iffts with specified name before watching.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("QUIT-AFTER-RUN-BEFORE")
                .required(false)
                .short("q")
                .long("quit")
                .help("Quit after iffts matching run-before have been executed."),
        )
        .arg(
            Arg::with_name("NOTIFICATIONS")
                .required(false)
                .short("n")
                .long("notifications")
                .help("Show desktop notifications."),
        )
        .arg(
            Arg::with_name("NO-IGNORE")
                .required(false)
                .long("no-ignore")
                .help("Do not respect (git)ignore files."),
        )
        .arg(
            Arg::with_name("VERBOSE")
                .required(false)
                .short("v")
                .long("--verbose"),
        )
        .get_matches();
    let mut configs = vec![];
    let watch_path = value_t!(matches, "WATCH-PATH", String).unwrap_or_else(|e| e.exit());
    let on_start_name = value_t!(matches, "ON-START", String);
    let run_before_name = value_t!(matches, "RUN-BEFORE", String);
    let quit_after_on_start = matches.is_present("QUIT-AFTER-RUN-BEFORE");
    let show_desktop_notifications = matches.is_present("NOTIFICATIONS");
    let no_ignore = matches.is_present("NO-IGNORE");
    let verbose = matches.is_present("VERBOSE");

    let canonical_watch_path = PathBuf::from(watch_path)
        .canonicalize()
        .expect("Bad watch patch.");

    {
        let mut num_iffts = 0;
        let walker = ignore::WalkBuilder::new(&canonical_watch_path)
            .standard_filters(!no_ignore)
            .build();
        for entry in walker {
            if let Err(e) = entry {
                println!("error: {}", e);
                continue;
            }
            let entry = entry.unwrap();
            let path = entry.into_path();
            if !(path.is_file() && path.file_name().unwrap() == "ifft.toml") {
                continue;
            }
            println!("Found config: {:?}", path);
            let mut config = read_and_parse_config(path);
            // Convert the config-specific IDs to unique, sequential global IDs.
            for ifft in &mut config.iffts {
                ifft.id += num_iffts;
            }
            num_iffts += config.iffts.len() as u32;
            configs.push(config);
        }
    }
    if let Err(e) = watch(
        canonical_watch_path,
        configs,
        on_start_name.ok().or_else(|| run_before_name.ok()),
        quit_after_on_start,
        show_desktop_notifications,
        verbose,
    ) {
        eprintln!("error: {:?}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        config_raw_to_config, linearize_iffts, Config, ConfigRaw, FilterResult, Glob, IfCond, Ifft,
        IfftRaw, Path, PathBuf,
    };
    use std::env;

    #[test]
    fn config_converter() {
        // Test non-existent root
        let config_raw = ConfigRaw {
            root: Some(String::from("/does-not-exist")),
            not: None,
            ifft: vec![],
        };
        let res = config_raw_to_config(config_raw, "/home".to_string());
        assert_eq!(res.unwrap_err(), "Root path is invalid: /does-not-exist");

        // Test relative root (still does not exist)
        let config_raw = ConfigRaw {
            root: Some(String::from("does-not-exist")),
            not: None,
            ifft: vec![],
        };
        let res = config_raw_to_config(config_raw, "/home".to_string());
        assert_eq!(res.unwrap_err(), "Root path is invalid: does-not-exist");

        // Test missing env var
        let config_raw = ConfigRaw {
            root: Some(String::from("/$DOESNOTEXIST/does-not-exist")),
            not: None,
            ifft: vec![],
        };
        let res = config_raw_to_config(config_raw, "/home".to_string());
        assert_eq!(
            res.unwrap_err(),
            "Environment variable $DOESNOTEXIST not set."
        );

        // Test bad root.not glob
        let config_raw = ConfigRaw {
            root: Some(String::from("~")),
            not: Some(vec![String::from("***")]),
            ifft: vec![],
        };
        let res = config_raw_to_config(config_raw, "/home".to_string());
        assert_eq!(
            res.unwrap_err(),
            "root.not: error parsing glob '***': invalid use of **; must be one path component"
        );

        // Test bad ifft.if glob
        let config_raw = ConfigRaw {
            root: Some(String::from("~")),
            not: None,
            ifft: vec![IfftRaw {
                name: None,
                working_dir: None,
                if_cond: Some(String::from("***")),
                not: None,
                then: String::from("ls"),
                after: None,
                emit: None,
            }],
        };
        let res = config_raw_to_config(config_raw, "/home".to_string());
        assert_eq!(
            res.unwrap_err(),
            "ifft.if: error parsing glob '***': invalid use of **; must be one path component"
        );

        // Test bad ifft.if listen
        let config_raw = ConfigRaw {
            root: Some(String::from("~")),
            not: None,
            ifft: vec![IfftRaw {
                name: None,
                working_dir: None,
                if_cond: Some(String::from("listen:../another-proj")),
                not: None,
                then: String::from("ls"),
                after: None,
                emit: None,
            }],
        };
        let res = config_raw_to_config(config_raw, "/home".to_string());
        assert_eq!(
            res.unwrap_err(),
            "ifft.if: Bad listen format: \"listen:PATH:TRIGGER\""
        );

        // Test bad ifft.if on start listen
        let config_raw = ConfigRaw {
            root: Some(String::from("~")),
            not: None,
            ifft: vec![IfftRaw {
                name: None,
                working_dir: None,
                if_cond: Some(String::from("on_start_listen:../another-proj")),
                not: None,
                then: String::from("ls"),
                after: None,
                emit: None,
            }],
        };
        let res = config_raw_to_config(config_raw, "/home".to_string());
        assert_eq!(
            res.unwrap_err(),
            "ifft.if: Bad on_start_listen format: \"on_start_listen:PATH:TRIGGER\""
        );

        // Test bad ifft.not glob
        let config_raw = ConfigRaw {
            root: Some(String::from("~")),
            not: None,
            ifft: vec![IfftRaw {
                name: None,
                working_dir: None,
                if_cond: None,
                not: Some(vec![String::from("***")]),
                then: String::from("ls"),
                after: None,
                emit: None,
            }],
        };
        let res = config_raw_to_config(config_raw, "/home".to_string());
        assert_eq!(
            res.unwrap_err(),
            "ifft.not: error parsing glob '***': invalid use of **; must be one path component"
        );

        // Test root uses config_path if omitted.
        let config_raw = ConfigRaw {
            root: None,
            not: None,
            ifft: vec![IfftRaw {
                name: None,
                working_dir: None,
                if_cond: None,
                not: None,
                then: String::from("ls"),
                after: None,
                emit: None,
            }],
        };
        let res = config_raw_to_config(config_raw, "/home".to_string());
        assert_eq!(res.unwrap().root, PathBuf::from("/home"),);
    }

    #[test]
    fn ifft_if() {
        let ifft = Ifft {
            id: 0,
            config_parent_path: PathBuf::from(""),
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: IfCond::Glob(Glob::new("a/b/c/**").unwrap()),
            nots: vec![],
            then: String::from("ls"),
            emit: None,
        };
        // Test pass case
        assert!(ifft.filter(&PathBuf::from("a/b/c/d")));
        // Test reject case
        assert!(!ifft.filter(&PathBuf::from("a/b")));

        // Test that a lack of if_cond rejects the path
        let ifft = Ifft {
            id: 0,
            config_parent_path: PathBuf::from(""),
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: IfCond::None,
            nots: vec![],
            then: String::from("ls"),
            emit: None,
        };
        assert!(!ifft.filter(&PathBuf::from("a/b")));
    }

    #[test]
    fn ifft_not() {
        let ifft = Ifft {
            id: 0,
            config_parent_path: PathBuf::from(""),
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: IfCond::Glob(Glob::new("a/b/c/**").unwrap()),
            nots: vec![Glob::new("*.swp").unwrap(), Glob::new("*.pyc").unwrap()],
            then: String::from("ls"),
            emit: None,
        };
        // Test pass case
        assert!(ifft.filter(&PathBuf::from("a/b/c/d")));
        // Test reject case
        assert!(!ifft.filter(&PathBuf::from("a/b/c/d.swp")));
        // Test reject case
        assert!(!ifft.filter(&PathBuf::from("a/b/c/d.pyc")));
    }

    #[test]
    fn ifft_then() {
        // Test default working directory
        let ifft = Ifft {
            id: 0,
            config_parent_path: PathBuf::from(""),
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: IfCond::None,
            nots: vec![],
            then: String::from("pwd"),
            emit: None,
        };
        let output = ifft
            .then_exec(&Some(Path::new("/dummy").to_path_buf()))
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            env::current_dir().unwrap().to_str().unwrap(),
            &stdout[..stdout.len() - 1]
        );

        // Test specified working_dir
        let ifft = Ifft {
            id: 1,
            config_parent_path: PathBuf::from(""),
            name: None,
            working_dir: PathBuf::from("/home"),
            if_cond: IfCond::None,
            nots: vec![],
            then: String::from("pwd"),
            emit: None,
        };
        let output = ifft
            .then_exec(&Some(Path::new("/dummy").to_path_buf()))
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!("/home\n", stdout);

        // Test non-existent working dir
        let ifft = Ifft {
            id: 2,
            config_parent_path: PathBuf::from(""),
            name: None,
            working_dir: PathBuf::from("/does-not-exist"),
            if_cond: IfCond::None,
            nots: vec![],
            then: String::from("pwd"),
            emit: None,
        };
        assert!(ifft
            .then_exec(&Some(Path::new("/dummy").to_path_buf()))
            .is_err());

        // Test file path substitution
        let ifft = Ifft {
            id: 3,
            config_parent_path: PathBuf::from(""),
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: IfCond::None,
            nots: vec![],
            then: String::from("echo {{}}"),
            emit: None,
        };
        let output = ifft
            .then_exec(&Some(Path::new("/a/b/c").to_path_buf()))
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!("/a/b/c\n", stdout);

        // Test file path substitution without path
        let ifft = Ifft {
            id: 3,
            config_parent_path: PathBuf::from(""),
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: IfCond::None,
            nots: vec![],
            then: String::from("echo {{}}"),
            emit: None,
        };
        let result = std::panic::catch_unwind(|| ifft.then_exec(&None).unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn config_not() {
        let ifft = Ifft {
            id: 0,
            config_parent_path: PathBuf::from(""),
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: IfCond::Glob(Glob::new("c/d/**").unwrap()),
            nots: vec![],
            then: String::from("ls"),
            emit: None,
        };
        let config = Config {
            root: PathBuf::from("/a/b"),
            nots: vec![Glob::new("*.swp").unwrap()],
            iffts: vec![ifft],
        };

        // Test pass
        let filter_result = config.filter(&Path::new("c/d/e"));
        if let FilterResult::Reject { .. } = filter_result {
            assert!(false);
        }

        // Test reject due to global not
        let filter_result = config.filter(&Path::new("c/d/e.swp"));
        match filter_result {
            FilterResult::Pass { .. } => assert!(false),
            FilterResult::Reject { global_not } => assert_eq!(global_not.unwrap(), &config.nots[0]),
        }
    }

    #[test]
    fn test_linearize_iffts() {
        let ifft1 = Ifft {
            id: 0,
            config_parent_path: PathBuf::from("/a"),
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: IfCond::Glob(Glob::new("c/d/**").unwrap()),
            nots: vec![],
            then: String::from("ls"),
            emit: None,
        };
        let ifft2 = Ifft {
            id: 0,
            config_parent_path: PathBuf::from("/b"),
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: IfCond::OnStartListen((PathBuf::from("/c"), String::from("built"))),
            nots: vec![],
            then: String::from("ls"),
            emit: Some(String::from("built")),
        };
        let ifft3 = Ifft {
            id: 0,
            config_parent_path: PathBuf::from("/c"),
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: IfCond::OnStartListen((PathBuf::from("/b"), String::from("built"))),
            nots: vec![],
            then: String::from("ls"),
            emit: Some(String::from("built")),
        };
        let ifft4 = Ifft {
            id: 0,
            config_parent_path: PathBuf::from("/c"),
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: IfCond::Glob(Glob::new("c/d/**").unwrap()),
            nots: vec![],
            then: String::from("ls"),
            emit: Some(String::from("built")),
        };

        // Try dependency cycles
        let res = linearize_iffts(vec![&ifft1, &ifft2, &ifft3]);
        assert!(res.is_err(), "Expected cycle error");

        // Try incomplete dependencies
        let res = linearize_iffts(vec![&ifft1, &ifft2]);
        assert!(res.is_err(), "Expected cycle error");

        // Test working case
        let res = linearize_iffts(vec![&ifft1, &ifft2, &ifft4]);
        assert!(res.is_ok(), "Expected to work");
    }
}
