extern crate chrono;
use chrono::Utc;
#[macro_use]
extern crate clap;
use clap::{App, Arg};
extern crate globset;
use globset::Glob;
extern crate notify;
use notify::{DebouncedEvent, RecommendedWatcher, RecursiveMode, Watcher};
#[macro_use]
extern crate serde_derive;
extern crate shellexpand;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{exit, Command, Output};
use std::sync::mpsc::{channel, Receiver};
use std::thread;
use std::time::{Duration, Instant};
extern crate toml;
extern crate walkdir;
use walkdir::{DirEntry, WalkDir};

fn watch(
    watch_path: String,
    configs: Vec<Config>,
    run_before_name: Option<String>,
    quit_after_run_before: bool,
) -> notify::Result<()> {
    let (event_tx, event_rx) = channel();
    let mut watcher: RecommendedWatcher = Watcher::new(event_tx, Duration::from_millis(250))?;
    if !quit_after_run_before {
        let canonical_watch_path = PathBuf::from(watch_path).canonicalize().unwrap();
        watcher.watch(&canonical_watch_path, RecursiveMode::Recursive)?;
    }

    let timer = Instant::now();
    let (then_tx, then_rx) = channel();

    let mut num_iffts = 0;
    for config in &configs {
        num_iffts += config.iffts.len();
    }
    thread::spawn(move || {
        process_events(num_iffts, timer, then_rx);
    });

    if run_before_name.is_some() {
        let mut ifft_offset = 0;
        for config in &configs {
            for ifft in &config.iffts {
                if ifft.name == run_before_name {
                    if ifft.then_needs_path_sub() {
                        println!(
                            "Run-Before: Ignoring ifft b/c it needs a path sub: {:?}",
                            config.root
                        );
                    } else {
                        println!("Run-Before: Match ifft name in config: {:?}", config.root);
                        then_tx
                            .send(Some((timer.elapsed(), ifft_offset, ifft.clone(), None)))
                            .unwrap();
                    }
                }
            }
            ifft_offset += config.iffts.len();
        }
    }
    if quit_after_run_before {
        then_tx.send(None).unwrap();
    }

    loop {
        match event_rx.recv() {
            Ok(event) => {
                let date = Utc::now();
                println!("[{}] Event: {:?}", date.format("%Y-%m-%d %H:%M:%SZ"), event);
                match event {
                    DebouncedEvent::NoticeWrite(path)
                    | DebouncedEvent::NoticeRemove(path)
                    | DebouncedEvent::Create(path)
                    | DebouncedEvent::Remove(path)
                    | DebouncedEvent::Write(path)
                    | DebouncedEvent::Chmod(path) => {
                        assert!(path.is_absolute());
                        let mut ifft_offset = 0;
                        for config in &configs {
                            let cur_ifft_offset = ifft_offset.clone();
                            ifft_offset += config.iffts.len();
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
                                    if let Some(ref if_cond) = ifft.if_cond {
                                        println!("  Matched if-cond: {:?}", if_cond.glob());
                                    }

                                    then_tx
                                        .send(Some((
                                            timer.elapsed(),
                                            cur_ifft_offset,
                                            ifft.clone(),
                                            Some(path.clone()),
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
                    _ => {
                        println!("  Skip: event type");
                    }
                }
            }
            Err(e) => eprintln!("watch error: {:?}", e),
        }
    }
}

fn process_events(
    num_iffts: usize,
    timer: Instant,
    rx: Receiver<Option<(Duration, usize, Ifft, Option<PathBuf>)>>,
) {
    let mut last_triggered = vec![None; num_iffts];
    loop {
        match rx.recv() {
            Ok(msg) => {
                if msg.is_none() {
                    println!("Exiting...");
                    exit(0);
                }
                let (ts, cur_ifft_offset, ifft, path) = msg.unwrap();
                let date = Utc::now();
                println!(
                    "[{}] Execute: {:?} from {:?}",
                    date.format("%Y-%m-%d %H:%M:%SZ"),
                    ifft.then,
                    ifft.working_dir,
                );
                let last_triggered_index = cur_ifft_offset + ifft.id as usize;
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
                let output_res = ifft.then_exec(&path);
                if let Err(e) = output_res {
                    eprintln!("  >Skipping due to error: {}", e);
                    continue;
                }
                let output = output_res.unwrap();
                if let Some(exit_code) = output.status.code() {
                    println!("  Exit code: {}", exit_code);
                }
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
            }
            Err(e) => eprintln!("process error: {:?}", e),
        }
    }
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
}

#[derive(Debug)]
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
        return FilterResult::Reject { global_not: None };
    }
}

#[derive(Clone, Debug)]
struct Ifft {
    id: u32,
    name: Option<String>,
    working_dir: PathBuf,
    if_cond: Option<Glob>,
    nots: Vec<Glob>,
    then: String,
}

impl Ifft {
    fn filter(&self, relpath: &Path) -> bool {
        assert!(relpath.is_relative());
        if let Some(ref if_cond) = self.if_cond {
            if !if_cond.compile_matcher().is_match(&relpath) {
                return false;
            }
        } else {
            // If no if_cond, never match.
            return false;
        }
        for not in &self.nots {
            if not.compile_matcher().is_match(&relpath) {
                return false;
            }
        }
        return true;
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
            &env::VarError::NotPresent => format!("Environment variable ${} not set.", var_name),
            &env::VarError::NotUnicode(_) => {
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

    let mut ifft_counter = 0;
    let mut iffts = vec![];
    for ifft_raw in &config_raw.ifft {
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
        let mut if_cond = None;
        if let Some(ref if_cond_raw) = ifft_raw.if_cond {
            let try_glob = Glob::new(&if_cond_raw);
            if let Err(e) = try_glob {
                return Err(format!("ifft.if: {}", e));
            }
            if_cond = Some(try_glob.unwrap())
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
            id: ifft_counter,
            name: ifft_raw.name.clone(),
            working_dir,
            if_cond,
            nots,
            then: ifft_raw.then.clone(),
        });
        ifft_counter += 1;
    }

    Ok(Config {
        root,
        nots: root_nots,
        iffts,
    })
}

fn read_and_parse_config(config_path: String) -> Config {
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
    let config = config_raw_to_config(config_raw, config_parent_path.clone());
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
                .required(true)
                .help("The path to an IFFT config file (.toml).")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("RUN-BEFORE")
                .required(false)
                .short("r")
                .long("run")
                .help("Run all iffts with specified name before watching.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("QUIT-AFTER-RUN-BEFORE")
                .required(false)
                .short("q")
                .long("quit")
                .help("Quit after iffts matching run-before have been executed.."),
        )
        .get_matches();
    let mut configs = vec![];
    let watch_path = value_t!(matches, "WATCH-PATH", String).unwrap_or_else(|e| e.exit());
    let run_before_name = value_t!(matches, "RUN-BEFORE", String);
    let quit_after_run_before = matches.is_present("QUIT-AFTER-RUN-BEFORE");
    fn is_hidden(entry: &DirEntry) -> bool {
        entry
            .file_name()
            .to_str()
            .map(|s| s.starts_with("."))
            .unwrap_or(false)
    }

    let walker = WalkDir::new(&watch_path).into_iter();
    for entry in walker.filter_entry(|e| !is_hidden(e)) {
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
        let config = read_and_parse_config(path_to_string(&path));
        configs.push(config);
    }
    if let Err(e) = watch(
        watch_path,
        configs,
        run_before_name.ok(),
        quit_after_run_before,
    ) {
        eprintln!("error: {:?}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        config_raw_to_config, Config, ConfigRaw, FilterResult, Glob, Ifft, IfftRaw, Path, PathBuf,
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
            }],
        };
        let res = config_raw_to_config(config_raw, "/home".to_string());
        assert_eq!(
            res.unwrap_err(),
            "ifft.if: error parsing glob '***': invalid use of **; must be one path component"
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
            }],
        };
        let res = config_raw_to_config(config_raw, "/home".to_string());
        assert_eq!(res.unwrap().root, PathBuf::from("/home"),);
    }

    #[test]
    fn ifft_if() {
        let ifft = Ifft {
            id: 0,
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: Some(Glob::new("a/b/c/**").unwrap()),
            nots: vec![],
            then: String::from("ls"),
        };
        // Test pass case
        assert!(ifft.filter(&PathBuf::from("a/b/c/d")));
        // Test reject case
        assert!(!ifft.filter(&PathBuf::from("a/b")));

        // Test that a lack of if_cond rejects the path
        let ifft = Ifft {
            id: 0,
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: None,
            nots: vec![],
            then: String::from("ls"),
        };
        assert!(!ifft.filter(&PathBuf::from("a/b")));
    }

    #[test]
    fn ifft_not() {
        let ifft = Ifft {
            id: 0,
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: Some(Glob::new("a/b/c/**").unwrap()),
            nots: vec![Glob::new("*.swp").unwrap(), Glob::new("*.pyc").unwrap()],
            then: String::from("ls"),
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
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: None,
            nots: vec![],
            then: String::from("pwd"),
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
            name: None,
            working_dir: PathBuf::from("/home"),
            if_cond: None,
            nots: vec![],
            then: String::from("pwd"),
        };
        let output = ifft
            .then_exec(&Some(Path::new("/dummy").to_path_buf()))
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!("/home\n", stdout);

        // Test non-existent working dir
        let ifft = Ifft {
            id: 2,
            name: None,
            working_dir: PathBuf::from("/does-not-exist"),
            if_cond: None,
            nots: vec![],
            then: String::from("pwd"),
        };
        ifft.then_exec(&Some(Path::new("/dummy").to_path_buf()))
            .is_err();

        // Test file path substitution
        let ifft = Ifft {
            id: 3,
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: None,
            nots: vec![],
            then: String::from("echo {{}}"),
        };
        let output = ifft
            .then_exec(&Some(Path::new("/a/b/c").to_path_buf()))
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!("/a/b/c\n", stdout);

        // Test file path substitution without path
        let ifft = Ifft {
            id: 3,
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: None,
            nots: vec![],
            then: String::from("echo {{}}"),
        };
        let result = std::panic::catch_unwind(|| ifft.then_exec(&None).unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn config_not() {
        let ifft = Ifft {
            id: 0,
            name: None,
            working_dir: PathBuf::from("."),
            if_cond: Some(Glob::new("c/d/**").unwrap()),
            nots: vec![],
            then: String::from("ls"),
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
}
