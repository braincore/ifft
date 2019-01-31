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
use std::sync::mpsc::channel;
use std::time::Duration;
extern crate toml;

fn watch(config: Config) -> notify::Result<()> {
    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = Watcher::new(tx, Duration::from_millis(250))?;
    // TODO: Compute the optimal path prefix for watching by finding the common prefix of all
    // if-cond paths. In other words, root is a convenient parent-path-invariance config but not
    // necessarily the optimal path to watch.
    watcher.watch(&config.root, RecursiveMode::Recursive)?;

    loop {
        match rx.recv() {
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
                        let relpath = path.strip_prefix(&config.root).unwrap();
                        assert!(relpath.is_relative());
                        match config.filter(relpath) {
                            FilterResult::Pass { ifft } => {
                                if let Some(ref name) = ifft.name {
                                    println!("  Matched ifft: {}", name);
                                }
                                if let Some(ref if_cond) = ifft.if_cond {
                                    println!("  Matched if-cond: {:?}", if_cond.glob());
                                }

                                println!(
                                    "  Executing: {:?} from {:?}",
                                    ifft.then,
                                    ifft.working_dir.as_ref().unwrap_or(&PathBuf::from("."))
                                );

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
                            FilterResult::Reject { global_not } => {
                                if let Some(global_not) = global_not {
                                    println!("  Skip: global not: {:?}", global_not.glob());
                                }
                                continue;
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

#[derive(Debug, Deserialize)]
struct ConfigRaw {
    root: String,
    not: Option<Vec<String>>,
    ifft: Vec<IffttRaw>,
}

#[derive(Debug, Deserialize)]
struct IffttRaw {
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
    iffts: Vec<Ifftt>,
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

#[derive(Debug)]
struct Ifftt {
    name: Option<String>,
    working_dir: Option<PathBuf>,
    if_cond: Option<Glob>,
    nots: Vec<Glob>,
    then: String,
}

impl Ifftt {
    fn filter(&self, relpath: &Path) -> bool {
        assert!(relpath.is_relative());
        if let Some(ref if_cond) = self.if_cond {
            if !if_cond.compile_matcher().is_match(&relpath) {
                return false;
            }
        }
        for not in &self.nots {
            if not.compile_matcher().is_match(&relpath) {
                return false;
            }
        }
        return true;
    }

    fn then_exec(&self, path: &Path) -> io::Result<Output> {
        let mut cmd = Command::new("sh");
        let then = self
            .then
            .replace("{{}}", path.to_str().expect("Non utf-8 path"));
        cmd.arg("-c").arg(&then);
        if let Some(ref working_dir) = self.working_dir {
            cmd.current_dir(working_dir);
        }
        cmd.output()
    }
}

enum FilterResult<'a> {
    Pass { ifft: &'a Ifftt },
    Reject { global_not: Option<&'a Glob> },
}

// Helper for converting ConfigRaw, which is serde's deserialize target.
// Because it results in a "loose" struct with optionals and primitive types,
// we convert it to a Config which is stricter and makes use of more fitting
// types.
fn config_raw_to_config(config_raw: ConfigRaw) -> Result<Config, String> {
    let root_shell_expanded = shellexpand::full(&config_raw.root);
    if let Err(shellexpand::LookupError {
        ref var_name,
        ref cause,
    }) = root_shell_expanded
    {
        return Err(match cause {
            &env::VarError::NotPresent => format!("Environment variable ${} not set.", var_name),
            &env::VarError::NotUnicode(_) => {
                format!("Environment variable ${} is not validd unicode.", var_name)
            }
        });
    }
    let root = PathBuf::from(&*root_shell_expanded.unwrap());
    if !root.exists() {
        return Err(format!("Root path is invalid: {}", root.to_str().unwrap()));
    }
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
        let mut working_dir = None;
        if let Some(ref working_dir_raw) = ifft_raw.working_dir {
            let test_path = PathBuf::from(working_dir_raw);
            if test_path.is_relative() {
                working_dir = Some(root.join(test_path));
            } else {
                working_dir = Some(test_path);
            }
        }
        iffts.push(Ifftt {
            name: ifft_raw.name.clone(),
            working_dir,
            if_cond,
            nots,
            then: ifft_raw.then.clone(),
        })
    }

    Ok(Config {
        root,
        nots: root_nots,
        iffts,
    })
}

fn main() {
    let matches = App::new("IFFT")
        .about("IF Filesystem-event Then")
        .arg(
            Arg::with_name("CONFIG-PATH")
                .required(true)
                .help("The path to an IFFTT config file (.toml).")
                .takes_value(true),
        )
        .get_matches();
    let config_path = value_t!(matches, "CONFIG-PATH", String).unwrap_or_else(|e| e.exit());
    let contents = fs::read_to_string(config_path);
    if let Err(e) = contents {
        eprintln!("error: Cannot read config: {}", e);
        exit(1);
    }
    let config_raw = toml::from_str(&contents.unwrap());
    if let Err(e) = config_raw {
        eprintln!("error: Cannot parse config: {}", e);
        exit(1);
    }
    let config = config_raw_to_config(config_raw.unwrap());
    match config {
        Ok(config) => {
            if let Err(e) = watch(config) {
                eprintln!("error: {:?}", e)
            }
        }
        Err(e) => {
            eprintln!("error: {}", e);
            exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        config_raw_to_config, Config, ConfigRaw, FilterResult, Glob, Ifftt, IffttRaw, Path, PathBuf,
    };
    use std::env;

    #[test]
    fn config_converter() {
        // Test non-existent root
        let config_raw = ConfigRaw {
            root: String::from("/does-not-exist"),
            not: None,
            ifft: vec![],
        };
        let res = config_raw_to_config(config_raw);
        assert_eq!(res.unwrap_err(), "Root path is invalid: /does-not-exist");

        // Test missing env var
        let config_raw = ConfigRaw {
            root: String::from("/$DOESNOTEXIST/does-not-exist"),
            not: None,
            ifft: vec![],
        };
        let res = config_raw_to_config(config_raw);
        assert_eq!(
            res.unwrap_err(),
            "Environment variable $DOESNOTEXIST not set."
        );

        // Test bad root.not glob
        let config_raw = ConfigRaw {
            root: String::from("~"),
            not: Some(vec![String::from("***")]),
            ifft: vec![],
        };
        let res = config_raw_to_config(config_raw);
        assert_eq!(
            res.unwrap_err(),
            "root.not: error parsing glob '***': invalid use of **; must be one path component"
        );

        // Test bad ifft.if glob
        let config_raw = ConfigRaw {
            root: String::from("~"),
            not: None,
            ifft: vec![IffttRaw {
                name: None,
                working_dir: None,
                if_cond: Some(String::from("***")),
                not: None,
                then: String::from("ls"),
            }],
        };
        let res = config_raw_to_config(config_raw);
        assert_eq!(
            res.unwrap_err(),
            "ifft.if: error parsing glob '***': invalid use of **; must be one path component"
        );

        // Test bad ifft.not glob
        let config_raw = ConfigRaw {
            root: String::from("~"),
            not: None,
            ifft: vec![IffttRaw {
                name: None,
                working_dir: None,
                if_cond: None,
                not: Some(vec![String::from("***")]),
                then: String::from("ls"),
            }],
        };
        let res = config_raw_to_config(config_raw);
        assert_eq!(
            res.unwrap_err(),
            "ifft.not: error parsing glob '***': invalid use of **; must be one path component"
        );
    }

    #[test]
    fn ifft_if() {
        let ifft = Ifftt {
            name: None,
            working_dir: None,
            if_cond: Some(Glob::new("a/b/c/**").unwrap()),
            nots: vec![],
            then: String::from("ls"),
        };
        // Test pass case
        assert!(ifft.filter(&PathBuf::from("a/b/c/d")));
        // Test reject case
        assert!(!ifft.filter(&PathBuf::from("a/b")));
    }

    #[test]
    fn ifft_not() {
        let ifft = Ifftt {
            name: None,
            working_dir: None,
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
        let ifft = Ifftt {
            name: None,
            working_dir: None,
            if_cond: None,
            nots: vec![],
            then: String::from("pwd"),
        };
        let output = ifft.then_exec(Path::new("/dummy")).unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            env::current_dir().unwrap().to_str().unwrap(),
            &stdout[..stdout.len() - 1]
        );

        // Test specified working_dir
        let ifft = Ifftt {
            name: None,
            working_dir: Some(PathBuf::from("/home")),
            if_cond: None,
            nots: vec![],
            then: String::from("pwd"),
        };
        let output = ifft.then_exec(Path::new("/dummy")).unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!("/home\n", stdout);

        // Test non-existent working dir
        let ifft = Ifftt {
            name: None,
            working_dir: Some(PathBuf::from("/does-not-exist")),
            if_cond: None,
            nots: vec![],
            then: String::from("pwd"),
        };
        ifft.then_exec(Path::new("/dummy")).is_err();

        // Test file path substitution
        let ifft = Ifftt {
            name: None,
            working_dir: None,
            if_cond: None,
            nots: vec![],
            then: String::from("echo {{}}"),
        };
        let output = ifft.then_exec(Path::new("/a/b/c")).unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!("/a/b/c\n", stdout);
    }

    #[test]
    fn config_not() {
        let ifft = Ifftt {
            name: None,
            working_dir: None,
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
