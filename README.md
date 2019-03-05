# IF Filesystem-event Then (IFFT) [![Latest Version]][crates.io] [![Build Status]][travis]

[Build Status]: https://api.travis-ci.com/braincore/ifft.svg?branch=master
[travis]: https://travis-ci.com/braincore/ifft
[Latest Version]: https://img.shields.io/crates/v/ifft.svg
[crates.io]: https://crates.io/crates/ifft

IF a filesystem event (create, write, remove, chmod) occurs in a watched folder
that is not filtered out by an exclusion rule THEN execute a shell command.

Use this to watch for code changes to trigger: process restart; code
compilation; or test run.

## Installation

If you have [rust installed](https://www.rust-lang.org/tools/install) on your
machine:

```
cargo install ifft
```

Otherwise, check [releases](https://github.com/braincore/ifft/releases) for
downloads.

## Usage

Create a config file (`ifft_config.toml`):

```toml
# The top-level folder to watch. Relative paths specified elsewhere will be
# relative to this folder. Supports ~ and env vars ($VAR).
root = "~/src"
# Never trigger on a backup or swap file. (VIM specific)
not = [
    "*~",
    "*.swp",
]

[[ifft]]
# my-c-prog is a folder in ~/src
# If any .c or .h files change, recompile.
if = "my-c-prog/**/*.{c,h}"
then = "make"
working_dir = "my-c-prog"

[[ifft]]
if = "my-rust-prog/*"
# Ignore changes in the target folder to avoid recursive triggering.
not = ["my-rust-prog/target/*"]
then = "cargo build"
working_dir = "my-rust-prog"

# Contrived example to demonstrate other features.
[[ifft]]
# Omitting the if condition -> trigger on all events under root.
# if =
# {{}} is substituted with the absolute path to the triggering file.
then = "cp -R {{}} ."
# working_dir can be an absolute path.
working_dir = "/tmp"
```

Run `ifft`:

```bash
ifft path/to/ifft_config.toml
```

Output:

`ifft` is verbose for easy debugging. Triggers report the match condition and
the exit code, stdout, and stderr of the triggered command:

```
[2019-01-31 04:51:28Z] Event: Create("/home/ken/src/my-rust-prog/src/main.rs")
  Matched if-cond: "my-rust-prog/*"
  Executing: "cargo build" from "/home/ken/src/my-rust-prog"
  Exit code: 0
  Stdout:
  Stderr:
       Compiling my-rust-prog v0.1.0 (/home/ken/src/my-rust-prog)
        Finished dev [unoptimized + debuginfo] target(s) in 0.27s
[2019-01-31 04:51:28Z] Event: Create("/home/ken/src/my-rust-prog/target/debug/incremental/my_rust_prog-1m194buzrsqka/s-f91jk9lg3a-wlnrr5.lock")
[2019-01-31 04:51:28Z] Event: Write("/home/ken/src/my-rust-prog/target/debug/deps/my_rust_prog-b5f4d74ed1175a94.d")
```

## Features

* Configure with a `toml` file.
* Use glob patterns for `if` and `not` conditions.
* `root` as an absolute path independent from `if` conditions as relative paths.
* `root` supports shell expansion: `~` and environment variables.
* Global `not` filtering and per-trigger `not` filtering.
* Multiple events that trigger the same `if` are buffered and only trigger one
  `then` execution.

## Platforms

Tested on Linux and OS X. Untested elsewhere.

## Usage with VirtualBox Shared Folders

On the guest OS, VirtualBox Shared Folders do not generate filesystem event
notifications. You'll need to use a separate filesystem event forwarder such as
[notify-forwarder](https://github.com/mhallin/notify-forwarder).

## Alternatives

* [watchexec](https://github.com/watchexec/watchexec) is a more full-featured
  program.
* [entr](http://eradman.com/entrproject/) has a clean Unixy interface.

## Todo

* [] Add `.gitignore` parsing support.
* [] Flag to ignore hidden files.
* [] Flag to control verbosity of prints.
* [] Group events in quick succession together and trigger only once.
* [] Allow customization of type of FS events that trigger.
* [] Low priority: Compute the optimal path prefix for watching.
* [] Performance: Do not compile glob before each use. Current hack to make it
  easy to access the glob pattern string if an error occurs.
