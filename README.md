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

### Hello, world.

Create a config file (`ifft.toml`) in a directory (let's say
`~/src/ifft-test`):

```toml
[[ifft]]
# Matches everything including sub-folders
if = "**/*"
then = "echo hello, world."
```

Run `ifft` with the directory containing your config as the argument:

```
$ ifft ~/src/ifft-test
Found config: "~/src/ifft-test/ifft.toml"
```

`ifft` found your config file. In later examples, we'll see that multiple
config files can be embedded throughout the filesystem tree.

Now let's create a file to trigger your ifft:

```
$ touch ~/src/ifft-test/test1
```

You'll see the following output:

```
[2019-05-12 14:55:57Z] Event: Create("~/src/ifft-test/test1")
  Match from config in: "~/src/ifft-test"
  Matched if-cond: "**/*"
[2019-05-12 14:55:57Z] Execute: "echo hello, world." from "~/src/ifft-test"
  Exit code: 0
  Stdout:
    hello, world.
  Stderr:
```

As you can see, the triggered command's match condition, exit code, stdout,
and stderr are printed.

That's it. `ifft` simply listens for file changes and takes action.

### Filters

Use the `not` argument to specify file patterns to filter out from triggering:

```toml
[[ifft]]
if = "**/*.{c,h}"
not = [
    "*~",
    "*.swp",  # Filter out swap files
    "dist/**/*",  # Filter out outputs of compilation
]
then = "gcc main.c -o dist/prog"
```

`not` can also be specified at the config-level which will apply to all iffts:

```
not = [
    "*~",
    "*.swp",  # Filter out swap files
    "dist/**/*",  # Filter out outputs of compilation
]

[[ifft]]
if = "**/*"
then = "gcc main.c -o dist/prog"
```

A roadmap feature is to offer a flag to automatically ignore patterns in
`.gitignore`.

### Working Directory

By default, the working directory used to execute the `then` clause is the
folder of the `ifft.toml` file being triggered. To override, use the
`working_dir` argument to `[[ifft]]`.

### Path Substitution

The `then` clause can use the `{{}}` placeholder which will be replaced by the
path of the modified file that triggered the ifft.

### On Start

If you want to automatically trigger iffts on start without any file event,
use the `-r` flag. The argument will trigger any iffts with matching names. For
example:

``` 
ifft ~/src/ifft-test -r build
```

Matches:

```toml
[[ifft]]
name = "build"  # Triggered by -r flag
not = ["target/*"]
then = "cargo build"
```

This is useful to ensure that projects are built on boot without having to wait
for a file event.

You can also use the `-q` flag to quit after the `-r` flag triggers have
completed. This can be used to initiate a one-time build or clean without
listening for changes afterwards.

### Distributing `iffts`

Imagine you have the following filesystem tree:

```
~/src/my-app
~/src/my-app/my-c-service
~/src/my-app/my-rust-service
```

While you could create one config file `~/src/my-app/ifft.toml` with the iffts
for all projects, a better approach is to create an `ifft.toml` in each of the
service directories.

When invoking `ifft` it will report the configs it has found:

```
$ ifft ~/src/my-app
Found config: "~/src/my-app/ifft.toml"
Found config: "~/src/my-app/my-c-service/ifft.toml"
Found config: "~/src/my-app/my-rust-service/ifft.toml"
```

This allows you to distribute config files across your filesystem tree, which
has the advantage of keeping them small and relevant to the folder they're in.

### Dependencies

If you have cross-project dependencies, you may want to trigger an ifft based
on another ifft. This is possible using `listen` and `emit`.

Assume the following filesystem tree:

```
~/src/my-app
~/src/my-app/my-c-service/ifft.toml
~/src/my-app/my-rust-service/ifft.toml
```

If `my-rust-service` depends on `my-c-service`, you can write the following:

```toml
[[ifft]]
if = "listen:../my-c-service:built"  # Listens for "built" from my-c-service
then = "cargo build"
```

`my-c-service/ifft.toml` can be written as follows:

```toml
[[ifft]]
if = "**/*.{c,h}"
then = "gcc *.c -o c-service"
emit = "built"  # Emits "built" to listeners
```

A similar pattern is used for "on start" iffts. Use `on_start_listen`:

```toml
#
# my-rust-service/ifft.toml
#

[[ifft]]
name = "build"
if = "on_start_listen:../my-c-service:built"
then = "cargo build"

#
# my-c-service/ifft.toml
#
[[ifft]]
name = "build"
then = "gcc *.c -o c-service"
emit = "built"
```

Using the on start syntax (`ifft my-app -r build -q`) will execute these iffts
in the correct order: first `my-c-service`; second `my-rust-service`.

## Features

* Configure with a `toml` file.
* Config files can be distributed throughout a filesystem tree.
* Use glob patterns for `if` and `not` conditions.
* Global `not` filtering and per-trigger `not` filtering.
* If multiple events trigger the same `if`, `then` is only executed if an event
  was triggered after the last time `then` was executed.
* On start, iffts with a matching name can be triggered without any file event.
* Events on paths with symlink components will also have their absolute-path
  equivalent tested against triggers.
* Dependencies
  * An ifft can be triggered by listening for an emitted tag from another.
  * On start, iffts can be ordered via a dependency graph.

## Platforms

Tested on Linux and OS X. Untested elsewhere.

## Usage with VirtualBox Shared Folders

On the guest OS, VirtualBox Shared Folders do not generate filesystem event
notifications. You'll need to use a separate filesystem event forwarder such as
[notify-forwarder](https://github.com/mhallin/notify-forwarder).

## Alternatives

* [bazel](https://bazel.build/) for a serious incremental build system.
* [watchexec](https://github.com/watchexec/watchexec) is a more full-featured
  program.
* [entr](http://eradman.com/entrproject/) has a clean Unixy interface.

## Todo

* [ ] Add `.gitignore` parsing support.
* [ ] Flag to ignore hidden files.
* [ ] Flag to control verbosity of prints.
* [ ] Group events in quick succession together and trigger only once.
* [ ] Allow customization of type of FS events that trigger.
* [ ] Low priority: Compute the optimal path prefix for watching.
* [ ] Performance: Do not compile glob before each use. Current hack to make it
  easy to access the glob pattern string if an error occurs.
