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

Create a config file (`ifft.toml`) in a directory (let's say `~/ifft-test`):

```toml
[[ifft]]
# Matches everything including sub-folders
if = "**/*"
then = "echo hello, world."
```

Run `ifft` with the directory containing your config as the argument:
`ifft ~/ifft-test`.

You'll see the following output, which indicates that `ifft` found your config
file:

```
Found config: "~/ifft-test/ifft.toml"
```

In later examples, we'll see that multiple config files can be embedded
throughout the directory tree.

Now let's create a file that will trigger `ifft`: `touch ~/src/test1`
You'll see the following output:

```
[2019-05-12 14:55:57Z] Event: Create("~/ifft-test/test1")
  Match from config in: "~/ifft-test"
  Matched if-cond: "**/*"
[2019-05-12 14:55:57Z] Execute: "echo hello, world." from "~/ifft-test"
  Exit code: 0
  Stdout:
    hello, world.
  Stderr:
```

As you can see, triggers report the match condition and the exit code, stdout,
and stderr of the triggered command.

That's it. `ifft` simply listens for file changes and takes action.

### Advanced

Here's a more complex `ifft` config that would be in a folder such as `~/src`
with sub-folders `my-c-prog` and `my-rust-prog`:

```toml
# Never trigger on a backup or swap file. (VIM specific)
not = [
    "*~",
    "*.swp",
]

[[ifft]]
# If any .c or .h files change, recompile.
if = "my-c-prog/**/*.{c,h}"
then = "make"
working_dir = "my-c-prog"

[[ifft]]
if = "my-rust-prog/**/*.{rs,toml}"
# Ignore changes in the target folder to avoid recursive triggering.
not = ["my-rust-prog/target/*"]
then = "cargo build"
working_dir = "my-rust-prog"

# Contrived example to demonstrate other features.
[[ifft]]
if = "*"
# {{}} is substituted with the absolute path to the triggering file.
then = "cp -R {{}} ."
# working_dir can be an absolute path. If omitted, the working_dir is set to
# root.
working_dir = "/tmp"
```

The second `ifft` condition could be moved into a new `ifft.toml` in the
`my-rust-prog` folder. For equivalent functionality, the contents would be:

```
[[ifft]]
if = "**/*.{rs,toml}"
not = ["target/*"]
then = "cargo build"
```

This allows you to distribute config files all over, which has the advantage
of keeping them small and relevant to the folder they're in.

### On start

If you want to automatically trigger iffts on start without any file event,
use the `-r` flag. The argument will trigger any iffts with matching names. For
example, running `ifft ~/ifft-test -r build` will match:

```toml
[[ifft]]
name = "build"
if = "**/*.{rs,toml}"
not = ["target/*"]
then = "cargo build"
```

This is useful to ensure that projects are built on boot without having to wait
for a file event.

## Features

* Configure with a `toml` file.
* Config files can be distributed throughout a directory tree.
* Use glob patterns for `if` and `not` conditions.
* Global `not` filtering and per-trigger `not` filtering.
* Multiple events that trigger the same `if` are buffered and only trigger one
  `then` execution.
* On start, iffts with a matching name can be triggered without any file event.

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

* [] Add `.gitignore` parsing support.
* [] Flag to ignore hidden files.
* [] Flag to control verbosity of prints.
* [] Group events in quick succession together and trigger only once.
* [] Allow customization of type of FS events that trigger.
* [] Low priority: Compute the optimal path prefix for watching.
* [] Performance: Do not compile glob before each use. Current hack to make it
  easy to access the glob pattern string if an error occurs.
