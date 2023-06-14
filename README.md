# fimbl

A very simple command line based file integrity checker for the
paranoid. `fimbl` just checks that files have not changed since it
last saw them.

Installation on MacOS: `brew install curvelogic/tap/fimbl`
On linux, build from source or try the release binary.
On windows, try the source, good luck.


Add files to the database (_manually_) with:

```shell
fimbl add ~/.zshrc ~/.profile
```

...and have them checked (somewhere in _automation_)
with `fimbl verify` e.g.

```shell
fimbl verify ~/.zshrc ~/.profile
if [ $? -ne 0 ] ; then
  # notify, panic, stamp and shout, whatever...
fi
```

...or use `fimbl verify-all` to verify everything in the database but
it's probably better to be explicit. The point of this is to alert you
to the unexpected after all.

If files have changed legitimately, accept them with:

```shell
fimbl accept ~/.zshrc
```

Currently uses SHA3_256 content hashes and records some file
attributes too. The database is
[sled](https://github.com/spacejam/sled) and should be maintained
transparently behind the scenes. If you want to test something with a
different database, specify a `--database` path.

More help on `fimbl --help` or `fimbl <command> --help`.

Note that `--tolerant` needs to be specified if you don't want `add`
complaining about pre-existing files or `remove` complaining about
missing files. The whole point is to alert you to the unexpected.

## Rationale and Provisos

This was conceived as an ultra simplistic tool to support periodic
checks that various configuration files were not being tampered with.

There are a zillion ways to do it better:

 - you could use git to manage these files and use git status
 - you might have a proper file integrity solution
 - you might have files under some regime managed by the OS
 - you could stick hashes in a public blockchain notarising them for all
   eternity...

...but whatever else is going on, you can still use `fimbl` to check in
periodically for peace of mind.

Of course, by itself, `fimbl` does not ensure the files are not being
tampered with. Someone can just `fimbl accept` the changes without
your knowledge, or tamper with `fimbl`'s database.
