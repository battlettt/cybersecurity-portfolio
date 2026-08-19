---
layout: post
title: "[TEMPLATE] OverTheWire Bandit — Levels 0 to 2"
date: 2026-08-18
categories: [overthewire, linux-fundamentals]
---

> **This post is a template, not a real completed write-up.** It exists to show the format
> and level of detail every future write-up in this blog should hit. Delete this banner and
> the placeholder note at the bottom once you've actually worked through Bandit yourself —
> write it in your own words, from your own terminal session.

## Room

[OverTheWire: Bandit](https://overthewire.org/wargames/bandit/) — a Linux command-line
wargame where each level's password is the login for the next. Levels 0–2 cover `ssh`,
`ls`, `cat`, and handling filenames with spaces/special characters.

## Level 0 → 1

Connect via SSH with the level 0 credentials (published on the Bandit site itself — this
level has no secret):

```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
```

Once connected, the level 1 password is sitting in a file called `readme` in the home
directory:

```bash
bandit0@bandit:~$ ls
readme
bandit0@bandit:~$ cat readme
<the level 1 password>
```

**What this level actually teaches:** confirming you can navigate to your home directory
and use `ls`/`cat` — the two commands you'll run more than any other for the rest of the
game (and honestly, for the rest of a security career).

## Level 1 → 2

The level 2 password is in a file literally named `-` in the home directory — a filename
that looks like a command-line flag, which is the actual lesson here:

```bash
bandit1@bandit:~$ ls
-
bandit1@bandit:~$ cat -
```

`cat -` doesn't work the way you'd expect — the shell interprets `-` as "read from stdin,"
not as a filename, so it just hangs waiting for keyboard input instead of reading the file.
The fix is to disambiguate the filename from a flag, either with a relative path or the
`--` end-of-options marker:

```bash
bandit1@bandit:~$ cat ./-
<the level 2 password>
```

**What this level actually teaches:** every CLI tool built on `getopt`-style argument
parsing treats a leading `-` specially. This shows up again constantly in real security
work — e.g., a filename an attacker deliberately names to break a naive shell script that
globs and passes filenames straight into a command.

## Level 2 → 3

The level 3 password is in a file with spaces in its name: `spaces in this filename`.

```bash
bandit2@bandit:~$ ls
spaces in this filename
bandit2@bandit:~$ cat "spaces in this filename"
<the level 3 password>
```

Quoting (or escaping each space with `\`) is required — otherwise the shell splits the
name into multiple arguments and `cat` looks for three separate files that don't exist.

## Takeaways

- These first few levels look trivial, but they're deliberately building the specific
  muscle memory (careful reading of `ls -la`, exact quoting, distrust of "obvious" filenames)
  that shows up constantly later — in log analysis, in exploit scripting, in not getting
  tripped up by an attacker's deliberately weird filenames.
- Next up: levels 3–10 (hidden files, file permissions, `find` with property filters, and
  the first level that requires actually reading a `man` page rather than guessing).

---

*Replace this entire post with your own write-up once you've worked through the room
yourself. Keep the same structure — room/context, what you tried, what worked, what it
actually teaches — that structure is what makes these useful to a reader (and to you, six
months later).*
