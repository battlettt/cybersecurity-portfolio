# Project 7 — CTF & Lab Write-Up Blog (scaffold)

A ready-to-publish Jekyll blog for documenting TryHackMe/HackTheBox/OverTheWire write-ups,
using GitHub Pages' built-in Jekyll support — **no local Ruby install or build step
required**, GitHub builds it for you on push.

This is genuinely one of the highest-signal things in a security portfolio: a growing,
dated record that you actually did hands-on work, in your own words, not just a list of
completed room names. Technical interviewers read these first.

## ⚠️ Important — the included post is a template, not a real write-up

`_posts/2026-08-18-overthewire-bandit-0-to-2-TEMPLATE.md` exists only to show the format
and level of detail to aim for. **It is explicitly banner-labeled as a template inside the
post itself.** Do not leave it in place claiming it's your own work — replace it with a
write-up of a room you've actually completed, in your own words, before you publish this
publicly or link it from a resume. Fabricated CTF write-ups are exactly the kind of thing
a technical interview will catch in the first follow-up question.

## Resume bullet (once you have 3+ real write-ups)

> Maintain a public technical blog documenting methodology for completed TryHackMe,
> HackTheBox, and OverTheWire challenges — [N] write-ups published, covering [topics].

## How to publish this on GitHub Pages

1. Push this directory as the root of its own repo (or a `docs/` folder — either works,
   just adjust the Pages source setting to match):
   ```bash
   cd 07-ctf-writeup-blog
   git init -q   # if not already part of the parent portfolio repo
   git add .
   git commit -m "Initial CTF write-up blog scaffold"
   git remote add origin https://github.com/<you>/ctf-writeups.git
   git push -u origin main
   ```
2. In the repo's GitHub settings → **Pages**, set the source to the branch/folder you
   pushed. GitHub detects `_config.yml` automatically and builds it with Jekyll — you don't
   need Ruby, Bundler, or `jekyll build` installed locally.
3. Your site is live at `https://<you>.github.io/<repo>/` within a couple minutes.

## How to add a new write-up

Add a new file to `_posts/` named `YYYY-MM-DD-short-title.md`, with this front matter:

```markdown
---
layout: post
title: "TryHackMe: <Room Name>"
date: 2026-08-25
categories: [tryhackme, web]
---

## Room
What it is, what it's testing.

## Approach
What you tried, in order — including dead ends. This is the actually useful part.

## Root cause / key technique
The one or two sentences that explain *why* the exploit/technique worked.

## Takeaways
What you'd do differently, or what this connects to that you already knew.
```

Keep every post structured the same way (room → approach → root cause → takeaways) — the
consistency is itself a signal of someone who documents work systematically, which is
exactly the habit a SOC/IR/pentest role needs.

## Local preview (optional)

If you want to preview locally before pushing, you'll need Ruby + Bundler:

```bash
gem install bundler jekyll
bundle init && bundle add jekyll
bundle exec jekyll serve
# -> http://localhost:4000
```

Not required — GitHub Pages builds it for you either way.
