# <img src="assets/favicon.svg" alt="Cyberdle" width="32" height="32" /> Cyberdle

Look, we all know cybersecurity has way too many dang acronyms. Half the time it feels like we're drowning in acronym soup. CNAPP, CSPM, XDR, SOC, MITRE... and that's just the first 2 minutes of this meeting. So let's try and have some fun while we learn!

Cyberdle is a Wordle-style word game designed for cybersecurity professionals, students, and acronym enthusiasts. Test your knowledge of cybersecurity acronyms by guessing the correct term based on its definition. Each guess provides color-coded feedback: green for letters in the correct position, yellow for letters present elsewhere, and gray for absent letters.

The entire game ships as static files (HTML, CSS, and a single dataset script), so you can double-click `index.html` and start playing immediately. No build step, server, or tooling required. Just pure, online/offline fun!

## Play Online

Come hang out at **[https://cyberdle.adilio.ca/](https://cyberdle.adilio.ca/)** — the live site is always up to date and ready for your next streak. Open it on desktop, mobile, or that ancient Chromebook collecting dust in the corner. It just works.

Want to stream it on Twitch? Throw it on the big screen in your SOC? Turn it into your team’s daily stand-up ritual? Go for it. It’s free and runs entirely in the browser.

## Quick Start

1. Read the definition and soak in the clues.
2. Guess the acronym (letters and numbers totally welcome).
3. Watch the tiles glow: 🟩 correct spot, 🟨 in the word but shuffled, ⬛ shaded for not in the acronym.
4. Solve in six tries or less, then flex your results with the built‑in share card.

You can play in **Daily mode** (same puzzle for everyone worldwide) or **Random mode** (hit refresh for endless chaos). Stats, streaks, and theme preference stick around thanks to localStorage—no accounts or trackers necessary.

## What You Get

- 🎯 Keyboard- and touch-friendly gameplay
- 🌗 Dark/light theme toggle that remembers your vibe
- 🎉 Confetti on the wins you’ll definitely brag about
- ♿ Thoughtful accessibility touches from the start
- 🧠 Completely offline-capable for planes, trains, and firewalled offices

## Run It Yourself

Clone the repo, then either:

```bash
# Option 1: double-click
open index.html

# Option 2: serve locally
python3 -m http.server
# visit http://localhost:8000
```

Everything lives in three files:

```
index.html          # UI + game logic
style.css           # Themes and layout
acronyms.js         # The acronym dataset
assets/
  favicon.svg       # Site icon
  cyberdle-share-card.png  # Social preview art
README.md           # This doc
LICENSE             # MIT license
```

## Contribute, Remix, Share

- Got new acronyms? Add them! (Send a PR so we all benefit.)
- Spot a bug? File an issue—or squash it and brag.
- Want to reskin or self-host? It’s MIT-licensed. Fork away.

We’re building a friendly corner of the cyber world where learning and laughing can co-exist. If you do something cool with Cyberdle, reach out—I’d love to hear about it.

Stay curious, keep your passwords long, and may your next guess be green. 💚
