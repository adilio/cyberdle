# Cyberdle

Cyberdle is a keyboard-first word game built for security practitioners, students, and acronym obsessives. The entire experience ships as static files (HTML, CSS, and a single dataset script), so you can double-click `index.html` and start playing. It is intentionally minimalist: NO build step or tooling required.

## How It Works

- `index.html` hosts the UI, game logic, and local-storage persistence (`cyberdle:simple:*`).
- `style.css` controls theming, layout, and accessibility-friendly spacing.
- `acronyms.js` exports the curated acronym list via `window.CYBERDLE_DATA`.
- Confetti celebrations and the win modal use DOM-driven animations, which work offline and under `file://`.

## Run Locally

```bash
# Optional: serve over HTTP instead of double-clicking
python3 -m http.server
# Visit http://localhost:8000
```

## Contribute

Pull requests and issues are welcome! You can:

- Extend or refine the dataset in `acronyms.js` (new acronyms, better definitions, typo fixes).
- Improve styling, accessibility, or keyboard handling.
- Report bugs or suggest features.

Cyberdle is MIT-licensed, so you’re free to fork it, reskin it, or build your own flavour. If you publish improvements, please consider opening a pull request so the community can benefit too.

## Project Layout

```
index.html   # UI + game logic
style.css    # theme + layout
acronyms.js  # curated acronym dataset (window.CYBERDLE_DATA)
LICENSE
README.md
AGENTS.md   # maintainer notes
```

## License

Released under the [MIT License](LICENSE).
