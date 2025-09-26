# Cyberdle

Look, we all know cybersecurity has way too many dang acronyms. Half the time it feels like we’re drowning in acronym soup. CNAPP, CSPM, XDR, SOC, MITRE... and that's jsut the first 2 minutes of this meeting. So lets try and have some fun with this!

Cyberdle is a Wordle-style word game designed for cybersecurity professionals, students, and acronym enthusiasts. Test your knowledge of cybersecurity acronyms by guessing the correct term based on its definition. Each guess provides color-coded feedback: green for letters in the correct position, yellow for letters present elsewhere, and gray for absent letters.

The entire game ships as static files (HTML, CSS, and a single dataset script), so you can double-click `index.html` and start playing immediately. No build step, server, or tooling required. Just pure, online/offline fun!

## How to Play

1. **Read the Definition**: Each puzzle presents a detailed definition of a cybersecurity acronym.
2. **Make Your Guess**: Type your guess using the on-screen keyboard or your physical keyboard.
3. **Get Feedback**: Letters turn green (correct position), yellow (present elsewhere), or gray (absent).
4. **Solve in 6 Tries**: Use the feedback to refine your guesses and solve the acronym.

Choose between **Daily Mode** (same puzzle for everyone each day) or **Random Mode** (fresh puzzle each time).

## Game Features

- **Keyboard-First Design**: Optimized for both physical and on-screen keyboards
- **Dark/Light Theme Toggle**: Switch themes to match your preference
- **Local Persistence**: Your stats and progress are saved in browser localStorage
- **Confetti Celebrations**: Win animations that work offline
- **Accessibility-Friendly**: Screen reader support and keyboard navigation
- **No External Dependencies**: Runs entirely from static files

## Technical Architecture

- `index.html` - Complete game UI, logic, and inline JavaScript
- `style.css` - Responsive styling with theme support and animations
- `acronyms.js` - Curated dataset of 50+ cybersecurity acronyms via `window.CYBERDLE_DATA`
- **Runtime**: Vanilla browser APIs only; works offline under `file://`
- **Storage**: Uses `cyberdle:simple:*` localStorage keys for persistence

## Run Locally

### Option 1

Double-click `index.html` in your file browser. The game will open directly in your default browser.

### Option 2

Serve over HTTP:

```bash
python3 -m http.server
# Visit http://localhost:8000
```

## Contribute

Pull requests and issues are welcome! Ways to contribute:

- **Expand the Dataset**: Add new acronyms, improve definitions, or fix typos in `acronyms.js`
- **Enhance Gameplay**: Improve keyboard handling, add new features, or refine the UI
- **Polish the Experience**: Better styling, animations, accessibility improvements
- **Bug Fixes**: Report and fix any issues you encounter

Cyberdle is MIT-licensed, so you're free to fork it, customize it, or build your own cybersecurity-themed variants. If you publish improvements, please consider opening a pull request to benefit the community.

## Project Structure

```
index.html      # Game UI + logic
style.css       # Themes + layout
acronyms.js     # Acronym dataset
README.md       # This file
LICENSE         # MIT license
```

## License

Released under the [MIT License](LICENSE).
