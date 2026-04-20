# PassGen

A minimal, privacy-first Chrome extension for generating secure passwords — no network requests, no tracking, no dependencies.

## Features

- **Cryptographically secure** — uses `crypto.getRandomValues()` with rejection sampling to eliminate modulo bias
- **Entropy-based strength meter** — real bit-entropy calculation, not a simple ruleset check
- **Guaranteed character coverage** — at least one character from every enabled set, then shuffled with Fisher-Yates
- **Configurable length** — 6 to 64 characters via slider
- **Character set toggles** — Uppercase (A–Z), Lowercase (a–z), Numbers (0–9), Symbols (!@#$…)
- **Avoid ambiguous characters** — optionally strips `0 O l I 1` to prevent misreading
- **One-click copy** — writes to clipboard via the `clipboardWrite` permission; no other permissions requested

## Strength Levels

| Label  | Min Entropy |
|--------|-------------|
| Weak   | < 40 bits   |
| Fair   | ≥ 40 bits   |
| Good   | ≥ 56 bits   |
| Strong | ≥ 72 bits   |
| Max    | ≥ 96 bits   |

## Installation (unpacked)

1. Clone or download this repository.
2. Open Chrome and go to `chrome://extensions`.
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select the project folder.
5. The PassGen icon appears in the toolbar — click it to open the popup.

> No build step required. All files are plain HTML, CSS, and JavaScript.

## Permissions

| Permission       | Reason                               |
|------------------|--------------------------------------|
| `clipboardWrite` | Copy the generated password on click |

No host permissions, no storage access, no internet access.

## Project Structure

```
password-generator/
├── manifest.json       # Extension manifest (MV3)
├── popup.html          # Extension popup UI
├── popup.css           # Styles
├── popup.js            # Password generation logic & UI bindings
└── icons/
    ├── icon16.png
    ├── icon48.png
    ├── icon128.png
    └── create-icons.html
```

## Security Notes

- All randomness comes from the Web Crypto API (`crypto.getRandomValues`), which is cryptographically secure.
- Rejection sampling ensures uniform distribution across the character pool with zero modulo bias.
- Generated passwords never leave the browser; no analytics or external calls are made.

## License

MIT
