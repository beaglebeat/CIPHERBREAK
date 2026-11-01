# CIPHERBREAK — Applied Cryptography CTF

A complete, responsive, dependency-free browser game for an undergraduate laboratory on **AES misuse: ECB, CBC, CTR, IVs/nonces, malleability, and GCM authentication**. Inspired by the ECE576 Symmetric Encryption project proposal and revised according to instructor feedback.

## Play now (no install)

**Open `index.html`** in a current Firefox or Chromium-based browser. No connection, extensions, Node, Python, build process, CDNs, or other dependencies. Or host the repository on GitHub Pages.

- **Five-family sprint:** Five unlabeled, shuffled missions; picks one of the two different GCM variants at random. Recommended budget: **20–35 minutes** for a class familiar with the basics.
- **Full bank:** All six built-in scenarios, shuffled. New instructor-added questions appear here automatically.
- **Required for every flag:** exploit the real generated packet, correctly diagnose the failure, **and** select a defensible remediation.
- **In-page tools:** text/hex converter, bytewise hex XOR, AES 16-byte block viewer, ECB encryption oracle, progressive hints, copy buttons and session timer.
- **Scoring:** +10 seconds per incorrect exploit or explanation; optional browser-local practice leaderboard. No tab tracking by default.

> **Important limitations:** Unlike the original Flask-backed proposal, this is a **100% static** game. The random key material, flags and grading logic necessarily exist in the browser and can be inspected with developer tools. It is ideal for ungraded learning, demonstrations, and self-practice, but **not tamper-resistant or authoritative for a graded leaderboard**. For competitive grading, put key generation, oracles, flag verification and scoring behind a server API. No browser-only code can keep a secret from its own user.

## GitHub Pages in two minutes

1. Create a GitHub repository and upload/commit the **contents** of this folder, with `index.html` at the repository root.
2. In the repository select **Settings → Pages → Build and deployment**.
3. Under **Source**, select **Deploy from a branch**, and choose **main** / **/(root)**, then Save.
4. Open the Pages URL provided by GitHub when deployment finishes. No build is necessary.

You can also open `index.html` with `file://`—there are no `fetch()` requests or ES modules, so Firefox and Chromium's local-file restrictions do not interfere with gameplay. `localStorage` may behave differently for `file://` among browsers, affecting only the optional local practice board.

## Customize or add questions

**Edit only [`js/challenges.js`](js/challenges.js).** Questions are declarative objects with an `id`, story/instructions, supported attack `type`, category, hints, and a multiple-choice remediation with an answer. Copy an entry and change its prose; a working scenario with fresh AES material is generated automatically. **See [docs/ADDING_QUESTIONS.md](docs/ADDING_QUESTIONS.md)** for the complete schema, worked example, and customization limits.

## Game coverage

| Family | Technical defect | Working browser exploit | Correct fix | 
|---|---|---|---|
| ECB | Deterministic equal-block encryption | Detect repeat patterns; test guesses against an ECB encryption oracle | Replace ECB with a securely used mode, preferably authenticated |
| CBC | Unauthenticated first-block IV malleability | Forge `IV' = IV XOR P XOR P'` | Authenticate IV+ciphertext (or use AEAD); fresh unpredictable IV for CBC |
| CTR nonce reuse | Repeated `(key, nonce, counter)` keystream | Recover plaintext from known-plaintext XOR | Ensure per-key nonce/counter uniqueness |
| No authentication | CTR ciphertext malleability with a **fresh nonce** | Forge `C' = C XOR P XOR P'` | Authentication (verified AEAD or secure MAC) |
| GCM skipped verification | Correct tag generated but ignored on decryption | Alter GCM ciphertext; compare buggy acceptance to proper tag rejection | Verify the authentication tag before processing plaintext |
| GCM repeated nonce | Identical GCM `(key, nonce)` reused | Recover target using identical keystream | Guarantee unique GCM nonces, including after restarts |

Five vulnerability **families**, six built-in attack **templates**. The GCM family deliberately has two cases because nonce reuse and skipped tag verification are not interchangeable failures.

## Architecture

```text
index.html                 Browser entry point (classic script tags; opens from file://)
css/style.css              All styling; responsive layout; no font downloads
js/aes.js                  Self-contained educational AES-128, CBC, CTR, GCM
js/challenges.js           ONLY FILE instructors edit to add questions
js/game.js                 Mission generation, evidence, grading, UI, timing, tools
assets/favicon.svg         Local logo
README.md                  This file
docs/ADDING_QUESTIONS.md   Worked example and field reference
docs/INSTRUCTOR_NOTES.md   Technical explanation, lab timing, assessment
tests/test-crypto.js       Known-answer tests and generated-attack tests (optional Node)
LICENSE                    MIT license
```

The game performs actual AES-128 encryption. The custom AES implementation is intentionally included to support ECB and to run even in insecure `file://` contexts, where WebCrypto APIs may be unavailable. It is for **education only**, not audited, constant-time, or suitable for production. If adapting to a real application, use a vetted platform library instead.

## Test (optional, development only)

With Node 18+ installed, run:

```sh
node tests/test-crypto.js
```

The tests cover AES NIST/FIPS known-answer vectors, AES-CBC and AES-CTR round trips, AES-GCM empty and nonempty plaintext known answers, tag rejection, and every built-in attack's correctness. **Students do not need Node.**

## Attribution and safety

This is a self-contained educational simulation. It sends no network traffic, does not attack real systems, and includes no third-party libraries. The synthetic plaintext is never personal data. The implementation is licensed under MIT (see LICENSE).
