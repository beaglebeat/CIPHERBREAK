# Instructor guide: add questions in one file

Open **`js/challenges.js`** in any text editor. Questions are plain JavaScript objects in `window.CIPHERBREAK_QUESTIONS`. No npm, frameworks, database, packaging, or server is required. For deployment to GitHub Pages, commit the modified file and refresh the page.

## Fastest way to add a question

1. Copy an existing object `{ id: '...', ... }` **including its opening and closing braces**, paste another entry into `CIPHERBREAK_QUESTIONS` with a comma separating the objects.
2. Give it a **unique `id`**. Keep the `type` and `family` from the template you copied.
3. Edit `title`, `kicker`, `briefing`, `objective`, `protocol`, `attackLabel`, `hints`, and the `remediation` multiple-choice question.
4. Keep `diagnosis` aligned with the implementation weakness and set `remediation.correct` to the ID of the best fix.
5. Save and reload `index.html`. A configuration error is displayed prominently if required fields are missing.

**Do not edit the engine just to add a new scenario.** The game creates new randomized AES keys, plaintext tokens, IVs, nonces, ciphertexts and flags at run time for the selected template type.

## Six supported templates (five families)

| `type` | `family` | Player's action | `diagnosis` |
|---|---|---|---|
| `ecb-codebook` | `ecb` | Query ECB encryption oracle and identify repeated role block | `ecb` |
| `cbc-iv` | `cbc` | Change unauthenticated CBC IV to forge first plaintext block | `cbc` |
| `ctr-reuse` | `ctr` | Recover a target using a known plaintext and repeated CTR keystream | `ctr` |
| `ctr-malleability` | `auth` | Flip CTR ciphertext bits without any message authenticator | `auth` |
| `gcm-skip-tag` | `gcm` | Change GCM ciphertext; buggy receiver ignores tag failure | `gcm-skip` |
| `gcm-reuse` | `gcm` | Recover plaintext using a repeated GCM nonce | `gcm-reuse` |

Five-family sprint selects one random question for each `family` and shuffles them. Full bank selects and shuffles **every question**. If you add three ECB questions, five-family sprint randomly picks one; full bank plays all three. Keep at least one question in each family.

## Example: add a second CBC question

Place this entry in the top-level array (with a comma before or after it as needed):

```javascript
{
  id: 'cbc-payroll',
  family: 'cbc',
  type: 'cbc-iv',
  title: 'The Payroll Message',
  kicker: 'MESSAGE HEADER TAMPERING',
  briefing: 'A payroll endpoint uses AES-CBC without authentication. An interceptor may replace the IV.',
  objective: 'Forge the IV so the first block becomes ROLE=ADMIN______ instead of ROLE=GUEST______.',
  protocol: 'CBC first-block plaintext is D_K(C1) XOR IV. IV confidentiality is not required.',
  attackLabel: 'Forged IV (32 hex digits)',
  hints: [
    'Only the first decrypted block is affected by IV replacement.',
    'Compute the XOR difference between the known and desired 16-byte strings.',
    'newIV = oldIV XOR knownPlaintext XOR desiredPlaintext.'
  ],
  diagnosis: 'cbc',
  remediation: {
    prompt: 'What fixes the vulnerability?',
    options: [
      {id: 'a', text: 'Hide the CBC IV.'},
      {id: 'b', text: 'Authenticate both IV and ciphertext, or use verified AEAD.'},
      {id: 'c', text: 'Reuse one IV indefinitely.'}
    ],
    correct: 'b',
    explanation: 'IV secrecy is not required; authenticity of both the IV and ciphertext prevents chosen edits.'
  }
}
```

### What is customizable without programming?

Titles, stories, evidence instructions, the correct root-cause category, number of hints, all fix options, grading penalties (`window.CIPHERBREAK_SETTINGS`), and number/order of scenarios (by editing the bank) are easy to change. Template-specific packet formats currently stay fixed: all role-forgery questions use `ROLE=GUEST______` and `ROLE=ADMIN______`, and all stream-reuse questions use a randomized `TOKEN=` message. This keeps the authoring API small and grading reliable.

To introduce a **new cryptographic attack mechanic**, extend `makeInstance`, `makeEvidence`, and `attack` in `js/game.js`. It is not supported by the question-bank-only API.

## Assessment and deployment limits

The static browser edition is optimized for accessible practice, not grading integrity. Its keys, flags, state, and validation run in JavaScript, so inspecting developer tools can reveal the solution. Local storage rankings are editable and remain only in that browser. An authoritative graded CTF would require a backend to hold keys and verify flags, plus a server-backed leaderboard. The file uses no accounts or remote analytics. Optional tab-visibility tracking defaults to **off**, and should never be used as proof of whether a student used AI.

## Pedagogical precision

ECB leaks equal-block structure. CBC IV modification demonstrates malleability *without authentication*, not IV secrecy. CBC encryption IVs should be unpredictable and fresh. CTR nonce/counter reuse leaks the keystream; CTR bit flips are a distinct integrity problem even with a fresh nonce. GCM nonce reuse and GCM skipped tag checking are separate defects: the former compromises a security assumption, and the latter defeats the authentication check of an otherwise correctly generated packet. Every flag requires both successful exploitation and the correct remediation choice.
