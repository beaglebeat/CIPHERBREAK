# Instructor notes: learning goals, assessment, and demonstrations

## Intended lab structure

**Prerequisite mini-lesson (8–12 minutes):** explain the block cipher versus its mode, ECB/CBC/CTR/GCM, XOR, nonces/IVs, integrity and authentication tags. Emphasize that AES remains secure in the game; the implementations violate usage assumptions.

**Lab (20–35 minutes, suggested starting budget):** use "Start five-family sprint". The game selects one random instance from each of five families; its default bank includes one of two GCM variants on any given run. If every student must see **both** GCM issues, select "Play all six scenarios" or schedule a second GCM-focused run. Duration is a planning suggestion, not an empirically validated measurement; adjust for the students' experience.

**Debrief (5–10 minutes):** discuss what the attack actually achieved, which security property failed, whether the nonce/IV was fresh, whether an authentication tag existed and was validated, and why the selected mitigation addresses the attack.

## Five families, six distinct attack templates

1. **ECB codebook / repeated blocks.** Find three identical ciphertext blocks and use an encryption oracle to identify the repeated 16-byte plaintext role. The failure is equality and pattern leakage. AES-ECB has no IV; obscuring block boundaries does not provide semantic security.
2. **CBC IV malleability.** With known P₁, desired P₁′, and recorded IV, compute `IV' = IV XOR P₁ XOR P₁′`. Leave C₁ unchanged. This changes the first decrypted plaintext block. This does **not** mean CBC IVs need secrecy: they need appropriate unpredictability/freshness during encryption, and the packet needs authentication against tampering.
3. **CTR nonce/counter reuse.** Obtain `keystream = knownPlaintext XOR knownCiphertext`, then `unknownPlaintext = unknownCiphertext XOR keystream`. The counter stream repeats under the same key, destroying confidentiality.
4. **CTR bit-flipping without authentication.** Fresh nonce, no MAC: `C' = C XOR originalPlaintext XOR desiredPlaintext`. This is a malleability attack that still works with a correctly unique nonce, because confidentiality alone does not imply integrity.
5. **GCM skipped tag verification.** The original GCM tag is generated correctly. Tampering with the ciphertext changes the plaintext, but makes the tag invalid. The *buggy* receiver still acts on the decrypted plaintext because it skips verification; the correct decryptor throws an error. Fix: strictly validate the tag **before** processing plaintext.
6. **GCM nonce reuse.** Two different AES-GCM messages share the same key and nonce; their encrypted data reuse the CTR keystream. Recover an unknown plaintext using a known plaintext. In this case the included tags are individually correct: tag checking alone does not repair nonce reuse. Fresh per-key unique nonces are mandatory.

## How students earn credit

Each question is *unlabeled*. To unlock a flag, the student must (i) submit a working exploit, (ii) identify the specific violated assumption from the six-category list, and (iii) select the appropriate repair from three multiple-choice answers. Wrong submissions add ten seconds, not an irreversible failure. Three progressive hints per challenge are free by default. A complete run therefore exercises **identify → exploit → remediate**. The app does not require a written short answer, but the instructor can ask for one in a separate reflection.

## Honest deployment / academic integrity caveat

The source proposal envisioned a Flask application that stores secret keys and flags server-side. To meet the revised request for a *dependency-free static browser game*, this edition intentionally places the simulation entirely on the client, including generated keys and validation. It provides **real AES computations**, but does **not** provide hidden answers against a student who inspects source, JavaScript memory or devtools. The optional leaderboard is browser-local. It cannot verify who played, stop tampering, detect second devices, or provide secure grading. Do not use the local times/flags as authoritative grades; assess students' explanations, or implement a backend for formal assessment.

## Suggested reflection prompts

- Why does a fresh IV alone not stop an attacker from modifying unauthenticated CBC messages in transit?
- Why can an attacker exploit a brand-new CTR nonce if the receiver has no authentication mechanism?
- In the GCM tag-bypass case, why does the *validity of the original tag* not help after ciphertext alteration?
- In the GCM nonce-reuse case, why does an otherwise correct tag-verification step not restore confidentiality?
- Why are the identical ECB ciphertext blocks evidence of plaintext equality rather than proof of exactly which plaintext occurred?
