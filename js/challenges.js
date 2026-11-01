/* EDIT THIS FILE TO ADD QUESTIONS. No code changes, build tools or dependencies required.
   Copy any object, give it a UNIQUE id, retain a supported type and family, and edit the text.
   Supported types: ecb-codebook, cbc-iv, ctr-reuse, ctr-malleability,
                    gcm-skip-tag, gcm-reuse.
   The engine generates fresh AES-128 keys, IVs/nonces, ciphertexts, and flags automatically.
   All questions are real AES demonstrations, not pre-recorded puzzles.
*/
window.CIPHERBREAK_QUESTIONS = [
  {
    id: 'archive-role-pattern', family: 'ecb', type: 'ecb-codebook',
    title: 'The Archive Terminal', kicker: 'INTERCEPTED RECORDS',
    briefing: 'A records server encrypts independent 16-byte fields with AES-ECB. Some records contain the same access role. You can submit one 16-byte guess to its encryption oracle at a time.',
    objective: 'Determine which role is encrypted in the block that appears THREE times among the captured blocks. Test a candidate against the oracle and submit the recovered role.',
    protocol: 'Possible 16-byte fields: ROLE=ADMIN______ ; ROLE=GUEST______ ; ROLE=EDITOR_____ . An identical 16-byte input produces an identical ECB ciphertext block under the same key.',
    attackLabel: 'Recovered repeated role',
    hints: [
      'ECB encrypts each 16-byte block independently. First find the block appearing three times.',
      'Submit a likely 16-byte ROLE=... field to the oracle and compare its ciphertext against the repeated block.',
      'Try ROLE=ADMIN______ or ROLE=GUEST______ or ROLE=EDITOR_____ — preserve the underscores and length.'
    ],
    diagnosis: 'ecb',
    remediation: {
      prompt: 'What is the most appropriate explanation and repair?',
      options: [
        {id:'a', text:'Use a properly implemented randomized/nonce-based secure encryption mode such as AES-GCM; ECB deterministically exposes equal blocks.'},
        {id:'b', text:'Keep AES-ECB, but hide ciphertext block boundaries from the user.'},
        {id:'c', text:'Publish a fresh but constant IV with every ECB message; this will randomize ECB.'}
      ], correct:'a',
      explanation:'ECB independently encrypts equal plaintext blocks into equal ciphertext blocks. It leaks equality and structure, even though AES itself may be secure. ECB has no IV. Use a secure mode with proper nonce handling, normally authenticated encryption.'
    }
  },
  {
    id:'enrollment-iv-swap', family:'cbc', type:'cbc-iv',
    title:'The Enrollment Gateway', kicker:'MODIFIABLE PACKET HEADER',
    briefing:'An old service decrypts one AES-CBC block and grants access based on the first decrypted field. The encrypted block is fixed, but the network attacker can replace its 16-byte IV. There is no message authentication.',
    objective:'Change only the IV so that the receiver decrypts ROLE=ADMIN______ instead of ROLE=GUEST______. Submit the full replacement IV in hex.',
    protocol:'Known first plaintext = ROLE=GUEST______ (16 bytes). Desired = ROLE=ADMIN______ (16 bytes). First-block CBC decryption: P₁ = Dₖ(C₁) XOR IV. The IV is not a secret.',
    attackLabel:'Replacement IV (32 hex characters)',
    hints:[
      'In CBC, modifying the IV modifies the first decrypted plaintext block, without changing C₁.',
      'Compute Δ = bytes("ROLE=GUEST______") XOR bytes("ROLE=ADMIN______").',
      'The forged IV is oldIV XOR Δ. Use the Hex/XOR workbench on the right; both byte strings must be 16 bytes.'
    ],
    diagnosis:'cbc',
    remediation:{prompt:'What exactly failed, and how should it be fixed?',
      options:[
        {id:'a',text:'The IV was visible. CBC IVs must remain secret to avoid this attack.'},
        {id:'b',text:'The IV and ciphertext were unauthenticated. Authenticate both (e.g., encrypt-then-MAC) or switch to AEAD, and use unpredictable fresh IVs for CBC encryption.'},
        {id:'c',text:'Reuse the same IV for every message, so attackers cannot predict whether it changes.'}
      ], correct:'b',
      explanation:'This is CBC first-block malleability when IV and ciphertext lack integrity protection. The CBC IV need not be secret; encryption requires an appropriate unpredictable IV. Authenticating the IV and ciphertext stops tampering.'}
  },
  {
    id:'telemetry-counter-collision', family:'ctr', type:'ctr-reuse',
    title:'The Telemetry Relay', kicker:'TWO MESSAGES, ONE COUNTER',
    briefing:'A monitoring service encrypted two short messages under the same AES-CTR key, 96-bit nonce and initial counter. You intercepted both; one plaintext is known.',
    objective:'Recover the FULL plaintext of the unknown message and enter it exactly, including punctuation and capitalization.',
    protocol:'CTR: C = P XOR keystream. When the (key, nonce, counter) repeats, C₁ XOR C₂ = P₁ XOR P₂. Both messages are 16 ASCII bytes.',
    attackLabel:'Recovered unknown plaintext (ASCII)',
    hints:[
      'First convert the known message from text into hex with the workbench.',
      'Compute keystream = known plaintext XOR known ciphertext.',
      'Recover unknown plaintext = unknown ciphertext XOR keystream, then convert hex to text.'
    ],
    diagnosis:'ctr',
    remediation:{prompt:'Which fix prevents this failure?',options:[
      {id:'a',text:'Ensure that every AES-CTR nonce/counter stream is unique for a given key, with wraparound prevented; authenticated encryption is preferable when integrity is needed.'},
      {id:'b',text:'Verify an authentication tag without changing the repeated nonce.'},
      {id:'c',text:'Make the plaintext longer; keystream reuse only affects one-block messages.'}
    ],correct:'a',explanation:'CTR reusing the same keystream leaks the XOR of plaintexts and can reveal an unknown message from a known one. A nonce/counter combination must never repeat under the same key. CTR alone also does not provide integrity.'}
  },
  {
    id:'dispatch-unauthenticated-change', family:'auth',type:'ctr-malleability',
    title:'The Dispatch Console', kicker:'NO AUTHENTICATION FIELD',
    briefing:'A dispatch endpoint uses AES-CTR with a unique nonce, but no MAC or authentication tag. The operator accepts and acts on every decrypted command.',
    objective:'Forge a ciphertext that makes the receiver process ROLE=ADMIN______ instead of the intercepted ROLE=GUEST______. Keep the original nonce.',
    protocol:'CTR encryption: C = P XOR keystream. Changing a ciphertext bit flips the corresponding plaintext bit. This attack does NOT depend on nonce reuse.',
    attackLabel:'Forged ciphertext (32 hex characters)',
    hints:[
      'The nonce is fresh here, so this is NOT the nonce-reuse attack.',
      'With known plaintext P and desired P′, calculate C′ = C XOR P XOR P′.',
      'Convert the two role strings to hex. XOR the result with the intercepted ciphertext using the workbench.'
    ],diagnosis:'auth',
    remediation:{prompt:'What change most directly defeats this attack?', options:[
      {id:'a',text:'Increase the nonce length but continue accepting ciphertext without integrity verification.'},
      {id:'b',text:'Use authenticated encryption such as AES-GCM with correct tag validation, or securely authenticate the entire CTR message before acting.'},
      {id:'c',text:'Keep the AES-CTR nonce secret instead of sending it with ciphertext.'}
    ],correct:'b',explanation:'CTR encryption offers confidentiality but not integrity. An attacker can predictably alter decrypted bytes by XORing the ciphertext. Fresh nonces do not stop malleability. Authentication of the entire message does.'}
  },
  {
    id:'vault-tag-ignored', family:'gcm',type:'gcm-skip-tag',
    title:'The Vault Receiver', kicker:'AUTHENTICATION BYPASSED',
    briefing:'A gateway uses AES-GCM with a fresh nonce and generates a genuine 128-bit tag. However, an application bug discards authentication errors and uses the decrypted plaintext anyway.',
    objective:'Alter the encrypted ROLE=GUEST______ command into ROLE=ADMIN______, leaving the original GCM tag and nonce untouched. The receiver must accept it only because it skips tag verification.',
    protocol:'AES-GCM encrypts with CTR-style keystream and also authenticates the packet with a tag. The nonce is NOT reused here. A correct receiver MUST reject any modified ciphertext whose tag no longer verifies.',
    attackLabel:'Tampered GCM ciphertext (32 hex characters)',
    hints:[
      'Do not alter the nonce or the tag. The bug is that the receiver ignores a failed tag check.',
      'GCM ciphertext is CTR-style: C′ = C XOR P XOR P′ for a chosen bit flip.',
      'Keep the supplied tag unchanged. A compliant GCM decryptor would reject your forged packet before processing plaintext.'
    ],diagnosis:'gcm-skip',
    remediation:{prompt:'Which remediation targets this exact GCM defect?', options:[
      {id:'a',text:'Verify the complete GCM tag successfully before releasing or processing any plaintext, and reject all failures.'},
      {id:'b',text:'Use a longer random nonce but continue processing failed-tag plaintext.'},
      {id:'c',text:'Hide the tag from a network attacker; GCM tags must be secret.'}
    ],correct:'a',explanation:'The nonce is fresh; GCM itself produces a correct tag. The application nullifies authentication by ignoring a failed tag verification. Never release or act on plaintext when tag validation fails.'}
  },
  {
    id:'vault-key-stream-reuse', family:'gcm',type:'gcm-reuse',
    title:'The Counter Reset', kicker:'SECOND GCM CASE / NONCE COLLISION',
    briefing:'A different AES-GCM service restarts after a crash and accidentally reuses a 96-bit nonce with the same key. Both messages have valid authentication tags, but one plaintext is known.',
    objective:'Recover the unknown message plaintext exactly. This is a confidentiality failure caused by GCM nonce reuse—not a failure to check its tags.',
    protocol:'Under a repeated (key, nonce), GCM reuses its CTR keystream. Thus C₁ XOR C₂ = P₁ XOR P₂. Valid tags do not prevent this confidentiality leak.',
    attackLabel:'Recovered unknown plaintext (ASCII)',
    hints:[
      'The two packets share a nonce. Their tags are not used in this confidentiality attack.',
      'Compute keystream = known plaintext XOR known ciphertext.',
      'Then XOR the keystream with the other ciphertext. Convert the resulting hex to ASCII.'
    ],diagnosis:'gcm-reuse',
    remediation:{prompt:'What fixes this separate GCM problem?', options:[
      {id:'a',text:'Make nonce reuse impossible for each key (including across restarts) or rotate to a fresh key before nonce collisions can occur.'},
      {id:'b',text:'Skip authentication verification so repeated packets are processed consistently.'},
      {id:'c',text:'Make the authentication tag longer; this restores confidentiality even when the keystream repeats.'}
    ],correct:'a',explanation:'AES-GCM requires nonce uniqueness per key. Reusing a nonce repeats the CTR keystream, compromising confidentiality and potentially integrity. Verifying tags is still essential, but it does not fix a repeated nonce.'}
  }
];

// The game chooses one RANDOM GCM question (five-family run). "Full bank" plays all six.
window.CIPHERBREAK_SETTINGS = {
  title:'CIPHERBREAK',
  penaltySeconds:10,
  hintPenaltySeconds:0,
  showTabSwitchTracker:false, // optional, informational only; NEVER use for grading
  scoreboardSize:8
};
