/* Cipherbreak: data-driven, local-only CTF controller. No libraries or network requests. */
(function () {
  'use strict';
  const C=window.CryptoLab, BANK=window.CIPHERBREAK_QUESTIONS, SETTINGS=window.CIPHERBREAK_SETTINGS;
  const CATEGORIES=[
    ['ecb','ECB: deterministic block equality / structural leak'],
    ['cbc','CBC: unauthenticated IV malleability'],
    ['ctr','CTR: repeated nonce/counter keystream'],
    ['auth','CTR: ciphertext malleability / no authentication'],
    ['gcm-skip','GCM: authentication tag verification skipped'],
    ['gcm-reuse','GCM: nonce reuse under the same key']
  ];
  const qs=id=>document.getElementById(id);
  const esc=value=>String(value).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const pad=n=>String(Math.floor(n)).padStart(2,'0');
  const fmt=t=>`${pad(t/3600)}:${pad(t/60%60)}:${pad(t%60)}`;
  const shuffle=list=>{const a=[...list];for(let i=a.length-1;i>0;i--){const j=C.random(1)[0]%(i+1);[a[i],a[j]]=[a[j],a[i]];}return a;};
  let state={screen:'home', questions:[],index:0,started:0,penalty:0,ended:0,missions:[],mode:'five',tabSwitches:0,saved:false};
  function pickQuestions(mode){if(mode==='all')return shuffle(BANK);const families=['ecb','cbc','ctr','auth','gcm'];return shuffle(families.map(f=>shuffle(BANK.filter(x=>x.family===f))[0]));}
  function validateBank(){const seen=new Set();const kinds=['ecb-codebook','cbc-iv','ctr-reuse','ctr-malleability','gcm-skip-tag','gcm-reuse'];const families=['ecb','cbc','ctr','auth','gcm'];
    if(!Array.isArray(BANK)||!BANK.length)throw Error('Question bank is empty');
    for(const q of BANK){if(!q.id||seen.has(q.id))throw Error('Question IDs must be nonempty and unique: '+q.id);seen.add(q.id);
      if(!kinds.includes(q.type)||!families.includes(q.family))throw Error('Unknown type/family for '+q.id);
      if(!q.title||!q.briefing||!q.objective||!q.protocol||!q.attackLabel||!q.diagnosis||!q.remediation||!Array.isArray(q.hints)||!q.hints.length)throw Error('Missing required question fields: '+q.id);
      const f=q.remediation;if(!Array.isArray(f.options)||f.options.length<2||!f.options.some(x=>x.id===f.correct))throw Error('Invalid remediation options: '+q.id);
      if(!CATEGORIES.some(([id])=>id===q.diagnosis))throw Error('Invalid diagnosis: '+q.id);
    }
    for(const f of families)if(!BANK.some(x=>x.family===f))throw Error('Need at least one question for family '+f);
  }
  function roleBytes(role){const val={ADMIN:'ROLE=ADMIN______',GUEST:'ROLE=GUEST______',EDITOR:'ROLE=EDITOR_____'}[role];if(!val)throw Error('Unknown role');return C.utf8(val);}
  function makeInstance(def){
    const key=C.random(16), nonce=C.random(12), iv=C.random(16), flag='FLAG{'+C.randomWord(12)+'}';
    const inst={def,key,nonce,iv,flag,stage:'attack',hintCount:0,attempts:0,probeCount:0,oracleMatches:new Set(),finishedAt:null};
    if(def.type==='ecb-codebook'){
      const roles=['ADMIN','GUEST','EDITOR'], target=shuffle(roles)[0], rest=roles.filter(r=>r!==target);
      const sequence=shuffle([target,target,target,rest[0],rest[1]]);
      Object.assign(inst,{targetRole:target,blocks:sequence.map(role=>C.encryptBlock(key,roleBytes(role)))});
    }else if(def.type==='cbc-iv'){
      inst.cipher=C.cbcEncryptBlock(key,iv,roleBytes('GUEST'));
    }else if(def.type==='ctr-reuse'||def.type==='gcm-reuse'){
      inst.known='TOKEN=KNOWNVALUE';inst.secret='TOKEN='+C.randomWord(10);
      const p1=C.utf8(inst.known),p2=C.utf8(inst.secret);
      if(def.type==='ctr-reuse'){inst.knownCipher=C.ctr(key,nonce,p1);inst.unknownCipher=C.ctr(key,nonce,p2);}
      else{const a=C.gcmEncrypt(key,nonce,p1),b=C.gcmEncrypt(key,nonce,p2);inst.knownCipher=a.cipher;inst.unknownCipher=b.cipher;inst.knownTag=a.tag;inst.unknownTag=b.tag;}
    }else if(def.type==='ctr-malleability'){
      inst.cipher=C.ctr(key,nonce,roleBytes('GUEST'));
    }else if(def.type==='gcm-skip-tag'){
      const r=C.gcmEncrypt(key,nonce,roleBytes('GUEST'));inst.cipher=r.cipher;inst.tag=r.tag;
    }
    return inst;
  }
  const current=()=>state.missions[state.index];
  function elapsed(){return state.ended?state.ended-state.started+state.penalty:state.screen==='playing'?Math.max(0,(performance.now()-state.started)/1000)+state.penalty:0;}
  function start(mode){state={screen:'playing',questions:pickQuestions(mode),index:0,started:performance.now(),penalty:0,ended:0,missions:[],mode,tabSwitches:0,saved:false};state.missions=state.questions.map(makeInstance);render();}
  function penalty(){state.penalty+=Number(SETTINGS.penaltySeconds)||0;}
  function message(s,kind='warn'){const el=qs('feedback');if(el){el.textContent=s;el.className='feedback '+kind;el.hidden=false;}}
  function valueOr(id){const el=qs(id);return el?el.value.trim():'';}
  function copyable(label,value){return `<div class="datum"><div class="datum-head"><span>${esc(label)}</span><button class="icon-btn" type="button" data-action="copy" data-copy="${esc(value)}" title="Copy ${esc(label)}" aria-label="Copy ${esc(label)}">COPY ↗</button></div><code class="data-value">${esc(value)}</code></div>`;}
  function makeEvidence(m){const d=m.def;
    if(d.type==='ecb-codebook')return `<div class="evidence-heading">CAPTURED ENCRYPTED BLOCKS <span class="chip">AES-ECB · 16B per block</span></div><div class="blocks">${m.blocks.map((b,i)=>`<div class="block-row"><span class="block-index">${String(i+1).padStart(2,'0')}</span><code>${C.hex(b)}</code><button type="button" data-action="copy" data-copy="${C.hex(b)}" title="Copy block ${i+1}" class="mini-copy">COPY</button></div>`).join('')}</div><div class="oracle"><div class="section-small">ECB ENCRYPTION ORACLE <span>— exact 16 ASCII bytes</span></div><div class="inline-fields"><input id="oracle-plain" type="text" placeholder="ROLE=ADMIN______" maxlength="16" aria-label="Oracle plaintext"/><button class="btn btn-secondary" data-action="oracle">Encrypt probe</button></div><div id="oracle-output" class="oracle-result" aria-live="polite">No probe sent yet.</div></div>`;
    if(d.type==='cbc-iv')return `<div class="evidence-grid">${copyable('CBC IV · editable',C.hex(m.iv))}${copyable('C₁ · fixed encrypted block',C.hex(m.cipher))}${copyable('Known P₁ · ASCII','ROLE=GUEST______')}${copyable('Required P₁′ · ASCII','ROLE=ADMIN______')}</div>`;
    if(d.type==='ctr-reuse'||d.type==='gcm-reuse')return `<div class="evidence-grid">${copyable('Shared 96-bit nonce',C.hex(m.nonce))}${copyable('Known plaintext · ASCII',m.known)}${copyable('Known-message ciphertext',C.hex(m.knownCipher))}${copyable('Unknown-message ciphertext',C.hex(m.unknownCipher))}${d.type==='gcm-reuse'?copyable('Known GCM tag (valid)',C.hex(m.knownTag))+copyable('Unknown GCM tag (valid)',C.hex(m.unknownTag)):''}</div>`;
    return `<div class="evidence-grid">${copyable('96-bit nonce · fixed',C.hex(m.nonce))}${copyable('Intercepted ciphertext',C.hex(m.cipher))}${copyable('Known plaintext · ASCII','ROLE=GUEST______')}${copyable('Target plaintext · ASCII','ROLE=ADMIN______')}${d.type==='gcm-skip-tag'?copyable('Original 128-bit tag · fixed',C.hex(m.tag)):''}</div>`;
  }
  function renderMission(){const m=current(),d=m.def;
    const attackDone=m.stage!=='attack',clear=m.stage==='complete';
    const step=['01 / EXPLOIT','02 / DIAGNOSE + REPAIR','03 / CAPTURE FLAG'];
    const form=attackDone?'':`<div class="answer-card"><div class="card-eyebrow">ATTACK SUBMISSION</div><label for="attack-answer" class="answer-label">${esc(d.attackLabel)}</label><div class="inline-fields"><input id="attack-answer" ${d.type==='ecb-codebook'?'maxlength="6"':''} type="text" spellcheck="false" autocomplete="off" placeholder="${d.type==='ecb-codebook'?'ADMIN / GUEST / EDITOR':d.type.includes('reuse')?'TOKEN=…':d.type==='ctr-reuse'?'TOKEN=…':'Paste modified hex bytes'}"/><button class="btn btn-primary" data-action="attack">Test exploit <span aria-hidden="true">↗</span></button></div><p class="helper">Experiments are local. Incorrect submissions add ${SETTINGS.penaltySeconds} seconds; hints are free.</p></div>`;
    const repair=attackDone&&!clear?`<div class="answer-card success-border"><div class="card-eyebrow success-text">EXPLOIT CONFIRMED · NEXT: EXPLAIN THE FAILURE</div><p class="repair-text">You exploited the behavior. To capture your flag, identify the <strong>specific violated assumption</strong> and choose an appropriate repair.</p><label class="answer-label" for="category-choice">Which vulnerability best explains this attack?</label><select id="category-choice"><option value="">Select the precise failure...</option>${CATEGORIES.map(([id,name])=>`<option value="${id}">${esc(name)}</option>`).join('')}</select><fieldset class="repair-options"><legend>${esc(d.remediation.prompt)}</legend>${d.remediation.options.map((o,i)=>`<label class="radio-option"><input type="radio" name="fix" value="${esc(o.id)}"/><span><small>${String.fromCharCode(65+i)}</small> ${esc(o.text)}</span></label>`).join('')}</fieldset><button class="btn btn-primary" data-action="diagnose">Validate diagnosis + repair ↗</button></div>`:'';
    const completed=clear?`<div class="complete-card"><div class="verified">✓ ATTACK · DIAGNOSIS · REPAIR VERIFIED</div><div class="flag-label">CAPTURED FLAG</div><div class="flag-row"><code>${esc(m.flag)}</code><button class="icon-btn" data-action="copy" data-copy="${esc(m.flag)}">COPY</button></div><p>${esc(d.remediation.explanation)}</p><button class="btn btn-primary" data-action="next">${state.index===state.missions.length-1?'Finish session':'Next intercepted system'} ↗</button></div>`:'';
    const stage=clear?3:attackDone?2:1;
    return `<div class="mission-head"><div><div class="eyebrow">MISSION ${pad(state.index+1)} / ${pad(state.missions.length)} · ${esc(d.kicker||'SECURITY AUDIT')}</div><h1>${esc(d.title)}</h1><p>${esc(d.briefing)}</p></div><div class="mission-number">${pad(state.index+1)}<span> / ${pad(state.missions.length)}</span></div></div>
      <div class="steps">${step.map((s,i)=>`<span class="step ${stage>i+1?'past':stage===i+1?'active':''}">${s}</span>`).join('')}</div>
      <div class="briefing-panel"><div class="card-eyebrow">YOUR OBJECTIVE</div><p>${esc(d.objective)}</p><div class="protocol-note"><span>PROTOCOL NOTES</span><p>${esc(d.protocol)}</p></div></div>
      <div class="evidence-panel"><div class="section-heading"><span>01</span><h2>Intercepted evidence</h2><div class="rule"></div></div>${makeEvidence(m)}</div>
      <div class="section-heading"><span>02</span><h2>${attackDone?'Root cause & remediation':'Exploit the implementation'}</h2><div class="rule"></div></div>
      ${form}${repair}${completed}<div id="feedback" class="feedback" hidden role="status" aria-live="polite"></div>`;
  }
  function sideNav(){const list=state.missions.map((m,i)=>{
    const done=m.stage==='complete',active=i===state.index;return `<div class="mission-nav-item ${active?'selected':''} ${done?'done':''}" aria-current="${active?'step':'false'}"><div class="nav-num">${done?'✓':pad(i+1)}</div><div class="nav-text"><strong>${esc(m.def.title)}</strong><span>${done?'FLAG CAPTURED':active?'IN PROGRESS':'ENCRYPTED TARGET'}</span></div><div class="nav-dot"></div></div>`;
  }).join('');return `<div class="sidebar-title">MISSION QUEUE <span>${state.missions.filter(m=>m.stage==='complete').length}/${state.missions.length}</span></div><div class="mission-nav">${list}</div><div class="sidebar-note"><strong>ATTACK THE ASSUMPTION</strong><p>Each mission has a real AES instance with randomized inputs. The encryption primitive is not broken—its deployment is.</p></div>`;}
  function loadScores(){try{return JSON.parse(localStorage.getItem('cipherbreak-scores-v1')||'[]')||[];}catch(_){return [];}}
  function saveScores(scores){try{localStorage.setItem('cipherbreak-scores-v1',JSON.stringify(scores));return true;}catch(_){return false;}}
  function scoreHTML(){const scores=loadScores();return `<div class="leader-title">LOCAL PRACTICE BOARD <span>THIS BROWSER ONLY</span></div>${scores.length?`<div class="score-table">${scores.slice(0,SETTINGS.scoreboardSize).map((x,i)=>`<div class="score-row"><b>${pad(i+1)}</b><span>${esc(x.name)}</span><small>${esc(x.mode==='all'?'FULL BANK':'FIVE FAMILIES')}${SETTINGS.showTabSwitchTracker?' · TAB LEAVES '+Number(x.tabSwitches||0):''}</small><strong>${fmt(x.time)}</strong></div>`).join('')}</div>`:'<p class="empty-scores">No completed sessions on this browser yet.</p>'}`;}
  function homeHTML(){return `<div class="landing"><div class="landing-tag"><span class="pulse-dot"></span> ACTIVE TRAINING ENVIRONMENT <span class="divider-mark">/</span> ECE576</div><h1>BREAK THE <em>IMPLEMENTATION.</em><br/>NOT THE CIPHER.</h1><p class="landing-description">An interactive capture-the-flag lab on encryption modes, IVs, nonces, malleability and authenticated encryption. Intercept packets, exploit a misuse of real AES, explain why it failed, and prescribe the fix to earn each flag.</p><div class="landing-metrics"><div><strong>05</strong><span>VULNERABILITY FAMILIES</span></div><div><strong>06</strong><span>QUESTION TEMPLATES</span></div><div><strong>00</strong><span>DEPENDENCIES</span></div></div><div class="landing-actions"><button class="btn btn-primary btn-large" data-action="start-five">Start five-family sprint ↗</button><button class="btn btn-outline btn-large" data-action="start-all">Play all six scenarios</button></div><p class="landing-footnote">Five-family sprint selects one of two distinct GCM cases each run. Approximately 20–35 minutes recommended for the sprint; self-paced. All challenges have randomized keys, nonces and flags.</p><div class="landing-bottom"><div class="learning-card"><div class="card-eyebrow">EACH MISSION</div><div class="learn-step">01 <span>EXAMINE packet evidence</span></div><div class="learn-step">02 <span>PERFORM a working exploit</span></div><div class="learn-step">03 <span>NAME the violated assumption</span></div><div class="learn-step">04 <span>SELECT the security repair</span></div><div class="learn-step">05 <span>CAPTURE the flag</span></div></div><div class="leaderboard">${scoreHTML()}</div></div><div class="fine-print">GitHub Pages / offline ready. No third-party scripts, accounts, uploads, or network connections. This static training edition is not tamper-resistant: answers and keys exist in the browser; local scores are not suitable for formal grading.</div></div>`;}
  function finalHTML(){const t=fmt(elapsed());return `<div class="finish"><div class="finish-icon">✓</div><div class="eyebrow">ALL TARGETS CLEARED</div><h1>SESSION COMPLETE.</h1><p>You've exploited the weaknesses, identified their root causes, and chosen a security repair for every mission.</p><div class="finish-stats"><div><strong>${t}</strong><span>TOTAL SCORE TIME</span></div><div><strong>${state.missions.length}/${state.missions.length}</strong><span>FLAGS CAPTURED</span></div><div><strong>+${state.penalty}s</strong><span>ERROR PENALTIES</span></div></div><div class="finish-flags">${state.missions.map((m,i)=>`<div><span>${pad(i+1)} · ${esc(m.def.title)}</span><code>${esc(m.flag)}</code></div>`).join('')}</div>${state.storageFailed?'<p class="feedback warn">Browser storage is unavailable. Your session still completed.</p>':''}${state.saved?'<p class="saved-note">Your result was added to this browser’s local practice board.</p>':`<div class="save-score"><label for="score-name">Local leaderboard name (optional)</label><div class="inline-fields"><input id="score-name" maxlength="22" placeholder="Student / alias"/><button class="btn btn-primary" data-action="save-score">Save local result</button></div></div>`}<div class="finish-actions"><button class="btn btn-secondary" data-action="restart">New randomized session</button></div><div class="leaderboard">${scoreHTML()}</div><p class="fine-print">Results are local and editable in browser developer tools. Use a server-backed scoreboard for graded competition.</p></div>`;}
  function toolsHTML(){return `<div class="tool-head"><div class="sidebar-title">FIELD WORKBENCH <span>BUILT-IN</span></div><p>Nothing leaves your browser. Use the tools to solve the attack.</p></div><div class="tool-tabs" role="tablist" aria-label="Workbench tools"><button class="tool-tab active" data-action="tool-tab" data-tool="xor" role="tab" aria-selected="true">XOR</button><button class="tool-tab" data-action="tool-tab" data-tool="convert" role="tab" aria-selected="false">ENCODE</button><button class="tool-tab" data-action="tool-tab" data-tool="blocks" role="tab" aria-selected="false">BLOCKS</button></div><div class="tool-body"><div class="tool-content" id="tool-xor"><label for="xor-a">HEX INPUT A</label><textarea id="xor-a" rows="2" placeholder="Paste even-length hex"></textarea><label for="xor-b">HEX INPUT B</label><textarea id="xor-b" rows="2" placeholder="Same byte length as A"></textarea><button class="btn btn-secondary btn-full" data-action="xor">XOR A ⊕ B</button><div class="tool-output"><div class="result-label">RESULT · HEX</div><code id="xor-out">—</code></div><button class="tiny-action" data-action="xor-swap">Use result as input A ↗</button></div><div class="tool-content" id="tool-convert" hidden><label for="convert-input">UTF-8 TEXT / HEX BYTES</label><textarea rows="3" id="convert-input" placeholder="Text or hexadecimal"></textarea><div class="tool-button-grid"><button class="btn btn-secondary" data-action="text-hex">Text → hex</button><button class="btn btn-secondary" data-action="hex-text">Hex → text</button></div><div class="tool-output"><div class="result-label">CONVERSION OUTPUT</div><code id="convert-out">—</code></div><button class="tiny-action" data-action="convert-to-xor">Send hex result to XOR A ↗</button></div><div class="tool-content" id="tool-blocks" hidden><label for="block-input">CIPHERTEXT IN HEX</label><textarea rows="3" id="block-input" placeholder="Paste multi-block ciphertext"></textarea><button class="btn btn-secondary btn-full" data-action="split-blocks">Display 16-byte AES blocks</button><div class="block-tool-output" id="block-out">—</div></div><div class="tool-feedback" id="tool-feedback" role="status" aria-live="polite"></div></div><div class="hint-zone"><div class="hint-zone-head">INTELLIGENCE HINTS <span id="hint-count"></span></div><p>Hints are incremental and don't affect your score.</p><button class="btn btn-hint btn-full" data-action="hint" id="hint-button">Reveal next hint ↗</button><div id="hint-list" class="hint-list"></div></div><div class="tool-disclaimer">AES-128 · Real CBC/CTR/GCM operations<br/>Pure JavaScript · Lab simulation only</div>`;}
  function render(){const playing=state.screen==='playing';qs('home').hidden=state.screen!=='home';qs('play').hidden=!playing;qs('final').hidden=state.screen!=='finished';qs('reset-top').hidden=state.screen==='home';qs('top-progress').textContent=state.screen==='home'?'READY':state.screen==='finished'?'COMPLETE':`${state.missions.filter(m=>m.stage==='complete').length}/${state.missions.length} FLAGS`;
    qs('top-timer').textContent=state.screen==='home'?'00:00:00':fmt(elapsed());
    if(state.screen==='home')qs('home').innerHTML=homeHTML();
    if(playing){qs('mission-list').innerHTML=sideNav();qs('mission-panel').innerHTML=renderMission();qs('workbench').innerHTML=toolsHTML();renderHints();}
    if(state.screen==='finished')qs('final').innerHTML=finalHTML();
  }
  function renderHints(){const m=current();if(!m)return;qs('hint-count').textContent=`${m.hintCount}/${m.def.hints.length}`;qs('hint-list').innerHTML=m.def.hints.slice(0,m.hintCount).map((h,i)=>`<div class="hint-item"><b>HINT ${i+1}</b><p>${esc(h)}</p></div>`).join('');qs('hint-button').disabled=m.hintCount>=m.def.hints.length;}
  function attack(){const m=current(),ans=valueOr('attack-answer'),type=m.def.type;try{if(!ans)throw Error('Enter an attack submission first.');let ok=false;
    if(type==='ecb-codebook'){const role=ans.toUpperCase();if(!['ADMIN','GUEST','EDITOR'].includes(role))throw Error('Enter ADMIN, GUEST or EDITOR.');if(!m.oracleMatches.has(role))throw Error('First use the ECB oracle to encrypt this precise role, then compare its block.');ok=role===m.targetRole;}
    else if(type==='cbc-iv'){const b=C.fromHex(ans);if(b.length!==16)throw Error('IV must contain exactly 16 bytes (32 hex digits)');ok=C.hex(C.cbcDecryptBlock(m.key,b,m.cipher))===C.hex(roleBytes('ADMIN'));}
    else if(type==='ctr-malleability'||type==='gcm-skip-tag'){const b=C.fromHex(ans);if(b.length!==16)throw Error('Ciphertext must be 16 bytes (32 hex digits)');if(type==='ctr-malleability')ok=C.hex(C.ctr(m.key,m.nonce,b))===C.hex(roleBytes('ADMIN'));
      else{const r=C.gcmDecrypt(m.key,m.nonce,b,m.tag,undefined,false);ok=C.hex(r.plain)===C.hex(roleBytes('ADMIN'))&&!r.authenticated;}}
    else if(type==='ctr-reuse'||type==='gcm-reuse'){ok=ans===m.secret;}
    if(!ok){m.attempts++;penalty();message(`The receiver did not accept this exploit. Review the evidence. +${SETTINGS.penaltySeconds}s penalty.`,'warn');return;}
    m.stage='repair';render();message(type==='gcm-skip-tag'?'Vulnerable receiver accepted the forged command. A proper GCM receiver rejects it because the unchanged tag FAILS authentication. Now diagnose and repair.':'Exploit validated. The next step is to identify the exact weakness and the correct repair.','success');
  }catch(e){message(e.message,'warn');}}
  function oracle(){const m=current();if(!m||m.def.type!=='ecb-codebook')return;const plain=valueOr('oracle-plain');const p=C.utf8(plain);if(p.length!==16){const out=qs('oracle-output');out.textContent='The oracle requires exactly 16 UTF-8 bytes. Current length: '+p.length;out.classList.add('error');return;}
    const h=C.hex(C.encryptBlock(m.key,p));m.probeCount++;const match=m.blocks.map((b,i)=>C.hex(b)===h?i+1:null).filter(Boolean);const out=qs('oracle-output');out.classList.remove('error');out.innerHTML=`<code>${h}</code><span>${match.length?`MATCHES captured blocks #${match.join(', #')}`:'No captured block matches this input.'}</span>`;
    for(const r of ['ADMIN','GUEST','EDITOR'])if(plain===C.text(roleBytes(r))&&match.length)m.oracleMatches.add(r);
  }
  function diagnose(){const m=current();const diagnosis=valueOr('category-choice'),fix=document.querySelector('input[name="fix"]:checked')?.value||'';
    if(!diagnosis||!fix){message('Choose both the violated assumption and a repair.','warn');return;}
    if(diagnosis!==m.def.diagnosis||fix!==m.def.remediation.correct){m.attempts++;penalty();message(`At least one selection is incorrect. Identify the precise failure, not merely the cipher name. +${SETTINGS.penaltySeconds}s penalty.`,'warn');return;}
    m.stage='complete';m.finishedAt=performance.now();render();
  }
  function next(){if(state.index===state.missions.length-1){state.ended=(performance.now()-state.started)/1000;state.screen='finished';render();}else{state.index++;render();}}
  function toolMessage(text,isError=false){const el=qs('tool-feedback');if(el){el.textContent=text;el.classList.toggle('error',isError);}}
  function runTool(action){try{if(action==='xor'){const a=C.fromHex(valueOr('xor-a')),b=C.fromHex(valueOr('xor-b'));const out=C.hex(C.xor(a,b));qs('xor-out').textContent=out;toolMessage(`${a.length} bytes XORed successfully.`);}
    else if(action==='xor-swap'){const h=qs('xor-out').textContent;if(!/^[0-9a-f]+$/i.test(h))throw Error('Calculate an XOR result first');qs('xor-a').value=h;toolMessage('Result copied into XOR input A.');}
    else if(action==='text-hex'){qs('convert-out').textContent=C.hex(C.utf8(qs('convert-input').value));toolMessage('Text encoded as UTF-8 hex.');}
    else if(action==='hex-text'){qs('convert-out').textContent=C.text(C.fromHex(valueOr('convert-input')));toolMessage('Hex decoded as UTF-8 text.');}
    else if(action==='convert-to-xor'){const v=qs('convert-out').textContent;if(!/^[0-9a-f]+$/i.test(v))throw Error('Convert text into hex first');qs('xor-a').value=v;toolMessage('Hex placed in XOR input A.');}
    else if(action==='split-blocks'){const a=C.fromHex(valueOr('block-input'));const count=Math.ceil(a.length/16);qs('block-out').innerHTML=Array.from({length:count},(_,i)=>`<div><b>BLOCK ${i+1}</b><code>${C.hex(a.slice(i*16,(i+1)*16))}</code></div>`).join('');toolMessage(`${count} AES block(s), final block may be partial.`);}
  }catch(e){toolMessage(e.message,true);}}
  function selectTool(name){for(const tab of document.querySelectorAll('.tool-tab')){const active=tab.dataset.tool===name;tab.classList.toggle('active',active);tab.setAttribute('aria-selected',String(active));}for(const pane of document.querySelectorAll('.tool-content'))pane.hidden=pane.id!=='tool-'+name;}
  async function copy(s){try{if(navigator.clipboard&&navigator.clipboard.writeText){await navigator.clipboard.writeText(s);return;} }catch(_){}const t=document.createElement('textarea');t.value=s;t.style.position='fixed';t.style.opacity='0';document.body.appendChild(t);t.select();try{document.execCommand('copy');}finally{t.remove();}}
  function saveScore(){if(state.saved)return;const alias=valueOr('score-name').replace(/\s+/g,' ').slice(0,22)||'Anonymous';const scores=loadScores();scores.push({name:alias,time:Math.round(elapsed()),mode:state.mode,tabSwitches:state.tabSwitches,date:new Date().toISOString()});scores.sort((a,b)=>a.time-b.time);if(!saveScores(scores.slice(0,100)))state.storageFailed=true;else state.saved=true;render();}
  document.addEventListener('click',e=>{const button=e.target.closest('[data-action]');if(!button||button.disabled)return;const a=button.dataset.action;
    if(a==='start-five')return start('five');if(a==='start-all')return start('all');if(a==='restart'||a==='reset')return (state={screen:'home',questions:[],missions:[],index:0,started:0,penalty:0,ended:0},render());
    if(a==='attack')return attack();if(a==='oracle')return oracle();if(a==='diagnose')return diagnose();if(a==='next')return next();
    if(a==='hint'){const m=current();if(m.hintCount<m.def.hints.length){m.hintCount++;state.penalty+=SETTINGS.hintPenaltySeconds||0;renderHints();}return;}
    if(a==='tool-tab')return selectTool(button.dataset.tool);
    if(['xor','xor-swap','text-hex','hex-text','convert-to-xor','split-blocks'].includes(a))return runTool(a);
    if(a==='copy'){copy(button.dataset.copy||'').then(()=>{if(state.screen==='playing')toolMessage('Copied to clipboard (if browser permits).');});return;}
    if(a==='save-score')return saveScore();
  });
  document.addEventListener('keydown',e=>{if(e.key==='Enter'&&e.target?.id==='attack-answer'){e.preventDefault();attack();}if(e.key==='Enter'&&e.target?.id==='oracle-plain'){e.preventDefault();oracle();}});
  document.addEventListener('visibilitychange',()=>{if(state.screen==='playing'&&document.hidden&&SETTINGS.showTabSwitchTracker)state.tabSwitches++;});
  setInterval(()=>{if(state.screen==='playing')qs('top-timer').textContent=fmt(elapsed());},250);
  try{validateBank();render();}catch(err){document.body.innerHTML=`<div style="margin:6rem auto;max-width:42rem;font:16px system-ui;color:#e8e8e8"><h1>Question bank configuration error</h1><p>${esc(err.message)}</p><p>Check js/challenges.js and docs/ADDING_QUESTIONS.md.</p></div>`;console.error(err);}
})();
