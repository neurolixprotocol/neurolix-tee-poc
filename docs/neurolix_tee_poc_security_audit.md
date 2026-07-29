# Security Audit — `neurolix-tee-poc`
### Confidential Compute / TEE (AMD SEV · Google Cloud Confidential Space) — Inferenza ML & LLM in enclave

**Auditor role:** AppSec Engineer / Senior Security Auditor (Confidential Computing, TEE, ML/LLM security) — modalità ipercritica.
**Scope:** `neurolix_inference.py`, `neurolix_llm.py`, `requirements.txt`, `neurolix_poc_report.json`.
**Data:** 2026-06-05
**Ground truth:** audit eseguito sui file caricati in questa sessione. Prima di applicare qualsiasi fix, **verificare che questi file coincidano con l'HEAD del repo** (la connessione GitHub è l'unica fonte di verità — non assumere parità).

---

## 0. Verdetto esecutivo (senza giri di parole)

Il PoC **non fornisce nessuna delle garanzie di confidenzialità che dichiara di fornire.** Non è un problema di "qualche bug da sistemare": è che la tesi centrale del prodotto — *"i dati non escono mai dalla memoria cifrata"* e *"computazione attestata dentro l'enclave"* — è **falsa così com'è scritta**, su tre assi indipendenti e simultanei:

1. **Non c'è cifratura.** Il `ENCRYPTED_PAYLOAD` è base64 di plaintext. I dati sanitari dei pazienti sono **in chiaro, hardcoded nel sorgente**.
2. **Non c'è attestazione.** `generate_attestation()` inventa stringhe (`"tee_type": "AMD SEV"`) e calcola un hash degli output. Non viene **mai** richiesto il token di attestazione di Confidential Space. Il commitment ancorato on-chain **non prova nulla** su dove sia girata la computazione.
3. **C'è esfiltrazione.** Entrambi gli script stampano i dati sanitari, i prompt riservati e gli output del modello su **stdout**, che in Confidential Space finisce in Cloud Logging — **fuori** dal confine cifrato e leggibile dall'operatore.

Il file `neurolix_poc_report.json` certifica `"data_exposed": false`: è una **falsa attestazione**, contraddetta dal codice stesso.

**Raccomandazione bloccante:** non promuovere questo PoC come "Confidential AI attestata" in nessun materiale pubblico né ancorarne i commitment on-chain come prova di confidenzialità finché C1–C5 non sono risolti. Allo stato attuale è *security theater* con un hash sopra.

---

## 1. Threat model assunto

- **Avversario 1 — Operatore del cloud / chi ha accesso al progetto GCP:** non deve poter leggere i dati dei pazienti. Vettori: Cloud Logging, serial console, core dump, metadati, rete in uscita.
- **Avversario 2 — Relying party / verificatore on-chain:** deve poter verificare *crittograficamente* che un output deriva da un'immagine nota eseguita in un TEE genuino, senza fidarsi del nodo. Vettore: attestazione falsa o non riproducibile.
- **Avversario 3 — Chi controlla l'input (sessione):** non deve poter mandare in crash l'enclave (DoS) né pilotare il "verdetto medico" attestato. Vettori: input non validato, modello non pinnato, sampling non deterministico.
- **Avversario 4 — Supply chain:** non deve poter eseguire codice dentro l'enclave (dove i dati sono in chiaro). Vettori: dipendenze non pinnate, modello scaricato a runtime.

---

## 2. CRITICAL

### C1 — `ENCRYPTED_PAYLOAD` non è cifrato: è base64 di plaintext, con PII hardcoded
**File:** `neurolix_inference.py` L11–17 (definizione), L19–20 (`decrypt_payload`)

```python
ENCRYPTED_PAYLOAD = base64.b64encode(json.dumps([...]).encode()).decode()
def decrypt_payload(encrypted):
    return json.loads(base64.b64decode(encrypted.encode()).decode())
```

`base64` è una codifica **reversibile senza chiave**. Non esiste cifratura, key management, KMS, envelope encryption. I record (`PATIENT_001`, age 63, glucose 148, …) sono **leggibili in chiaro nel sorgente** e quindi nell'immagine del container, nei layer, nella history Git, ecc. La nomenclatura `ENCRYPTED_PAYLOAD` / `decrypt_payload` **mente sulle proprietà di sicurezza** del codice — particolarmente grave in un repo che verrà auditato/forkato.

`payload_hash = sha256(base64(plaintext))` è quindi solo un checksum d'integrità di **dati pubblici**: non offre confidenzialità e, poiché il plaintext è nel sorgente, non offre nemmeno binding utile.

**Impatto:** confidenzialità = 0. La premessa del protocollo è violata alla radice.
**Fix:**
- Il dato deve arrivare **già cifrato** (envelope encryption: DEK random per payload, DEK wrappata con una KMS key del *data owner*).
- La chiave di decrittazione deve essere rilasciata **solo** su verifica dell'attestazione (Workload Identity Pool con policy sul digest dell'immagine — vedi §6). La decifratura avviene **dentro** l'enclave, dopo l'attestation-gated key release.
- Mai dati in chiaro nel sorgente/immagine. Rinominare le entità per riflettere la realtà crittografica.

---

### C2 — Attestazione completamente fittizia: nessun token TEE viene mai richiesto
**File:** `neurolix_inference.py` L43–54; `neurolix_llm.py` L40–52

```python
attestation = {
    "tee_type":               "AMD SEV",          # stringa statica
    "cloud_provider":         "Google Cloud ...", # stringa statica
    "computation_commitment": commitment,         # sha256(output)
    ...
}
```

Questi sono **claim auto-dichiarati**, non prove. Il codice non interroga mai il servizio di attestazione. Il `commitment = sha256(results ‖ payload_hash)` è un hash degli **output**: lo si può calcolare su un laptop qualunque. **Zero binding** con l'hardware, con l'immagine eseguita o con un nonce. Ancorato on-chain, attesta il nulla.

**Come funziona l'attestazione vera in Confidential Space** (da verificare sulla doc GCP corrente):
- All'avvio, un token OIDC con i *claim di attestazione verificati* è disponibile nel container in `/run/container_launcher/attestation_verifier_claims_token` (scade dopo ~60 min, refresh automatico).
- In alternativa/on-demand: HTTP `GET http://localhost/v1/token` su Unix domain socket `/run/container_launcher/teeserver.sock` (rate limit ~5 q/s per progetto/regione).
- Google Cloud Attestation verifica la quote del vTPM, riproduce l'event log ed emette il token OIDC, che contiene tra i claim il **digest dell'immagine container**, l'hardware, ecc.
- Il verificatore valida la firma del JWT contro il `jwks_uri` (tipo OIDC) **oppure** contro la root PKI (tipo `PKI`, self-contained, verificabile anche offline).

Nessuno di questi passi è presente. Si può (e si deve) inserire un **nonce custom** nella richiesta del token (audience/`eat_nonce`) per legarlo a una sessione specifica.

**Impatto:** la "prova on-chain di computazione confidenziale" è non-verificabile. Un nodo malevolo produce commitment validi senza alcun TEE.
**Fix:** richiedere il token reale, includere un nonce legato alla sessione on-chain, allegarlo al bundle di attestazione, e far sì che il verificatore (off-chain o on-chain) ne controlli firma/issuer/`image_digest`/nonce prima di accettare il commitment (§6).

---

### C3 — Esfiltrazione dei dati sensibili via `stdout` → Cloud Logging / serial console
**File:** `neurolix_inference.py` L73, L78–79; `neurolix_llm.py` L28–29, L36–37

```python
print(f"      {r['patient_id']} → {r['classification']} (score: {r['risk_score']})")  # inference
print(f"      '{PROMPT}'")        # prompt riservato
print(f"      '{response}'")      # output del modello
```

La cifratura di memoria di SEV protegge la RAM **dal lettura dell'host**; **non** protegge da egress a livello applicativo. `stdout`/`stderr` e la serial console di una VM Confidential Space sono catturati **fuori** dal confine dell'enclave (Cloud Logging / serial port) e leggibili da chiunque abbia il ruolo IAM adeguato sul progetto — cioè dall'operatore, esattamente l'avversario da cui ci si vuole proteggere.

Gli output dell'inferenza (classificazione/score) **sono** il dato sensibile; il prompt `[CONFIDENTIAL]` e la generazione GPT-2 idem. Il codice li stampa testualmente.

**Impatto:** il claim "i dati non escono mai dalla memoria cifrata" è falso a ogni esecuzione.
**Fix:**
- Nessun dato in chiaro su stdout/stderr/log. I log possono contenere **solo** metadati non sensibili e il token/commitment.
- I risultati vanno restituiti al *data owner* su canale cifrato (es. ricifrati con la sua KMS key, o consegnati via mTLS a un endpoint che riceve la chiave solo dopo attestazione valida).
- Logging strutturato con allowlist esplicita dei campi; vietare interpolazione di variabili contenenti payload.

---

### C4 — Download del modello a runtime senza pinning d'integrità (supply chain dentro l'enclave)
**File:** `neurolix_llm.py` L17

```python
generator = pipeline("text-generation", model="gpt2")  # scarica ~500MB da HF a runtime
```

Conseguenze in contesto TEE:
- **Egress di rete dall'enclave** verso huggingface.co: superficie d'attacco e canale osservabile. Una computazione confidenziale non dovrebbe avere bisogno di Internet a runtime.
- **Nessuna verifica d'integrità** dei pesi: niente hash pin, niente firma. Un modello avvelenato (HF compromesso, MITM, typosquatting) altera arbitrariamente l'output — incluse le "raccomandazioni mediche" — e l'attestazione **firmerebbe felicemente l'output avvelenato**.
- I pesi del modello sono **fuori dal boundary attestato**: l'attestazione misura l'immagine container, non un file scaricato dopo l'avvio. Il claim `"model": "GPT-2 (124M)"` non è dimostrabile.

**Impatto:** rompe l'integrità della computazione — il pilastro complementare alla confidenzialità.
**Fix:** i pesi devono essere **dentro l'immagine misurata** (baked-in, formato `safetensors`, digest noto), nessun download a runtime, nessuna libreria di rete. Il `model_digest` entra nel commitment (§6). Build offline/air-gapped del container.

---

### C5 — Falsi claim di attestazione negli artefatti (`data_exposed: false`, `instance_confidentiality: 1`, `verified_by`)
**File:** `neurolix_llm.py` L50 (`"data_exposed": False`); `neurolix_poc_report.json` (tutto il blocco `tee`/`computation`)

```json
"verified_by": "https://accounts.google.com",   // endpoint di login OAuth, NON un verificatore di attestazione
"instance_confidentiality": 1,                   // flag magico senza provenienza
"data_exposed": false                            // contraddetto da C3
```

- `accounts.google.com` è l'endpoint di autenticazione utente, **non** il verificatore di attestazione (Google Cloud Attestation / `confidentialcomputing.googleapis.com`, validazione via JWKS o root PKI). Citarlo come "verified_by" rivela un fraintendimento della catena di trust.
- `instance_confidentiality: 1` è un booleano auto-riportato travestito da metrica: non deriva da nessun token.
- Il report è **auto-generato e non firmato**: chiunque può produrlo, non ha peso crittografico.

**Impatto:** è la categoria più pericolosa — i consumatori a valle (e il contratto on-chain) si fidano dell'attestazione, che qui asserisce il falso.
**Fix:** il report deve **incorporare ed essere firmato insieme al** token di attestazione reale (JWT), al `image_digest`, al report SEV-SNP e al nonce. Rimuovere ogni claim non derivato da una verifica effettiva. Niente campi "confidenzialità = vero" hardcoded.

---

## 3. HIGH

### H1 — Commitment non riproducibile ⇒ non verificabile (verifiable compute che non si verifica)
**File:** `neurolix_llm.py` L31–39 (sampling); `neurolix_inference.py` L24–31 (train+predict)

```python
output = generator(PROMPT, max_new_tokens=50, temperature=0.7, do_sample=True, ...)  # stocastico
```

Il commitment è calcolato su un output **stocastico**. Anche con `set_seed(42)`, il risultato dipende da versione di `torch`/`transformers`, CPU vs GPU, numero di thread, kernel BLAS → un verificatore indipendente, su uno stack diverso, **non riproduce gli stessi token** e quindi **non può verificare il commitment**. Stesso problema per il RandomForest: deterministico **solo** a parità esatta di stack `sklearn`/`numpy`/BLAS.

**Impatto:** per un sistema il cui valore è la *computazione verificabile*, l'output non è ricontrollabile. La verifica collassa anche se tutto il resto fosse corretto.
**Fix:** inferenza **deterministica** (`do_sample=False` o greedy/beam fissato, seed fissi, versioni pinnate esatte, thread fissati, target hardware dichiarato). In alternativa, non puntare sulla *riproducibilità dell'output* ma sull'*attestazione dell'immagine* + commitment dell'output prodotto **dentro** l'enclave attestata (il trust si sposta dal "rifai e confronta" al "il TEE attesta di averlo prodotto"). Scegliere esplicitamente uno dei due modelli di verifica e documentarlo.

---

### H2 — Nessun nonce / freshness / replay-protection; nessun binding alla sessione on-chain
**File:** `neurolix_inference.py` L44–46; `neurolix_llm.py` L42–44

Il commitment è **deterministico dati gli input** e non contiene nonce, challenge della chain, `session_id`, blocco o `chain_id`. Conseguenze:
- **Replay**: lo stesso commitment è riutilizzabile.
- **Precomputazione**: chi conosce gli input calcola il commitment senza eseguire nulla.
- **Nessun legame** con la sessione di pagamento di `NeurolixGateway` (il `SESSION_ROLE` / session id discussi nell'audit del Gateway — fix P10): l'attestazione e il pagamento confidenziale vivono in due mondi scollegati.

**Impatto:** un commitment valido non dimostra né freschezza né appartenenza a una sessione pagata.
**Fix:** `nonce = session_id` (o un challenge on-chain) iniettato nella richiesta del token di attestazione **e** incluso nel commitment; il contratto verifica la corrispondenza nonce↔sessione.

---

### H3 — Zero input validation ⇒ DoS dell'enclave e controllo del "verdetto" da parte dell'attaccante
**File:** `neurolix_inference.py` L22–41; `neurolix_llm.py` L19–23

`train_model`/`run_inference` assumono che ogni record abbia tutte le chiavi numeriche; il prompt è passato al modello senza alcun limite. In deployment reale (payload da sessione):
- record malformato → `KeyError`/`ValueError` → **crash** del processo (vedi H4).
- prompt/payload illimitato → **OOM**. Su VM Confidential Space lo **swap è disabilitato**: un uso eccessivo di memoria **fa crashare il workload** → DoS diretto.
- nessun bound sui valori (età negativa, `glucose=0`) → logica di rischio corrotta.
- chi controlla l'input controlla l'output **attestato**: per GPT-2 (base LM, non instruction-tuned) il "prompt injection" classico è meno rilevante, ma il punto di sicurezza è che **l'attaccante pilota la "raccomandazione medica" che il sistema firma crittograficamente**.

**Impatto:** disponibilità (crash dell'enclave) + integrità (verdetto attestato pilotabile).
**Fix:** validazione di schema rigorosa (es. `pydantic`/JSON Schema) su tipi, presenza chiavi e range fisiologici; limiti hard su lunghezza prompt e dimensione payload (token count + byte); rigetto fail-closed con errore scrubbed (no traceback, no dato).

---

### H4 — Nessuna gestione delle eccezioni / nessuno scrubbing: i traceback finiscono nei log
**File:** entrambi, ovunque (nessun `try/except`)

Qualunque eccezione emette un **traceback completo** su `stderr` → Cloud Logging: flusso d'esecuzione, path, versioni delle librerie, numeri di riga e — secondo configurazione — **valori delle variabili locali** (cioè potenzialmente i dati). Non esiste un percorso di fallimento controllato che **azzeri i dati sensibili prima di uscire**.

**Impatto:** canale di leak passivo (info-leak su flusso/ambiente; possibile leak di dati) + nessuna pulizia in caso di crash a metà inferenza.
**Fix:** `try/except` ai confini con messaggi d'errore sanificati; handler globale che cattura, **scrubba i buffer sensibili** e termina fail-closed; mai loggare l'eccezione grezza; disabilitare il dump di locals nei log.

---

## 4. MEDIUM

### M1 — Dipendenze non pinnate (`>=`): build non riproducibili + supply chain illimitata dentro l'enclave
**File:** `requirements.txt`

```
numpy>=1.26
scikit-learn>=1.4
transformers>=4.38
torch>=2.2
```

- **Riproducibilità:** `>=` ⇒ build a tempi diversi tirano versioni diverse ⇒ float diversi ⇒ commitment diversi (vedi H1). Per un sistema attestato le dipendenze vanno **pinnate esatte (`==`) e hash-locked** (`pip --require-hashes` con lockfile: `uv lock` / `pip-compile` / `poetry.lock`).
- **Supply chain:** `>=` ⇒ una release futura (anche transitiva) compromessa viene tirata automaticamente. L'albero transitivo di `transformers`/`torch` è enorme; **codice di una qualunque dipendenza gira a import-time dentro l'enclave, con accesso ai dati in chiaro**. Senza lockfile non c'è controllo sulle transitive.
- **Nessuna verifica hash:** anche le versioni pinnate vanno hash-locked contro mirror/account PyPI compromessi.

**Fix:** lockfile con hash, `--require-hashes`, build riproducibile dell'immagine, scansione SCA (es. `pip-audit`/`osv`) in CI.

---

### M2 — Bloat di `torch`+`transformers` e librerie di rete nell'immagine attestata
**File:** `requirements.txt`; `neurolix_llm.py`

`torch>=2.2` di default tira lo stack CUDA (centinaia di MB) su una VM SEV **CPU-only** (la confidential GPU è uno scenario diverso/più recente). `transformers` porta `huggingface_hub`+`requests` (i vettori di egress di C4). Più byte nell'immagine = più superficie d'attacco e immagine misurata più grande/complessa.

**Fix:** `torch` CPU-only (indice `+cpu`) o runtime più leggero; rimuovere le librerie capaci di rete; per GPT-2 valutare un runtime minimale. Ogni dipendenza non necessaria va eliminata dall'immagine misurata.

---

### M3 — Nessuna igiene della memoria / protezione dai core dump
**File:** entrambi

Array sensibili (`X`, `y`, `records`, `results`, `response`) mai azzerati; nessun `mlock`/`madvise(MADV_DONTDUMP)`. Python rende l'azzeramento di fatto impossibile (stringhe immutabili, copie del GC, riallocazioni numpy): il dato in chiaro vive a lungo e in più copie. Un **core dump** scritto dal guest OS (su disco interno alla VM o su volume montato) può **persistere il plaintext** (SEV protegge la RAM dall'host, non un dump scritto su storage).

**Fix:** minimizzare la finestra di plaintext; disabilitare i core dump (`RLIMIT_CORE=0`), `MADV_DONTDUMP` sulle pagine sensibili; per dati ad alta sensibilità valutare un runtime compilato con controllo della memoria (vedi O2). Verificare la config di storage/dump della VM.

---

### M4 — Train + inference sullo **stesso** dataset n=5: il "verdetto" committato è statisticamente nullo
**File:** `neurolix_inference.py` L22–41

Il modello è addestrato sui 5 record su cui poi predice (overfitting su 5 punti). I `risk_score` sono un artefatto memorizzato, non inferenza. Il commitment lega un output **medicalmente privo di significato**. È un problema di integrità sostanziale, non solo di qualità: si sta firmando "rumore" come verdetto clinico.

**Fix:** separare train/inference; per un PoC usare un modello pre-addestrato e versionato (digest nel commitment), o esplicitare che è una demo di pipeline e **non** un verdetto. Mai presentare gli score come clinici.

---

### M5 — Costruzione dell'hash senza domain separation / length-prefixing
**File:** `neurolix_inference.py` L44–46; `neurolix_llm.py` L42–44

```python
sha256((json.dumps(results, sort_keys=True) + payload_hash).encode())
sha256((PROMPT + response + "AMD-SEV-NEUROLIX").encode())
```

Concatenazione ambigua: dove finisce un campo e inizia l'altro? Senza separatore di dominio / length-prefix, due input distinti possono produrre la stessa preimage se il formato cambia (`a‖bc` vs `ab‖c`). `sort_keys=True` è corretto per il dict ma non risolve l'ambiguità della concatenazione.

**Fix:** struttura tipizzata e length-prefixed (es. TLV o `abi.encode`-style), con tag di dominio e versione dello schema di hashing: `H( DST ‖ version ‖ len(image_digest)‖image_digest ‖ … )`. Allinearlo allo schema che il contratto on-chain si aspetta.

---

## 5. LOW / Code Quality / Enclave Optimization

- **L1 — Naming ingannevole:** `ENCRYPTED_PAYLOAD`, `decrypt_payload` descrivono proprietà di sicurezza inesistenti. In un repo auditato, il naming che mente è un rischio in sé. Rinominare secondo la realtà crittografica.
- **L2 — Seed deterministici (`42`):** ottimi per la riproducibilità (H1) ma nessuna entropia per-sessione (tensione con H2). Decidere consapevolmente: determinismo per la verifica **+** nonce separato per la freschezza.
- **L3 — `glucose=0`/`insulin=0` come sentinella di "missing":** corrompe il modello (M4). Gestire i missing esplicitamente, non con 0.
- **O1 — Separare fase build/untrusted da fase runtime/attested:** download modello, pip install, fetch dati pubblici → **build-time**, fuori dalla sessione confidenziale; la sessione confidenziale fa **solo** la computazione sensibile su artefatti già misurati.
- **O2 — Python è un cattivo runtime per memoria sensibile:** valutare un componente compilato (Rust/Go) per il path sensibile, o almeno isolare e minimizzare il plaintext; usare cleanup strutturato (`finally`/context manager) che scrubba.
- **O3 — Output channel:** emettere nei log **solo** token di attestazione + commitment; i risultati reali vanno al data owner su canale cifrato (KMS-wrapped o mTLS con key release attestation-gated). Mai plaintext nei log.

---

## 6. Come si fa "fatto bene" (flusso corretto, end-to-end)

1. **Cifratura lato data owner.** Payload cifrato con DEK random; DEK wrappata con una **Cloud KMS key del data owner**. Il rilascio della key è governato da una **policy del Workload Identity Pool** che controlla i claim del token di attestazione (in primis l'`image_digest`).
2. **Immagine riproducibile e firmata.** Dipendenze pinnate+hash-locked, **pesi del modello baked-in** (`safetensors`, digest noto), nessuna rete. Firma `Cosign` (Sigstore); le firme sono verificate dal servizio di attestazione e riflesse nei claim.
3. **Attestazione + nonce di sessione.** A runtime, nell'enclave: leggere `/run/container_launcher/attestation_verifier_claims_token` **oppure** richiedere il token via `teeserver.sock` (`http://localhost/v1/token`), iniettando `nonce = session_id` (challenge on-chain) come audience/`eat_nonce`. Così il token è legato alla sessione.
4. **Key release attestation-gated → decrittazione → inferenza deterministica.** La DEK viene rilasciata **solo** se l'attestazione passa la policy. Si decifra **dentro** l'enclave; inferenza deterministica (versioni pinnate, no sampling, thread/HW fissati).
5. **Commitment strutturato, domain-separated:**
   `commitment = H( DST ‖ ver ‖ image_digest ‖ model_digest ‖ input_commitment ‖ output_commitment ‖ session_nonce )`
6. **Ancoraggio on-chain (contratto core `0xDcCCda8662996b479bE5C5d44115a03a43a92F1B`).** Idealmente un verificatore (off-chain o on-chain) controlla **firma/issuer/`image_digest`/nonce** del token prima che il commitment sia accettato; il contratto memorizza `{commitment, image_digest, session_nonce, token_ref}` e lo lega alla sessione di `NeurolixGateway`. **Nessun plaintext** nei log; risultati al data owner su canale cifrato.

> Nota sul modello di trust on-chain: la verifica completa di un JWT OIDC on-chain è costosa/complessa. Pattern realistici su Base: (a) **verificatore off-chain** che valida il token e firma un attestato che il contratto accetta (trust nel verificatore, da minimizzare/decentralizzare); oppure (b) token **PKI self-contained** con verifica della catena `x5c` contro la root Confidential Space, ed eventuale verifica on-chain ottimizzata. Da decidere esplicitamente in base a costi gas e modello di decentralizzazione.

---

## 7. Checklist di remediation (prioritizzata)

| ID | Severità | Azione | Blocca il claim "Confidential AI"? |
|----|----------|--------|-----------------------------------|
| C1 | Critical | Cifratura reale + KMS + key release attestation-gated; niente PII nel sorgente | Sì |
| C2 | Critical | Richiedere il token di attestazione reale; binding immagine+nonce | Sì |
| C3 | Critical | Eliminare ogni plaintext da stdout/stderr/log | Sì |
| C4 | Critical | Modello baked-in, pinnato, verificato; no download a runtime | Sì |
| C5 | Critical | Report firmato che incorpora il token reale; rimuovere claim falsi | Sì |
| H1 | High | Inferenza deterministica **o** modello di verifica basato su attestazione | Sì |
| H2 | High | Nonce/session-binding + anti-replay nel commitment | Sì |
| H3 | High | Validazione input + limiti hard (anti-DoS/anti-manipolazione) | — |
| H4 | High | Exception handling fail-closed con scrubbing | — |
| M1 | Medium | Lockfile hash-locked + SCA in CI | (riproducibilità) |
| M2 | Medium | torch CPU-only; rimuovere librerie di rete | — |
| M3 | Medium | No core dump, `MADV_DONTDUMP`, minimizzare plaintext | — |
| M4 | Medium | Separare train/inference; modello versionato | — |
| M5 | Medium | Hash strutturato/domain-separated allineato all'on-chain | — |

---

## 8. Caveat finale (ground truth)
Questo audit copre i file caricati. La preference di progetto impone il repo GitHub come unica fonte di verità: **confermare che `neurolix_inference.py`, `neurolix_llm.py`, `requirements.txt` e `neurolix_poc_report.json` in repo coincidano con queste versioni** prima di aprire una PR di remediation. Se in repo esistono già un Dockerfile, una policy WIP o uno script di attestazione non inclusi qui, vanno auditati insieme — il confine di sicurezza di Confidential Space dipende tanto dall'immagine e dalla policy quanto dal codice Python.
