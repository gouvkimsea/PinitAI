# PinIt Risk & Confidence Scoring Model

## 1. Architectural Philosophy: Separation of Risk and Confidence

Conventional threat detection systems conflate risk and confidence into a single scalar number. This leads to dangerous false assumptions:
- A high score might mean *"we found a severe threat with undeniable proof"* or *"we saw an obscure heuristic flag once in an unverified sample."*
- A low score might mean *"we thoroughly inspected the sample across 6 deep engines and found zero threats"* or *"we barely scanned anything and have no idea what it is."*

PinIt's redesigned scoring engine treats **Risk** and **Confidence** as two orthogonal, independent dimensions:

| Dimension | Definition | Range | Key Question |
| :--- | :--- | :--- | :--- |
| **Risk** | How suspicious, malicious, or dangerous the observed evidence appears. | `0` to `100` | *"If this evidence is real, how much damage or deception does it represent?"* |
| **Confidence** | How certain PinIt is that its assessment is correct and representative. | `0` to `100` | *"How thoroughly was the sample analyzed, how reliable are the sources, and did independent engines corroborate?"* |

---

## 2. The 2D Decision Matrix

By plotting Risk against Confidence, PinIt supports five distinct assessment states:

```
CONFIDENCE (0 - 100)
    ▲
100 ┤ [SAFE / LOW RISK]                  [CONFIRMED MALICIOUS]
    │ High confidence clean              High confidence threat (corroborated /
    │ Multiple engines agree clean       known signatures / blocklist listings)
 70 ┤──────────────────────────────────────────────────────────────────────────
    │                                    [HIGH RISK]
    │                                    Strong indicators, moderate corroboration
 40 ┤──────────────────────────────────────────────────────────────────────────
    │ [INSUFFICIENT EVIDENCE / UNKNOWN]  [INSUFFICIENT EVIDENCE / UNKNOWN]
    │ Sparse data, single weak engine,   Flagged high risk by an uncorroborated
    │ insufficient telemetry to decide   source; requires verification before action
  0 └────────────────────────────────────┬────────────────────────────────────►
    0                                   60                                   100
                                RISK (0 - 100)
```

### State Definitions & Thresholds

1. **`SAFE_LOW_RISK`** (`Risk <= 20`, `Confidence >= 40`):
   - Strong evidence that no significant scam indicators were found across active engines.
2. **`SUSPICIOUS`** (`20 < Risk < 60`, `Confidence >= 40`):
   - Mild irregularities, unverified domains, or potential deceptive patterns found.
3. **`HIGH_RISK`** (`Risk >= 60`, `Confidence >= 40`):
   - High likelihood of scam, social engineering, or brand impersonation with moderate-to-high confidence.
4. **`CONFIRMED_MALICIOUS`** (`Risk >= 80`, `Confidence >= 70` OR verified critical security rule):
   - Active phishing feeds, known malware hashes, private SSRF network probes, or verified multi-engine consensus.
5. **`INSUFFICIENT_EVIDENCE`** (`Confidence < 40`):
   - Evaluation sample is too short, only 1 engine ran without corroboration, or detector certainty is minimal.
   - Prevents unilateral false positives while cautioning the user that verification is needed.

---

## 3. Evidence-Based Signal Contract

Every indicator emitted by any detector must implement the standardized `EvidenceSignal` contract with **7 mandatory attributes**:

```typescript
export interface EvidenceSignal {
  /** 1. Source detector name (e.g. 'url_security_detector', 'impersonation_detector') */
  source: string;

  /** 2. Signal category type (e.g. 'url', 'text', 'pattern', 'reputation', 'file') */
  signalType: string;

  /** 3. Severity grade: 'safe' | 'low' | 'medium' | 'high' | 'critical' */
  severity: SignalSeverity;

  /** 4. Intrinsic reliability of the detector source (0.0 to 1.0) */
  reliability: number;

  /** 5. Detector certainty in this specific extraction (0 to 100) */
  confidence: number;

  /** 6. ISO 8601 UTC timestamp of signal extraction */
  timestamp: string;

  /** 7. Human-readable explanation and context */
  explanation: string;

  /** Numerical score contribution (0 to 100) */
  score?: number;

  /** Semantic grouping key to prevent double counting */
  correlationGroup?: string;
}
```

### Intrinsic Reliability by Source

| Detector Source | Intrinsic Reliability | Rationale |
| :--- | :--- | :--- |
| `file_security_detector` | `0.95` | Deterministic SHA256 AV signatures, magic bytes inspection. |
| `reputation_signal_detector` | `0.90` | Curated threat feeds (Google Safe Browsing, PhishTank, Spamhaus). |
| `impersonation_detector` | `0.85` | Curated official domain dictionaries, verified brand names. |
| `scam_pattern_detector` | `0.80` | High-precision regex pattern matchers and threat intelligence. |
| `url_security_detector` | `0.80` | Structural entropy, SSRF probes, redirect hops. |
| `community_intelligence_detector`| `0.75` | Confirmed community incident reports. |
| `text_linguistic_detector` | `0.70` | Natural language heuristics, urgency tone analysis. |
| `ai_model_detector` | `0.65` | Machine learning probabilistic scoring. |

---

## 4. Preventing Double-Counting of Correlated Signals

### The Problem
If an attacker registers `login-secure-paypal-update.xyz`, a naive scoring system might fire:
1. High Shannon entropy (`+35`)
2. Unusual TLD `.xyz` (`+35`)
3. Excessive hyphens (`+30`)
4. Number of subdomains (`+20`)
5. Digit-to-letter ratio (`+20`)

Linear summation produces a score of `140`, artificially catapulting a mildly suspicious domain into an extreme critical alert even if no malware or active attack was confirmed.

### PinIt's De-Correlation Solution
Signals with shared underlying characteristics are mapped into common **Correlation Groups**:
- `url:domain_structure`: Entropy, hyphens, digit ratio, suspicious TLD, subdomain depth.
- `linguistic:urgency`: Fear phrasing, coercive urgency, arrest threats.
- `pattern:financial_lure`: Crypto doubling, giveaway scams, lottery claims.
- `pattern:credential_harvesting`: OTP requests, fake banking portals, account freeze warnings.
- `payload:binary_threat`: Executable headers, obfuscated shellcode, suspicious file extensions.

### De-Correlation Mathematical Formula

Within each correlation group $G$:
1. Signals are ranked by relevance: $R_i = \text{score}_i \times \text{reliability}_i$.
2. The primary signal $S_{\text{primary}}$ contributes **100%** of its score.
3. Secondary signals $S_2, S_3, \dots, S_n$ are dampened by the intra-group dampening factor $\delta$ (default $\delta = 0.25$):

$$\text{EffectiveGroupScore}(G) = \min\left(100, \text{score}(S_{\text{primary}}) + \sum_{i=2}^n \left(\text{score}(S_i) \times \delta\right)\right)$$

This ensures that five related URL features from the same domain structure cannot unilaterally force a score above `80`, preventing artificial risk inflation while preserving nuanced evidence.

---

## 5. Confidence Calculation Formula

PinIt computes orthogonal confidence through multi-factor telemetry:

$$\text{Confidence} = \text{CoverageScore} + \text{CorroborationBonus} + \Delta\text{Reliability} + \Delta\text{Certainty}$$

Where:
- **Coverage Score** ($30$ to $50$): Proportional to the number of engines evaluated ($\text{Ran} \times 5$).
- **Corroboration Bonus**:
  - $\ge 3$ distinct engines triggered: $+40$
  - $2$ distinct engines triggered: $+25$
  - $\ge 3$ engines clean (unanimous safe): $+40$
  - $1$ engine triggered: $+5$
- **Reliability Adjustment** ($\Delta\text{Reliability}$): $(\overline{\text{Reliability}} - 0.5) \times 15$
- **Certainty Adjustment** ($\Delta\text{Certainty}$): $(\overline{\text{Confidence}_{\text{detectors}}} - 70) \times 0.2$
- **Sparse Data Penalty**: If $\text{TotalRan} \le 1$ and $\text{SignalCount} \le 1$, confidence is strictly capped at $35\%$, forcing the `INSUFFICIENT_EVIDENCE` state.
- **Critical Security Override**: If a verified cryptographic hash or AV signature triggers an explicit critical rule, confidence is immediately set to $95\%$.

---

## 6. Verification and Boundary Testing

The model is validated in `tests/riskScoringModel.test.ts` across all boundary conditions:
1. **High Risk + Low Confidence** $\to$ Verified to yield `INSUFFICIENT_EVIDENCE`.
2. **Low Risk + High Confidence** $\to$ Verified to yield `SAFE_LOW_RISK`.
3. **7-Field Signal Compliance** $\to$ Verified on all emitted signals.
4. **Correlated Feature Dampening** $\to$ 5 domain features verified to dampen from raw $185$ down to effective $80$.
5. **State Transitions** $\to$ All boundary transitions verified.
