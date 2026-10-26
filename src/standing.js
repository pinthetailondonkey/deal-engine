import { verifyCheckpoint, verifyWitnessStatement, verifyRefusal, CADENCE_MS, verifyForkEvidence } from './checkpoint.js';
import { keyTimelineResolve, forkEvidenceGrade } from './rotation.js';
import { adjudicateFork } from './adjudication.js';
import { bytesToHex, H, canonicalBytes } from './canonical.js';

// Standing: the 7-state lifecycle, computed from evidence in front of the
// observer, on the observer's clock. The states are computed, not judged,
// and two can hold at once (fresh but refused; current but forked). VOIDED
// deals sit beside the count — the count never decrements.
//
// Attack round two hardened every seam the lying caller used: non-array view
// fields degrade instead of crashing; a vendor clock cannot confirm the
// FUTURE; refusals keep their history after they age out; void lines count
// only when they are structurally signed things.
//
// Standing can be computed only from what the evidence SAYS. Honest limit:
// timestamps inside bodies are self-claimed, so a thief with a stolen live
// key can forge bodies dated before their revocation and this view cannot
// tell — the forgery window is bounded only by the revocation tick (see
// rotation.js, BACKDATING WINDOW). The lifecycle here is honest about the
// evidence, never about the world.

// The checks live in priority order; the first match wins, but everything
// the evidence supports gets reported too.
export function standing(view, now) {
  const arr = (value) => (Array.isArray(value) ? value : []);
  const checkpointsIn = arr(view.checkpoints);
  const allCheckpoints = checkpointsIn.filter(verifyCheckpoint);
  const timeline = Array.isArray(view.keyTimeline) ? view.keyTimeline : null;

  const out = {
    standing: 'vendor-signed-claim',  // a claim, not standing — the floor
    current: false,
    stale: false,
    breached: false,
    forked: false,
    truncated: false,
    refused: false,
    neverAudited: true,
    details: {
      checkpoints: allCheckpoints.length,
      latestWitnessedAt: 0,
      cadenceMs: CADENCE_MS,
      sizeHistory: arr(view.sizeHistory),
      voidedCount: arr(view.voided).filter(voidLooksSigned).length,
    },
  };
  if (view.keyTimeline && !timeline) out.details.keyTimelineInvalid = true;

  // key-state scoring: a checkpoint only counts if its signer key was a
  // valid vendor-role key AT ITS OWN ISSUE TIME (the stolen-key rule; a
  // timeline listing a stranger key as role 'witness' does not license
  // checkpoints — role matters now, attack round two protocol F3.2).
  const checkpoints = timeline
    ? allCheckpoints.filter((stc) => {
      const resolved = keyTimelineResolve(timeline, stc.key, stc.body.issuedAt);
      return resolved.valid && resolved.role === 'vendor';
    })
    : allCheckpoints;

  // FORKED, now with adjudication: valid fork evidence alone is no longer a
  // verdict. It takes either a shared witness that signed BOTH sides of the
  // split (proved, no judge) or the vendor's own signed admission of one
  // line. Equal-strength incompatible lines stay VISIBLE but un-accused —
  // a partition is possible, and pretending otherwise was the design's
  // original sin. Assessed against the key timeline exactly as before.
  const evidence = arr(view.forkEvidence).filter((evidence) => verifyForkEvidence(evidence));
  // the key-state gate applies only when the view carries a timeline — a
  // view without one grades every verifying checkpoint the old way, and
  // evidence must follow the same convention.
  const genuine = timeline
    ? evidence.filter((e) => forkEvidenceGrade(e, timeline) === 'genuine')
    : evidence.slice();
  const suspect = evidence.filter((e) => !genuine.includes(e));
  const opts = {
    vendorAdmission: view.vendorAdmission,
    witnessRotations: arr(view.witnessRotations),
    keyTimeline: timeline,
  };
  const verdicts = genuine.map((e) => adjudicateFork(e, arr(view.witnessStatements), opts));
  const proved = genuine.filter((e, i) => ['fork-proved', 'vendor-confirmed'].includes(verdicts[i].verdict));
  if (proved.length > 0) {
    out.forked = true;
    out.adjudication = 'closed';
  }
  // A vendor-confirmed verdict has consequences: the line the vendor's own
  // signed admission declared DEAD stops driving freshness, continuity and
  // the count (attack round two, F5 — the dead line previously stayed the
  // newest checkpoint and read `current: true` against the admission).
  const droppedHeads = verdicts
    .filter((v) => v.verdict === 'vendor-confirmed' && v.dropped)
    .map((v) => v.dropped);
  const keptHeads = verdicts
    .filter((v) => v.verdict === 'vendor-confirmed' && v.kept)
    .map((v) => v.kept);
  if (keptHeads.length > 0) out.details.adjudicatedKept = keptHeads;
  const dead = new Set(droppedHeads);
  let grew = true;
  while (grew) {
    grew = false;
    for (const c of checkpoints) {
      if (dead.has(c.head)) continue;
      if (dead.has(c.body.prevHead)) {
        dead.add(c.head);
        grew = true;
      }
    }
  }
  const liveCheckpoints = checkpoints.filter((c) => !dead.has(c.head));
  const stc = liveCheckpoints[liveCheckpoints.length - 1] || null;
  const unresolved = [...suspect, ...genuine.filter((e) => !proved.includes(e))];
  out.suspectedForkEvidence = unresolved.length > 0 && !out.forked;
  if (out.suspectedForkEvidence) out.adjudication = 'open';

  if (stc) {
    // Freshness = time since the newest WITNESSED checkpoint, on the
    // observer's clock, against the protocol's cadence. A witnessed
    // checkpoint is the only thing that confirms history.
    // A stolen witness key the timeline retired stops speaking (attack
    // round two, protocol F4): when a witness key appears on the timeline
    // and resolves invalid at the checkpoint's own issue time, its
    // statements count for nothing here.
    const statements = arr(view.witnessStatements).filter((statement) => {
      // the machinery now carries the timeline itself (attack round three,
      // protocol P1/P7): the statement gate and inheritance seats grade
      // against it, so the same gate holds in adjudication too
      if (!verifyWitnessStatement(stc, statement, opts.witnessRotations, { keyTimeline: timeline })) return false;
      return true;
    });
    if (statements.length > 0) {
      out.details.latestWitnessedAt = stc.body.issuedAt;
      out.details.witnesses = statements.length;
      out.neverAudited = false;
      // CURRENT: newest witnessed checkpoint inside the cadence — on the
      // OBSERVER's clock. A vendor date in the future confers nothing
      // (attack round two, API F3): one future-dated checkpoint used to
      // hold `current: true` for ~97 years and bury the 7-day cadence.
      const age = now - stc.body.issuedAt;
      if (age < 0) {
        out.details.futureDatedCheckpoint = stc.body.issuedAt;
        out.stale = true;
      } else {
        out.current = age < CADENCE_MS;
        if (!out.current) out.stale = true;
      }
    } else {
      // a checkpoint exists but no witness came for it: not current
      out.stale = true;
    }

    // continuity: the newest exists only if its prior head chain checks
    out.details.extendsPrior = extendsPrior(liveCheckpoints);
  }

  // TRUNCATED: the vendor attested that history ends at a stated checkpoint.
  if (view.truncation) out.truncated = true;

  // BREACHED: computed only by a granted evidence window — an accumulated
  // verdict that a claim was contradicted. Not this module's call alone.
  if (view.breached) out.breached = true;

  // REFUSED: a signed refusal that ages like staleness. The refusal must
  // still be remembered after it stops screaming (attack round two, F9:
  // refusals aged out leaving no trace, which is laundering) — so the whole
  // valid history is surfaced in details, forever.
  const refusals = arr(view.refusals).filter(verifyRefusal);
  if (refusals.length > 0) {
    out.details.refusalHistory = refusals
      .map((r) => ({ at: r.body.at, keyId: r.keyId }))
      .sort((a, b) => a.at - b.at);
    const newest = refusals.reduce((a, r) => (r.body.at > a.body.at ? r : a));
    if (now - newest.body.at < CADENCE_MS) {
      if (newest.body.at > now) {
        out.details.futureDatedRefusal = newest.body.at;
      } else {
        out.refused = true;
      }
    }
  }

  return out;
}

function extendsPrior(checkpoints) {
  // every adjacent pair: prevHead matches the previous head's hash, and
  // sizes only grow. If any break exists, continuity is false.
  for (let i = 1; i < checkpoints.length; i += 1) {
    const a = checkpoints[i - 1];
    const b = checkpoints[i];
    if (b.body.prevHead !== a.head) return false;
    if (b.body.treeSize < a.body.treeSize) return false;
    if (b.body.seq <= a.body.seq) return false;
  }
  return checkpoints.length >= 1;
}

// A void entry counts only if it is structurally a signed void statement:
// right tag, a body whose hash binds to it, a signed role entry, a sane
// time. (`'🔫'.length` stopped counting as two voided deals — attack round
// two, API F13.) Full cryptographic verification needs the record the void
// names, which the view may not carry; that check stays with the engine.
// The engine's log wraps its voids as { record, voided } — accept both.
function voidLooksSigned(entry) {
  const voided = entry?.voided ?? entry;
  try {
    if (!voided?.body || voided.tag !== 'Deal void v1') return false;
    if (!voided.sigs || Object.keys(voided.sigs).length === 0) return false;
    if (!Number.isInteger(voided.body.at) || voided.body.at <= 0) return false;
    if (typeof voided.body.voids !== 'string' || voided.body.voids === '') return false;
    return bytesToHex(H('Deal void v1', canonicalBytes(voided.body))) === voided.hash;
  } catch {
    return false;
  }
}
