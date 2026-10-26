import { verifyCheckpoint, verifyWitnessStatement, verifyRefusal, CADENCE_MS, verifyForkEvidence, admittedWitness } from './checkpoint.js';
import { verifyConsistencyProof } from './merkle.js';
import { keyTimelineResolve, forkEvidenceGrade } from './rotation.js';
import { adjudicateFork } from './adjudication.js';

// Standing: the 7-state lifecycle, computed from evidence in front of the
// observer, on the observer's clock. The states are computed, not judged,
// and two can hold at once (fresh but refused; current but forked). VOIDED
// deals sit beside the count — the count never decrements.

// The checks live in priority order; the first match wins, but everything
// the evidence supports gets reported too.
export function standing(view, now) {
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
      checkpoints: (view.checkpoints || []).filter(verifyCheckpoint).length,
      latestWitnessedAt: 0,
      cadenceMs: CADENCE_MS,
      sizeHistory: (view.sizeHistory || []),
      voidedCount: (view.voided || []).length,
    },
  };

  const allCheckpoints = (view.checkpoints || []).filter(verifyCheckpoint);
  // key-state scoring: a checkpoint only counts if its signer key was a
  // valid vendor key AT ITS OWN ISSUE TIME (the stolen-key rule; without a
  // timeline every key that verifies is trusted, as before).
  const checkpoints = view.keyTimeline
    ? allCheckpoints.filter((stc) => keyTimelineResolve(view.keyTimeline, stc.key, stc.body.issuedAt).valid)
    : allCheckpoints;
  const stc = checkpoints[checkpoints.length - 1] || null;

  // FORKED, now with adjudication: valid fork evidence alone is no longer a
  // verdict. It takes either a shared witness that signed BOTH sides of the
  // split (proved, no judge) or the vendor's own signed admission of one
  // line. Equal-strength incompatible lines stay VISIBLE but un-accused —
  // a partition is possible, and pretending otherwise was the design's
  // original sin. Assessed against the key timeline exactly as before.
  const evidence = (view.forkEvidence || []).filter((evidence) => verifyForkEvidence(evidence));
  // the key-state gate applies only when the view carries a timeline — a
  // view without one grades every verifying checkpoint the old way, and
  // evidence must follow the same convention.
  const genuine = view.keyTimeline
    ? evidence.filter((e) => forkEvidenceGrade(e, view.keyTimeline) === 'genuine')
    : evidence.slice();
  const suspect = evidence.filter((e) => !genuine.includes(e));
  const opts = {
    vendorAdmission: view.vendorAdmission,
    witnessRotations: view.witnessRotations || [],
    keyTimeline: view.keyTimeline || null,
  };
  const verdicts = genuine.map((e) => adjudicateFork(e, view.witnessStatements || [], opts));
  const proved = genuine.filter((e, i) => ['fork-proved', 'vendor-confirmed'].includes(verdicts[i].verdict));
  if (proved.length > 0) {
    out.forked = true;
    out.adjudication = 'closed';
  }
  const unresolved = [...suspect, ...genuine.filter((e) => !proved.includes(e))];
  out.suspectedForkEvidence = unresolved.length > 0 && !out.forked;
  if (out.suspectedForkEvidence) out.adjudication = 'open';

  if (stc) {
    // Freshness = time since the newest WITNEEDED checkpoint, on the
    // observer's clock, against the protocol's cadence. A witnessed
    // checkpoint is the only thing that confirms history.
    const statements = (view.witnessStatements || []).filter(
      (statement) => verifyWitnessStatement(stc, statement, view.witnessRotations || []),
    );
    if (statements.length > 0) {
      out.details.latestWitnessedAt = stc.body.issuedAt;
      out.details.witnesses = statements.length;
      out.neverAudited = false;
      // CURRENT: newest witnessed checkpoint inside the cadence.
      out.current = (now - stc.body.issuedAt) < CADENCE_MS;
      if (!out.current) out.stale = true;
    } else {
      // a checkpoint exists but no witness came for it: not current
      out.stale = true;
    }

    // continuity: the newest exists only if its prior head chain checks
    out.details.extendsPrior = extendsPrior(checkpoints);
  }

  // TRUNCATED: the vendor attested that history ends at a stated checkpoint.
  if (view.truncation) out.truncated = true;

  // BREACHED: computed only by a granted evidence window — an accumulated
  // verdict that a claim was contradicted. Not this module's call alone.
  if (view.breached) out.breached = true;

  // REFUSED: a signed refusal that ages like staleness.
  if ((view.refusals || []).some((r) => verifyRefusal(r))) {
    const newest = (view.refusals || []).filter(verifyRefusal)
      .sort((a, b) => b.body.at - a.body.at)[0];
    if (now - newest.body.at < CADENCE_MS) out.refused = true;
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
