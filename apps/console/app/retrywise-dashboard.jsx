'use client';

import { useEffect, useMemo, useState } from 'react';

const NAV_ITEMS = [
  ['command', 'Overview', '01'],
  ['cases', 'Recoveries', '02'],
  ['approvals', 'Decisions', '03'],
  ['evidence', 'Audit trail', '04'],
  ['impact', 'Performance', '05'],
  ['controls', 'Controls', '06'],
];

const LIVE_REFRESH_MS = 5000;

const REPLAY_BASELINES = [
  { key: 'B0', name: 'Do nothing', value: 0, amount: '₹0', note: 'No intervention' },
  { key: 'B1', name: 'Retry everyone', value: 61, amount: '₹16.27L', note: '2,487 hard violations' },
  { key: 'B2', name: 'Fixed rules', value: 37, amount: '₹9.89L', note: 'No incident awareness' },
  { key: 'B3', name: 'Incident-aware rules', value: 64, amount: '₹17.07L', note: 'Strongest safe baseline' },
  { key: 'RW', name: 'RetryWise', value: 76, amount: '₹20.11L', note: '0 hard violations' },
];

function formatMoney(minor, currency = 'INR') {
  const value = Number(minor);
  if (!Number.isFinite(value)) return '—';
  return new Intl.NumberFormat('en-IN', {
    style: 'currency',
    currency,
    maximumFractionDigits: value % 100 === 0 ? 0 : 2,
  }).format(value / 100);
}

function formatLakh(minor) {
  const value = Number(minor);
  return Number.isFinite(value) ? `₹${(value / 10_000_000).toFixed(2)}L` : '—';
}

function formatTime(value, includeDate = false) {
  if (!value) return 'Awaiting event';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat('en-IN', {
    day: includeDate ? '2-digit' : undefined,
    month: includeDate ? 'short' : undefined,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date);
}

function elapsed(start, end) {
  if (!start || !end) return '—';
  const seconds = Math.max(0, Math.round((new Date(end) - new Date(start)) / 1000));
  if (!Number.isFinite(seconds)) return '—';
  const minutes = Math.floor(seconds / 60);
  return minutes ? `${minutes}m ${String(seconds % 60).padStart(2, '0')}s` : `${seconds}s`;
}

function compactId(value, head = 10, tail = 6) {
  if (!value) return 'not issued';
  const text = String(value);
  return text.length <= head + tail + 1 ? text : `${text.slice(0, head)}…${text.slice(-tail)}`;
}

function label(value) {
  return String(value || 'unknown').replaceAll('_', ' ').toLowerCase();
}

function diagnosisEngineLabel(decision) {
  if (!decision) return 'Assessment pending';
  if (decision.requested_diagnosis_mode === 'SHADOW') {
    const agreement = decision.shadow_diagnosis?.agreed;
    return `Local ML · Gemini shadow ${agreement === true ? 'agreed' : agreement === false ? 'disagreed' : 'unavailable'}`;
  }
  if (decision.executed_diagnosis_engine === 'GEMINI') {
    return `Gemini · ${decision.diagnosis_latency_ms ?? 0} ms`;
  }
  if (decision.diagnosis_fallback_reason_code) {
    return `Local ML fallback · ${label(decision.diagnosis_fallback_reason_code)}`;
  }
  return 'Local ML · deterministic artifact';
}

function latest(items) {
  return items?.length ? items[items.length - 1] : null;
}

function latestDiagnosis(items) {
  return items?.length
    ? [...items].reverse().find((item) => item.requested_diagnosis_mode) || null
    : null;
}

function topProbability(decision) {
  const probabilities = decision?.class_probabilities;
  if (!probabilities || typeof probabilities !== 'object') return null;
  return Object.entries(probabilities)
    .map(([name, value]) => [name, Number(value)])
    .filter(([, value]) => Number.isFinite(value))
    .sort((a, b) => b[1] - a[1])[0] || null;
}

function sourceBadge(apiState, mode) {
  if (apiState === 'loading' || apiState === 'refreshing') return ['syncing', apiState === 'refreshing' ? 'Refreshing provider evidence' : 'Syncing evidence'];
  if (apiState === 'connected') return ['live', mode === 'test' ? 'Provider evidence connected' : 'Replay engine connected'];
  return ['offline', mode === 'test' ? 'Runtime unavailable' : 'Bundled evidence'];
}

function ModeSwitch({ mode, onChange }) {
  return (
    <div className="mode-switch" aria-label="Evidence environment">
      <button type="button" className={mode === 'test' ? 'active' : ''} onClick={() => onChange('test')} aria-pressed={mode === 'test'}><span className="mode-light provider" /> Razorpay test</button>
      <button type="button" className={mode === 'replay' ? 'active' : ''} onClick={() => onChange('replay')} aria-pressed={mode === 'replay'}><span className="mode-light replay" /> Impact replay</button>
    </div>
  );
}

function StateBadge({ state }) {
  const safeState = String(state || 'UNKNOWN');
  const tone = ['RECOVERED', 'PAID', 'APPROVED'].includes(safeState)
    ? 'success'
    : safeState.includes('SUPPRESSED') || safeState === 'REJECTED'
      ? 'restrained'
      : ['APPROVAL_REQUIRED', 'PENDING'].includes(safeState) ? 'approval' : 'active';
  return <span className={`state-badge ${tone}`}><i />{label(safeState)}</span>;
}

function ProofId({ eyebrow, value, tone = 'neutral' }) {
  return <div className={`proof-id ${tone}`}><span>{eyebrow}</span><code title={value || undefined}>{compactId(value)}</code></div>;
}

function EmptyState({ title, copy }) {
  return <section className="empty-state"><div className="empty-signal"><span /><span /><span /></div><p className="eyebrow">Strict evidence boundary</p><h2>{title}</h2><p>{copy}</p></section>;
}

function RecoveryRail({ summary, detail, approval, audit }) {
  const decision = latestDiagnosis(detail?.decisions);
  const action = latest(detail?.actions);
  const instrument = latest(detail?.instruments);
  const stages = [
    ['danger', 'Failure received', `${summary?.payment_method || 'Payment'} · ${formatMoney(summary?.amount_minor, summary?.currency)}`, summary?.created_at, Boolean(summary)],
    ['violet', decision?.abstained ? 'Model abstained safely' : 'Failure classified', decision?.out_of_distribution ? 'Out-of-distribution · policy took control' : label(topProbability(decision)?.[0]), decision?.created_at, Boolean(decision)],
    ['amber', approval?.verdict === 'APPROVED' ? 'Human authority granted' : 'Human approval required', approval ? `Bound to aggregate v${approval.aggregate_version}` : 'Version-bound decision pending', approval?.acted_at || approval?.requested_at, approval?.verdict === 'APPROVED'],
    ['blue', action ? 'One recovery link created' : 'Provider effect gated', action ? `Effect gate ${label(action.effect_gate_verdict)}` : 'No provider call without authority', action?.completed_at, action?.status === 'SUCCEEDED'],
    ['success', instrument?.status === 'PAID' ? 'Recovery payment captured' : 'Awaiting money truth', instrument?.status === 'PAID' ? `${formatMoney(instrument.collected_minor, instrument.currency)} provider-confirmed` : 'No synthetic completion allowed', detail?.terminal_at, instrument?.status === 'PAID' && audit?.valid],
  ];
  return (
    <section className="recovery-rail" aria-label="End-to-end recovery sequence">
      <div className="section-heading rail-heading"><div><p className="eyebrow">Recovery spine</p><h2>One journey. Every consequential boundary.</h2></div><span className="rail-duration">failure → proof <strong>{elapsed(summary?.created_at, detail?.terminal_at)}</strong></span></div>
      <ol>{stages.map(([tone, title, copy, time, complete], index) => <li className={`${complete ? 'complete' : ''} ${tone}`} key={title}><div className="stage-index"><span>{complete ? '✓' : String(index + 1).padStart(2, '0')}</span></div><div className="stage-copy"><strong>{title}</strong><p>{copy}</p><time>{formatTime(time)}</time></div></li>)}</ol>
    </section>
  );
}

function OperationalFlow({ summary, detail, approval, audit, incidents }) {
  const decision = latestDiagnosis(detail?.decisions);
  const action = latest(detail?.actions);
  const instrument = latest(detail?.instruments);
  const probability = topProbability(decision);
  const restrained = String(summary?.state || '').includes('SUPPRESSED');
  const approvalResolved = !approval || approval.verdict !== 'PENDING';
  const stages = [
    {
      number: '01',
      label: 'Trigger',
      title: 'Razorpay payment.failed',
      copy: 'A signed provider webhook opens or updates one merchant-scoped recovery case.',
      value: summary ? `${summary.payment_method || 'payment'} · ${formatMoney(summary.amount_minor, summary.currency)}` : 'Awaiting event',
      complete: Boolean(summary),
    },
    {
      number: '02',
      label: 'Trust + enrich',
      title: 'Verify, deduplicate, re-read',
      copy: 'HMAC, account binding, and idempotency are checked before current Payment and Order truth is fetched.',
      value: detail?.provider_snapshot_at ? `Snapshot ${formatTime(detail.provider_snapshot_at)}` : 'Provider snapshot pending',
      complete: Boolean(detail?.provider_snapshot_at),
    },
    {
      number: '03',
      label: 'Detect',
      title: 'Classify failure and uncertainty',
      copy: 'Structured payment signals and rail health produce a failure class, confidence, and abstention decision.',
      value: probability ? `${label(probability[0])} · ${(probability[1] * 100).toFixed(1)}%` : 'Assessment pending',
      complete: Boolean(decision),
    },
    {
      number: '04',
      label: 'Authorize',
      title: restrained ? 'Policy closed the unsafe path' : 'Deterministic policy owns the effect',
      copy: restrained ? 'Expired or denied authority becomes a terminal restraint; no stale decision can authorize collection.' : 'Late-capture timing, incidents, limits, and aggregate version decide whether to wait, block, or require approval.',
      value: restrained ? label(summary?.terminal_reason_code || summary?.state) : approval ? `${label(approval.verdict)} · aggregate v${approval.aggregate_version}` : label(decision?.planning_gate_verdict),
      complete: Boolean(decision) && (approvalResolved || restrained),
    },
    {
      number: '05',
      label: 'Recover',
      title: restrained ? 'Recovery safely withheld' : 'Create one bounded payment path',
      copy: restrained ? 'Policy reached a terminal restraint without creating a new collection surface.' : 'The worker fresh-checks every execution fence, then creates at most one deterministic Razorpay Payment Link.',
      value: action ? `${label(action.status)} · attempt ${action.attempt_number}` : restrained ? label(summary?.terminal_reason_code || summary?.state) : 'Effect held',
      complete: action?.status === 'SUCCEEDED' || restrained,
    },
    {
      number: '06',
      label: 'Reconcile',
      title: restrained ? 'Close with a proven restraint' : 'Close only on provider money truth',
      copy: restrained ? 'The case closes without collection while the audit chain preserves why no effect was allowed.' : 'Captured payment and link events update the case; the audit chain proves every authority transition.',
      value: restrained ? `${label(summary?.state)} · audit ${audit?.valid ? 'valid' : 'verifying'}` : instrument ? `${label(instrument.status)} · ${formatMoney(instrument.collected_minor, instrument.currency)}` : 'Awaiting provider outcome',
      complete: restrained ? Boolean(audit?.valid) : instrument?.status === 'PAID' && audit?.valid,
    },
  ];
  const activeIndex = stages.findIndex((stage) => !stage.complete);
  const activeStage = activeIndex >= 0 ? stages[activeIndex] : stages[stages.length - 1];
  const events = [
    summary && { name: 'Failure persisted', detail: 'Signed payment.failed accepted', time: summary.created_at, tone: 'danger' },
    detail?.provider_snapshot_at && { name: 'Provider truth refreshed', detail: 'Payment and Order re-read', time: detail.provider_snapshot_at, tone: 'blue' },
    decision && { name: decision.abstained ? 'Assessment abstained' : 'Failure classified', detail: decision.abstained ? 'Policy retained authority' : label(probability?.[0]), time: decision.created_at, tone: 'violet' },
    approval && { name: approval.verdict === 'PENDING' ? 'Approval requested' : `Approval ${label(approval.verdict)}`, detail: `Aggregate v${approval.aggregate_version}`, time: approval.acted_at || approval.requested_at, tone: 'amber' },
    action && { name: 'Recovery instrument created', detail: compactId(action.provider_resource_id, 9, 5), time: action.completed_at, tone: 'blue' },
    restrained && { name: 'Collection safely restrained', detail: label(summary.terminal_reason_code || summary.state), time: summary.updated_at, tone: 'amber' },
    instrument?.status === 'PAID' && { name: 'Recovery payment confirmed', detail: formatMoney(instrument.collected_minor, instrument.currency), time: detail?.terminal_at || instrument.last_reconciled_at, tone: 'success' },
  ].filter(Boolean);
  return (
    <section className="operational-flow">
      <div className="section-heading flow-heading">
        <div><p className="eyebrow">Operating path</p><h2>How a failed payment becomes a governed recovery.</h2><p>The event activates RetryWise automatically. Detection informs the decision; deterministic controls authorize any provider effect.</p></div>
        <div className="integration-status"><span className="source-orb live" /><div><strong>Razorpay Test connected</strong><small>{incidents?.length || 0} tracked rail incidents</small></div></div>
      </div>
      <div className="live-trace-bar" aria-live="polite"><span className={activeIndex >= 0 ? 'trace-pulse active' : 'trace-pulse complete'} /><div><small>{activeIndex >= 0 ? `CURRENT STAGE · ${activeStage.number}` : 'JOURNEY COMPLETE'}</small><strong>{activeStage.title}</strong></div><code>{summary ? compactId(summary.id, 12, 8) : 'awaiting payment.failed'}</code></div>
      <ol className="flow-grid">{stages.map((stage, index) => {
        const state = stage.complete ? 'complete' : index === activeIndex ? 'active' : 'pending';
        return <li className={state} key={stage.number} aria-current={state === 'active' ? 'step' : undefined}><span className="flow-progress" aria-hidden="true" /><header><span>{stage.number}</span><b>{stage.label}</b><i>{stage.complete ? '✓' : state === 'active' ? '↻' : '·'}</i></header><h3>{stage.title}</h3><p>{stage.copy}</p><footer>{stage.value}</footer></li>;
      })}</ol>
      <div className="signal-strip">
        <div><span>Ingress event</span><code>payment.failed</code></div>
        <div><span>Observation deadline</span><strong>{formatTime(detail?.observation_deadline_at || detail?.evaluation_deadline_at, true)}</strong></div>
        <div><span>Diagnosis engine</span><strong>{diagnosisEngineLabel(decision)}</strong></div>
        <div><span>Current money truth</span><strong>{detail?.canonical_truth || 'AWAITING'}</strong></div>
      </div>
      <div className="event-stream">
        <header><div><p className="eyebrow">Live case events</p><h3>What RetryWise has actually observed and done.</h3></div><span><i />auto-tracking</span></header>
        <ol>{events.map((event, index) => <li className={event.tone} key={`${event.name}-${event.time || index}`}><time>{formatTime(event.time)}</time><i /><div><strong>{event.name}</strong><span>{event.detail}</span></div></li>)}</ol>
      </div>
    </section>
  );
}

function TestTriggerGuide({ apiState, lastSyncedAt, pendingApprovals, onNavigate }) {
  return (
    <section className="test-trigger-guide">
      <div className="trigger-heading"><div><p className="eyebrow">Start a fresh Test recovery</p><h2>Trigger it in Razorpay. Watch the same ₹10 move here.</h2><p>This console does not manufacture a case. A real Test Mode failure enters through the public signed webhook, then this workspace follows its persisted state every five seconds.</p></div><div className="trigger-readiness"><span className={apiState === 'connected' || apiState === 'refreshing' ? 'ready' : 'blocked'}><i />API {apiState === 'connected' || apiState === 'refreshing' ? 'connected' : 'unavailable'}</span><span className="ready"><i />Auto-tracking · 5s</span><span className="external"><i />Public HTTPS required</span><small>Last evidence sync · {formatTime(lastSyncedAt)}</small></div></div>
      <ol className="trigger-steps">
        <li><span>01</span><div><strong>Create the attempt</strong><p>In Razorpay Test Mode, create or open a ₹10 Payment Link or Checkout backed by the enrolled test account.</p></div><b>RAZORPAY</b></li>
        <li><span>02</span><div><strong>Choose Failure</strong><p>Use the Test Mode Failure control or UPI ID <code>failure@razorpay</code>. Razorpay emits <code>payment.failed</code>.</p></div><b>TRIGGER</b></li>
        <li><span>03</span><div><strong>Follow the live trace</strong><p>The newest case appears automatically. Watch verification, the two-minute late-capture wait, assessment, and policy advance.</p></div><b>RETRYWISE</b></li>
        <li><span>04</span><div><strong>Complete recovery</strong><p>{pendingApprovals ? 'A decision is ready. Approve it, then open the single new link from Razorpay Test Payment Links and choose Success.' : 'If authority is requested, approve it in Decisions; then open the single new link from Razorpay Test Payment Links and choose Success.'}</p></div><button type="button" onClick={() => onNavigate(pendingApprovals ? 'approvals' : 'cases')}>{pendingApprovals ? `Open ${pendingApprovals} decision${pendingApprovals === 1 ? '' : 's'} →` : 'Open recoveries →'}</button></li>
      </ol>
      <footer><span><i />What should change here</span><p><b>Failed</b> → observed → assessed → approved if needed → one Payment Link → <b>recovered</b>. The original failed payment is never retried.</p></footer>
    </section>
  );
}

function TestCommandCenter({ overview, apiState, evidence, selectedId, onSelect, onNavigate, caseDetail, audit, lastSyncedAt }) {
  if (!['connected', 'refreshing'].includes(apiState)) return <EmptyState title="Waiting for the RetryWise runtime" copy="Start the API and worker to load signature-verified provider truth. This Test Mode workspace never substitutes replay fixtures." />;
  if (!evidence.cases.length) return <div className="command-view"><EmptyState title="Ready for the first Razorpay Test failure" copy="The runtime is connected. Trigger a real Test Mode failure through the enrolled Razorpay account and the case will appear here automatically." /><TestTriggerGuide apiState={apiState} lastSyncedAt={lastSyncedAt} pendingApprovals={0} onNavigate={onNavigate} /></div>;
  const summary = evidence.cases.find((item) => item.id === selectedId) || evidence.cases[0];
  const detail = caseDetail?.id === summary.id ? caseDetail : null;
  const approval = evidence.approvals.find((item) => item.recovery_case_id === summary.id);
  const decision = latestDiagnosis(detail?.decisions);
  const action = latest(detail?.actions);
  const instrument = latest(detail?.instruments);
  const probability = topProbability(decision);
  const recovered = summary.state === 'RECOVERED';
  return (
    <div className="command-view">
      <section className={`mission-hero ${recovered ? 'recovered' : ''}`}>
        <div className="hero-grid" aria-hidden="true" />
        <div className="hero-copy">
          <div className="hero-kicker"><span>Recovery operations</span><b>Razorpay Test Mode · no real money</b></div>
          <StateBadge state={summary.state} />
          <h1>{recovered ? 'Recovered revenue without retrying the original payment.' : 'A failed payment is being evaluated before recovery begins.'}</h1>
          <p>RetryWise listens for failed-payment events, waits for late settlement, detects the likely failure context, and creates a controlled recovery path only when current provider truth and policy permit it.</p>
          <div className="hero-actions"><button className="primary-action" type="button" onClick={() => onNavigate('cases')}>Open recovery case</button><button className="secondary-action" type="button" onClick={() => onNavigate('evidence')}>Review audit trail</button></div>
        </div>
        <div className="recovery-core" aria-label={`${formatMoney(instrument?.collected_minor || 0, summary.currency)} recovered`}>
          <div className="core-halo halo-one" /><div className="core-halo halo-two" />
          <div className="before-after before"><span>Original attempt</span><strong>FAILED</strong><small>{summary.payment_method || 'payment'} · provider-confirmed failure</small></div>
          <div className="money-core"><span>Provider-confirmed</span><strong>{formatMoney(instrument?.collected_minor || overview?.test_mode_recovered_minor || 0, summary.currency)}</strong><small>{recovered ? 'RECOVERED' : 'IN PROGRESS'}</small></div>
          <div className="before-after after"><span>Recovery path</span><strong>{instrument?.status || 'AWAITING'}</strong><small>{instrument ? compactId(instrument.provider_payment_id, 8, 5) : 'no instrument yet'}</small></div>
        </div>
      </section>

      <OperationalFlow summary={summary} detail={detail} approval={approval} audit={audit} incidents={evidence.incidents} />

      <TestTriggerGuide apiState={apiState} lastSyncedAt={lastSyncedAt} pendingApprovals={evidence.approvals.filter((item) => item.verdict === 'PENDING').length} onNavigate={onNavigate} />

      <section className="proof-metrics" aria-label="Runtime proof metrics">
        <article><span>Recovered in Test Mode</span><strong>{formatMoney(overview?.test_mode_recovered_minor || 0)}</strong><small>{overview?.recovered_cases || 0} provider-confirmed recoveries</small></article>
        <article><span>Hard safety violations</span><strong className="safe-number">{overview?.hard_safety_violations ?? '—'}</strong><small>computed from persisted invariants</small></article>
        <article><span>Payment Links created</span><strong>{overview?.provider_create_runs ?? '—'}</strong><small>one active instrument per action</small></article>
        <article><span>Audit-chain integrity</span><strong>{audit?.valid ? 'VALID' : 'VERIFYING'}</strong><small>{audit?.checked_entries || 0} entries recomputed</small></article>
      </section>

      <RecoveryRail summary={summary} detail={detail} approval={approval} audit={audit} />

      <section className="intelligence-grid">
        <article className="intelligence-card decision-card">
          <div className="card-topline"><span className="signal-icon violet">{decision?.executed_diagnosis_engine === 'GEMINI' ? 'AI' : 'ML'}</span><div><p className="eyebrow">Failure detection</p><h2>Uncertainty became an explicit operating state.</h2></div><span className="micro-status">{diagnosisEngineLabel(decision)}</span></div>
          <div className="decision-callout"><div><span>Most likely cause</span><strong>{probability ? label(probability[0]) : 'awaiting assessment'}</strong></div><strong className="probability">{probability ? `${(probability[1] * 100).toFixed(1)}%` : '—'}</strong></div>
          <div className="decision-grid"><div><span>Engine requested</span><strong>{label(decision?.requested_diagnosis_mode)}</strong></div><div><span>Engine executed</span><strong>{label(decision?.executed_diagnosis_engine)}</strong></div><div><span>Model abstained</span><strong className={decision?.abstained ? 'warn' : ''}>{decision?.abstained ? 'YES' : 'NO'}</strong></div><div><span>Planning verdict</span><strong>{label(decision?.planning_gate_verdict)}</strong></div></div>
          <p className="explain-line"><i />The model proposed context; policy owned authority. Low confidence could not silently become a payment effect.</p>
        </article>

        <article className="intelligence-card provider-card">
          <div className="card-topline"><span className="signal-icon blue">RP</span><div><p className="eyebrow">Provider effect proof</p><h2>Real Razorpay objects, reconciled back.</h2></div><StateBadge state={instrument?.status || action?.status} /></div>
          <div className="provider-flow"><ProofId eyebrow="Payment link" value={instrument?.provider_payment_link_id || action?.provider_resource_id} tone="blue" /><span className="flow-arrow">→</span><ProofId eyebrow="Recovery order" value={instrument?.provider_order_id} /><span className="flow-arrow">→</span><ProofId eyebrow="Captured payment" value={instrument?.provider_payment_id} tone="green" /></div>
          <div className="provider-footer"><span>Effect gate <strong>{label(action?.effect_gate_verdict)}</strong></span><span>Reconciliation <strong>{label(instrument?.reconciliation_status || action?.reconciliation_status)}</strong></span><span>Collected <strong>{formatMoney(instrument?.collected_minor || 0, instrument?.currency)}</strong></span></div>
        </article>
      </section>

      <section className="why-panel">
        <div className="section-heading"><div><p className="eyebrow">Operating model</p><h2>Recovery without duplicate-collection risk.</h2></div><button className="text-action" type="button" onClick={() => onNavigate('controls')}>Open all controls →</button></div>
        <div className="why-grid">
          <article><span>01</span><strong>Wait before acting</strong><p>A late-capture window protects customers from duplicate collection when the original payment settles slowly.</p></article>
          <article><span>02</span><strong>Abstain under uncertainty</strong><p>Out-of-distribution failures escalate to policy and human authority instead of forcing a model answer.</p></article>
          <article><span>03</span><strong>Fence every effect</strong><p>Fresh provider truth, incident health, kill switches, aggregate version, and idempotency are checked at execution time.</p></article>
          <article><span>04</span><strong>Prove what happened</strong><p>Provider IDs, money truth, immutable audit entries, and deterministic references make the outcome independently verifiable.</p></article>
        </div>
      </section>

      <section className="case-switcher"><div><p className="eyebrow">Persisted Test Mode cases</p><h2>Compare recovery with restraint.</h2></div><div className="case-pills">{evidence.cases.map((item) => <button type="button" key={item.id} className={item.id === summary.id ? 'active' : ''} onClick={() => onSelect(item.id)}><StateBadge state={item.state} /><span>{formatMoney(item.amount_minor, item.currency)}</span><code>{compactId(item.id, 7, 4)}</code></button>)}</div></section>
    </div>
  );
}

function ReplayCommandCenter({ overview, apiState, onNavigate, onRun, runState }) {
  const caseCount = Number(overview?.manifest?.case_count || 2000);
  const lift = overview?.net_lift_vs_b3_minor ?? 30357423;
  const value = overview?.offline_simulated_incremental_value_minor ?? 201077673;
  return (
    <div className="command-view">
      <section className="mission-hero replay-hero">
        <div className="hero-grid" aria-hidden="true" />
        <div className="hero-copy">
          <div className="hero-kicker"><span>Counterfactual proof</span><b>Offline synthetic replay · no real money</b></div>
          <StateBadge state="MODEL-BOUND EVIDENCE" />
          <h1>Better than smart retries: measured value with zero hard violations.</h1>
          <p>Every policy sees the same {caseCount.toLocaleString('en-IN')} journeys. RetryWise is compared with the strongest incident-aware rules to measure when recovery creates value—and when restraint protects more.</p>
          <div className="hero-actions"><button className="primary-action" type="button" onClick={onRun} disabled={runState === 'running'}>{runState === 'running' ? 'Running paired replay…' : 'Reproduce the evidence'}</button><button className="secondary-action" type="button" onClick={() => onNavigate('impact')}>Open performance view</button></div>
        </div>
        <div className="impact-core"><span>Incremental simulated value</span><strong>{formatLakh(value)}</strong><small>+{formatLakh(lift)} vs B3</small><div className="impact-ring"><i style={{ '--score': '76%' }} /></div></div>
      </section>
      <section className="proof-metrics">
        <article><span>Paired journeys</span><strong>{caseCount.toLocaleString('en-IN')}</strong><small>same outcomes for every policy</small></article>
        <article><span>Lift vs strongest rules</span><strong>{formatLakh(lift)}</strong><small>merchant-clustered evaluation</small></article>
        <article><span>Safely suppressed</span><strong>{overview?.safely_suppressed_original_successes ?? 193}</strong><small>original successes protected</small></article>
        <article><span>Hard violations</span><strong className="safe-number">{overview?.hard_safety_violations ?? 0}</strong><small>effect invariants preserved</small></article>
      </section>
      <ImpactLab overview={overview} apiState={apiState} embedded />
    </div>
  );
}

function CasesView({ evidence, selectedId, onSelect, detail, audit }) {
  if (!evidence.cases.length) return <EmptyState title="No persisted recovery cases" copy="Cases appear here only after a verified provider event creates a tenant-bound aggregate." />;
  const summary = evidence.cases.find((item) => item.id === selectedId) || evidence.cases[0];
  const decision = latestDiagnosis(detail?.decisions);
  const action = latest(detail?.actions);
  const instrument = latest(detail?.instruments);
  return (
    <div className="split-view">
      <section className="queue-panel">
        <div className="section-heading"><div><p className="eyebrow">Merchant-scoped queue</p><h1>Recovery cases</h1><p>Real Test Mode state. No replay rows.</p></div><span className="count-chip">{evidence.cases.length} cases</span></div>
        <div className="case-list">{evidence.cases.map((item) => <button type="button" key={item.id} onClick={() => onSelect(item.id)} className={item.id === summary.id ? 'active' : ''}><div><StateBadge state={item.state} /><strong>{formatMoney(item.amount_minor, item.currency)}</strong></div><p>{item.payment_method || 'provider payment'} <span>·</span> {compactId(item.merchant_order_reference, 18, 7)}</p><footer><code>{compactId(item.id, 10, 5)}</code><time>{formatTime(item.updated_at, true)}</time></footer></button>)}</div>
      </section>
      <section className="case-dossier">
        <div className="dossier-head"><div><p className="eyebrow">Case dossier</p><h2>{compactId(summary.id, 14, 8)}</h2></div><StateBadge state={summary.state} /></div>
        <div className="dossier-money"><span>Amount under recovery</span><strong>{formatMoney(summary.amount_minor, summary.currency)}</strong><small>{summary.payment_method || 'payment method unavailable'} · aggregate v{detail?.version ?? summary.version}</small></div>
        <div className="truth-board"><div><span>Canonical truth</span><strong>{detail?.canonical_truth || 'loading'}</strong></div><div><span>Decision</span><strong>{label(decision?.planning_gate_verdict)}</strong></div><div><span>Effect gate</span><strong>{label(action?.effect_gate_verdict)}</strong></div><div><span>Instrument</span><strong>{label(instrument?.status)}</strong></div></div>
        <RecoveryRail summary={summary} detail={detail} approval={evidence.approvals.find((item) => item.recovery_case_id === summary.id)} audit={audit} />
        <div className="dossier-footer"><ProofId eyebrow="Case identity" value={summary.id} /><ProofId eyebrow="Last decision" value={summary.last_decision_id} /><ProofId eyebrow="Last action" value={summary.last_action_id} tone="green" /></div>
      </section>
    </div>
  );
}

function ApprovalsView({ approvals, actionState, onAct }) {
  if (!approvals.length) return <EmptyState title="No approval records yet" copy="When uncertainty or policy thresholds require human authority, a version-bound request appears here." />;
  const pending = approvals.filter((item) => item.verdict === 'PENDING').length;
  return (
    <div className="page-stack">
      <section className="page-hero compact"><div><p className="eyebrow">Human authority boundary</p><h1>{pending ? `${pending} decision waiting for you.` : 'Every approval has a durable outcome.'}</h1><p>Approval never calls Razorpay directly. It authorizes a worker command that must re-check fresh provider truth and every effect-time invariant.</p></div><div className="hero-stat"><span>Pending</span><strong>{pending}</strong><small>version-bound</small></div></section>
      <section className="approval-list">{approvals.map((item) => {
        const busy = actionState.id === item.id && actionState.status === 'running';
        const message = actionState.id === item.id ? actionState.message : '';
        return <article className="approval-card" key={item.id}><header><div><p className="eyebrow">Approval {compactId(item.id, 10, 5)}</p><h2>{formatMoney(item.amount_minor, item.currency)}</h2></div><StateBadge state={item.verdict} /></header><div className="approval-binding"><div><span>Recovery case</span><code>{compactId(item.recovery_case_id)}</code></div><div><span>Decision</span><code>{compactId(item.decision_id)}</code></div><div><span>Aggregate fence</span><strong>v{item.aggregate_version}</strong></div><div><span>Expires</span><strong>{formatTime(item.expires_at, true)}</strong></div></div><p className="approval-explain">The model abstained. Approval binds authority to this exact decision and aggregate version; stale approval cannot authorize a newer case.</p>{message ? <p className={`action-message ${actionState.status}`}>{message}</p> : null}{item.verdict === 'PENDING' ? <footer><button className="danger-action" type="button" disabled={busy} onClick={() => onAct(item.id, 'REJECTED')}>Reject safely</button><button className="primary-action" type="button" disabled={busy} onClick={() => onAct(item.id, 'APPROVED')}>{busy ? 'Recording…' : 'Approve with fresh recheck'}</button></footer> : <footer className="acted-footer"><span>Reason <strong>{label(item.reason_code)}</strong></span><span>Acted <strong>{formatTime(item.acted_at, true)}</strong></span></footer>}</article>;
      })}</section>
    </div>
  );
}

function EvidenceView({ summary, detail, audit }) {
  if (!summary) return <EmptyState title="Select a recovery case" copy="Evidence is computed for one tenant-bound case at a time." />;
  const instrument = latest(detail?.instruments);
  return (
    <div className="page-stack">
      <section className={`audit-hero ${audit?.valid ? 'valid' : ''}`}><div className="audit-seal"><span>{audit?.valid ? '✓' : '…'}</span><i /><i /></div><div><p className="eyebrow">Postgres audit chain v1</p><h1>{audit?.valid ? 'Every consequential decision recomputes cleanly.' : 'Verifying immutable evidence…'}</h1><p>Canonical facts are hashed with the previous entry. Editing, deleting, reordering, or crossing tenant boundaries breaks verification.</p></div><div className="audit-summary"><span>Chain status</span><strong>{audit?.valid ? 'VALID' : 'CHECKING'}</strong><small>{audit?.checked_entries || 0} entries · error sequence {audit?.error_sequence || 'none'}</small></div></section>
      <section className="evidence-layout">
        <article className="chain-panel"><div className="section-heading"><div><p className="eyebrow">Immutable chronology</p><h2>Decision-to-effect chain</h2></div><span className="count-chip">{audit?.entries?.length || 0} entries</span></div><ol className="audit-chain">{(audit?.entries || []).map((entry) => <li key={entry.id}><span className="chain-node">{String(entry.sequence_number).padStart(2, '0')}</span><div><strong>{label(entry.entry_type)}</strong><p>{label(entry.actor_type)} · {formatTime(entry.created_at, true)}</p><code title={entry.entry_hash}>{compactId(entry.entry_hash, 16, 12)}</code></div><span className="chain-check">verified</span></li>)}</ol></article>
        <aside className="provider-proof-panel"><p className="eyebrow">Provider truth bundle</p><h2>Reconciled Razorpay resources.</h2><div className="proof-stack"><ProofId eyebrow="Original order" value={detail?.original_provider_order_id} /><ProofId eyebrow="Recovery link" value={instrument?.provider_payment_link_id} tone="blue" /><ProofId eyebrow="Recovery order" value={instrument?.provider_order_id} /><ProofId eyebrow="Captured payment" value={instrument?.provider_payment_id} tone="green" /><ProofId eyebrow="Deterministic reference" value={instrument?.reference_id} /></div><div className="truth-total"><span>Provider-collected amount</span><strong>{formatMoney(instrument?.collected_minor || 0, instrument?.currency)}</strong><small>{label(instrument?.last_provider_status)} · {label(instrument?.reconciliation_status)}</small></div><p className="boundary-note"><i />Test Mode events are signature-verified and account-bound. Replay fixtures are never rendered in this environment.</p></aside>
      </section>
    </div>
  );
}

function ImpactLab({ overview, apiState, embedded = false }) {
  const interval = overview?.paired_interval_vs_b3_minor;
  const lift = overview?.net_lift_vs_b3_minor ?? 30357423;
  return (
    <section className={embedded ? 'impact-lab embedded' : 'impact-lab'}>
      <div className="section-heading"><div><p className="eyebrow">Paired counterfactual evaluation</p><h2>RetryWise beats the strongest safe rule baseline.</h2><p>Same synthetic journey, same outcome draw, same cost assumptions—only the policy changes.</p></div><span className={`source-chip ${apiState === 'connected' ? 'connected' : ''}`}>{apiState === 'connected' ? 'source-bound replay' : 'bundled snapshot'}</span></div>
      <div className="impact-evidence"><div className="baseline-chart">{REPLAY_BASELINES.map((item) => <div className={item.key === 'RW' ? 'winner' : ''} key={item.key}><span className="baseline-key">{item.key}</span><div><header><strong>{item.name}</strong><b>{item.amount}</b></header><span className="bar-track"><i style={{ width: `${item.value}%` }} /></span><small>{item.note}</small></div></div>)}</div><aside className="lift-card"><span>Net lift over B3</span><strong>{formatLakh(lift)}</strong><p>95% merchant-clustered interval</p><b>{formatLakh(interval?.low ?? 3827280)} → {formatLakh(interval?.high ?? 58493901)}</b><footer><span>Hard violations</span><strong>{overview?.hard_safety_violations ?? 0}</strong></footer></aside></div>
    </section>
  );
}

function ImpactView({ overview, apiState, onRun, runState }) {
  return <div className="page-stack"><section className="page-hero compact"><div><p className="eyebrow">Policy performance</p><h1>Measure recovery value against safe baselines.</h1><p>Paired replay compares the same payment journeys across do-nothing, retry-all, fixed-rule, incident-aware, and RetryWise policies while tracking safety violations separately.</p></div><button className="primary-action" type="button" onClick={onRun} disabled={runState === 'running'}>{runState === 'running' ? 'Running 2,000 journeys…' : 'Run performance replay'}</button></section><ImpactLab overview={overview} apiState={apiState} /></div>;
}

function ControlsView({ control, diagnosisControl, overview, actionState, diagnosisActionState, onToggle, onDiagnosisMode }) {
  const enabled = Boolean(control?.collection_effects_enabled);
  const guardrails = [
    ['01', 'Fresh money truth', 'Re-read Payment and Order immediately before effect. Paid or stale truth stops collection.'],
    ['02', 'One active instrument', 'Database uniqueness and deterministic references prevent duplicate recovery links.'],
    ['03', 'Version-fenced authority', 'Approval, decision, action, and aggregate versions must agree exactly.'],
    ['04', 'Incident-aware restraint', 'Degraded payment rails pause affected interventions without freezing healthy methods.'],
    ['05', 'Dual kill switches', 'Deployment and merchant controls deny new effects independently and default closed.'],
    ['06', 'Uncertain-result reconciliation', 'Ambiguous provider outcomes are looked up by reference—never blindly retried.'],
  ];
  return (
    <div className="page-stack">
      <section className={`control-hero ${enabled ? 'armed' : 'held'}`}><div><p className="eyebrow">Fail-closed effect boundary</p><h1>{enabled ? 'Test collection effects are armed—inside six independent fences.' : 'Collection effects are held.'}</h1><p>A model never owns credentials or calls Razorpay. The isolated worker proves current authority immediately before any provider effect.</p></div><div className="control-switch"><span>{enabled ? 'EFFECTS ARMED' : 'EFFECTS HELD'}</span><button type="button" onClick={onToggle} disabled={!control || actionState.status === 'running'} aria-label={enabled ? 'Arm merchant kill switch' : 'Remove merchant kill switch'}><i className={enabled ? 'on' : ''} /></button><small>Razorpay Test Mode only</small></div></section>
      {actionState.message ? <p className={`action-message global ${actionState.status}`}>{actionState.message}</p> : null}
      <section className="diagnosis-control-panel">
        <header><div><p className="eyebrow">Diagnosis routing</p><h2>Choose how failure context is classified.</h2><p>Only seven normalized categorical signals leave the payment pipeline. The selected model proposes a class and confidence; deterministic policy still owns every effect.</p></div><span className={diagnosisControl?.gemini_configured ? 'configured' : 'unconfigured'}><i />Gemini {diagnosisControl?.gemini_configured ? 'configured' : 'key not enrolled'}</span></header>
        <div className="diagnosis-mode-grid">
          {[
            ['LOCAL_ML', 'Local ML', 'Fast, offline and reproducible. Uses the pinned categorical model for every case.', 'LOCAL'],
            ['HYBRID_GEMINI', 'Gemini + fallback', 'Gemini classifies the redacted vector. Any timeout, invalid output, or outage falls back to local ML and requires approval.', 'LIVE'],
            ['SHADOW', 'Shadow comparison', 'Local ML remains authoritative while Gemini runs beside it; agreement is stored without changing the action path.', 'SAFE TEST'],
          ].map(([engineMode, title, copy, badge]) => <button type="button" key={engineMode} className={diagnosisControl?.mode === engineMode ? 'active' : ''} disabled={!diagnosisControl || diagnosisActionState.status === 'running'} onClick={() => onDiagnosisMode(engineMode)} aria-pressed={diagnosisControl?.mode === engineMode}><span>{badge}</span><strong>{title}</strong><p>{copy}</p><i>{diagnosisControl?.mode === engineMode ? 'ACTIVE' : 'SELECT'}</i></button>)}
        </div>
        <footer><span><b>Privacy boundary</b> No IDs, phone, email, UPI address, notes, card data, amount, or customer fields are sent.</span><span><b>Outage boundary</b> 2.5s timeout · circuit breaker · schema validation · local fallback.</span><span><b>Authority boundary</b> Gemini has no Razorpay credentials, tools, or execution access.</span></footer>
      </section>
      {diagnosisActionState.message ? <p className={`action-message global ${diagnosisActionState.status}`}>{diagnosisActionState.message}</p> : null}
      <section className="guardrail-grid">{guardrails.map(([number, title, copy]) => <article key={number}><span>{number}</span><i>✓</i><h2>{title}</h2><p>{copy}</p></article>)}</section>
      <section className="invariant-strip"><div><span>Persisted hard violations</span><strong>{overview?.hard_safety_violations ?? '—'}</strong></div><div><span>Credential mode</span><strong>VERSIONED TEST SECRET</strong></div><div><span>Environment</span><strong>RAZORPAY TEST</strong></div><div><span>Real-money effects</span><strong>IMPOSSIBLE</strong></div></section>
    </div>
  );
}

export default function RetryWiseDashboard() {
  const [mode, setMode] = useState('test');
  const [view, setView] = useState('command');
  const [apiState, setApiState] = useState('loading');
  const [overview, setOverview] = useState(null);
  const [evidence, setEvidence] = useState({ cases: [], incidents: [], approvals: [], control: null, diagnosisControl: null });
  const [selectedId, setSelectedId] = useState(null);
  const [followNewest, setFollowNewest] = useState(true);
  const [caseDetail, setCaseDetail] = useState(null);
  const [audit, setAudit] = useState(null);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [lastSyncedAt, setLastSyncedAt] = useState(null);
  const [runState, setRunState] = useState('ready');
  const [approvalActionState, setApprovalActionState] = useState({ id: null, status: 'idle', message: '' });
  const [controlActionState, setControlActionState] = useState({ status: 'idle', message: '' });
  const [diagnosisActionState, setDiagnosisActionState] = useState({ status: 'idle', message: '' });

  const selectedSummary = useMemo(() => evidence.cases.find((item) => item.id === selectedId) || evidence.cases[0] || null, [evidence.cases, selectedId]);

  useEffect(() => {
    const controller = new AbortController();
    const environment = mode === 'test' ? 'RAZORPAY_TEST_MODE' : 'REPLAY';
    setApiState((current) => current === 'connected' || current === 'refreshing' ? 'refreshing' : 'loading');
    const overviewRequest = fetch(`/api/retrywise/overview?environment=${environment}`, { cache: 'no-store', signal: controller.signal }).then(async (response) => {
      if (!response.ok) throw new Error('overview unavailable');
      return response.json();
    });
    const evidenceRequest = mode === 'test' ? Promise.all([
      fetch('/api/retrywise/cases', { cache: 'no-store', signal: controller.signal }),
      fetch('/api/retrywise/incidents', { cache: 'no-store', signal: controller.signal }),
      fetch('/api/retrywise/approvals', { cache: 'no-store', signal: controller.signal }),
      fetch('/api/retrywise/controls/kill-switch', { cache: 'no-store', signal: controller.signal }),
      fetch('/api/retrywise/controls/diagnosis-engine', { cache: 'no-store', signal: controller.signal }),
    ]).then(async (responses) => {
      if (responses.some((response) => !response.ok)) throw new Error('runtime evidence unavailable');
      const [casesPayload, incidentsPayload, approvalsPayload, controlPayload, diagnosisControlPayload] = await Promise.all(responses.map((response) => response.json()));
      return { cases: casesPayload.cases || [], incidents: incidentsPayload.incidents || [], approvals: approvalsPayload.approvals || [], control: controlPayload, diagnosisControl: diagnosisControlPayload };
    }) : Promise.resolve(null);
    Promise.all([overviewRequest, evidenceRequest]).then(([overviewPayload, evidencePayload]) => {
      setOverview(overviewPayload);
      if (evidencePayload) {
        setEvidence(evidencePayload);
        setSelectedId((current) => followNewest || !current || !evidencePayload.cases.some((item) => item.id === current) ? evidencePayload.cases[0]?.id || null : current);
      }
      setLastSyncedAt(new Date().toISOString());
      setApiState('connected');
    }).catch((error) => { if (error.name !== 'AbortError') setApiState('snapshot'); });
    return () => controller.abort();
  }, [mode, refreshVersion, followNewest]);

  useEffect(() => {
    if (mode !== 'test') return undefined;
    const refreshEvidence = () => setRefreshVersion((value) => value + 1);
    const interval = window.setInterval(refreshEvidence, LIVE_REFRESH_MS);
    const refreshWhenVisible = () => { if (document.visibilityState === 'visible') refreshEvidence(); };
    document.addEventListener('visibilitychange', refreshWhenVisible);
    return () => {
      window.clearInterval(interval);
      document.removeEventListener('visibilitychange', refreshWhenVisible);
    };
  }, [mode]);

  useEffect(() => {
    if (mode !== 'test' || !selectedSummary?.id) {
      setCaseDetail(null);
      setAudit(null);
      return undefined;
    }
    setCaseDetail(null);
    setAudit(null);
    return undefined;
  }, [mode, selectedSummary?.id]);

  useEffect(() => {
    if (mode !== 'test' || !selectedSummary?.id) return undefined;
    const controller = new AbortController();
    Promise.all([
      fetch(`/api/retrywise/cases/${selectedSummary.id}`, { cache: 'no-store', signal: controller.signal }),
      fetch(`/api/retrywise/cases/${selectedSummary.id}/audit`, { cache: 'no-store', signal: controller.signal }),
    ]).then(async ([detailResponse, auditResponse]) => {
      if (!detailResponse.ok || !auditResponse.ok) throw new Error('case proof unavailable');
      const [detailPayload, auditPayload] = await Promise.all([detailResponse.json(), auditResponse.json()]);
      setCaseDetail(detailPayload);
      setAudit(auditPayload);
    }).catch((error) => { if (error.name !== 'AbortError') setApiState('snapshot'); });
    return () => controller.abort();
  }, [mode, selectedSummary?.id, refreshVersion]);

  async function runReplay() {
    if (runState === 'running') return;
    setRunState('running');
    try {
      const response = await fetch('/api/retrywise/impact', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ seed: 42, case_count: 2000, bootstrap_samples: 400 }) });
      if (!response.ok) throw new Error('replay failed');
      setOverview(await response.json());
      setApiState('connected');
      setRunState('complete');
    } catch {
      setRunState('error');
      setApiState('snapshot');
    }
  }

  async function actOnApproval(id, verdict) {
    if (approvalActionState.status === 'running') return;
    setApprovalActionState({ id, status: 'running', message: '' });
    try {
      const response = await fetch(`/api/retrywise/approvals/${id}/decision`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': `console-approval-${crypto.randomUUID()}` }, body: JSON.stringify({ verdict, reason_code: verdict === 'APPROVED' ? 'operator_verified' : 'operator_rejected' }) });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.code || payload.detail?.code || 'decision_failed');
      setApprovalActionState({ id, status: 'complete', message: verdict === 'APPROVED' ? 'Approval queued. The worker will fresh-read provider truth before any effect.' : 'Rejected. The case remains safely restrained.' });
      setRefreshVersion((value) => value + 1);
    } catch (error) {
      setApprovalActionState({ id, status: 'error', message: `Decision was not recorded: ${error instanceof Error ? error.message : 'unknown_error'}` });
    }
  }

  async function toggleMerchantKillSwitch() {
    if (!evidence.control || controlActionState.status === 'running') return;
    const enabled = !evidence.control.kill_switch_enabled;
    const prompt = enabled ? 'Pause every new collection effect for this merchant?' : 'Enable gated collection effects for the bound Razorpay Test account?';
    if (!window.confirm(prompt)) return;
    setControlActionState({ status: 'running', message: '' });
    try {
      const response = await fetch('/api/retrywise/controls/kill-switch', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': `console-control-${crypto.randomUUID()}` }, body: JSON.stringify({ enabled, reason_code: enabled ? 'emergency_stop' : 'enable_test_mode_effects' }) });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.code || payload.detail?.code || 'control_failed');
      setEvidence((current) => ({ ...current, control: payload }));
      setControlActionState({ status: 'complete', message: enabled ? 'Merchant kill switch armed. New collection effects are blocked.' : 'Merchant hold removed. Every provider effect remains fresh-truth and policy gated.' });
    } catch (error) {
      setControlActionState({ status: 'error', message: `Control change failed: ${error instanceof Error ? error.message : 'unknown_error'}` });
    }
  }

  async function changeDiagnosisMode(nextMode) {
    if (!evidence.diagnosisControl || diagnosisActionState.status === 'running' || evidence.diagnosisControl.mode === nextMode) return;
    if (!evidence.diagnosisControl.gemini_configured && nextMode !== 'LOCAL_ML') {
      const proceed = window.confirm('Gemini is not enrolled yet. Select this mode anyway to exercise the audited local fallback?');
      if (!proceed) return;
    }
    setDiagnosisActionState({ status: 'running', message: '' });
    try {
      const response = await fetch('/api/retrywise/controls/diagnosis-engine', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': `console-diagnosis-${crypto.randomUUID()}` }, body: JSON.stringify({ mode: nextMode }) });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.code || payload.detail?.code || 'diagnosis_control_failed');
      setEvidence((current) => ({ ...current, diagnosisControl: payload }));
      const messages = {
        LOCAL_ML: 'Local ML selected for future assessments. Existing decisions remain immutable.',
        HYBRID_GEMINI: payload.gemini_configured ? 'Gemini selected with bounded local fallback for future assessments.' : 'Hybrid selected. Until a Gemini key is enrolled, future assessments use audited local fallback and require approval.',
        SHADOW: payload.gemini_configured ? 'Shadow comparison selected. Local ML remains authoritative.' : 'Shadow selected. Local ML remains authoritative; Gemini availability will be recorded.',
      };
      setDiagnosisActionState({ status: 'complete', message: messages[nextMode] });
    } catch (error) {
      setDiagnosisActionState({ status: 'error', message: `Diagnosis mode change failed: ${error instanceof Error ? error.message : 'unknown_error'}` });
    }
  }

  function changeMode(nextMode) {
    setFollowNewest(true);
    setMode(nextMode);
    setView(nextMode === 'test' ? 'command' : 'impact');
  }

  function selectCase(id) {
    setSelectedId(id);
    setFollowNewest(id === evidence.cases[0]?.id);
  }

  function navigate(nextView) {
    if (nextView === 'impact' && mode === 'test') {
      setMode('replay');
      setView('impact');
      return;
    }
    setView(nextView);
  }

  const [sourceTone, sourceCopy] = sourceBadge(apiState, mode);
  const activeLabel = NAV_ITEMS.find(([key]) => key === view)?.[1] || 'Overview';
  const pendingApprovals = evidence.approvals.filter((item) => item.verdict === 'PENDING').length;
  return (
    <div className="control-room">
      <div className="ambient ambient-one" /><div className="ambient ambient-two" />
      <aside className="side-rail">
        <div className="brand-lockup"><span className="brand-symbol">RW<i /></span><div><strong>RetryWise</strong><small>Recovery intelligence</small></div></div>
        <nav aria-label="Primary navigation"><p>Control plane</p>{NAV_ITEMS.map(([key, name, number]) => <button type="button" key={key} className={view === key ? 'active' : ''} onClick={() => navigate(key)} aria-current={view === key ? 'page' : undefined}><span>{number}</span><strong>{name}</strong>{key === 'approvals' && pendingApprovals ? <b>{pendingApprovals}</b> : null}</button>)}</nav>
        <div className="rail-safety"><header><span className="pulse-dot" /><strong>Safety kernel</strong></header><p>Models propose.<br />Policy authorizes.<br />Workers prove.</p><div><span>Hard violations</span><strong>{overview?.hard_safety_violations ?? '—'}</strong></div></div>
        <div className="rail-foot"><span className={`source-orb ${sourceTone}`} /><div><strong>{sourceCopy}</strong><small>{mode === 'test' ? 'Sandbox effects · no real money' : 'Synthetic outcomes · offline'}</small></div></div>
      </aside>

      <main className="main-deck">
        <header className="deck-header"><div><p>Operations / {activeLabel}</p><h2>{activeLabel}</h2></div><div className="header-actions"><ModeSwitch mode={mode} onChange={changeMode} /><button className={`refresh-button ${apiState === 'refreshing' ? 'syncing' : ''}`} type="button" onClick={() => setRefreshVersion((value) => value + 1)} aria-label="Refresh evidence">↻</button><span className="operator-chip"><i>AV</i><span><strong>Operator</strong><small>Test authority</small></span></span></div></header>
        <div className="environment-strip"><span className={mode === 'test' ? 'provider' : 'replay'}>{mode === 'test' ? 'RAZORPAY TEST MODE' : 'OFFLINE IMPACT REPLAY'}</span><p>{mode === 'test' ? `Persisted provider evidence · ${followNewest ? 'following newest case' : 'inspecting selected case'} · ${LIVE_REFRESH_MS / 1000}s refresh · synced ${formatTime(lastSyncedAt)}` : 'Synthetic counterfactuals are isolated from provider execution.'}</p><code>{selectedSummary ? compactId(selectedSummary.id, 12, 8) : mode === 'replay' ? 'seed:42 · cases:2,000' : 'awaiting-case'}</code></div>
        <section className="deck-content">
          {view === 'command' && mode === 'test' ? <TestCommandCenter overview={overview} apiState={apiState} evidence={evidence} selectedId={selectedSummary?.id} onSelect={selectCase} onNavigate={navigate} caseDetail={caseDetail} audit={audit} lastSyncedAt={lastSyncedAt} /> : null}
          {view === 'command' && mode === 'replay' ? <ReplayCommandCenter overview={overview} apiState={apiState} onNavigate={navigate} onRun={runReplay} runState={runState} /> : null}
          {view === 'cases' ? mode === 'test' ? <CasesView evidence={evidence} selectedId={selectedSummary?.id} onSelect={selectCase} detail={caseDetail} audit={audit} /> : <EmptyState title="Recovery cases are provider-bound" copy="Switch to Razorpay Test Mode to inspect persisted cases. Replay remains synthetic and read-only." /> : null}
          {view === 'approvals' ? mode === 'test' ? <ApprovalsView approvals={evidence.approvals} actionState={approvalActionState} onAct={actOnApproval} /> : <EmptyState title="Human mutations are disabled in replay" copy="Switch to Razorpay Test Mode to act on version-bound approval records." /> : null}
          {view === 'evidence' ? mode === 'test' ? <EvidenceView summary={selectedSummary} detail={caseDetail} audit={audit} /> : <EmptyState title="Provider evidence is isolated from replay" copy="Switch to Razorpay Test Mode for the immutable decision chain and reconciled provider objects." /> : null}
          {view === 'impact' ? <ImpactView overview={mode === 'replay' ? overview : null} apiState={apiState} onRun={runReplay} runState={runState} /> : null}
          {view === 'controls' ? mode === 'test' ? <ControlsView control={evidence.control} diagnosisControl={evidence.diagnosisControl} overview={overview} actionState={controlActionState} diagnosisActionState={diagnosisActionState} onToggle={toggleMerchantKillSwitch} onDiagnosisMode={changeDiagnosisMode} /> : <ControlsView control={null} diagnosisControl={null} overview={overview} actionState={{ status: 'idle', message: '' }} diagnosisActionState={{ status: 'idle', message: '' }} onToggle={() => {}} onDiagnosisMode={() => {}} /> : null}
        </section>
      </main>
    </div>
  );
}
