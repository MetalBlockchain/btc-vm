import * as chain from './chain.js';
import * as passkey from './passkey.js';
import * as units from './units.js';
import { confirmationsFor, describeTiers } from './tiers.js';
import { createAddressBook } from './addressbook-ui.js';

const $ = (id) => document.getElementById(id);
const KEY_STORE = 'btcvm.key';
const PASSKEY_STORE = 'btcvm.key.passkey'; // the key, encrypted to a passkey
const WITHDRAW_STORE = 'btcvm.withdrawals';
const SETUP_STORE = 'btcvm.setup'; // per address: {backedUp, hidden}
const UNIT_STORE = 'btcvm.unit'; // btc | sats | usd

let info = null;
let key = null; // Uint8Array, or null
let depositShownFor = null;
let utxos = []; // BTCVM
let btcUtxos = []; // Bitcoin
let btcState = 'unknown'; // unknown | ready | syncing | off
// What the setup checklist knows of each network: whether the key has ever
// had BTC there. null until the balance has loaded.
let seenVm = null;
let seenBTC = null;
// Confirmed balances as the API gives them, or null until loaded.
let vmBalance = null;
let btcBalance = null;
// The address book, and its pickers on the Send and Withdraw forms; null
// until the book has started (see startAddressBook).
let addressBook = null;
let sendPicker = null;
let withdrawPicker = null;

// generation counts key changes. Work started for one key checks it before
// touching the page, so a slow response never shows under another key.
let generation = 0;

// Stored values survive reloads; storage can be unavailable (private mode).
const store = {
  get(name) { try { return localStorage.getItem(name); } catch { return null; } },
  set(name, value) {
    try { localStorage.setItem(name, value); return localStorage.getItem(name) === value; } catch { return false; }
  },
  remove(name) { try { localStorage.removeItem(name); } catch { /* ignore */ } },
};

// APIError carries the HTTP status; status 0 means no response arrived.
class APIError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

async function api(path, body) {
  let res;
  try {
    res = await fetch(path, body === undefined ? {} : {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch {
    throw new APIError("can't reach the bridge", 0);
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new APIError(data.error || `request failed (${res.status})`, res.status);
  return data;
}

// --- units ---------------------------------------------------------------------

// Amounts show in the unit the viewer picks: BTC, sats or US dollars. Only
// what is shown and typed changes; payments are always exact satoshis.
let unit = units.UNITS.includes(store.get(UNIT_STORE)) ? store.get(UNIT_STORE) : 'btc';
let price = null; // {usd, time}: dollars per BTC, and when it was fetched

// usdPrice is the price if it may be used: fetched in the last 10 minutes,
// and only on mainnet, where BTC has a price.
const usdPrice = () => (info && info.bitcoinNetwork === 'mainnet' ? units.freshPrice(price) : null);
// shownUnit is the unit amounts show in: the one picked, or BTC while there
// is no dollar price.
const shownUnit = () => (unit === 'usd' && !usdPrice() ? 'btc' : unit);

// API amounts are BTC decimal strings with 8 places.
const sats = (s) => chain.parseBTC(String(s).replace('-', '').replace(/,/g, ''));
const showSats = (n) => units.format(n, shownUnit(), usdPrice());
const show = (s) => showSats(sats(s));
// showExact is for what is about to be signed: in dollars it gives the
// exact BTC too.
const showExact = (n) => (shownUnit() === 'usd'
  ? `${units.format(n, 'btc')} (≈ ${units.format(n, 'usd', usdPrice())})` : showSats(n));
const short = (txid) => `${txid.slice(0, 10)}…${txid.slice(-6)}`;

function showResult(el, message, ok, txid, network = 'vm') {
  el.textContent = message;
  el.className = 'result ' + (ok ? 'ok' : 'error');
  if (txid) {
    // The full transaction, in the right explorer, to check the outcome.
    const a = document.createElement('a');
    a.href = network === 'btc' ? `https://mempool.space/tx/${txid}` : `/explorer#/tx/${txid}`;
    if (network === 'btc') { a.target = '_blank'; a.rel = 'noopener noreferrer'; }
    a.textContent = txid;
    a.className = 'mono';
    el.append(' ', a);
  }
}

function item(...texts) {
  const li = document.createElement('li');
  for (const t of texts) {
    const span = document.createElement('span');
    if (typeof t === 'string') span.textContent = t;
    else { span.textContent = t.text; span.className = t.class; }
    li.append(span);
  }
  return li;
}

function empty(text) {
  const li = document.createElement('li');
  li.className = 'empty';
  li.textContent = text;
  return li;
}

// --- tabs ------------------------------------------------------------------

const tabs = () => [...document.querySelectorAll('[role=tab]')].filter((t) => !t.hidden);

// selectTab shows a panel. Only the selected tab is in the tab order; arrow
// keys move between tabs, as the WAI-ARIA tabs pattern expects.
function selectTab(name) {
  for (const tab of document.querySelectorAll('[role=tab]')) {
    const selected = tab.id === `tab-${name}`;
    tab.setAttribute('aria-selected', String(selected));
    tab.tabIndex = selected ? 0 : -1;
    $(tab.getAttribute('aria-controls')).hidden = !selected;
  }
  if (name === 'deposit') showDeposit();
  if (name === 'withdraw') renderWithdrawals();
}

for (const tab of document.querySelectorAll('[role=tab]')) {
  tab.addEventListener('click', () => selectTab(tab.id.replace('tab-', '')));
}
selectTab('wallet');
for (const b of document.querySelectorAll('[data-goto-tab]')) {
  b.addEventListener('click', () => selectTab(b.dataset.gotoTab));
}

document.querySelector('[role=tablist]').addEventListener('keydown', (e) => {
  const list = tabs();
  const i = list.indexOf(document.activeElement);
  if (i < 0) return;
  const next = {
    ArrowRight: list[(i + 1) % list.length],
    ArrowLeft: list[(i + list.length - 1) % list.length],
    Home: list[0],
    End: list[list.length - 1],
  }[e.key];
  if (!next) return;
  e.preventDefault();
  next.focus();
  selectTab(next.id.replace('tab-', ''));
});

document.addEventListener('click', async (e) => {
  const target = e.target.closest('button.copy');
  if (!target) return;
  const text = $(target.dataset.copy).textContent;
  try {
    await navigator.clipboard.writeText(text);
    target.textContent = 'Copied';
  } catch {
    // Select the text so it can be copied by hand.
    getSelection().selectAllChildren($(target.dataset.copy));
    target.textContent = /Mac|iPhone|iPad/.test(navigator.platform) ? 'Press ⌘C' : 'Press Ctrl+C';
  }
  setTimeout(() => { target.textContent = target.dataset.label || 'Copy'; }, 2000);
});

// --- network and peg ---------------------------------------------------------

async function loadInfo() {
  info = await api('/api/info');
  $('signers').textContent =
    `Held by ${info.signers.required} of ${info.signers.publicKeys.length} signers. Peg address on Bitcoin: ${info.pegAddress}`;
  const mainnet = info.bitcoinNetwork === 'mainnet';
  const band = $('network-band');
  band.hidden = false;
  $('import-key').placeholder = mainnet ? 'K…, L… or 64 hex characters' : 'c… or 64 hex characters';
  if (mainnet) {
    $('network-name').textContent = 'beta';
    band.textContent = 'Beta, with real BTC. Keep amounts small: the bridge is new and has not been audited.';
  } else {
    $('network-name').textContent = 'testnet';
    band.textContent = 'Testnet. These coins have no value, and the network may be reset at any time.';
  }
  if (info.faucet.enabled) $('tab-faucet').hidden = false;
  renderInfo();
}

// renderInfo shows the bridge's fees and limits, in the unit picked.
function renderInfo() {
  $('confs-needed-top').textContent = describeTiers(info, show);
  $('vm-fee').textContent = show(info.vmFee);
  $('min-deposit').textContent = show(info.minDeposit);
  $('btc-fee').textContent = show(info.payoutFee);
  $('min-pegout').textContent = show(info.minPegOut);
  const limits = [];
  if (chain.parseBTC(info.maxDeposit) > 0n) limits.push(`Deposits over ${show(info.maxDeposit)} are not credited; they are held for a refund.`);
  if (chain.parseBTC(info.maxCirculating) > 0n) limits.push(`At most ${show(info.maxCirculating)} can be on BTCVM in total during the beta.`);
  $('deposit-limits').textContent = limits.length ? ' ' + limits.join(' ') : '';
  if (info.faucet.enabled) {
    $('faucet-text').textContent =
      `The faucet sends ${show(info.faucet.amount)} straight to your BTCVM address, once a day.`;
  }
}

// The peg's figures as last loaded, to redraw in another unit.
let lastAudit = null;

function renderPeg() {
  const a = lastAudit;
  if (!a) return;
  $('peg-capacity').textContent = sats(info.maxCirculating) > 0n
    ? `Beta capacity: ${show(a.circulating)} of ${show(info.maxCirculating)} in use.`
    : '';
  $('locked').textContent = show(a.locked);
  $('circulating').textContent = show(a.circulating);
  $('pending-in').textContent = show(a.pendingPegIns);
  $('pending-out').textContent = show(a.pendingPegOuts);
}

// renderConnection sets the light over the block heights: green when this
// page reaches the bridge, its live updates are flowing and its Bitcoin node
// is caught up; orange while connecting, syncing or paused; red when the
// bridge can't be reached or its Bitcoin node is offline.
let lastStatus = null;
let statusFailed = false;
let eventStream = null;
function renderConnection() {
  const s = lastStatus;
  const sync = s && s.bitcoinSync;
  let state = 'wait';
  let text = 'Connecting…';
  if (statusFailed) [state, text] = ['down', "Can't reach the bridge"];
  else if (!s) [state, text] = ['wait', 'Connecting…'];
  else if (sync && sync.available === false) [state, text] = ['down', "The bridge's Bitcoin node is offline"];
  else if (sync && sync.syncing) [state, text] = ['wait', 'Bitcoin node syncing'];
  else if (s.paused) [state, text] = ['wait', 'Connected, bridge paused'];
  else if (!eventStream || eventStream.readyState !== EventSource.OPEN) [state, text] = ['wait', 'Connected, reconnecting live updates…'];
  else [state, text] = ['live', 'Connected and synced'];
  $('conn').className = `conn ${state}`;
  if ($('conn-text').textContent !== text) $('conn-text').textContent = text;
}

async function refreshStatus() {
  try {
    const s = await api('/api/status');
    lastStatus = s;
    statusFailed = false;
    renderConnection();
    // An emergency pause: nothing is credited or paid until it ends.
    const band = $('pause-band');
    band.hidden = !s.paused;
    if (s.paused) {
      const text = `The bridge is paused: ${s.paused.reason} Deposits and withdrawals already sent are processed when it resumes.`;
      if (band.textContent !== text) band.textContent = text;
    }
    btcBlockTime = s.bitcoinBlockTime || 0;
    renderInflight(); // the quiet-Bitcoin note counts up between blocks
    $('vm-height').textContent = s.btcvmHeight.toLocaleString('en-US');
    // Finality, measured live on this site's own payments.
    const f = s.finality;
    $('vm-finality').hidden = !f;
    if (f) {
      const secs = (ms) => `${(ms / 1000).toFixed(1)} s`;
      $('vm-finality').textContent = f.payments === 1
        ? `Last payment final in ${secs(f.medianMs)}.`
        : `Payments final in ${secs(f.medianMs)}: the median of the last ${f.payments}.`;
    }
    // While the bridge's Bitcoin node catches up, show how far it has got
    // rather than a block number that looks like the chain tip.
    const sync = s.bitcoinSync;
    const syncing = Boolean(sync && sync.syncing);
    const offline = Boolean(sync && sync.available === false);
    $('sync-meter').hidden = !syncing || offline;
    $('sync-of').hidden = !syncing && !offline;
    $('deposit-sync').hidden = !syncing;
    $('btc-height').textContent = s.bitcoinHeight.toLocaleString('en-US');
    if (offline) {
      $('btc-height').textContent = '–';
      $('sync-of').textContent = "The bridge's Bitcoin node is offline.";
    } else if (syncing) {
      // Bitcoin Core's progress is weighted by transactions. Early blocks
      // are nearly empty, so a block count races ahead and then stalls.
      const pct = Math.min(99, Math.floor(sync.progress * 100));
      $('sync-fill').style.width = `${pct}%`;
      $('sync-of').textContent = `Node catching up: ${pct}%. Latest block ${sync.headers.toLocaleString('en-US')}.`;
      $('deposit-sync').textContent =
        `The bridge's Bitcoin node is catching up (${pct}%). It sees and credits new deposits only once it reaches the present.`;
    }
    if (!s.audit) {
      $('verdict').textContent = 'The bridge cannot read both chains right now.';
      $('verdict').className = 'peg-verdict bad';
      return;
    }
    const a = s.audit;
    const locked = chain.parseBTC(a.locked);
    const circulating = chain.parseBTC(a.circulating);
    // During the beta the bars are drawn against the circulating cap, so
    // they show how much of the beta's room is used.
    const cap = chain.parseBTC(info.maxCirculating);
    let max = locked > circulating ? locked : circulating;
    if (cap > max) max = cap;
    const pct = (v) => (max === 0n ? 0 : Number((v * 1000n) / max) / 10);
    $('locked-fill').style.width = `${pct(locked)}%`;
    $('circulating-fill').style.width = `${pct(circulating)}%`;
    lastAudit = a;
    renderPeg();
    // Bitcoin's supply, from the bridge's own node, once it has caught up.
    const supply = s.bitcoinSupply;
    $('btc-supply').hidden = !supply;
    if (supply) {
      const total = BigInt(supply.amount);
      $('supply-total').textContent = total.toLocaleString('en-US');
      $('supply-total').title = `At Bitcoin block ${supply.height.toLocaleString('en-US')}`;
      const share = total > 0n ? Number(circulating) / Number(total * chain.SATS) * 100 : 0;
      $('supply-share').textContent = share === 0 ? '0%'
        : share < 0.0001 ? 'under 0.0001%' : `${share.toPrecision(2)}%`;
    }
    let verdict;
    let cls = 'peg-verdict';
    if (!a.solvent) {
      verdict = 'Not fully backed: the bridge has stopped moving BTC.';
      cls += ' bad';
    } else if (locked === 0n && circulating === 0n) {
      verdict = 'Nothing locked yet. The first deposit starts the peg.';
      cls += ' quiet';
    } else if (chain.parseBTC(a.surplus) > 0n) {
      // Locked BTC beyond what BTCVM owes: fees and small change the peg
      // kept, or deposits not yet claimed. Never less than circulating.
      verdict = `Fully backed, with ${show(a.surplus)} more locked than circulates.`;
    } else {
      verdict = 'Fully backed.';
    }
    // Announce the verdict only when it changes, not on every poll.
    if ($('verdict').textContent !== verdict) $('verdict').textContent = verdict;
    $('verdict').className = cls;
  } catch (err) {
    statusFailed = true;
    renderConnection();
    $('verdict').textContent = `Can't reach the bridge: ${err.message}`;
    $('verdict').className = 'peg-verdict bad';
  }
}

// --- key and wallet ------------------------------------------------------------

const myDest = () => chain.keyDestination(key);
const myAddress = () => chain.encodeAddress(myDest(), info.btcvmVersions);
const myBTCAddress = () => chain.encodeAddress(myDest(), info.bitcoinVersions);

// setKey switches keys. It clears everything shown for the previous key.
// mode is 'store' (keep the key in this browser), 'unlocked' (a passkey
// opened it; keep nothing new) or 'lock' (forget it until unlocked again).
// setKey(null) with the default mode removes the key from the browser.
function setKey(newKey, mode = 'store') {
  key = newKey;
  generation++;
  utxos = [];
  btcUtxos = [];
  btcState = 'unknown';
  seenVm = null;
  seenBTC = null;
  lastDeposits = [];
  withdrawalStatus.clear();
  shownConfirmations.clear();
  $('inflight').hidden = true;
  vmBalance = null;
  btcBalance = null;
  lastVm = null;
  lastBTC = null;
  depositShownFor = null;
  let warning = '';
  if (key && mode === 'store') {
    if (!store.set(KEY_STORE, chain.hex(key))) {
      warning = "This browser won't keep your key: it will be gone when you close the page. Back it up now, under \"Show or remove your key\".";
    }
  } else if (!key && mode === 'store') {
    store.remove(KEY_STORE);
    store.remove(PASSKEY_STORE);
  }
  const held = Boolean(key) || store.get(PASSKEY_STORE) !== null;
  $('create-key').disabled = held;
  $('import-submit').disabled = held;
  $('passkey-result').textContent = '';
  $('key-warning').textContent = warning;
  $('key-warning').hidden = !warning;
  hideSecrets();
  $('key-details').open = false;
  $('balance').textContent = '…';
  $('balance-unit').textContent = 'BTC';
  $('balance-pending').textContent = '';
  $('history').replaceChildren();
  $('btc-balance').textContent = '…';
  $('btc-balance-unit').textContent = 'BTC';
  $('btc-pending').textContent = '';
  $('btc-history').replaceChildren();
  $('btc-import').hidden = true;
  $('deposit-address').textContent = '…';
  $('deposit-verified').textContent = '';
  $('deposit-qr').replaceChildren();
  $('deposits').replaceChildren();
  $('withdrawals').replaceChildren();
  for (const id of ['send-result', 'withdraw-result', 'faucet-result', 'move-result', 'btc-import-result']) {
    $(id).textContent = '';
    $(id).className = 'result';
  }
  renderAvailable();
  renderKey();
}

function renderKey() {
  const has = key !== null;
  const locked = !has && store.get(PASSKEY_STORE) !== null;
  $('wallet-locked').hidden = !locked;
  $('no-key').hidden = has || locked;
  $('has-key').hidden = !has;
  renderPasskey();
  renderSetup();
  for (const el of document.querySelectorAll('.needs-key')) el.hidden = has;
  for (const el of document.querySelectorAll('.with-key')) el.hidden = !has;
  if (!has) return;
  $('my-address').textContent = myAddress();
  // On mainnet the two networks share address versions, so one key has the
  // same address on both.
  const same = myAddress() === myBTCAddress();
  $('address-label').textContent = same ? 'Your address' : 'Your BTCVM address';
  $('address-note').textContent = same ? 'The same on Bitcoin and BTCVM: one key, two networks.' : '';
  $('btc-address-line').hidden = same;
  $('my-btc-address').textContent = same ? '' : myBTCAddress();
  refreshWallet();
  refreshBTCWallet();
  refreshDeposits();
  refreshWithdrawalStatus();
  renderInflight();
  if (!$('panel-deposit').hidden) showDeposit();
  if (!$('panel-withdraw').hidden) renderWithdrawals();
}

// The key's text form is in the page only while "Show or remove your key"
// is open.
function hideSecrets() {
  $('wif-vm').textContent = '';
  $('wif-btc').textContent = '';
  $('secrets').hidden = true;
}
$('key-details').addEventListener('toggle', () => {
  if (!$('key-details').open || !key) { hideSecrets(); return; }
  $('wif-vm').textContent = chain.wif(key, info.btcvmVersions);
  $('wif-btc').textContent = chain.wif(key, info.bitcoinVersions);
  $('secrets').hidden = false;
});

async function refreshWallet() {
  if (!key) return;
  const gen = generation;
  try {
    const a = await api(`/api/address/${myAddress()}`);
    if (gen !== generation) return;
    utxos = a.utxos;
    lastVm = a;
    renderVmWallet();
    settleOutgoing('vm', a.history);
    vmBalance = a.confirmed;
    renderAvailable();
    seenVm = a.history.length > 0 || chain.parseBTC(a.confirmed) > 0n;
    renderSetup();
  } catch (err) {
    if (gen !== generation) return;
    lastVm = null;
    $('balance').textContent = '…';
    $('balance-unit').textContent = 'BTC';
    $('balance-pending').textContent = `Can't load your balance: ${err.message}`;
  }
}

// The wallet's balances as last loaded, to redraw in another unit.
let lastVm = null;
let lastBTC = null;

// showBalance fills a balance: its figure large, its unit small.
function showBalance(id, amount) {
  const p = units.parts(sats(amount), shownUnit(), usdPrice());
  $(id).textContent = p.value;
  $(`${id}-unit`).textContent = p.unit;
}

function renderVmWallet() {
  const a = lastVm;
  if (!a) return;
  showBalance('balance', a.confirmed);
  const pending = chain.parseBTC(a.pending);
  $('balance-pending').textContent = pending > 0n ? `${show(a.pending)} arriving in the next block` : '';
  renderHistory($('history'), a.history, 'Nothing yet. Move BTC over from Bitcoin on the Deposit tab.');
}

function renderHistory(list, history, emptyText) {
  list.replaceChildren(...(history.length === 0
    ? [empty(emptyText)]
    : history.map((h) => {
      const sent = h.net.startsWith('-');
      return item(
        { text: short(h.txid), class: 'mono' },
        `${sent ? '−' : '+'}${show(h.net)}${h.confirmations > 0 ? '' : ' (pending)'}`,
      );
    })));
}

// refreshBTCWallet shows the key's Bitcoin balance, registering the
// address with the bridge's Bitcoin index first if need be.
// The Bitcoin send option and the one-click move need the Bitcoin
// balance; until it's available they're disabled, with the reason shown.
function setBTCReady(ready, why = '') {
  const radio = document.querySelector('input[name=send-network][value=btc]');
  radio.disabled = !ready;
  if (!ready && radio.checked) document.querySelector('input[name=send-network][value=vm]').checked = true;
  radio.parentElement.title = ready ? '' : why;
  $('move-form').querySelector('button[type=submit]').disabled = !ready;
}

// renderAvailable shows what can be spent next to the Send and Withdraw
// forms, for the network chosen.
function renderAvailable() {
  const onBTC = document.querySelector('input[name=send-network]:checked').value === 'btc';
  // box shows a network's spendable balance, or why it isn't shown yet.
  const box = (el, network, balance, note) => {
    const label = document.createElement('span');
    label.className = 'available-label';
    label.textContent = `Available on ${network}`;
    const value = document.createElement('span');
    if (balance === null) {
      value.className = 'available-note';
      value.textContent = note;
    } else {
      value.className = 'available-amount amount';
      value.textContent = `${show(balance)}`;
    }
    el.replaceChildren(label, value);
  };
  const send = $('send-available');
  send.className = `available ${onBTC ? 'available-btc' : 'available-vm'}`;
  if (onBTC) box(send, 'Bitcoin', btcBalance, $('btc-pending').textContent || 'Loading…');
  else box(send, 'BTCVM', vmBalance, 'Loading…');
  box($('withdraw-available'), 'BTCVM', vmBalance, 'Loading…');
  renderFees(onBTC);
  if (sendPicker) sendPicker.refresh(); // what is typed may be saved for the other network
}

// renderFees says what a payment costs, before it's sent: on BTCVM a
// satoshi; on Bitcoin, today's rate for a typical payment (141 vB).
function renderFees(onBTC) {
  if (!info) return;
  const rate = BigInt(Math.max(info.btcFeeRate || 0, 1));
  $('send-fee').textContent = onBTC
    ? `Network fee: about ${showSats(141n * rate)} (${rate} sat/vB), paid to Bitcoin's miners.`
    : `Network fee: ${showSats(1n)}, whatever the amount.`;
  $('withdraw-fee').textContent =
    `Fees: ${showSats(1n)} on BTCVM, then Bitcoin's network fee, about ${show(info.payoutFee)} today, out of the amount.`;
}
for (const radio of document.querySelectorAll('input[name=send-network]')) radio.addEventListener('change', renderAvailable);

async function refreshBTCWallet() {
  if (!key || !info.btcWallet) {
    $('btc-balance').textContent = '–';
    $('btc-balance-unit').textContent = 'BTC';
    $('btc-pending').textContent = 'Not available from this bridge.';
    btcState = 'off';
    setBTCReady(false, "This bridge doesn't serve Bitcoin balances.");
    return;
  }
  const gen = generation;
  const address = myBTCAddress();
  try {
    let a;
    try {
      a = await api(`/api/btc/address/${address}`);
    } catch (err) {
      if (err.status !== 404) throw err;
      await api('/api/btc/watch', { address });
      a = await api(`/api/btc/address/${address}`);
    }
    if (gen !== generation) return;
    btcState = 'ready';
    setBTCReady(true);
    btcUtxos = a.utxos;
    settleOutgoing('btc', a.history);
    lastBTC = a;
    renderBTCWallet();
    btcBalance = a.confirmed;
    renderAvailable();
    seenBTC = a.history.length > 0 || chain.parseBTC(a.confirmed) > 0n;
    renderSetup();
    $('btc-import').hidden = false;
  } catch (err) {
    if (gen !== generation) return;
    lastBTC = null;
    $('btc-balance-unit').textContent = 'BTC';
    btcState = err.status === 503 ? 'syncing' : 'unknown';
    setBTCReady(false, "Available once the bridge's Bitcoin node has caught up.");
    $('btc-balance').textContent = '…';
    $('btc-pending').textContent = err.status === 503
      ? "Shows once the bridge's Bitcoin node has caught up."
      : `Can't load your Bitcoin balance: ${err.message}`;
    $('move-available').textContent = $('btc-pending').textContent;
    renderAvailable();
    $('btc-history').replaceChildren(empty(err.status === 503
      ? "Your Bitcoin activity appears once the bridge's Bitcoin node has caught up."
      : "Can't load your Bitcoin activity right now."));
  }
}

$('btc-import-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const button = e.submitter;
  button.disabled = true;
  try {
    const txid = $('btc-import-txid').value.trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(txid)) throw new Error('A transaction ID is 64 hexadecimal characters.');
    const r = await api('/api/btc/import', { address: myBTCAddress(), txid });
    showResult($('btc-import-result'), `Added ${r.imported} payment${r.imported === 1 ? '' : 's'}.`, true);
    $('btc-import-form').reset();
    refreshBTCWallet();
  } catch (err) {
    showResult($('btc-import-result'), err.message, false);
  } finally {
    button.disabled = false;
  }
});

function renderBTCWallet() {
  const a = lastBTC;
  if (!a) return;
  showBalance('btc-balance', a.confirmed);
  const pending = chain.parseBTC(a.pending.replace('-', ''));
  const change = outgoing().filter((o) => o.network === 'btc').reduce((n, o) => n + BigInt(o.change), 0n);
  $('btc-pending').textContent = pending === 0n ? ''
    : a.pending.startsWith('-')
      ? `${show(a.pending)} leaving${change > 0n ? `; ${showSats(change)} change comes back` : ''} when it confirms, usually within about 10 minutes.`
      : `${show(a.pending)} arriving, waiting for a block.`;
  renderHistory($('btc-history'), a.history, 'Nothing yet. Send BTC to your address from any Bitcoin wallet.');
  $('move-available').textContent = `Available on Bitcoin: ${show(a.confirmed)}.`;
}

// --- setup checklist -------------------------------------------------------------

// The checklist walks a new wallet through backing up, protecting, funding
// and a first round trip. Each step ticks itself off from what the wallet
// can see, and points at the controls that already do the work.
const setupStore = () => `${SETUP_STORE}.${myAddress()}`;
function setupState() {
  try { return JSON.parse(store.get(setupStore()) || '{}'); } catch { return {}; }
}
function saveSetup(change) {
  if (!key) return;
  store.set(setupStore(), JSON.stringify({ ...setupState(), ...change }));
  renderSetup();
}

// goTo shows a control, opening its tab or section first, and focuses it.
function goTo(tab, id) {
  if (tab) selectTab(tab);
  const el = $(id);
  el.scrollIntoView({ block: 'center', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
  el.focus({ preventScroll: true });
}

function setupSteps() {
  const state = setupState();
  const protectedByPasskey = store.get(PASSKEY_STORE) !== null;
  const funded = seenBTC === true || seenVm === true;
  const steps = [
    {
      title: 'Back up your key',
      text: "It's your wallet on both networks. Without a copy, BTC here can't be recovered if this browser's data is cleared.",
      done: state.backedUp === true,
      actions: [
        ['Show my key', () => { $('key-details').open = true; goTo(null, 'key-details'); }],
        ["I've saved it", () => saveSetup({ backedUp: true })],
      ],
    },
    passkey.available() && {
      title: 'Protect it with a passkey',
      text: 'Optional. Your key is then kept encrypted, and opening the wallet takes your passkey, for example in 1Password.',
      done: protectedByPasskey,
      actions: [['Protect with a passkey', () => $('passkey-protect').click()]],
    },
    {
      title: 'Get BTC on Bitcoin',
      text: btcState === 'syncing'
        ? "Send BTC to your address above from any wallet or exchange. It shows here once the bridge's Bitcoin node has caught up."
        : 'Send BTC to your address above from any wallet or exchange.',
      done: funded,
      actions: [['Copy my address', async (button) => {
        try {
          await navigator.clipboard.writeText(myBTCAddress());
          button.textContent = 'Copied';
          setTimeout(() => { button.textContent = 'Copy my address'; }, 2000);
        } catch {
          goTo(null, 'my-address');
          getSelection().selectAllChildren($('my-address'));
        }
      }]],
    },
    {
      title: 'Move it to BTCVM',
      text: 'Move BTC across the bridge from the Deposit tab. Payments on BTCVM are final within seconds.',
      done: seenVm === true,
      actions: [['Go to Deposit', () => goTo('deposit', 'move-amount')]],
    },
    {
      title: 'Withdraw some back',
      text: 'Send BTC back to your own Bitcoin address to complete the round trip.',
      done: savedWithdrawals().length > 0,
      actions: [['Go to Withdraw', () => goTo('withdraw', 'withdraw-to')]],
    },
  ];
  return steps.filter(Boolean);
}

function renderSetup() {
  if (!key || !info) {
    $('setup').hidden = true;
    $('setup-reopen').hidden = true;
    return;
  }
  const steps = setupSteps();
  const finished = steps.every((s) => s.done);
  const hidden = setupState().hidden === true || finished;
  $('setup').hidden = hidden;
  $('setup-reopen').hidden = !hidden || finished;
  if (hidden) return;
  const next = steps.findIndex((s) => !s.done);
  $('setup-steps').replaceChildren(...steps.map((s, i) => {
    const li = document.createElement('li');
    li.className = s.done ? 'done' : i === next ? 'current' : '';
    const title = document.createElement('p');
    title.className = 'setup-title';
    title.textContent = s.title;
    if (s.done) title.append(Object.assign(document.createElement('span'), { className: 'visually-hidden', textContent: ' (done)' }));
    li.append(title);
    if (!s.done) {
      const text = document.createElement('p');
      text.className = 'setup-text';
      text.textContent = s.text;
      li.append(text);
      if (i === next) {
        const row = document.createElement('div');
        row.className = 'setup-actions';
        s.actions.forEach(([label, run], n) => {
          const b = document.createElement('button');
          b.type = 'button';
          if (n === 0) b.className = 'primary';
          b.textContent = label;
          b.addEventListener('click', () => run(b));
          row.append(b);
        });
        li.append(row);
      }
    }
    return li;
  }));
}

$('setup-hide').addEventListener('click', () => { saveSetup({ hidden: true }); $('setup-show').focus(); });
$('setup-show').addEventListener('click', () => { saveSetup({ hidden: false }); $('setup-title').focus(); });

// --- passkey ---------------------------------------------------------------------

function renderPasskey() {
  const section = $('passkey-section');
  section.hidden = !key || !passkey.available();
  if (section.hidden) return;
  const backup = store.get(PASSKEY_STORE);
  $('passkey-status').textContent = backup
    ? 'Protected with a passkey: this browser keeps your key only in encrypted form. Keep the encrypted backup somewhere safe; with your passkey it restores this wallet on another device.' +
      (passkey.madeUnverified(backup)
        ? ' This backup was made before the wallet required your PIN or biometric, so it may open with a touch alone. For that protection, make a new passkey backup (restore the key into a fresh browser profile, then protect it again).'
        : '')
    : 'Protect this wallet with a passkey. Your key is then kept encrypted, and opening the wallet takes Face ID, Touch ID or your security key.';
  $('passkey-protect').hidden = Boolean(backup);
  $('passkey-lock').hidden = !backup;
  $('passkey-backup-copy').hidden = !backup;
  $('passkey-backup').textContent = backup || '';
}

$('passkey-protect').addEventListener('click', async (e) => {
  e.target.disabled = true;
  // The passkey prompt takes a while; if the wallet changes meanwhile, this
  // backup belongs to the old key, so drop it.
  const gen = generation;
  const protecting = key;
  try {
    const backup = await passkey.protect(protecting);
    if (gen !== generation) return;
    if (!store.set(PASSKEY_STORE, backup)) throw new Error("This browser won't store the encrypted key, so nothing was changed.");
    store.remove(KEY_STORE);
    showResult($('passkey-result'), 'Done. Copy the encrypted backup and keep it somewhere safe.', true);
    renderPasskey();
    renderSetup();
  } catch (err) {
    showResult($('passkey-result'), err.message, false);
  } finally {
    e.target.disabled = false;
  }
});

$('passkey-lock').addEventListener('click', () => setKey(null, 'lock'));

$('unlock-key').addEventListener('click', async (e) => {
  e.target.disabled = true;
  try {
    setKey(await passkey.unlock(store.get(PASSKEY_STORE)), 'unlocked');
  } catch (err) {
    showResult($('unlock-result'), err.message, false);
  } finally {
    e.target.disabled = false;
  }
});

$('create-key').addEventListener('click', () => {
  // Never replace a key this browser already holds.
  if (key || store.get(KEY_STORE) || store.get(PASSKEY_STORE)) return;
  setKey(chain.newPrivateKey());
});

$('import-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!info || key || store.get(KEY_STORE) || store.get(PASSKEY_STORE)) return;
  const value = $('import-key').value;
  try {
    if (passkey.isBackup(value)) {
      // A passkey backup: open it with its passkey, and keep it encrypted.
      const restored = await passkey.unlock(value);
      if (!store.set(PASSKEY_STORE, value.trim())) throw new Error("This browser won't store the encrypted key.");
      setKey(restored, 'unlocked');
    } else {
      setKey(chain.parseKey(value));
    }
    // An imported key is one the viewer already has a copy of.
    saveSetup({ backedUp: true });
    $('import-key').value = '';
  } catch (err) {
    $('import-key').setCustomValidity(err.message);
    $('import-key').reportValidity();
    $('import-key').addEventListener('input', () => $('import-key').setCustomValidity(''), { once: true });
  }
});

$('forget-key').addEventListener('click', () => {
  if (confirm('Remove this key from the browser? Without a backup, its BTC is gone.')) setKey(null);
});

// Each network's coins, and where to check and broadcast its transactions.
const networks = {
  vm: {
    utxos: () => utxos,
    getRawTx: async (txid) => (await api(`/api/rawtx/${txid}`)).hex,
    broadcast: '/api/tx',
    refresh: () => refreshWallet(),
  },
  btc: {
    utxos: () => btcUtxos,
    getRawTx: btcRawTx,
    broadcast: '/api/btc/tx',
    refresh: () => refreshBTCWallet(),
  },
};

// --- review before signing ----------------------------------------------------

function reviewLine(label, address, value, note, cls, saved) {
  const li = document.createElement('li');
  if (cls) li.className = cls;
  const add = (tag, className, text) => {
    const n = document.createElement(tag);
    n.className = className;
    n.textContent = text;
    li.append(n);
  };
  add('span', 'review-label', label);
  add('span', 'review-amount', value === null ? '' : showExact(value));
  // A saved name labels the address; the full address is still shown.
  if (address && saved) {
    add('span', `review-saved${saved.sameNetwork ? '' : ' warn'}`, saved.sameNetwork
      ? `Saved as "${saved.name}"`
      : `Saved as "${saved.name}", for ${saved.network === 'btc' ? 'Bitcoin' : 'BTCVM'}. Check it is right to pay it here.`);
  }
  if (address) add('span', 'review-address', address);
  if (note) add('p', 'review-note', note);
  return li;
}

// review shows what a planned transaction does, decoded from its own bytes
// rather than from the form, and resolves true only if the viewer confirms.
// context names addresses the page expects: the peg reserve for a
// withdrawal, the deposit address for a move.
function review(plan, network, context = {}) {
  const btc = network === 'btc';
  const versions = btc ? info.bitcoinVersions : info.btcvmVersions;
  const mine = btc ? myBTCAddress() : myAddress();
  const lines = [];
  const problems = [];
  let change = 0n;
  let outTotal = 0n;
  for (const o of chain.reviewOutputs(plan.unsignedHex, versions)) {
    outTotal += o.value;
    if (o.address === mine) {
      change += o.value;
      lines.push(reviewLine('Back to you (change)', o.address, o.value));
    } else if (o.data) {
      const dest = chain.pegOutDestination(o.data, info.bitcoinVersions);
      if (dest && context.withdrawTo === dest) {
        lines.push(reviewLine('The bridge then pays on Bitcoin', dest, null, null, null, savedAs(dest, 'btc')));
      } else {
        problems.push('The transaction carries a bridge instruction this page did not ask for.');
      }
    } else if (o.address && o.address === context.reserve) {
      const gets = o.value - chain.parseBTC(info.payoutFee);
      lines.push(reviewLine('To the bridge, to withdraw', o.address, o.value,
        `You receive about ${showSats(gets > 0n ? gets : 0n)} on Bitcoin, after a network fee of about ${show(info.payoutFee)} at today's rate (${info.btcFeeRate} sat/vB). The exact fee is set when the bridge pays.`));
    } else if (o.address && o.address === context.deposit) {
      const gets = o.value - chain.parseBTC(info.vmFee);
      lines.push(reviewLine('To your deposit address', o.address, o.value,
        `Credited as ${showSats(gets > 0n ? gets : 0n)} on BTCVM after ${confirmationsFor(info, o.value)} Bitcoin confirmation${confirmationsFor(info, o.value) === 1 ? '' : 's'}, less the ${show(info.vmFee)} bridge fee.`));
    } else if (o.address) {
      lines.push(reviewLine('To', o.address, o.value, null, null, savedAs(o.address, network)));
    } else {
      problems.push('The transaction pays a script this page cannot read.');
    }
  }
  if (outTotal + plan.fee !== plan.inputTotal) problems.push("The transaction's amounts don't add up.");
  if (context.reserve && context.withdrawTo === undefined) problems.push('A withdrawal needs a Bitcoin address.');
  lines.push(reviewLine('Network fee', null, plan.fee));
  lines.push(reviewLine('Leaves your wallet', null, plan.inputTotal - change, null, 'review-total'));

  $('review-network').textContent = btc ? 'On Bitcoin' : 'On BTCVM';
  $('review-network').className = `review-network${btc ? ' btc' : ''}`;
  $('review-lines').replaceChildren(...lines);
  $('review-problem').hidden = problems.length === 0;
  $('review-problem').textContent = problems.length ? `${problems.join(' ')} Don't send it.` : '';
  $('review-confirm').disabled = problems.length > 0;

  const dialog = $('review');
  return new Promise((resolve) => {
    dialog.returnValue = '';
    dialog.addEventListener('close', () => resolve(problems.length === 0 && dialog.returnValue === 'confirm'), { once: true });
    dialog.showModal();
    $('review-cancel').focus();
  });
}

// cancelled is the error a payment ends with when its review is dismissed.
const cancelled = () => Object.assign(new Error('Cancelled. Nothing was sent.'), { cancelled: true });

// showFailure shows why a payment didn't happen; a cancel isn't an error.
function showFailure(el, err) {
  if (!err.cancelled) return showResult(el, err.message, false);
  el.textContent = err.message;
  el.className = 'result';
}

// btcRawTx fetches a Bitcoin transaction's bytes, to check a coin it
// spends. The bridge's node is pruned, so it may no longer have an old one:
// then public explorers are asked. chain.js accepts only bytes that hash to
// the txid, so it doesn't matter who supplies them.
async function btcRawTx(txid) {
  try {
    return (await api(`/api/btc/rawtx/${txid}`)).hex;
  } catch (err) {
    if (err.status !== 404) throw err;
  }
  if (info.bitcoinNetwork === 'mainnet') {
    for (const base of ['https://mempool.space/api/tx/', 'https://blockstream.info/api/tx/']) {
      try {
        const res = await fetch(`${base}${txid}/hex`);
        if (res.ok) return (await res.text()).trim();
      } catch { /* try the next */ }
    }
  }
  throw new Error(`couldn't find Bitcoin transaction ${txid} to check the coin it spends`);
}

// pay plans a payment on a network ('vm' or 'btc'), shows it for review,
// signs it once confirmed, calls beforeBroadcast with its txid (so a record
// exists even if the broadcast response is lost), and broadcasts it. It
// returns {txid, unknown}: unknown is true if the bridge never answered, so
// the payment may or may not have gone through.
async function pay(script, amount, data, beforeBroadcast, network = 'vm', context = {}) {
  const net = networks[network];
  if (network === 'btc' && btcState !== 'ready') {
    throw new Error("Your Bitcoin balance isn't available yet; try again once it shows.");
  }
  const gen = generation;
  // Coins a payment still confirming already spends can't be spent again.
  const inUse = coinsInUse(network);
  const plan = await chain.planPayment({
    key, utxos: net.utxos().filter((u) => !inUse.has(`${u.txid}:${u.vout}`)), getRawTx: net.getRawTx,
    script, amount, data,
    feeRate: BigInt(Math.max(info.btcFeeRate || 0, 1)),
    vm: network === 'vm',
  });
  if (!(await review(plan, network, context))) throw cancelled();
  if (gen !== generation || !key) throw new Error('The wallet changed during review, so nothing was sent.');
  const built = await chain.signPlan(plan, key);
  if (beforeBroadcast) beforeBroadcast(built.txid);
  rememberOutgoing(plan, built.txid, network, context, amount);
  try {
    const { txid } = await api(net.broadcast, { hex: built.hex });
    if (txid !== built.txid) throw new Error(`the bridge reported txid ${txid}, expected ${built.txid}`);
  } catch (err) {
    if (err.status === 0 || err.status >= 500) return { txid: built.txid, unknown: true };
    err.rejected = true;
    forgetOutgoing(built.txid);
    throw err;
  } finally {
    renderInflight();
    setTimeout(net.refresh, 1500);
  }
  return { txid: built.txid, unknown: false };
}


// --- payments in flight ------------------------------------------------------------

// Each payment this wallet sends is remembered until it confirms: the coins
// it spends (so they aren't offered again) and its change (so a balance
// that reads 0 while it confirms shows where the BTC is).
const OUTGOING_STORE = 'btcvm.outgoing';
const outgoingStore = () => `${OUTGOING_STORE}.${myAddress()}`;
function outgoing() {
  try { return JSON.parse(store.get(outgoingStore()) || '[]'); } catch { return []; }
}
const saveOutgoing = (list) => store.set(outgoingStore(), JSON.stringify(list.slice(0, 50)));

function rememberOutgoing(plan, txid, network, context, amount) {
  const versions = network === 'btc' ? info.bitcoinVersions : info.btcvmVersions;
  const mine = network === 'btc' ? myBTCAddress() : myAddress();
  const outs = chain.reviewOutputs(plan.unsignedHex, versions);
  const change = outs.filter((o) => o.address === mine).reduce((n, o) => n + o.value, 0n);
  const kind = context.deposit ? 'move' : context.reserve ? 'withdraw' : 'send';
  const to = context.withdrawTo || context.deposit || outs.find((o) => o.address && o.address !== mine)?.address || '';
  saveOutgoing([{
    txid, network, kind, to, amount: String(amount), change: String(change), time: Date.now(),
    spent: plan.tx.inputs.map((i) => `${i.txid}:${i.vout}`),
  }, ...outgoing().filter((o) => o.txid !== txid)]);
}

function forgetOutgoing(txid) {
  saveOutgoing(outgoing().filter((o) => o.txid !== txid));
}

function coinsInUse(network) {
  return new Set(outgoing().filter((o) => o.network === network).flatMap((o) => o.spent));
}

// settleOutgoing drops payments a chain now shows confirmed, or that it has
// never shown after an hour (dropped by the network).
function settleOutgoing(network, history) {
  const seen = new Map(history.map((h) => [h.txid, h.confirmations]));
  const hour = 60 * 60 * 1000;
  const keep = outgoing().filter((o) => o.network !== network
    || (seen.has(o.txid) ? seen.get(o.txid) === 0 : Date.now() - o.time < hour));
  if (keep.length !== outgoing().length) saveOutgoing(keep);
}

// What the panel draws from, refreshed as each list loads.
let lastDeposits = [];
let btcBlockTime = 0; // when the latest Bitcoin block was found, unix seconds
const withdrawalStatus = new Map(); // txid -> /api/pegout answer
const shownConfirmations = new Map(); // deposit -> confirmations drawn, to animate new ones

async function refreshWithdrawalStatus() {
  if (!key) return;
  const gen = generation;
  const open = savedWithdrawals().filter((w) => !(withdrawalStatus.get(w.txid)?.paymentConfirmations > 0));
  await Promise.all(open.map(async (w) => {
    try {
      const p = await api(`/api/pegout/${w.txid}`);
      if (gen === generation) withdrawalStatus.set(w.txid, p);
    } catch { /* next block */ }
  }));
  if (gen === generation) renderInflight();
}

// minutes is how long n Bitcoin blocks usually take: about 10 minutes each.
const minutes = (n) => {
  const m = Math.max(n, 1) * 10;
  if (m < 60) return `about ${m} minutes`;
  const h = Math.round(m / 30) / 2;
  return h === 1 ? 'about an hour' : `about ${h} hours`;
};

// card builds one in-flight entry: a title, an optional progress row, and
// a line of detail.
function card(title, progress, detail, cls = '') {
  const li = document.createElement('li');
  li.className = `inflight-card ${cls}`;
  const h = document.createElement('p');
  h.className = 'inflight-title';
  h.textContent = title;
  li.append(h);
  if (progress) li.append(progress);
  const d = document.createElement('p');
  d.className = 'inflight-detail';
  d.textContent = detail;
  li.append(d);
  return li;
}

// blocks draws confirmations as a row of blocks, the newest popping in.
function blocks(id, have, need) {
  const row = document.createElement('div');
  row.className = 'inflight-blocks';
  row.setAttribute('role', 'img');
  row.setAttribute('aria-label', `${Math.min(have, need)} of ${need} confirmations`);
  const before = shownConfirmations.get(id) ?? have;
  for (let i = 0; i < need; i++) {
    const b = document.createElement('span');
    b.className = i < have ? 'block filled' : 'block';
    if (i < have && i >= before) b.classList.add('new');
    row.append(b);
  }
  shownConfirmations.set(id, have);
  return row;
}

// btcWaiting marks a card as waiting on the next Bitcoin block.
function btcWaiting(c) {
  c.dataset.bitcoin = '1';
  return c;
}

// steps draws a withdrawal's stages.
function steps(list) {
  const ol = document.createElement('ol');
  ol.className = 'inflight-steps';
  for (const [label, done] of list) {
    const li = document.createElement('li');
    li.className = done ? 'done' : '';
    li.textContent = label;
    ol.append(li);
  }
  return ol;
}

function renderInflight() {
  if (!key || !info) return;
  const cards = [];
  const depositTxids = new Set(lastDeposits.map((d) => d.txid));

  for (const d of lastDeposits) {
    if (['credited', 'refunded'].includes(d.status)) continue;
    const credit = sats(d.amount) - sats(info.vmFee);
    const gets = showSats(credit > 0n ? credit : 0n);
    const title = `Moving ${show(d.amount)} to BTCVM`;
    if (d.status === 'held') {
      cards.push(card(title, null, `Held for a refund: ${d.reason}`, 'held'));
    } else if (d.status === 'crediting' || d.confirmations >= d.required) {
      cards.push(card(title, blocks(`${d.txid}:${d.vout}`, d.required, d.required), `Confirmed. Crediting ${gets} now.`));
    } else if (d.status === 'waiting_for_capacity') {
      cards.push(card(title, null, 'Confirmed, and waiting for room under the beta limit.'));
    } else {
      const left = d.required - d.confirmations;
      cards.push(btcWaiting(card(title, blocks(`${d.txid}:${d.vout}`, d.confirmations, d.required),
        `${d.confirmations} of ${d.required} confirmations. ${minutes(left)[0].toUpperCase()}${minutes(left).slice(1)} left, then ${gets} arrives.`)));
    }
  }

  for (const w of savedWithdrawals()) {
    const p = withdrawalStatus.get(w.txid);
    if (!p || p.paymentConfirmations > 0) continue;
    const final = p.status === 'pending' || p.status === 'paid';
    const paid = p.status === 'paid';
    const detail = paid ? `${show(p.pays)} is on its way; it confirms in the next Bitcoin block, usually within about 10 minutes. If fees rise and it waits half an hour, the bridge resends it with a higher fee.`
      : final ? 'The bridge pays it within seconds.' : 'Waiting for it to be final on BTCVM, a few seconds.';
    const c = card(`Withdrawing ${show(w.amount)} to ${savedName(w.to, 'btc') || 'Bitcoin'}`,
      steps([['Final on BTCVM', final], ['Paid on Bitcoin', paid], ['In a Bitcoin block', false]]), detail);
    cards.push(paid ? btcWaiting(c) : c);
  }

  for (const o of outgoing()) {
    if (o.network !== 'btc' || o.kind === 'withdraw') continue;
    if (o.kind === 'move' && depositTxids.has(o.txid)) continue; // the deposit card covers it
    const change = BigInt(o.change);
    const back = change > 0n ? ` ${showSats(change)} change comes back when it confirms.` : '';
    const title = o.kind === 'move' ? `Moving ${showSats(BigInt(o.amount))} to BTCVM`
      : `Sending ${showSats(BigInt(o.amount))}${savedName(o.to, 'btc') ? ` to ${savedName(o.to, 'btc')}` : ''} on Bitcoin`;
    cards.push(btcWaiting(card(title, steps([['Sent', true], ['In a Bitcoin block', false]]),
      `Waiting for a Bitcoin block, usually within about 10 minutes.${back}`)));
  }

  // Bitcoin blocks come at random. When one is slow, say so rather than
  // leave a countdown that looks stuck.
  const quiet = btcBlockTime ? Math.floor((Date.now() / 1000 - btcBlockTime) / 60) : 0;
  if (quiet >= 30) {
    for (const c of cards.filter((c) => c.dataset.bitcoin)) {
      const p = document.createElement('p');
      p.className = 'inflight-quiet';
      p.textContent = `Bitcoin hasn't found a block for ${quiet} minutes. Blocks average 10 minutes but come at random; this continues when the next one arrives.`;
      c.append(p);
    }
  }
  $('inflight-list').replaceChildren(...cards);
  $('inflight').hidden = cards.length === 0;
}

const unknownOutcome = 'No answer from the bridge, so this may or may not have gone through. Check the transaction before trying again:';

$('send-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const button = e.submitter;
  button.disabled = true;
  try {
    const network = document.querySelector('input[name=send-network]:checked').value;
    const versions = network === 'btc' ? info.bitcoinVersions : info.btcvmVersions;
    const to = chain.decodeAddress($('send-to').value, versions);
    const amount = readAmount('send-amount');
    const { txid, unknown } = await pay(chain.pkScript(to), amount, undefined, undefined, network);
    const where = network === 'btc' ? 'on Bitcoin' : 'on BTCVM';
    if (unknown) showResult($('send-result'), unknownOutcome, false, txid, network);
    else showResult($('send-result'), `Sent ${where}. Transaction:`, true, txid, network);
    $('send-to').value = '';
    sendPicker?.clear();
    resetAmount('send-amount');
  } catch (err) {
    showFailure($('send-result'), err);
  } finally {
    button.disabled = false;
  }
});

// --- deposit -------------------------------------------------------------------

async function showDeposit() {
  if (!key) return;
  const gen = generation;
  const addr = myAddress();
  if (depositShownFor !== addr) {
    try {
      const d = await api('/api/deposit-address', { address: addr });
      if (gen !== generation) return;
      // The page derives the address itself from the signers' public keys;
      // if the server says otherwise, show nothing to send to.
      const expected = chain.depositAddress(myDest(), info.signers, info.bitcoinVersions);
      if (d.depositAddress !== expected) {
        $('deposit-address').textContent = 'Unavailable';
        $('deposit-qr').replaceChildren();
        showResult($('deposit-verified'),
          'The bridge sent a deposit address that does not match the peg signers, so it is not shown. Do not deposit until this is fixed.', false);
        return;
      }
      const { default: qrcode } = await import('./vendor/qrcode-generator-2.0.4/qrcode.mjs');
      if (gen !== generation) return;
      $('deposit-address').textContent = expected;
      $('deposit-verified').className = 'verified';
      $('deposit-verified').textContent =
        `Consistency check passed: your browser derived the same address from the ${info.signers.required}-of-${info.signers.publicKeys.length} peg signers' keys and your BTCVM address.`;
      const qr = qrcode(0, 'M');
      qr.addData(expected);
      qr.make();
      $('deposit-qr').innerHTML = qr.createSvgTag({ cellSize: 4, margin: 0, scalable: true });
      depositShownFor = addr;
    } catch (err) {
      if (gen !== generation) return;
      $('deposit-address').textContent = `Can't get a deposit address: ${err.message}`;
      return;
    }
  }
  refreshDeposits();
}

// The one-click deposit: pay the personal deposit address from the key's own
// Bitcoin balance. The address is the one this page derives from the
// signers' keys, and it is registered with the bridge first.
$('move-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const button = e.submitter;
  button.disabled = true;
  try {
    const amount = readAmount('move-amount');
    const min = chain.parseBTC(info.minDeposit);
    const max = chain.parseBTC(info.maxDeposit);
    if (amount < min) throw new Error(`The smallest deposit is ${show(info.minDeposit)}.`);
    if (max > 0n && amount > max) {
      throw new Error(`During the beta a deposit can be at most ${show(info.maxDeposit)}; a larger one is held for a refund.`);
    }
    if (depositShownFor !== myAddress()) await showDeposit();
    if (depositShownFor !== myAddress()) throw new Error("Your deposit address couldn't be checked, so nothing was sent. See below.");
    const expected = chain.depositAddress(myDest(), info.signers, info.bitcoinVersions);
    const script = chain.pkScript(chain.decodeAddress(expected, info.bitcoinVersions));
    const { txid, unknown } = await pay(script, amount, undefined, undefined, 'btc', { deposit: expected });
    if (unknown) {
      showResult($('move-result'), unknownOutcome, false, txid, 'btc');
    } else {
      const n = confirmationsFor(info, amount);
      showResult($('move-result'),
        `Sent to your deposit address. It's credited on BTCVM after ${n} Bitcoin confirmation${n === 1 ? '' : 's'}, ${minutes(n)}. Transaction:`, true, txid, 'btc');
    }
    resetAmount('move-amount');
    setTimeout(refreshDeposits, 3000);
  } catch (err) {
    showFailure($('move-result'), err);
  } finally {
    button.disabled = false;
  }
});

function depositStatus(d) {
  switch (d.status) {
    case 'credited': return { text: `Credited ${show(d.credited)}`, class: 'status-done' };
    case 'refunded': return { text: 'Refunded on Bitcoin', class: 'status-done' };
    case 'held': return { text: `Held for a refund: ${d.reason}`, class: 'status-held' };
    case 'waiting_for_capacity': return { text: 'Confirmed; waiting for room under the beta limit', class: 'status-waiting' };
    case 'crediting': return { text: 'Confirmed; crediting now', class: 'status-waiting' };
    default: return { text: `${Math.min(d.confirmations, d.required)} of ${d.required} confirmations`, class: 'status-waiting' };
  }
}

async function refreshDeposits() {
  if (!key) return;
  const gen = generation;
  try {
    const deposits = await api(`/api/deposits/${myAddress()}`);
    if (gen !== generation) return;
    lastDeposits = deposits;
    renderInflight();
    $('deposits').replaceChildren(...(deposits.length === 0
      ? [empty('No deposits yet. They show up here once Bitcoin sees them.')]
      : deposits.map((d) => item(`${show(d.amount)}`, depositStatus(d)))));
  } catch { /* try again on the next poll */ }
}

// --- withdraw ------------------------------------------------------------------

// Withdrawals are remembered per address, so switching keys shows the right
// ones.
const withdrawStore = () => `${WITHDRAW_STORE}.${myAddress()}`;
function savedWithdrawals() {
  try { return JSON.parse(store.get(withdrawStore()) || '[]'); } catch { return []; }
}
const saveWithdrawals = (list) => store.set(withdrawStore(), JSON.stringify(list.slice(0, 20)));

$('withdraw-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const button = e.submitter;
  button.disabled = true;
  let pendingTxid = null;
  try {
    const toText = $('withdraw-to').value.trim();
    const to = chain.decodeAddress(toText, info.bitcoinVersions);
    if (chain.encodeAddress(to, info.bitcoinVersions) === info.pegAddress) {
      throw new Error("That's the bridge's own address. Withdraw to a Bitcoin address of yours.");
    }
    const amount = readAmount('withdraw-amount');
    if (amount < chain.parseBTC(info.minPegOut)) throw new Error(`The minimum withdrawal is ${show(info.minPegOut)}.`);
    const reserve = chain.decodeAddress(info.reserveAddress, info.btcvmVersions);
    const { txid, unknown } = await pay(chain.pkScript(reserve), amount, chain.pegOutData(to), (id) => {
      pendingTxid = id;
      saveWithdrawals([{ txid: id, to: toText, amount: chain.formatBTC(amount) }, ...savedWithdrawals()]);
    }, 'vm', { reserve: info.reserveAddress, withdrawTo: chain.encodeAddress(to, info.bitcoinVersions) });
    if (unknown) showResult($('withdraw-result'), unknownOutcome, false, txid);
    else showResult($('withdraw-result'), 'Withdrawal sent. The bridge pays out once it is in a block. Transaction:', true, txid);
    $('withdraw-form').reset();
    withdrawPicker?.clear();
    resetAmount('withdraw-amount');
  } catch (err) {
    // The bridge refused it, so it will never be paid; forget it.
    if (err.rejected && pendingTxid) saveWithdrawals(savedWithdrawals().filter((w) => w.txid !== pendingTxid));
    showFailure($('withdraw-result'), err);
  } finally {
    button.disabled = false;
    renderWithdrawals();
    refreshWithdrawalStatus();
  }
});

$('withdraw-to-mine').addEventListener('click', () => {
  if (!key) return;
  $('withdraw-to').value = myBTCAddress();
  withdrawPicker?.refresh();
  $('withdraw-amount').focus();
});

async function renderWithdrawals() {
  if (!key) return;
  const gen = generation;
  const rows = savedWithdrawals().map((w) => {
    const name = savedName(w.to, 'btc');
    const li = item(`${show(w.amount)} to ${name ? `${name} (${w.to.slice(0, 8)}…)` : `${w.to.slice(0, 8)}…`}`, { text: 'Checking…', class: 'status-waiting' });
    api(`/api/pegout/${w.txid}`).then((p) => {
      if (gen !== generation) return;
      if (p.status === 'paid') {
        li.lastChild.textContent = `Paid ${show(p.pays)} on Bitcoin`;
        li.lastChild.className = 'status-done';
      } else if (p.status === 'pending') {
        li.lastChild.textContent = 'Waiting for the bridge';
      } else {
        li.lastChild.textContent = 'Not in a block yet';
      }
    }).catch(() => { if (gen === generation) li.lastChild.textContent = 'Status unavailable'; });
    return li;
  });
  $('withdrawals').replaceChildren(...rows);
}

// --- faucet --------------------------------------------------------------------

$('faucet-claim').addEventListener('click', async (e) => {
  e.target.disabled = true;
  try {
    const r = await api('/api/faucet', { address: myAddress() });
    showResult($('faucet-result'), `Sent ${show(r.amount)}. It arrives in the next block.`, true);
    setTimeout(refreshWallet, 3000);
  } catch (err) {
    showResult($('faucet-result'), err.message, false);
  } finally {
    e.target.disabled = false;
  }
});

// --- address book ----------------------------------------------------------------

// Saved names for addresses, in this browser only (addressbook-ui.js). The
// book starts once the network's address formats are known.
const versionsFor = (network) => (network === 'btc' ? info.bitcoinVersions : info.btcvmVersions);

// savedAs is what the book knows of an address on a network, or null.
const savedAs = (address, network) => (addressBook && address ? addressBook.lookup(address, network) : null);
const savedName = (address, network) => savedAs(address, network)?.name || '';

function startAddressBook() {
  try {
    addressBook = createAddressBook({
      $, store,
      // The forms' own decoder: an address is saved as it reads back.
      decode: (address, network) => chain.encodeAddress(chain.decodeAddress(address, versionsFor(network)), versionsFor(network)),
    });
    sendPicker = addressBook.attach({
      input: $('send-to'),
      network: () => document.querySelector('input[name=send-network]:checked').value,
      // An address saved for the other network switches the Send form to
      // it, if it can: the review still shows which network pays.
      onPick: (e) => {
        const radio = document.querySelector(`input[name=send-network][value=${e.network}]`);
        if (radio && !radio.disabled && !radio.checked) {
          radio.checked = true;
          radio.dispatchEvent(new Event('change', { bubbles: true }));
        }
      },
    });
    withdrawPicker = addressBook.attach({ input: $('withdraw-to'), network: () => 'btc', only: true });
  } catch (err) {
    // The wallet works without its address book.
    addressBook = null;
    sendPicker = null;
    withdrawPicker = null;
    console.error('address book unavailable:', err);
  }
}

// --- unit toggle and amount fields -------------------------------------------------

const PRICE_URL = 'https://mempool.space/api/v1/prices';
const amountFields = ['send-amount', 'move-amount', 'withdraw-amount'];
let priceUsable = false;

// refreshPrice fetches BTC's dollar price. It is used for ten minutes, so a
// failed fetch or two leaves the last one in place; after that USD is off
// until a fetch succeeds.
async function refreshPrice() {
  if (info && info.bitcoinNetwork === 'mainnet') {
    try {
      const res = await fetch(PRICE_URL, { cache: 'no-store' });
      if (res.ok) {
        const usd = Number((await res.json()).USD);
        if (Number.isFinite(usd) && usd > 0) price = { usd, time: Date.now() };
      }
    } catch { /* keep the last price until it is too old */ }
  }
  renderUnits();
}

// Text for an amount field, in a unit; plain digits, so it reads back.
function inputText(n, u) {
  if (u === 'sats') return n.toString();
  if (u === 'usd') return units.format(n, 'usd', usdPrice()).replace(/[$,<\s]/g, '');
  return units.format(n, 'btc').replace(/[,\sBTC]/g, '');
}

// Each amount field keeps the unit its text was typed in (data-unit), so a
// change of unit or a price that expires never reinterprets it: dollars
// typed with no current price are refused, not read as BTC.
function readAmount(id) {
  const field = $(id);
  return units.parse(field.value, field.dataset.unit || shownUnit(), usdPrice());
}

// renderAmountField labels a field with its unit and shows, under it,
// exactly what would be sent.
function renderAmountField(id) {
  const field = $(id);
  const u = field.dataset.unit || shownUnit();
  field.inputMode = u === 'sats' ? 'numeric' : 'decimal';
  field.placeholder = { btc: '0.0001', sats: '10,000', usd: '6.42' }[u];
  $(`${id}-unit`).textContent = { btc: 'BTC', sats: 'sats', usd: 'USD' }[u];
  const hint = $(`${id}-hint`);
  if (!field.value.trim()) {
    hint.textContent = '';
    hint.className = 'amount-hint';
    return;
  }
  try {
    const n = readAmount(id);
    const at = u === 'usd' ? ` at ${units.format(chain.SATS, 'usd', usdPrice())} per BTC` : '';
    hint.textContent = `Sends exactly ${units.exact(n)}${at}.`;
    hint.className = 'amount-hint';
  } catch (err) {
    hint.textContent = err.message[0].toUpperCase() + err.message.slice(1);
    hint.className = 'amount-hint error';
  }
}

function resetAmount(id) {
  $(id).value = '';
  $(id).dataset.unit = shownUnit();
  renderAmountField(id);
}

for (const id of amountFields) $(id).addEventListener('input', () => renderAmountField(id));

// renderUnits redraws every amount in the unit shown, and the toggle.
function renderUnits() {
  const usable = Boolean(usdPrice());
  priceUsable = usable;
  for (const b of document.querySelectorAll('.unit-toggle button')) {
    b.setAttribute('aria-pressed', String(b.dataset.unit === shownUnit()));
    if (b.dataset.unit !== 'usd') continue;
    b.setAttribute('aria-disabled', String(!usable));
    b.title = usable ? `1 BTC = ${units.format(chain.SATS, 'usd', usdPrice())}, from mempool.space`
      : info && info.bitcoinNetwork !== 'mainnet' ? 'Test coins have no dollar price.'
        : "The BTC price isn't available right now.";
  }
  for (const id of amountFields) {
    if (!$(id).value.trim()) $(id).dataset.unit = shownUnit();
    renderAmountField(id);
  }
  if (!info) return;
  renderInfo();
  renderPeg();
  renderVmWallet();
  renderBTCWallet();
  renderAvailable();
  renderInflight();
  refreshDeposits();
  if (!$('panel-withdraw').hidden) renderWithdrawals();
}

// setUnit picks the unit amounts show in, and converts what is typed in
// the amount fields to it.
function setUnit(u) {
  if (!units.UNITS.includes(u) || (u === 'usd' && !usdPrice())) return;
  for (const id of amountFields) {
    const field = $(id);
    if (!field.value.trim()) continue;
    try { field.value = inputText(readAmount(id), u); } catch { /* left as typed */ }
    field.dataset.unit = u;
  }
  unit = u;
  store.set(UNIT_STORE, u);
  renderUnits();
}

// nextUnit cycles BTC, sats, USD, skipping USD without a price.
function nextUnit() {
  const list = units.UNITS.filter((u) => u !== 'usd' || usdPrice());
  setUnit(list[(list.indexOf(shownUnit()) + 1) % list.length]);
}

for (const b of document.querySelectorAll('.unit-toggle button')) {
  b.addEventListener('click', () => setUnit(b.dataset.unit));
}
for (const el of document.querySelectorAll('.balance')) {
  el.addEventListener('click', nextUnit);
  el.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    e.preventDefault();
    nextUnit();
  });
}
renderUnits();

// --- start -----------------------------------------------------------------------

// start loads the network's settings, retrying until the bridge answers,
// then the saved key. The key buttons stay disabled until then, so a click
// during loading can't replace a saved key.
async function start() {
  for (let delay = 2000; ; delay = Math.min(delay * 2, 30000)) {
    try {
      await loadInfo();
      break;
    } catch (err) {
      $('wallet-start').textContent = `Can't reach the bridge (${err.message}). Retrying…`;
      $('wallet-start').className = 'result error';
      $('verdict').textContent = `Can't reach the bridge: ${err.message}`;
      $('verdict').className = 'peg-verdict bad';
      await new Promise((r) => { setTimeout(r, delay); });
    }
  }
  $('wallet-start').textContent = '';
  $('wallet-start').className = 'result';
  startAddressBook();
  const saved = store.get(KEY_STORE);
  if (saved) {
    try {
      key = chain.parseKey(saved);
    } catch {
      $('wallet-start').textContent = 'The key saved in this browser is unreadable, so it was not loaded.';
      $('wallet-start').className = 'result error';
    }
  }
  if (!saved && store.get(PASSKEY_STORE) === null) {
    $('create-key').disabled = false;
    $('import-submit').disabled = false;
  }
  renderKey();
  refreshStatus();
  refreshPrice();
  setInterval(refreshPrice, 5 * 60 * 1000);
  // A price that has aged out turns USD off, even between fetches.
  setInterval(() => { if (Boolean(usdPrice()) !== priceUsable) renderUnits(); }, 30 * 1000);
  const stream = listenForBlocks();
  // A fallback for when the event stream is down; while it's up, blocks
  // drive the refreshes and this only keeps the status (a pause, sync
  // progress) current.
  setInterval(() => {
    refreshStatus();
    if (stream.readyState === EventSource.OPEN) return;
    refreshWallet();
    refreshBTCWallet();
    refreshDeposits();
    refreshWithdrawalStatus();
    if (!$('panel-withdraw').hidden) renderWithdrawals();
  }, 15000);
}

// soon runs fn once for any number of calls within 100 ms, so a burst of
// events makes one set of requests.
const scheduled = new Map();
function soon(fn) {
  if (scheduled.has(fn)) return;
  scheduled.set(fn, setTimeout(() => { scheduled.delete(fn); fn(); }, 100));
}

// listenForBlocks refreshes the wallet the moment either chain has a new
// block. On BTCVM a block is final once accepted, so a payment shows
// as soon as it is final. The browser reconnects by itself if it drops.
function listenForBlocks() {
  const stream = new EventSource('/api/events');
  eventStream = stream;
  stream.addEventListener('open', renderConnection);
  stream.addEventListener('error', renderConnection);
  stream.addEventListener('block', (e) => {
    let chain;
    try { ({ chain } = JSON.parse(e.data)); } catch { return; }
    soon(refreshStatus);
    if (chain === 'btcvm') {
      soon(refreshWallet); // payments, and deposits being credited
      soon(refreshDeposits);
    } else if (chain === 'bitcoin') {
      soon(refreshBTCWallet);
      soon(refreshDeposits); // confirmations counting up
    }
    soon(refreshWithdrawalStatus); // final, paid, then in a Bitcoin block
    if (!$('panel-withdraw').hidden) soon(renderWithdrawals);
  });
  return stream;
}

// Transaction, block and address pages used to open on this page; they're
// on the explorer now.
if (/^#\/(tx|block|address)\//.test(location.hash)) location.replace(`/explorer${location.hash}`);
else start();
