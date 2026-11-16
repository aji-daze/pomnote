// OneDrive に直接つなぐ同期先（Microsoft Graph）。GitHub のトークンも PC の同期も要らない。
// 「ぽちゃ文庫」と同じ方式で、自分の Microsoft アカウントに登録したアプリ（クライアント ID）を使う。
//
// 認証は「認可コード + PKCE」。ブラウザだけで完結し、秘密鍵（client secret）は持たない。
// 更新用のトークンはこの端末の IndexedDB にだけ置く。Microsoft 以外のどこにも送らない。
//
// 同期の規則はほかの同期先と同じ（sync.js の3方向比較）。ハッシュも同じ git blob 方式で計算するので、
// GitHub 経由から切り替えても、同じ内容の原稿は「変更なし」と判定される。
import * as db from './db.js';
import { blobSha } from './sync.js';

const AUTH = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize';
const TOKEN = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
const GRAPH = 'https://graph.microsoft.com/v1.0';
const SCOPE = 'Files.ReadWrite offline_access User.Read';
const VERIFIER_KEY = 'pomnote.od.verifier';
const STATE_KEY = 'pomnote.od.state';
const TEXT_FILE = /\.(md|txt)$/i;
const MAX_BYTES = 5 * 1024 * 1024;
const SECRET_MARK = '【要保管】'; // パスワードや鍵のメモ。端末へ持ってこない
export const DEFAULT_EXCLUDE = ['Personal Vault', 'Microsoft Copilot Chat ファイル', 'アプリ', 'Desktop', '画像', '動画', 'music', '重要'];

export const redirectUri = () => location.origin + location.pathname;
export const getClientId = () => db.kvGet('odClientId', '');
export const setClientId = (id) => db.kvSet('odClientId', id.trim());
export const linked = async () => !!(await db.kvGet('odRefresh'));

let token = null;
let tokenExp = 0;

const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function randomString(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return b64url(a).slice(0, n);
}

// サインイン画面へ移る。戻ってきたら finishSignIn() が受け取る
export async function connect() {
  const clientId = await getClientId();
  if (!clientId) throw new Error('クライアント ID が入っていません');
  const verifier = randomString(64);
  const state = randomString(16);
  sessionStorage.setItem(VERIFIER_KEY, verifier);
  sessionStorage.setItem(STATE_KEY, state);
  const u = new URL(AUTH);
  u.searchParams.set('client_id', clientId);
  u.searchParams.set('response_type', 'code');
  u.searchParams.set('redirect_uri', redirectUri());
  u.searchParams.set('scope', SCOPE);
  u.searchParams.set('code_challenge', b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
  u.searchParams.set('code_challenge_method', 'S256');
  u.searchParams.set('state', state);
  location.assign(u.toString());
  return new Promise(() => {}); // 画面が切り替わるまで待つ
}

async function exchange(body) {
  let r;
  try {
    r = await fetch(TOKEN, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: await getClientId(), scope: SCOPE, ...body }),
    });
  } catch {
    throw offline();
  }
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    const e = new Error(j.error_description?.split('\n')[0] || j.error || `サインインに失敗しました（${r.status}）`);
    e.auth = true;
    throw e;
  }
  token = j.access_token;
  tokenExp = Date.now() + (Number(j.expires_in || 3600) - 120) * 1000;
  if (j.refresh_token) await db.kvSet('odRefresh', j.refresh_token);
}

// 起動時に呼ぶ。サインインから戻ってきていれば受け取って、アドレスを掃除する
export async function finishSignIn() {
  const q = new URLSearchParams(location.search);
  const code = q.get('code');
  const err = q.get('error');
  if (!q.get('state') || (!code && !err)) return null;
  const verifier = sessionStorage.getItem(VERIFIER_KEY);
  const want = sessionStorage.getItem(STATE_KEY);
  if (!want) return null; // こちらが始めたサインインではない
  sessionStorage.removeItem(VERIFIER_KEY);
  sessionStorage.removeItem(STATE_KEY);
  history.replaceState(null, '', location.pathname);
  if (err) return { ok: false, message: q.get('error_description')?.split('\n')[0] || err };
  if (!verifier || want !== q.get('state')) return { ok: false, message: 'サインインの照合に失敗しました。もう一度つないでください' };
  try {
    await exchange({ grant_type: 'authorization_code', code, redirect_uri: redirectUri(), code_verifier: verifier });
    return { ok: true };
  } catch (e) {
    return { ok: false, message: e.message };
  }
}

export async function signOut() {
  token = null;
  tokenExp = 0;
  for (const k of ['odRefresh', 'odDelta', 'odMeta']) await db.del('kv', k);
}

function offline() {
  const e = new Error('通信できません（オフライン）');
  e.offline = true;
  return e;
}

async function ensureToken() {
  if (token && Date.now() < tokenExp) return;
  const refresh = await db.kvGet('odRefresh');
  if (!refresh) {
    const e = new Error('OneDrive につながっていません（⚙ →「同期」でつないでください）');
    e.auth = true;
    throw e;
  }
  try {
    await exchange({ grant_type: 'refresh_token', refresh_token: refresh });
  } catch (e) {
    if (e.auth) e.message = `OneDrive へのサインインが切れました。⚙ →「同期」でつなぎ直してください（${e.message}）`;
    throw e;
  }
}

async function api(method, url, { headers = {}, body, raw = false } = {}) {
  await ensureToken();
  let r;
  try {
    r = await fetch(url.startsWith('http') ? url : GRAPH + url, { method, headers: { Authorization: `Bearer ${token}`, ...headers }, body, cache: 'no-store' });
  } catch {
    throw offline();
  }
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    const e = new Error(`OneDrive ${r.status}: ${j.error?.message || r.statusText}`);
    e.status = r.status;
    throw e;
  }
  return raw || r.status === 204 ? r : r.json();
}

const encPath = (p) => p.split('/').map(encodeURIComponent).join('/');
const fatal = new TextDecoder('utf-8', { fatal: true });

export async function backend(cfg) {
  const exclude = new Set(cfg.exclude?.length ? cfg.exclude : DEFAULT_EXCLUDE);
  // delta: OneDrive の全項目の控え { link: 続きの印, rootId, items: { id: { n: 名前, p: 親, d: フォルダか, e: eTag, c: cTag, s: 大きさ } } }
  let delta = await db.kvGet('odDelta', null);
  let meta = await db.kvGet('odMeta', {}); // id → { c: cTag, sha }（変わっていないファイルは読み直さない）
  const texts = new Map(); // この回に読んだ本文
  let byPath = new Map(); // パス → id

  const pathOf = (id) => {
    const parts = [];
    for (let cur = delta.items[id], n = 0; cur; cur = delta.items[cur.p], n++) {
      if (n > 40) return null;
      parts.unshift(cur.n);
      if (cur.p === delta.rootId) return parts.join('/');
    }
    return null; // 親が見つからない（ごみ箱の中など）
  };

  const refresh = async () => {
    let url = delta?.link || '/me/drive/root/delta?$select=id,name,size,file,folder,deleted,root,eTag,cTag,parentReference';
    if (!delta) delta = { link: '', rootId: '', items: {} };
    for (;;) {
      let j;
      try {
        j = await api('GET', url);
      } catch (e) {
        if (e.status !== 410) throw e; // 410: 控えが古すぎる → 最初から取り直す
        delta = null;
        return refresh();
      }
      for (const it of j.value || []) {
        if (it.root) { delta.rootId = it.id; continue; }
        if (it.deleted) { delete delta.items[it.id]; continue; }
        delta.items[it.id] = { n: it.name, p: it.parentReference?.id || '', d: it.folder ? 1 : 0, e: it.eTag || '', c: it.cTag || it.eTag || '', s: Number(it.size || 0) };
      }
      if (j['@odata.nextLink']) { url = j['@odata.nextLink']; continue; }
      delta.link = j['@odata.deltaLink'] || '';
      break;
    }
    await db.kvSet('odDelta', delta);
  };

  const download = async (id) => {
    const j = await api('GET', `/me/drive/items/${id}?$select=id,@microsoft.graph.downloadUrl`);
    const url = j['@microsoft.graph.downloadUrl'];
    if (!url) throw new Error('OneDrive からダウンロードできませんでした');
    let r;
    try { r = await fetch(url); } catch { throw offline(); } // 署名済みの一時 URL。Authorization は付けない
    if (!r.ok) throw new Error(`OneDrive からのダウンロードに失敗しました（${r.status}）`);
    return new Uint8Array(await r.arrayBuffer());
  };

  const remember = async (id, item, content) => {
    delta.items[id] = { n: item.name, p: item.parentReference?.id || delta.items[id]?.p || '', d: 0, e: item.eTag || '', c: item.cTag || item.eTag || '', s: Number(item.size || 0) };
    meta[id] = { c: delta.items[id].c, sha: await blobSha(content) };
    await db.kvSet('odDelta', delta);
    await db.kvSet('odMeta', meta);
    return meta[id].sha;
  };
  const changedError = (path) => new Error(`「${path}」が同期の途中で書き換えられました。もう一度同期してください`);

  return {
    label: 'OneDrive版',
    async tree(state) {
      await refresh();
      byPath = new Map();
      const want = [];
      for (const [id, it] of Object.entries(delta.items)) {
        if (it.d || !TEXT_FILE.test(it.n)) continue;
        const path = pathOf(id);
        if (!path) continue;
        const parts = path.split('/');
        if (parts.some((p) => p.startsWith('.') || p.includes(SECRET_MARK)) || parts.slice(0, -1).some((p) => exclude.has(p))) continue;
        byPath.set(path, id);
        if (it.s > MAX_BYTES) { state?.skipped?.add(path); continue; }
        want.push([path, id, it]);
      }
      const map = new Map();
      const next = {};
      let i = 0;
      const worker = async () => {
        while (i < want.length) {
          const [path, id, it] = want[i++];
          let m = meta[id];
          if (!m || m.c !== it.c) {
            let text = null;
            try { text = fatal.decode(await download(id)); } catch (e) { if (e.offline || e.status) throw e; }
            m = { c: it.c, sha: text === null ? null : await blobSha(text) };
            if (text !== null) texts.set(path, text);
          }
          next[id] = m;
          if (m.sha) map.set(path, m.sha);
          else state?.skipped?.add(path); // UTF-8 でないファイルは、どちら側も変更しない
        }
      };
      await Promise.all([worker(), worker(), worker(), worker()]);
      meta = next;
      await db.kvSet('odMeta', meta);
      return map;
    },
    async read(path) {
      if (texts.has(path)) return texts.get(path);
      const id = byPath.get(path);
      if (!id) throw changedError(path);
      return fatal.decode(await download(id));
    },
    // 前回見た内容（prevSha）のままのときだけ書き込む。null は「まだ無いはず」
    async write(state, path, content, prevSha) {
      const id = byPath.get(path);
      const body = new Blob([content], { type: 'text/plain' });
      let item;
      try {
        if (id) {
          if ((meta[id]?.sha || null) !== (prevSha || null)) throw changedError(path);
          item = await api('PUT', `/me/drive/items/${id}/content`, { headers: { 'If-Match': delta.items[id].e, 'Content-Type': 'text/plain' }, body });
        } else {
          if (prevSha) throw changedError(path);
          item = await api('PUT', `/me/drive/root:/${encPath(path)}:/content?@microsoft.graph.conflictBehavior=fail`, { headers: { 'Content-Type': 'text/plain' }, body });
        }
      } catch (e) {
        if (e.status === 412 || e.status === 409) throw changedError(path);
        throw e;
      }
      byPath.set(path, item.id);
      return remember(item.id, item, content);
    },
    // OneDrive のごみ箱へ移る（OneDrive の「ごみ箱」から元に戻せる）
    async remove(path, sha) {
      const id = byPath.get(path);
      if (!id) return;
      if (meta[id]?.sha !== sha) throw changedError(path);
      try {
        await api('DELETE', `/me/drive/items/${id}`, { headers: { 'If-Match': delta.items[id].e }, raw: true });
      } catch (e) {
        if (e.status === 412) throw changedError(path);
        if (e.status !== 404) throw e;
      }
      delete delta.items[id];
      delete meta[id];
      byPath.delete(path);
      await db.kvSet('odDelta', delta);
      await db.kvSet('odMeta', meta);
    },
  };
}

export async function test() {
  if (!(await linked())) return { ok: false, warn: 'まだ OneDrive につながっていません。「OneDrive につなぐ」を押してください。' };
  const me = await api('GET', '/me/drive?$select=owner,driveType');
  const who = me.owner?.user?.displayName || '';
  return { ok: true, info: `OneDrive につながっています${who ? `（${who}）` : ''}。「今すぐ同期」で原稿を読み込みます。` };
}
