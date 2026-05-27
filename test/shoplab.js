'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// ShopLab — deliberately vulnerable e-commerce API + UI
// For use with accguard security testing ONLY.
// DO NOT deploy to any public server.
//
// Four deliberate IDOR vulnerabilities — no ownership checks on:
//   [1] GET /api/orders/:id
//   [2] GET /api/payment/:id
//   [3] GET /api/documents/:id
//   [4] GET /api/users/:id
// ─────────────────────────────────────────────────────────────────────────────

const http = require('http');
const PORT = parseInt(process.env.SHOPLAB_PORT || '3100', 10);

// ── Data ──────────────────────────────────────────────────────────────────────

const USERS = {
  'user-alice': { id: 'user-alice', name: 'Alice Summers', email: 'alice@shoplab.dev', token: 'tok-alice', address: '12 Oak Street, Portland OR' },
  'user-bob':   { id: 'user-bob',   name: 'Bob Trenton',   email: 'bob@shoplab.dev',   token: 'tok-bob',   address: '88 Maple Ave, Austin TX'   },
};

const TOKEN_MAP = { 'tok-alice': 'user-alice', 'tok-bob': 'user-bob' };

const ORDERS = {
  'ord-1001': { id: 'ord-1001', owner: 'user-alice', item: 'Mechanical Keyboard', total: 149.99, status: 'shipped'    },
  'ord-1002': { id: 'ord-1002', owner: 'user-alice', item: 'USB-C Hub',           total:  49.99, status: 'delivered'  },
  'ord-2001': { id: 'ord-2001', owner: 'user-bob',   item: 'Monitor Stand',       total:  89.00, status: 'processing' },
  'ord-2002': { id: 'ord-2002', owner: 'user-bob',   item: 'Webcam HD',           total:  79.99, status: 'shipped'    },
};

const PAYMENTS = {
  'pay-1': { id: 'pay-1', owner: 'user-alice', type: 'Visa',       last4: '4242', expiry: '09/27' },
  'pay-2': { id: 'pay-2', owner: 'user-bob',   type: 'Mastercard', last4: '8888', expiry: '03/26' },
};

const DOCUMENTS = {
  'doc-101': { id: 'doc-101', owner: 'user-alice', title: 'Q1 Sales Report',   content: 'Revenue: $142,000. Margin: 34%.' },
  'doc-201': { id: 'doc-201', owner: 'user-bob',   title: 'Personal Budget',   content: 'Savings: $8,400. Monthly: $3,200.' },
};

const PRODUCTS = [
  { id: 'p-01', name: 'Mechanical Keyboard', price: 149.99, stock: 12 },
  { id: 'p-02', name: 'USB-C Hub',           price:  49.99, stock: 34 },
  { id: 'p-03', name: 'Monitor Stand',       price:  89.00, stock:  8 },
  { id: 'p-04', name: 'Webcam HD',           price:  79.99, stock: 21 },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function getUser(req) {
  const auth = (req.headers['authorization'] || '').replace(/^bearer\s+/i, '').trim();
  const uid  = TOKEN_MAP[auth];
  return uid ? USERS[uid] : null;
}

function readBody(req) {
  return new Promise(resolve => {
    const chunks = [];
    req.on('data', c => chunks.push(c));
    req.on('end',  () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); }
      catch { resolve({}); }
    });
  });
}

function send(res, status, data) {
  const body = JSON.stringify(data, null, 2);
  res.writeHead(status, {
    'content-type':                'application/json',
    'content-length':              Buffer.byteLength(body),
    'access-control-allow-origin': '*',
  });
  res.end(body);
}

function sendHtml(res, content) {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(content);
}

// ── Router ────────────────────────────────────────────────────────────────────

async function router(req, res) {
  const url    = new URL(req.url, 'http://localhost');
  const p      = url.pathname;
  const method = req.method.toUpperCase();
  const user   = getUser(req);

  // Public
  if (method === 'GET'  && p === '/')             return sendHtml(res, FRONTEND);
  if (method === 'GET'  && p === '/api/health')   return send(res, 200, { ok: true });
  if (method === 'GET'  && p === '/api/products') return send(res, 200, PRODUCTS);

  if (method === 'POST' && p === '/api/auth/login') {
    const body  = await readBody(req);
    const found = Object.values(USERS).find(u => u.email === body.email);
    if (!found) return send(res, 401, { error: 'invalid credentials' });
    return send(res, 200, { token: found.token, name: found.name, id: found.id });
  }

  // Auth required
  if (!user) return send(res, 401, { error: 'unauthorized' });

  // /api/me — correct: own profile only
  if (method === 'GET' && p === '/api/me')
    return send(res, 200, { id: user.id, name: user.name, email: user.email, address: user.address });

  // GET /api/users/:id — BUG [4]: no ownership check
  const userM = p.match(/^\/api\/users\/([^/]+)$/);
  if (method === 'GET' && userM) {
    const t = USERS[userM[1]];
    if (!t) return send(res, 404, { error: 'not found' });
    return send(res, 200, { id: t.id, name: t.name, email: t.email, address: t.address });
  }

  // GET /api/orders — correct: own orders only
  if (method === 'GET' && p === '/api/orders')
    return send(res, 200, Object.values(ORDERS).filter(o => o.owner === user.id));

  // GET /api/orders/:id — BUG [1]: no ownership check
  const orderM = p.match(/^\/api\/orders\/([^/]+)$/);
  if (method === 'GET' && orderM) {
    const o = ORDERS[orderM[1]];
    if (!o) return send(res, 404, { error: 'not found' });
    return send(res, 200, o);
  }

  // GET /api/payment — correct: own payment methods only
  if (method === 'GET' && p === '/api/payment')
    return send(res, 200, Object.values(PAYMENTS).filter(pm => pm.owner === user.id));

  // GET /api/payment/:id — BUG [2]: no ownership check
  const payM = p.match(/^\/api\/payment\/([^/]+)$/);
  if (method === 'GET' && payM) {
    const pm = PAYMENTS[payM[1]];
    if (!pm) return send(res, 404, { error: 'not found' });
    return send(res, 200, pm);
  }

  // GET /api/documents — correct: own documents only
  if (method === 'GET' && p === '/api/documents')
    return send(res, 200, Object.values(DOCUMENTS).filter(d => d.owner === user.id));

  // GET /api/documents/:id — BUG [3]: no ownership check
  const docM = p.match(/^\/api\/documents\/([^/]+)$/);
  if (method === 'GET' && docM) {
    const d = DOCUMENTS[docM[1]];
    if (!d) return send(res, 404, { error: 'not found' });
    return send(res, 200, d);
  }

  return send(res, 404, { error: 'not found' });
}

// ── Frontend ──────────────────────────────────────────────────────────────────

const FRONTEND = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShopLab — accguard demo</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500&display=swap');
:root{--bg:#0a0a0a;--s:#111;--b:#1e1e1e;--accent:#e8ff47;--text:#e0e0e0;--muted:#555;--red:#ff4f4f;--green:#4fff8a;--blue:#47aaff}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'IBM Plex Sans',sans-serif;font-size:13px;min-height:100vh}
header{border-bottom:1px solid var(--b);padding:14px 24px;display:flex;align-items:center;justify-content:space-between}
.logo{font-family:'IBM Plex Mono',monospace;font-size:15px;color:var(--accent)}
.logo span{color:var(--muted);font-size:11px}
#who{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted)}
#who.on{color:var(--green)}
.layout{display:grid;grid-template-columns:200px 1fr 260px;height:calc(100vh - 49px)}
nav{border-right:1px solid var(--b);padding:16px 0}
.ns{padding:6px 18px 3px;font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.nb{display:block;width:100%;text-align:left;padding:7px 18px;background:none;border:none;color:var(--text);font-size:13px;cursor:pointer}
.nb:hover{background:var(--s)}
.nb.active{color:var(--accent);background:var(--s)}
main{padding:20px;overflow-y:auto}
.st{font-family:'IBM Plex Mono',monospace;font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:14px}
.card{background:var(--s);border:1px solid var(--b);border-radius:5px;padding:14px;margin-bottom:8px}
.ct{font-weight:500;margin-bottom:3px}
.cs{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted);margin-top:2px}
.bdg{display:inline-block;font-family:'IBM Plex Mono',monospace;font-size:10px;padding:1px 7px;border-radius:20px;margin-left:6px}
.sh{background:#1a2535;color:var(--blue)}.dl{background:#152515;color:var(--green)}.pr{background:#251a0a;color:#ffaa47}
aside{border-left:1px solid var(--b);padding:16px;overflow-y:auto}
.le{font-family:'IBM Plex Mono',monospace;font-size:11px;padding:3px 0;border-bottom:1px solid #161616;line-height:1.5}
.lm{color:var(--accent)}.l2{color:var(--green)}.l4{color:var(--red)}.l0{color:var(--muted)}
.lp{display:flex;flex-direction:column;gap:8px;max-width:300px}
.ub{padding:13px 14px;border:1px solid var(--b);border-radius:5px;background:var(--s);color:var(--text);font-size:13px;cursor:pointer;text-align:left}
.ub:hover{border-color:var(--accent)}
.ue{font-family:'IBM Plex Mono',monospace;font-size:11px;color:var(--muted);margin-top:2px}
.lb{margin-top:6px;padding:5px 10px;background:none;border:1px solid var(--b);border-radius:4px;color:var(--muted);font-family:'IBM Plex Mono',monospace;font-size:11px;cursor:pointer}
.lb:hover{border-color:var(--red);color:var(--red)}
.em{color:var(--muted);padding:16px 0}
</style>
</head>
<body>
<header>
  <div class="logo">ShopLab <span>// accguard demo &nbsp;·&nbsp; 4 hidden IDOR vulnerabilities</span></div>
  <div id="who">not logged in</div>
</header>
<div class="layout">
<nav>
  <div class="ns">Store</div>
  <button class="nb active" data-v="products" onclick="show(this)">Products</button>
  <div class="ns" style="margin-top:10px">Account</div>
  <button class="nb" data-v="login"     onclick="show(this)">Login</button>
  <button class="nb" data-v="profile"   onclick="show(this)">My Profile</button>
  <button class="nb" data-v="orders"    onclick="show(this)">My Orders</button>
  <button class="nb" data-v="payment"   onclick="show(this)">Payment Methods</button>
  <button class="nb" data-v="documents" onclick="show(this)">Documents</button>
</nav>
<main id="main"></main>
<aside>
  <div class="st">Request log</div>
  <div id="log"></div>
</aside>
</div>
<script>
let token=null;
async function api(method,path,body){
  const o={method,headers:{'content-type':'application/json'}};
  if(token)o.headers['authorization']='Bearer '+token;
  if(body)o.body=JSON.stringify(body);
  const r=await fetch(path,o);
  const d=await r.json().catch(()=>({}));
  const e=document.createElement('div');
  e.className='le';
  const sc=r.status<300?'l2':r.status<500?'l4':'l0';
  e.innerHTML='<span class="lm">'+method+'</span> '+path+' <span class="'+sc+'">'+r.status+'</span>';
  document.getElementById('log').prepend(e);
  return{s:r.status,d};
}
function render(h){document.getElementById('main').innerHTML=h;}
function show(btn){
  document.querySelectorAll('.nb').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  const v=btn.dataset.v;
  if(v==='products'){
    render('<div class="st">Products</div><div id="pl"><div class="em">Loading...</div></div>');
    api('GET','/api/products').then(r=>{
      document.getElementById('pl').innerHTML=r.d.map(p=>'<div class="card"><div class="ct">'+p.name+'</div><div class="cs">$'+p.price.toFixed(2)+' · '+p.stock+' in stock</div></div>').join('');
    });
  }
  if(v==='login'){
    render('<div class="st">Login as</div><div class="lp"><button class="ub" onclick="login(\'alice@shoplab.dev\')"><div>Alice Summers</div><div class="ue">alice@shoplab.dev · tok-alice</div></button><button class="ub" onclick="login(\'bob@shoplab.dev\')"><div>Bob Trenton</div><div class="ue">bob@shoplab.dev · tok-bob</div></button>'+(token?'<button class="lb" onclick="logout()">logout</button>':'')+'</div>');
  }
  if(v==='profile'){
    if(!token)return render('<div class="em">Login first.</div>');
    api('GET','/api/me').then(r=>{render('<div class="st">My Profile</div><div class="card"><div class="ct">'+r.d.name+'</div><div class="cs">'+r.d.email+'</div><div class="cs" style="margin-top:5px">'+r.d.address+'</div></div>');});
  }
  if(v==='orders'){
    if(!token)return render('<div class="em">Login first.</div>');
    api('GET','/api/orders').then(r=>{
      render('<div class="st">My Orders</div>'+r.d.map(o=>'<div class="card"><div class="ct">'+o.item+'<span class="bdg '+o.status.substring(0,2)+'">'+o.status+'</span></div><div class="cs">'+o.id+' · $'+o.total.toFixed(2)+'</div></div>').join(''));
    });
  }
  if(v==='payment'){
    if(!token)return render('<div class="em">Login first.</div>');
    api('GET','/api/payment').then(r=>{
      render('<div class="st">Payment Methods</div>'+r.d.map(p=>'<div class="card"><div class="ct">'+p.type+' ending in '+p.last4+'</div><div class="cs">Expires '+p.expiry+'</div></div>').join(''));
    });
  }
  if(v==='documents'){
    if(!token)return render('<div class="em">Login first.</div>');
    api('GET','/api/documents').then(r=>{
      render('<div class="st">Documents</div>'+r.d.map(d=>'<div class="card"><div class="ct">'+d.title+'</div><div class="cs">'+d.content+'</div></div>').join(''));
    });
  }
}
async function login(email){
  const r=await api('POST','/api/auth/login',{email});
  if(r.s===200){token=r.d.token;const w=document.getElementById('who');w.textContent='logged in as '+r.d.name;w.className='on';}
}
function logout(){token=null;const w=document.getElementById('who');w.textContent='not logged in';w.className='';}
show(document.querySelector('.nb.active'));
</script>
</body>
</html>`;

// ── Server ────────────────────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  router(req, res).catch(err => {
    console.error('[shoplab]', err.message);
    res.writeHead(500);
    res.end('{"error":"internal server error"}');
  });
});

if (require.main === module) {
  server.listen(PORT, '127.0.0.1', () => {
    console.log(`
╔══════════════════════════════════════════════╗
║  ShopLab — accguard demo target              ║
║  http://127.0.0.1:${PORT}                       ║
╠══════════════════════════════════════════════╣
║  Alice  tok-alice   alice@shoplab.dev        ║
║  Bob    tok-bob     bob@shoplab.dev          ║
╠══════════════════════════════════════════════╣
║  4 deliberate IDOR vulnerabilities inside    ║
║  Run accguard to find them                   ║
╚══════════════════════════════════════════════╝
    `);
  });
}

module.exports = server;
