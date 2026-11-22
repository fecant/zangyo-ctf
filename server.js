'use strict';
/**
 * 残業 — 社畜猫娘的多阶段 Web 密室
 * 五个洞：信息泄露 → IDOR → 上传绕过 → SSRF → 命令注入
 *
 * 环境变量：
 *   PORT      监听端口（默认 3000）
 *   CTF_FLAG  平台注入的 flag；不设时用内置值
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = '0.0.0.0';
const INNER_PORT = parseInt(process.env.INNER_PORT || '9999', 10);

/* flag 取值：平台注入的变量名五花八门，这里做归一化匹配
 * CTF_FLAG / CTF-FLAG / ctf_flag / GZCTF_FLAG / FLAG / DASCTF_FLAG 都能认
 * （去掉非字母字符后大写比较，所以连字符、下划线、大小写都不影响） */
const flagKey = (k) => String(k).toUpperCase().replace(/[^A-Z]/g, '');
const FLAG_KEYS = new Set(['CTF_FLAG', 'GZCTF_FLAG', 'FLAG', 'DASCTF_FLAG'].map(flagKey));
const FLAG = (() => {
  for (const [k, v] of Object.entries(process.env)) {
    if (v && String(v).trim() && FLAG_KEYS.has(flagKey(k))) return String(v).trim();
  }
  return 'flag{N0m4d_c4tg1rl_n3v3r_d1d_4nyth1ng_wr0ng}';
})();
/** 把 flag 均分成 5 段，每关露一段 */
const PARTS = (() => {
  const n = 5, size = Math.ceil(FLAG.length / n), out = [];
  for (let i = 0; i < n; i++) out.push(FLAG.slice(i * size, (i + 1) * size));
  return out;
})();

const PUBLIC = path.join(__dirname, 'public');

/* ---------------- 会话 ----------------
 * 进度（已登录 / 已拿到的碎片 / 已上传文件）全部签名后放进 cookie，
 * 服务端不存任何状态：进程重启、沙箱换实例、玩家关浏览器重进，进度都还在。
 * 签名密钥取自 CTF_SECRET（没设就用 flag 本身），伪造 cookie 需要先知道 flag。
 */
const SECRET = process.env.CTF_SECRET || FLAG;
const FILE_KEEP = 240;          // 单个文件进 cookie 的正文上限
const b64u = (x) => Buffer.from(x).toString('base64url');
const mac = (body) => crypto.createHmac('sha256', SECRET).update(body).digest('base64url').slice(0, 22);

function packSession(s) {
  const base = { u: s.user ? 1 : 0, p: [...s.parts].sort((a, b) => a - b) };
  const files = s.files.slice(-8).map((f) => [String(f.name).slice(0, 80), String(f.content).slice(0, FILE_KEEP)]);
  // cookie 有 4KB 上限：超了就从最旧的文件开始丢，进度位永远保留
  for (let i = files.length; i >= 0; i--) {
    const body = b64u(JSON.stringify({ ...base, f: files.slice(files.length - i) }));
    if (body.length <= 3000 || i === 0) return body + '.' + mac(body);
  }
}

function unpackSession(v) {
  const [body, sig] = String(v || '').split('.');
  if (!body || !sig) return null;
  const want = mac(body);
  if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return null;
  try {
    const o = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    return {
      user: o.u ? 'nomad' : null,
      parts: new Set(Array.isArray(o.p) ? o.p.filter((n) => n >= 1 && n <= 5) : []),
      files: Array.isArray(o.f) ? o.f.map(([name, content]) => ({ name, content })) : [],
    };
  } catch (_) { return null; }
}

function getSession(req, res) {
  const m = String(req.headers.cookie || '').match(/(?:^|;\s*)sid=([A-Za-z0-9._-]{8,4000})/);
  const s = (m && unpackSession(m[1])) || { user: null, parts: new Set(), files: [] };
  // grant 发生在路由里，所以把写 cookie 的时机延迟到真正写响应头的那一刻
  const writeHead = res.writeHead.bind(res);
  res.writeHead = (code, headers) => {
    res.setHeader('Set-Cookie',
      `sid=${packSession(s)}; Path=/; Max-Age=1209600; HttpOnly; SameSite=Lax`);
    return writeHead(code, headers);
  };
  s.req = req;
  return s;
}
const grant = (s, n) => { if (n >= 1 && n <= 5) s.parts.add(n); };

/* ---------------- 工具 ---------------- */
const esc = (x) => String(x == null ? '' : x)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

function send(res, body, code = 200, type = 'text/html; charset=utf-8') {
  res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store' });
  res.end(body);
}

/** 容错的 URL 解码：畸形百分号编码不抛错，原样返回 */
function decPart(x) {
  try { return decodeURIComponent(String(x).replace(/\+/g, ' ')); }
  catch (_) { return String(x); }
}

/** 容错的 URL 解析：非法 URL 退化成根路径，不让异常冒到外层 */
function parseUrl(raw) {
  try { return new URL(raw, 'http://localhost'); }
  catch (_) { return new URL('/', 'http://localhost'); }
}

function readBody(req) {
  return new Promise((resolve) => {
    let d = '';
    req.on('data', (c) => { d += c; if (d.length > 2e6) req.destroy(); });
    req.on('end', () => {
      const o = {};
      for (const kv of d.split('&')) {
        if (!kv) continue;
        const i = kv.indexOf('=');
        // 畸形百分号编码（%zz、单个 %）会让 decodeURIComponent 抛错，
        // 之前没有兜底 → async 处理器 reject → 整个进程退出（表现为 504）
        const k = decPart(i < 0 ? kv : kv.slice(0, i));
        const v = i < 0 ? '' : decPart(kv.slice(i + 1));
        o[k] = v;
      }
      resolve(o);
    });
    req.on('error', () => resolve({}));
  });
}

/* ---------------- 页面骨架（暗色极简） ---------------- */
const CSS = `
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d0d0d; --ink:#ffffff; --dim:#8d8d8d; --line:#262626; --panel:#131313; --warn:#e8e8e8;
}
html,body{background:var(--bg);color:var(--ink)}
body{
  font-family:"Helvetica Neue",Inter,"PingFang SC","Hiragino Sans GB","Microsoft YaHei",system-ui,sans-serif;
  -webkit-font-smoothing:antialiased;line-height:1.55;
}
a{color:inherit;text-decoration:none}
.wrap{max-width:1240px;margin:0 auto;padding:0 56px;position:relative;z-index:2}
.stagebg{position:fixed;inset:0;z-index:0;background-size:cover;background-position:50% 30%;background-repeat:no-repeat;
  filter:brightness(.86) saturate(1.04) contrast(1.02);pointer-events:none}
/* 遮罩：左边压暗保文字对比，右边放亮让画面露出来（不是四周往里压） */
.veil{position:fixed;inset:0;z-index:1;pointer-events:none;
  background:
    linear-gradient(90deg,rgba(13,13,13,.94) 0%,rgba(13,13,13,.9) 38%,rgba(13,13,13,.58) 58%,rgba(13,13,13,.13) 72%,rgba(13,13,13,.28) 100%),
    linear-gradient(180deg,rgba(13,13,13,.62) 0%,rgba(13,13,13,.06) 15%,rgba(13,13,13,0) 50%,rgba(13,13,13,.34) 86%,rgba(13,13,13,.94) 100%)}
@media(max-width:900px){.veil{background:
  linear-gradient(180deg,rgba(13,13,13,.92) 0%,rgba(13,13,13,.66) 34%,rgba(13,13,13,.62) 60%,rgba(13,13,13,.82) 88%,#0d0d0d 100%)}}
nav{display:flex;align-items:center;gap:44px;padding:38px 0 0}
nav .brand{font-size:15px;font-weight:700;letter-spacing:.01em;margin-right:8px}
nav a.link{font-size:13.5px;color:var(--dim);letter-spacing:.02em}
nav .right{margin-left:auto;display:flex;gap:12px;align-items:center}
.btn{display:inline-block;padding:11px 22px;font-size:12.5px;letter-spacing:.06em;border:1px solid transparent;cursor:pointer;background:none;color:inherit;font-family:inherit}
.btn.solid{background:#fff;color:#101010}
.btn.ghost{border-color:#3a3a3a;color:#d8d8d8}
.hero{display:grid;grid-template-columns:1.05fr .95fr;align-items:center;gap:24px;min-height:74vh;padding:26px 0 40px}
h1.big{font-size:clamp(74px,11.4vw,176px);line-height:.86;letter-spacing:-.045em;font-weight:800}
.lead{margin-top:56px;max-width:520px;color:#b4b4b4;font-size:15px;line-height:1.8}
.lead em{color:#e9e9e9;font-style:normal}
.actions{margin-top:34px;display:flex;gap:14px;align-items:center}
.actions .plain{font-size:12.5px;letter-spacing:.06em;color:#c9c9c9;display:flex;gap:9px;align-items:center}
.dot{width:26px;height:26px;border-radius:50%;border:1px solid #4a4a4a;display:grid;place-items:center;font-size:9px}
.scroll{margin-top:52px;font-size:12.5px;color:var(--dim);display:flex;gap:10px;align-items:center}
.orb{position:relative;justify-self:end;width:min(100%,540px);aspect-ratio:1;border-radius:50%;overflow:hidden;
  box-shadow:0 0 0 1px #1d1d1d, 0 40px 120px rgba(0,0,0,.9) inset}
.orb img{width:100%;height:100%;object-fit:cover;object-position:38% 42%;filter:brightness(.98) contrast(1.04) saturate(.95)}
.orb:after{content:"";position:absolute;inset:0;border-radius:50%;
  background:radial-gradient(circle at 50% 45%,rgba(0,0,0,0) 44%,rgba(13,13,13,.42) 76%,#0d0d0d 100%)}
.ending{display:grid;grid-template-columns:322px 1fr;gap:38px;align-items:start;margin-top:34px}
.ending img{width:100%;display:block;border:1px solid #3a3a3a;filter:brightness(1.06) contrast(1.04);box-shadow:0 26px 70px rgba(0,0,0,.85)}
@media(max-width:900px){.ending{grid-template-columns:1fr;gap:22px}.ending img{max-width:322px}}
@media(max-width:900px){.hero{grid-template-columns:1fr;min-height:auto;padding-top:10px}.orb{justify-self:start;width:min(100%,420px);order:-1}h1.big{font-size:clamp(56px,16vw,96px)}.cards{grid-template-columns:1fr}.card{border-right:none;border-bottom:1px solid var(--line)}nav{gap:22px;flex-wrap:wrap}.wrap{padding:0 22px}}
.cards{display:grid;grid-template-columns:1fr 1fr 1fr;gap:0;border-top:1px solid var(--line);margin-top:8px}
.card{padding:26px 26px 30px;border-right:1px solid var(--line)}
.card:last-child{border-right:none}a.card{display:block;color:inherit}
.card .tag{font-size:10.5px;letter-spacing:.16em;color:#8d8d8d;margin-bottom:10px}
.card .t{font-size:13px;color:#cfcfcf;letter-spacing:.02em;line-height:1.6}
.card .s{font-size:12px;color:#8d8d8d;margin-top:8px}
footer{padding:40px 0 60px;color:var(--dim);font-size:11.5px;letter-spacing:.04em;display:flex;gap:18px}

/* 内页 */
.article{margin-top:34px}
.article img{width:100%;max-width:620px;display:block;border:1px solid #262626;margin-bottom:32px;filter:brightness(.96)}
.article p{color:#bfbfbf;font-size:14.5px;line-height:2.1;margin-bottom:4px}
.jp{margin-top:46px;padding-top:28px;border-top:1px solid #242424;font-size:25px;line-height:1.85;color:#fff;
  letter-spacing:.02em;font-weight:700}
.page{padding:34px 0 80px;max-width:880px}
.kicker{font-size:10.5px;letter-spacing:.2em;color:#9a9a9a}
.page h2{font-size:clamp(30px,4vw,46px);letter-spacing:-.02em;font-weight:800;margin:10px 0 0}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.panel{margin-top:26px;border:1px solid var(--line);background:rgba(13,13,13,.74);padding:22px;
  -webkit-backdrop-filter:blur(10px);backdrop-filter:blur(10px)}
.joke{display:inline-block;max-width:100%;margin-top:20px;padding:16px 18px;border:1px dashed #2c2c2c;background:rgba(8,8,8,.86);
  -webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px);
  font-size:13.5px;line-height:2;color:#a6a6a6}
.joke b{color:#fff;font-weight:600}
.say{color:#c9c9c9;font-size:14px;border-left:2px solid #3a3a3a;padding-left:16px;margin-top:22px}
.say b{color:#fff;font-weight:600}
label{display:block;font-size:11px;letter-spacing:.12em;color:#8d8d8d;margin:14px 0 7px}
input[type=text],input[type=password],textarea,select{
  width:100%;background:#0a0a0a;border:1px solid #2e2e2e;color:#f2f2f2;padding:11px 13px;
  font-size:13.5px;font-family:inherit}
input:focus,textarea:focus{border-color:#5a5a5a}
textarea{min-height:110px;resize:vertical;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px}
.row{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap}
.row > div{flex:1;min-width:180px}
pre.out{margin-top:16px;background:#080808;border:1px solid #242424;padding:14px;font-size:12.5px;
  color:#cfcfcf;white-space:pre-wrap;word-break:break-all;max-height:340px;overflow:auto;
  font-family:ui-monospace,Menlo,Consolas,monospace}
.flagline{margin-top:16px;border:1px solid #3c3c3c;padding:14px;font-size:13px;color:#fff;background:#101010}
.flagline code{color:#fff}
.parts{display:flex;gap:6px;margin-top:30px;flex-wrap:wrap;align-items:center}
.parts span{font-size:10.5px;letter-spacing:.1em;color:#8f8f8f}
.chip{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;border:1px solid #333;
  padding:4px 9px;color:#9d9d9d;background:#0a0a0a}
.chip.on{color:#fff;border-color:#666;background:#151515}
.note{color:#8d8d8d;font-size:11.5px;margin-top:12px}
.dim{color:#8d8d8d}
.leak{background:#070707;border:1px solid #222;padding:16px;font-size:12.5px;color:#a8a8a8;
  font-family:ui-monospace,Menlo,Consolas,monospace;white-space:pre-wrap;line-height:1.75}
ul.list{list-style:none;margin-top:10px}
ul.list li{padding:9px 0;border-bottom:1px solid #1e1e1e;font-size:13px;display:flex;gap:14px;justify-content:space-between}
ul.list li span.id{color:var(--dim);font-family:ui-monospace,Menlo,monospace;font-size:12px}

/* 提示页 */
.tipbar{margin-top:22px;display:flex;align-items:center;gap:14px;font-size:11px;letter-spacing:.14em;color:#8d8d8d}
.tipbar .btn{padding:7px 15px;font-size:11px;letter-spacing:.1em}
.tipimg{width:100%;max-width:320px;display:block;border:1px solid #2a2a2a;margin:12px 0 8px}
.tipcap{font-size:11px;color:#8d8d8d;letter-spacing:.05em;margin-bottom:6px}
.tipcard{margin-top:18px;border:1px solid var(--line);border-left:2px solid #3f3f3f;
  background:rgba(16,16,16,.92);padding:20px 22px;
  -webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px)}
.tipno{font-size:10.5px;letter-spacing:.18em;color:#9a9a9a;margin-bottom:12px}
.tipsay{color:#c9c9c9;font-size:14.5px;line-height:1.95}
.tipsay b{color:#fff;font-weight:600}
.tipsay i{color:#a8a8a8;font-style:normal;font-size:14.5px}

/* ============================================================================
   动效 / 交互规范落地（01-motion.md v? + 02-interaction.md v1.1）
   五条铁律：
   1) 基线永远是"内容可见"，所有 opacity:0 / transform 起始态只写在
      @media (prefers-reduced-motion:no-preference) 里；
   2) 绝不给 .panel / .joke / .tipcard / .stagebg / .wrap / body 加 transform——
      它们带 backdrop-filter，加 transform 会重建 backdrop root，磨砂当场失效；
   3) 颜色只允许出现在 transition，不允许出现在 @keyframes；
   4) 带 fill-mode:both 的动画，末帧必须是惰性终态（opacity:0 或元素本该有的静态终态），
      视觉正确性不能押在 animationend / classList 清理上（断点外不触发就会留下一层永久的白）；
   5) 任何"事件加上去、另一个事件摘掉"的状态，先问中间那条路径取消了会怎样：
      Esc 取消导航没有 pageshow、断点外没有 animationend。扛不住取消的状态就不要引入。
   ========================================================================== */

/* 2.5 一次性 token 块：后续效果只能引用 token，禁止裸数值 */
:root{
  --m-dur-1:90ms;--m-dur-2:160ms;--m-dur-3:240ms;--m-dur-4:380ms;--m-dur-5:520ms;--m-dur-6:700ms;
  --m-ease-out:cubic-bezier(.22,.61,.36,1);
  --m-ease-snap:cubic-bezier(.16,1,.3,1);
  --m-ease-glide:cubic-bezier(.19,1,.22,1);
  --m-ease-in:cubic-bezier(.55,.06,.68,.19);
  --m-ease-line:cubic-bezier(.4,0,.2,1);
  --m-ease-step:steps(5,end);
  --m-dx-1:2px;--m-dx-2:6px;--m-dx-3:12px;--m-dx-4:22px;--m-dx-5:40px;--m-dx-6:30px;
  --m-scale-in:.985;--m-scale-orb:.965;--m-scale-bg:1.045;
  --m-d-1:0ms;--m-d-2:90ms;--m-d-3:200ms;--m-d-4:300ms;--m-d-5:380ms;--m-d-6:560ms;
  --m-stagger:70ms;--m-line-stagger:22ms;
  --m-blur-1:8px;--m-blur-2:10px;
}
/* 过渡属性白名单（替换掉原先 .18s / .2s 的裸写法） */
.btn,nav a.link,a.card,.tipcard,.chip,ul.list li{
  transition:color var(--m-dur-2) var(--m-ease-line),
             background-color var(--m-dur-2) var(--m-ease-line),
             border-color var(--m-dur-2) var(--m-ease-line),
             box-shadow var(--m-dur-2) var(--m-ease-line),
             transform var(--m-dur-2) var(--m-ease-line);
}

/* 3. 入场基元：m-rise / m-light / m-fade / m-scan（keyframes 本身是惰性的） */
@keyframes m-rise-sm{from{opacity:0;transform:translate3d(0,var(--m-dx-2),0)}to{opacity:1;transform:translate3d(0,0,0)}}
@keyframes m-rise{from{opacity:0;transform:translate3d(0,var(--m-dx-3),0)}to{opacity:1;transform:translate3d(0,0,0)}}
@keyframes m-rise-lg{from{opacity:0;transform:translate3d(0,var(--m-dx-4),0)}to{opacity:1;transform:translate3d(0,0,0)}}
@keyframes m-rise-xl{from{opacity:0;transform:translate3d(0,var(--m-dx-6),0)}to{opacity:1;transform:translate3d(0,0,0)}}
@keyframes m-light{from{opacity:0;transform:scale(var(--m-scale-orb))}to{opacity:1;transform:scale(1)}}
@keyframes m-fade{from{opacity:0}to{opacity:1}}
/* m-scan（V1 最终版）：亮带放在渐变下缘 100%，行程 -100% -> 0 才覆盖整块；
   末帧 opacity:0 是惰性终态——视觉正确性不能押在 animationend 清理上 */
@keyframes m-scan{
  from{opacity:0;transform:translateY(-100%)}
  20%{opacity:1}
  80%{opacity:1}
  to{opacity:0;transform:translateY(0)}
}

/* 6.1 标题拆字：残 0ms / 業 70ms。
   整块 h1 无法只让第二个字晚 70ms，所以用两个 inline-block 子元素分两层；
   两条 span 之间不写空白，复制粘贴仍是"残業"；letter-spacing 从 h1 继承，字距不变 */
h1.big .ch{display:inline-block}
/* 5.2 主视觉：位移挂 .orb（JS 写 --m-oy），缩放挂 .orb img——
   对带 border-radius/overflow 的 .orb 本体做 scale 会让裁切与阴影逐帧重算 */
.orb{transform:translate3d(0,var(--m-oy,0px),0)}
/* 5.1 背景垫量与视差：先 scale(1.045) 再位移，位移上限 ±1.1%（JS 写 --m-py） */
.stagebg{transform:scale(var(--m-scale-bg)) translate3d(0,var(--m-py,0%),0);transform-origin:50% 30%}

/* 2. 首屏入场：纯 CSS，不依赖 JS。js 未执行也照常播，只是退化为静态终态 */
@media (prefers-reduced-motion:no-preference){
  .hero h1.big .ch{animation:m-rise-xl var(--m-dur-6) var(--m-ease-glide) both;will-change:opacity,transform}
  .hero h1.big .ch:first-child{animation-delay:var(--m-d-1)}
  .hero h1.big .ch:last-child{animation-delay:var(--m-d-2)}
  .hero .lead{animation:m-rise var(--m-dur-5) var(--m-ease-glide) var(--m-d-3) both}
  .hero .actions{animation:m-rise-sm var(--m-dur-5) var(--m-ease-glide) var(--m-d-4) both}
  .hero .orb{animation:m-fade var(--m-dur-6) var(--m-ease-out) var(--m-d-5) both;will-change:opacity}
  .hero .orb img{animation:m-light var(--m-dur-6) var(--m-ease-out) var(--m-d-5) both}
  .hero .scroll{animation:m-fade var(--m-dur-4) var(--m-ease-out) var(--m-d-6) both}
}

/* 内页首访入场：只在该路径第一次进入时播（JS 加 .enter-page），
   提交后整页重载不会重播；只碰头部三件，.panel 的磨砂不做 transform */
@media (prefers-reduced-motion:no-preference){
  html.enter-page .page > .kicker{animation:m-rise-sm var(--m-dur-4) var(--m-ease-glide) var(--m-d-1) both}
  html.enter-page .page > h2{animation:m-rise-xl var(--m-dur-6) var(--m-ease-glide) var(--m-d-2) both}
  html.enter-page .page > .say{animation:m-rise var(--m-dur-5) var(--m-ease-glide) var(--m-d-3) both}
}
/* 打印与"动画不跑"的环境兜底：入场动画一旦停摆，fill:both 会让元素停在 opacity:0 */
@media print{*{animation:none!important;transition:none!important}}

/* 8. 加班费到账：机械步进逐格亮起，和 chip 入账共用"继电器"语言 */
@keyframes m-chip-on{from{opacity:.28}to{opacity:1}}
@media (prefers-reduced-motion:no-preference){
  .parts .chip.on{animation:m-chip-on var(--m-dur-3) steps(3,end) both}
  .parts .chip.on:nth-of-type(3){animation-delay:calc(var(--m-stagger)*1)}
  .parts .chip.on:nth-of-type(4){animation-delay:calc(var(--m-stagger)*2)}
  .parts .chip.on:nth-of-type(5){animation-delay:calc(var(--m-stagger)*3)}
  .parts .chip.on:nth-of-type(6){animation-delay:calc(var(--m-stagger)*4)}
}
/* 9. 大图淡入：隐藏态只挂在 html.js 下，无 JS 时图片照常可见 */
html.js .lazy-img{opacity:0;transition:opacity var(--m-dur-6) var(--m-ease-out)}
html.js .lazy-img.is-loaded{opacity:1}
/* 10. 404：背景缓慢失焦，一次性，forwards 停住不再回焦 */
@keyframes m-defocus{
  from{filter:brightness(.96) saturate(.98) contrast(1.02) blur(0)}
  to{filter:brightness(.78) saturate(.6) contrast(1.02) blur(5px)}
}
@media (prefers-reduced-motion:no-preference){.stagebg.soft{animation:m-defocus 9s var(--m-ease-out) forwards}}
/* 3.4 / 6.1 首页不抑制内页入场，但历史回退必须零入场 */
html.no-enter .hero h1.big .ch,html.no-enter .hero .lead,html.no-enter .hero .actions,
html.no-enter .hero .scroll,html.no-enter .hero .orb,html.no-enter .hero .orb img{animation:none!important}
/* 只有历史回退才零入场；站内导航与刷新都播完整入场——
   之前"二次访问压到 240ms"正是"一刷新就太快"的元凶 */

/* 3. 滚动 reveal（JS 增强）：隐藏态只挂在 html.js 上，
   一行 classList.remove('js') 就能让全站退回静态可用态 */
.reveal{will-change:auto}
html.js .reveal{opacity:0;transform:translate3d(0,var(--m-dx-3),0)}
html.js .reveal.in{opacity:1;transform:none;
  transition:opacity var(--m-dur-4) var(--m-ease-out),transform var(--m-dur-4) var(--m-ease-out)}
html.js .reveal.in.instant{transition:none}

/* 4. 焦点可见性：焦点环必须瞬时，任何延迟都算无障碍缺陷 */
:focus-visible{outline:2px solid #e8e8e8;outline-offset:3px;transition:none;animation:none}
/* 输入类不做 :focus-visible 门控：焦点态本身就是任务状态（02 §5.1 / V3） */
input:focus,textarea:focus,select:focus{outline:2px solid #e8e8e8;outline-offset:1px;border-color:#6a6a6a}
nav a.link:focus-visible{outline-offset:4px}
a.card:focus-visible{outline-offset:-2px}
pre.out:focus-visible{outline:1px solid var(--dim);outline-offset:-2px}
main:focus{outline:none}

/* 5. skip link：全站唯一被键盘唤起时出现的"白块" */
.skip{position:fixed;left:-9999px;top:0;z-index:99;background:#fff;color:#101010;
  padding:10px 16px;font-size:12.5px;letter-spacing:.06em;border:1px solid #fff}
.skip:focus{left:0;top:0}

/* 7. .outlabel：取代"没有绑定控件的 label 元素"（非法用法）。
   颜色走 var(--dim)：灰阶已收敛成 3 档（原来最低的三档灰已全部并入 --dim），
   层级改由字号与字距承担 */
.outlabel{display:block;font-size:11px;letter-spacing:.12em;color:var(--dim);margin:18px 0 7px}

/* 8. 结果块扫光：::after 绝对定位 + pointer-events:none，只动 transform/opacity。
   亮带在渐变下缘（100%），行程 -100% -> 0 全程零正溢出，不闪滚动条也不动 scrollHeight（V1）。
   基线写 opacity:0，所以断点外 / 动画缺席时它只是一块看不见的伪元素，不靠清理事件收尾 */
pre.out{position:relative}
pre.out.fresh::after{content:"";position:absolute;inset:0;pointer-events:none;
  background:linear-gradient(180deg,
    rgba(255,255,255,0) 0%,
    rgba(255,255,255,.04) 55%,
    rgba(255,255,255,.14) 88%,
    rgba(255,255,255,.19) 100%);
  opacity:0}
@media (prefers-reduced-motion:no-preference) and (min-width:901px){
  pre.out.fresh::after{animation:m-scan var(--m-dur-5) var(--m-ease-step) both}
}

/* 9. 全站不存在"提交中 / 等待中"视觉。纯 CSS 无法"保持到跳转"，任何近似
   （拿语义属性当样式钩子、挂 .busy class、用 focus-within）都会在用户按 Esc
   取消或请求 500 后把按钮永久留在半透明态，看起来像禁用。
   浏览器自己的 tab spinner 已经在做等待信号，真正的"结果到了"信号是下一页 pre.out 的落定。
   只保留按压反馈 ↓ */

/* 10. 悬停态只给真指针设备；触屏用 :active 换同等强度的回执 */
@media (hover:hover) and (pointer:fine){
  nav a.link:hover{color:#fff}
nav a.link[aria-current]{color:#fff;position:relative}
nav a.link[aria-current]::after{content:"";position:absolute;left:0;right:0;bottom:-7px;height:1px;background:currentColor;opacity:.5}
  .btn.solid:hover{background:#e2e2e2}
  .btn.ghost:hover{border-color:#6a6a6a;color:#fff}
  a.card:hover{background:#111}
  .tipcard:hover{border-left-color:#6a6a6a}
  ul.list li:hover{background:#0f0f0f}
}
/* iOS 不对非链接/非按钮元素派发 :active，所以 .tipcard（一个 div）只能静态兜底，
   不做状态切换；a / button 的 :active 在 iOS 上正常 */
@media (hover:none){
  .btn.solid:active{background:#e2e2e2}
  .btn.ghost:active{border-color:#6a6a6a;color:#fff}
  a.card:active{background:#111}
  .tipcard{border-left-color:#5a5a5a}
}
/* 按压反馈：抬起即复位，终止由指针物理状态保证，不依赖任何清理事件 */
.btn.solid:active{transform:translateY(1px)}
.btn:active{opacity:.55;transition-duration:var(--m-dur-1)}

/* 8.4 移动端：拆字分层与延迟阶梯关掉（时长不变） */
@media (max-width:900px){
  .hero h1.big .ch{animation-delay:0ms!important}
  .hero .lead{animation-delay:var(--m-d-1)!important}
  .hero .actions{animation-delay:var(--m-d-2)!important}
  .hero .orb,.hero .orb img,.hero .scroll{animation-delay:var(--m-d-3)!important}
}

/* 11. 降级：结构性门控（上面所有 no-preference）+ 一条安全网，两套都要有。
   注意 animation-duration:.001ms 对 animation-timeline 无效，所以视差靠 JS 门控而不是靠这里 */
@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{
    animation-duration:.001ms!important;animation-delay:0ms!important;
    animation-iteration-count:1!important;
    transition-duration:.001ms!important;transition-delay:0ms!important;
    scroll-behavior:auto!important;
  }
  .flagline{border-color:#fff}
}
`;

/* 页面背景图：按 layout 的标题取 [文件名, 焦点, 亮度] */
const PAGE_BG = {
  '打卡': ['stage1.jpg', '50% 46%', 1],
  '工资单': ['stage2.jpg', '50% 26%', 1],
  '头像上传': ['stage3.jpg', '58% 40%', 1],
  '链接预览': ['stage4.jpg', '50% 30%', 1],
  '日志检索': ['stage5b.jpg', '50% 28%', 1.02, .96],
  '关于本喵': ['about.jpg', '50% 34%', .96],
  '结局': ['endbg.jpg', '50% 44%', .98],
  '404': ['404.jpg', '46% 30%', .96, .98],
};

/* 每关右下角的“去问社长”入口 */
const tipLink = (n) => `
  <div class="tipbar">
    <span>卡住了喵</span>
    <a class="btn ghost" href="/tips?n=${n}">去问社长</a>
  </div>`;

function layout(title, body, s, bg) {
  const parts = [1, 2, 3, 4, 5].map((i) =>
    `<span class="chip ${s && s.parts.has(i) ? 'on' : ''}">${s && s.parts.has(i) ? '加班' + i : '？'}</span>`
  ).join('');
  const pick = PAGE_BG[title];
  const bgFile = bg || (pick ? pick[0] : '');
  const bgPos = pick ? pick[1] : '50% 30%';
  const bgLum = pick && pick[2] ? pick[2] : .55;
  const bgSat = pick && pick[3] ? pick[3] : 1.04;
  const backdrop = bgFile
    ? `<div class="stagebg${title === '404' ? ' soft' : ''}" style="background-image:url('/assets/${bgFile}');background-position:${bgPos};filter:brightness(${bgLum}) saturate(${bgSat}) contrast(1.02)"></div><div class="veil"></div>`
    : '';
  const cur = { '首页': '/', '关于本喵': '/about', '打卡': '/lobby', '工资单': '/lobby', '头像上传': '/lobby', '链接预览': '/lobby', '日志检索': '/lobby', '结局': '/end' }[title] || '';
  const navLink = (t, h) => `<a class="link" href="${h}"${cur === h ? ' aria-current="page"' : ''}>${t}</a>`;
  return `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · 残業</title>
<style>${CSS}</style>
<script>(function(){var d=document.documentElement,R=!1,x,seen=!1,i;
try{R=matchMedia('(prefers-reduced-motion: reduce)').matches}catch(e){}
try{x=performance.getEntriesByType('navigation')[0]}catch(e){}
var back=!!x&&x.type==='back_forward';
if(back)d.classList.add('no-enter');else{
try{seen=!!sessionStorage.getItem('seen')}catch(e){}
if(seen)d.classList.add('short-enter');else{try{sessionStorage.setItem('seen','1')}catch(e){}}}
var p='p:'+location.pathname,fe=0;
if(!back){try{fe=!sessionStorage.getItem(p);if(fe)sessionStorage.setItem(p,1)}catch(e){}}
if(fe&&location.pathname!=='/')d.classList.add('enter-page');
var IO=!!window.IntersectionObserver&&!R;
if(IO)d.classList.add('js');
function init(){try{
if(IO){
var SK='.panel,.joke,.tipcard,.stagebg,.veil,.wrap,ul.list';
var els=[].filter.call(document.querySelectorAll('.page > *,.cards > *,.article > p,.panel > *,.list li'),function(el){return !el.matches(SK)});
var io=new IntersectionObserver(function(es){for(var j=0;j<es.length;j++){if(es[j].isIntersecting){es[j].target.classList.add('in');io.unobserve(es[j].target)}}},{rootMargin:'0px 0px 120px 0px',threshold:0});
var vh=innerHeight;
for(i=0;i<els.length;i++){if(els[i].getBoundingClientRect().top<vh+120)els[i].classList.add('reveal','in','instant');else{els[i].classList.add('reveal');io.observe(els[i])}}
setTimeout(function(){for(var j=0;j<els.length;j++){if(!els[j].classList.contains('in'))els[j].classList.add('in','instant')}},2000)}
var res=document.querySelector('.flagline')||[].slice.call(document.querySelectorAll('pre.out')).pop();
if(res&&!back){res.classList.add('in','instant');res.classList.add('fresh');
res.addEventListener('animationend',function h(e){if(e.target!==res)return;res.classList.remove('fresh');res.removeEventListener('animationend',h)});
var r=res.getBoundingClientRect();
if(r.top>=innerHeight||r.bottom<=0)res.scrollIntoView({block:'nearest',behavior:'auto'});
try{res.focus({preventScroll:!0})}catch(e){}}
var bg=document.querySelector('.stagebg'),orb=document.querySelector('.orb');
if(!R&&innerWidth>900&&(bg||orb)){
var t=0,tick=function(){t=0;var p=Math.min((pageYOffset||0)/(innerHeight||1),1);
if(bg)bg.style.setProperty('--m-py',(-1.1+2.2*p).toFixed(2)+'%');
if(orb)orb.style.setProperty('--m-oy',(-40*p).toFixed(1)+'px')};
addEventListener('scroll',function(){if(!t)t=requestAnimationFrame(tick)},{passive:!0});tick()}
var li=document.querySelectorAll('img.lazy-img');
for(var k=0;k<li.length;k++){(function(im){
if(im.complete&&im.naturalWidth){im.classList.add('is-loaded')}else{
im.addEventListener('load',function(){im.classList.add('is-loaded')},{once:!0});
im.addEventListener('error',function(){im.classList.add('is-loaded')},{once:!0})}})(li[k])}
var b=document.querySelector('nav .brand');
if(b){var nc=0,nt=0;b.onclick=function(){var w=Date.now();if(w-nt>1600)nc=0;nt=w;
if(++nc<5)return;nc=0;var s=b.querySelector('#egg');
if(!s){s=document.createElement('span');s.id='egg';s.textContent='…别点了喵';
s.style.cssText='font:11px/1.6 inherit;color:#8d8d8d;margin-left:8px;opacity:0;transition:opacity .24s';
b.appendChild(s);requestAnimationFrame(function(){s.style.opacity=1})}
s.style.opacity=1;clearTimeout(b._t);b._t=setTimeout(function(){s.style.opacity=0},2200)}}
}catch(e){d.classList.remove('js')}}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',init);else init();
addEventListener('pageshow',function(e){try{
if(e.persisted){d.classList.add('no-enter');
var a=document.getAnimations?document.getAnimations():[];
for(var j=0;j<a.length;j++){try{a[j].finish()}catch(_){}}}
}catch(_){}});
})();</script></head><body>
<a class="skip" href="#main">跳到主内容</a>
${backdrop}
<div class="wrap">
<nav>
  <div class="brand">残業</div>
  ${navLink('首页', '/')}
  ${navLink('关于本喵', '/about')}
  ${navLink('打卡', '/lobby')}
  ${navLink('结局', '/end')}
  <div class="right">
    <a class="btn ghost" href="/lobby">登录</a>
    <a class="btn solid" href="/lobby">开始受苦</a>
  </div>
</nav>
<main id="main" tabindex="-1">
${body}
</main>
<footer><span>© 残業 / NOMAD</span><span>本喵什么都没做错喵</span></footer>
</div></body></html>`;
}

const partsStrip = (s) => {
  const chips = [1, 2, 3, 4, 5].map((i) =>
    `<span class="chip ${s.parts.has(i) ? 'on' : ''}">${s.parts.has(i) ? '加班费 ' + i + ' 到手' : '加班费 ' + i + ' 没着落'}</span>`
  ).join('');
  return `<div class="parts"><span>本喵的加班费</span>${chips}</div>`;
};

/* ---------------- 首页 ---------------- */
function pageHome(s) {
  return layout('首页', `
<div class="hero">
  <div>
    <h1 class="big"><span class="ch">残</span><span class="ch">業</span></h1>
    <p class="lead">
      一个关于打卡、报销、还有一点点无法解释的恶意的故事喵<br>
      你只要顺着走就行，别问为什么喵，<em>反正问了也没有答案喵</em>
    </p>
    <div class="actions">
      <a class="btn solid" href="/lobby">开始受苦</a>
      <a class="plain" href="/about"><span class="dot">▶</span>先看看说明</a>
    </div>
    <div class="scroll">↓ 往下拉喵</div>
  </div>
  <div class="orb"><img src="/assets/hero.jpg" alt=""></div>
</div>
<div class="cards">
  <div class="card"><div class="tag">最新</div><div class="t">第 5 次加班申请已提交喵</div>
    <div class="s">状态：审批中（审批人是本喵）</div></div>
  <a class="card" href="/column"><div class="tag">专栏</div><div class="t">为什么大家都觉得是本喵的错喵</div>
    <div class="s">阅读 0 · 没有人关心喵 →</div></a>
  <div class="card"><div class="tag">新功能</div><div class="t">全新的自我检讨模板 上架喵</div>
    <div class="s">写了三行，第四行写不下去了喵</div></div>
</div>`, s);
}

/* ---------------- 专栏：为什么大家都觉得是本喵的错喵 ---------------- */
function pageColumn(s) {
  return layout('专栏', `
<div class="page">
  <div class="kicker">专栏 · 第 0 篇</div>
  <h2>为什么大家都觉得是本喵的错喵</h2>
  <div class="article">
    <img class="lazy-img" src="/assets/column.png" alt="" loading="lazy" decoding="async">
    <p>今天又被社长吊了喵</p>
    <p>他说本喵的周报写得像遗书，本喵说那正好，省一份喵</p>
    <p>回来的路上本喵才想起来，今天只有一份饭钱喵</p>
    <p>结果「不小心」，全买了美味烟烟喵</p>
    <p>就是很便宜的那种，抽起来像在烧塑料袋喵</p>
    <p>……连💩都要跟我抢喵</p>
    <p>本喵明明什么都没有做错</p>
    <div class="jp">何もない、何もない、もう終わりだ、終わりだ、笑ったら殺すからね</div>
  </div>
</div>`, s);
}

/* ---------------- 关于 / 检讨书 ---------------- */
function pageAbout(s) {
  return layout('关于本喵', `
<div class="page">
  <div class="kicker">关于本喵</div>
  <h2>检讨书</h2>
  <div class="panel">
    <div class="say">
      第一，本喵不该在上班时间睡觉喵<br>
      第二，本喵不该把咖啡打翻在课长的西装上喵 —— 虽然那件西装本来就很难看喵<br>
      第三，本喵不该把第三条也写进检讨书喵<br><br>
      以上，本喵已经深刻反省了喵<br>
      <span class="dim">（并没有）</span>
    </div>
  </div>
  <div class="say" style="margin-top:26px">
    <b>玩法</b>　五个洞，一条链喵，每一个洞给你一笔加班费喵，
    五笔凑齐才是完整的 flag 喵<br>
    本喵不会拦你喵，本喵也拦不住喵，本喵只是个打工的喵
  </div>
  ${partsStrip(s)}
</div>`, s);
}

/* ---------------- 第 1 关：打卡系统（信息泄露） ---------------- */
function pageLobby(s, msg) {
  return layout('打卡', `
<div class="page">
  <div class="kicker">STAGE 01 · 打卡机</div>
  <h2>迟到的人请举手</h2>
  <div class="say">
    打卡机又坏了喵，修不修都一样，反正工资照扣喵<br>
    你要是想进来，就自己找门喵，门这种东西，本喵从来不锁喵
  </div>
  <div class="panel">
    <form method="post" action="/login">
      <div class="row">
        <div><label for="f-u">工号</label><input id="f-u" type="text" name="u" autocomplete="username" placeholder="nomad"></div>
        <div><label for="f-p">密码</label><input id="f-p" type="password" name="p" autocomplete="current-password" placeholder="********"></div>
        <div style="flex:0 0 auto"><button class="btn solid" type="submit">打卡</button></div>
      </div>
    </form>
    ${msg ? `<div class="outlabel" id="out-lbl-lobby">打卡结果</div><pre class="out" tabindex="0" aria-labelledby="out-lbl-lobby">${esc(msg)}</pre>` : ''}
    <div class="note">提示：机器不会告诉你密码喵，但机器也不懂得藏东西喵</div>
  </div>
  ${tipLink(1)}
  ${partsStrip(s)}
</div>`, s);
}

/* ---------------- 第 2 关：工资单（IDOR） ---------------- */
function pagePayslip(s, out) {
  return layout('工资单', `
<div class="page">
  <div class="kicker">STAGE 02 · 人事</div>
  <h2>本月工资单</h2>
  <div class="say">
    工资单上写着 21 万日元，实际到账 8 万喵，差额去哪了<br>
    本喵也不知道喵，本喵只是个打工的喵
  </div>
  <div class="panel">
    <form method="get" action="/s2">
      <div class="row">
        <div><label for="f-id">查询工号（id）</label><input id="f-id" type="text" name="id" inputmode="numeric" value="1042"></div>
        <div style="flex:0 0 auto"><button class="btn ghost" type="submit">查询</button></div>
      </div>
    </form>
    ${out ? `<div class="outlabel" id="out-lbl-s2">工资单查询结果</div><pre class="out" tabindex="0" aria-labelledby="out-lbl-s2">${esc(out)}</pre>` : ''}
    <div class="note">接口是 GET 的喵，本喵懒得改喵</div>
  </div>
  ${tipLink(2)}
  ${partsStrip(s)}
</div>`, s);
}

/* ---------------- 第 3 关：上传（绕过） ---------------- */
function pageUpload(s, out, list) {
  const files = (list || []).length
    ? `<ul class="list">${list.map((f) =>
        `<li><span>${esc(f)}</span><span class="id"><a href="/s3/file?name=${encodeURIComponent(f)}">查看</a></span></li>`).join('')}</ul>`
    : `<div class="note">还没有上传过任何东西喵</div>`;
  return layout('头像上传', `
<div class="page">
  <div class="kicker">STAGE 03 · HR</div>
  <h2>换一张头像吧</h2>
  <div class="say">
    HR 说头像要上传，还要审核喵<br>
    审核标准是本喵定的喵，所以应该很好过喵，本喵只挡 php 喵
  </div>
  <div class="panel">
    <form method="post" action="/s3/upload">
      <div class="row">
        <div><label for="f-name">文件名</label><input id="f-name" type="text" name="name" placeholder="avatar.txt"></div>
      </div>
      <label for="f-content">内容</label>
      <textarea id="f-content" name="content" placeholder="本喵的头像喵"></textarea>
      <div style="margin-top:16px"><button class="btn solid" type="submit">上传</button></div>
    </form>
    ${out ? `<div class="outlabel" id="out-lbl-s3">上传结果</div><pre class="out" tabindex="0" aria-labelledby="out-lbl-s3">${esc(out)}</pre>` : ''}
    <div class="outlabel">已上传</div>
    ${files}
  </div>
  ${tipLink(3)}
  ${partsStrip(s)}
</div>`, s);
}

/* ---------------- 第 4 关：链接预览（SSRF） ---------------- */
function pagePreview(s, out, url) {
  return layout('链接预览', `
<div class="page">
  <div class="kicker">STAGE 04 · 内网</div>
  <h2>链接预览</h2>
  <div class="say">
    这个功能是给课长看的喵，课长说要看内部系统，本喵就做了个预览喵<br>
    为什么要把这种事交给本喵喵……
  </div>
  <div class="panel">
    <form method="get" action="/s4">
      <div class="row">
        <div><label for="f-url">要预览的地址</label><input id="f-url" type="text" name="url" inputmode="url" value="${esc(url || '')}" placeholder="http://127.0.0.1:${INNER_ACTIVE}/intranet/"></div>
        <div style="flex:0 0 auto"><button class="btn ghost" type="submit">预览</button></div>
      </div>
    </form>
    ${out ? `<div class="outlabel" id="out-lbl-s4">预览结果</div><pre class="out" tabindex="0" aria-labelledby="out-lbl-s4">${esc(out)}</pre>` : ''}
    <div class="note">本喵有黑名单的喵，很严格的喵</div>
  </div>
  ${tipLink(4)}
  ${partsStrip(s)}
</div>`, s);
}

/* ---------------- 第 5 关：日志检索（命令注入） ---------------- */
function pageConsole(s, cmd, out, q) {
  /* 结果块模板：label 用 .outlabel（不是 <label>——它没有绑定控件），
     pre 带 tabindex=0（可被程序化聚焦 + 键盘滚动），可访问名来自前面那行小标签 */
  const block = (id, label, text) =>
    `<div class="outlabel" id="${id}">${label}</div><pre class="out" tabindex="0" aria-labelledby="${id}">${esc(text)}</pre>`;
  /* 只要本次真的执行过一次检索（cmd 非空）就必须渲染输出块：
     原先 `${out ? ... : ''}` 把空字符串当 falsy，整块不渲染，
     玩家看到命令、看不到输出，分不清"没有输出"还是"页面没刷新" */
  const ran = !!cmd;
  return layout('日志检索', `
<div class="page">
  <div class="kicker">STAGE 05 · 运维</div>
  <h2>日志检索</h2>
  <div class="say">
    日志里全是本喵的名字喵，明明什么都没做错喵<br>为什么要这样对我，本喵明明什么都没做错喵
  </div>
  <div class="joke">
    问：flag 为什么从来不下棋<br>
    答：它自己就是<b>旗手</b>，被人举着的那种，动不了<br>
    好冷喵
  </div>
  <div class="panel">
    <form method="get" action="/s5">
      <div class="row">
        <div><label for="f-q">在日志里搜什么</label><input id="f-q" type="text" name="q" value="${esc(q || '')}" placeholder="nomad"></div>
        <div style="flex:0 0 auto"><button class="btn solid" type="submit">检索</button></div>
      </div>
    </form>
    ${ran ? block('out-lbl-cmd', '实际执行的命令', cmd) : ''}
    ${(ran || out) ? block('out-lbl-out', '输出', out || '（没有输出喵）') : ''}
    <div class="note">中间件是课长写的喵，本喵不敢改喵</div>
  </div>
  ${tipLink(5)}
  ${partsStrip(s)}
</div>`, s);
}

/* ---------------- 提示页（社长的办公室，一次只讲一条） ---------------- */
const STAGE_ROUTE = ['', '/lobby', '/s2', '/s3', '/s4', '/s5'];
const TIPS = [
  [1, '打卡机', `哼 来了啊……才没等你<br>
    机器进门前要看张<b>告示</b> 就是给爬虫看的那种 叫 robots<br>
    上面写着禁止入内 禁止入内就是里面有宝物 神域常识<br>
    <i>别问在哪 吾也不知道</i>`],
  [2, '工资单', `工资单？吾也想查……不是 吾是说你堕落<br>
    只看自己那栏 傻 全局懂不懂 别人呢<br>
    别提权限 权限骗笨蛋的 你就是<br>
    <i>你 1042 那 <b>1 号</b>是谁 吾知道 但天机……好吧忘了 编号连着的 自己数</i>`],
  [3, '头像上传', `HR 又让你干杂活 吾回头扣她分<br>
    秘密 他们只挡<b>小写</b>的 php<br>
    你懂吧……吾意思是你笨<br>
    <i>传完点那个<b>查看</b> 神迹显灵才算 塞抽屉的叫库存</i>`],
  [4, '链接预览', `进不去？心不诚<br>
    门<b>名字不止一种</b>写法 你写全名 它当然不放你进 当然不放你进<br>
    换个名字叫它 把中间那截省掉试试 吾随口举例 不是教你<br>
    <i>规矩吾写的 只写了最常见的两个 剩下自己悟 吾渴了</i>`],
  [5, '日志检索', `最后这个 吾觉得你不行 但还是说<br>
    搜索框写的东西 会被塞进一条<b>命令</b>里 粗鲁 但好用<br>
    多写一句 它照念 先把<b>引号</b>关上 写你要的 再打开一个<br>
    <i>……说太细了 反正你听不懂</i>`],
];

function pageTips(s, n) {
  const [no, name, text] = TIPS[n - 1];
  return layout('提示', `
<div class="page">
  <div class="kicker">社长的办公室 · 非请勿入</div>
  <div class="say" style="margin-top:14px">
    “听好了，尼古喵喵，你现在明显处于脑子被吃掉了状态，提示呢应该适度且健康的享受。”
  </div>
  <img class="tipimg" src="/assets/tips.jpg" alt="">
  <div class="tipcap">社长把最后一颗糖塞进嘴里，往后一靠 —— 她觉得自己这个比喻很妙，其实并没有。</div>
  <div class="tipcard">
    <div class="tipno">STAGE 0${no} · ${name}${s.parts.has(no) ? ' · 已过' : ''}</div>
    <div class="tipsay">${text}</div>
  </div>
  <div class="say" style="margin-top:28px">
    吾一次只讲一条 还卡着就回去再看一遍 比坐这儿有用<br>
    做完了也别来 吾不想看见你这张脸
  </div>
  ${partsStrip(s)}
  <div class="tipbar"><a class="btn ghost" href="${STAGE_ROUTE[no]}">回 STAGE 0${no}</a></div>
</div>`, s);
}

/* ---------------- 结局 ---------------- */
function pageEnd(s) {
  const all = [1, 2, 3, 4, 5].every((i) => s.parts.has(i));
  if (!all) {
    return layout('结局', `
<div class="page">
  <div class="kicker">ENDING</div>
  <h2>还没到呢</h2>
  <div class="say">五笔加班费还差一点喵，本喵在门口等你，反正本喵也没别的地方去喵</div>
  ${partsStrip(s)}
</div>`, s);
  }
  return layout('结局', `
<div class="page">
  <div class="kicker">ENDING</div>
  <h2>月亮很圆喵</h2>
  <div class="panel">
    <div class="outlabel" id="out-lbl-flag">完整 flag</div>
    <div class="flagline" tabindex="0" aria-labelledby="out-lbl-flag">五笔都齐了喵：<br><br><code>${esc(FLAG)}</code></div>
  </div>
  <div class="ending">
    <img class="lazy-img" src="/assets/ending.png" alt="" loading="lazy" decoding="async">
    <div class="say" style="margin:0">
      深夜真安静，月亮也很圆喵<br>
      啊，就剩最后一根了，本喵发誓以后再也不抽了（嘛，怎么可能）<br>
      明天，嘿嘿，让明天的我戒，关我什么事<br>
      尼古万岁喵...咳咳
    </div>
  </div>
  ${partsStrip(s)}
</div>`, s);
}

/* ---------------- 第 1 关的材料 ---------------- */
const ROBOTS = 'User-agent: *\nDisallow: /backroom/\nDisallow: /hr/\n# 本喵写的，别乱看喵\n';
const NOTICE = [
  '=== 打卡系统 临时用工 交接便签 ===',
  '临时工号：nomad',
  '临时密码：neko2024',
  '',
  '-- 备注 --',
  '本喵知道这个文件不该放这儿喵',
  '但本喵忘了挪喵，反正也没人会看喵',
].join('\n');

/* ---------------- 工资单数据 ---------------- */
const PAYSLIPS = {
  1042: { id: 1042, name: 'NOMAD（本喵）', base: '210,000', paid: '80,000', note: '差额：公司规定喵' },
  1: {
    id: 1, name: '課長・田中', base: '980,000', paid: '980,000',
    note: '本喵的工资里扣掉的那 13 万，记在课长的「特别津贴」里喵，' +
      '随信附上第 2 笔加班费，课长说存这儿最安全喵：' + PARTS[1],
  },
  1017: { id: 1017, name: '同期的猫（已离职）', base: '205,000', paid: '0', note: '上个月就不来了喵' },
};

/* ---------------- 内网服务（只对本机开放） ---------------- */
/** 实际生效的内网端口：默认 9999，被占用时顺延，题面占位符跟着变 */
let INNER_ACTIVE = INNER_PORT;
function startInner(tryPort = INNER_PORT, hops = 0) {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://127.0.0.1');
    if (u.pathname === '/intranet/' || u.pathname === '/intranet') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end('<h1>社内システム</h1><p>課長専用ページ</p><ul><li><a href="/intranet/vault">金庫</a></li></ul>');
    }
    if (u.pathname === '/intranet/vault') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify({
        owner: '課長・田中',
        memo: '本喵把第 4 笔加班费放内网了喵，外面的人看不到喵，很安全喵',
        part4: PARTS[3],
      }, null, 2));
    }
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('not found');
  });
  srv.listen(tryPort, '127.0.0.1', () => {
    INNER_ACTIVE = tryPort;
    console.log(`inner intranet on 127.0.0.1:${tryPort}`);
  }).on('error', (e) => {
    // 端口被占：顺延一个再试，最多试 9 次，避免整关断链
    if (e.code === 'EADDRINUSE' && hops < 9) {
      console.log(`inner intranet ${tryPort} 被占用，试 ${tryPort + 1}`);
      return startInner(tryPort + 1, hops + 1);
    }
    console.log(`inner intranet 没起来（${e.code}），第 4 关的 SSRF 会拿不到内网内容`);
  });
}

/* ---------------- 假 shell（日志检索的后端） ---------------- */
const VFS = {
  '/var/log/nomad/app.log': [
    '2026-11-18 09:01:12 INFO  打卡 nomad 迟到 4 分钟',
    '2026-11-18 09:02:03 WARN  nomad 在工位睡着了',
    '2026-11-18 09:14:51 ERROR 咖啡泼在课长西装上',
    '2026-11-18 10:00:00 INFO  检讨书已提交（内容为空）',
    '2026-11-18 10:00:01 INFO  以上，本喵已经深刻反省了喵',
  ].join('\n'),
  '/var/log/nomad/audit.log': 'audit: 无人访问 (本喵没有权限查看喵)',
  '/etc/motd': '本喵在加班喵',
  '/flag': PARTS[4],
};

function fakeShell(cmd) {
  const segs = cmd.split(/;|&&|\|\|/).map((x) => x.trim()).filter(Boolean);
  const outs = [];
  for (const seg of segs) {
    const argv = seg.split(/\s+/).filter(Boolean);
    if (!argv.length) continue;
    const c = argv[0];
    if (c === 'cat') {
      const p = argv[1] || '';
      outs.push(VFS[p] !== undefined ? VFS[p] : `cat: ${p}: No such file or directory`);
    } else if (c === 'ls') {
      const p = argv[1] || '/var/log/nomad';
      const names = Object.keys(VFS).filter((k) => k.startsWith(p));
      outs.push(names.length ? names.join('\n') : `ls: ${p}: No such file or directory`);
    } else if (c === 'grep') {
      const pat = (argv[argv.length - 1] || '').replace(/^["']|["']$/g, '');
      const hits = VFS['/var/log/nomad/app.log'].split('\n').filter((l) => l.includes(pat));
      outs.push(hits.length ? hits.join('\n') : `grep: ${pat}: 没有匹配喵`);
    } else if (c === 'echo') {
      outs.push(argv.slice(1).join(' '));
    } else if (c === 'whoami' || c === 'id') {
      outs.push('nomad');
    } else if (c === 'pwd') {
      outs.push('/var/log/nomad');
    } else {
      outs.push(`sh: ${c}: command not found 喵`);
    }
  }
  return outs.join('\n');
}

/* ---------------- 路由 ---------------- */
async function handle(req, res) {
  const s = getSession(req, res);
  const url = parseUrl(req.url);
  const p = url.pathname;

  // 静态
  if (p.startsWith('/assets/')) {
    const f = path.join(PUBLIC, 'assets', path.basename(p));
    if (fs.existsSync(f)) {
      const ext = path.extname(f).toLowerCase();
      const type = ext === '.jpg' || ext === '.jpeg' ? 'image/jpeg'
        : ext === '.png' ? 'image/png' : ext === '.svg' ? 'image/svg+xml' : 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'public, max-age=86400' });
      return res.end(fs.readFileSync(f));
    }
    return send(res, 'not found', 404, 'text/plain; charset=utf-8');
  }

  if (p === '/') return send(res, pageHome(s));
  if (p === '/about') return send(res, pageAbout(s));
  if (p === '/tips') {
    const want = parseInt(url.searchParams.get('n') || '', 10);
    const n = want >= 1 && want <= 5
      ? want
      : ([1, 2, 3, 4, 5].find((i) => !s.parts.has(i)) || 5);
    return send(res, pageTips(s, n));
  }
  if (p === '/column') return send(res, pageColumn(s));
  if (p === '/lobby') return send(res, pageLobby(s, url.searchParams.get('msg') || ''));

  if (p === '/version') return send(res, JSON.stringify({
    build: process.env.BUILD_ID || '2026-11-22',
    rev: '7903191',
    uptime: Math.round(process.uptime()),
    node: process.version,
  }, null, 2), 200, 'application/json; charset=utf-8');
  if (p === '/robots.txt') return send(res, ROBOTS, 200, 'text/plain; charset=utf-8');
  if (p === '/backroom/notice.txt') return send(res, NOTICE, 200, 'text/plain; charset=utf-8');

  // robots 里列出的两个目录：目录确实存在（403 而不是 404），但都不给列索引
  if (p === '/backroom/' || p === '/backroom') {
    return send(res, layout('403', `<div class="page">
  <div class="kicker">403</div>
  <h2>目录不给列喵</h2>
  <div class="say">这个目录是有的喵，但本喵没开索引喵<br>
  本喵给文件起的名字都很直白喵，你猜得到的喵</div>
</div>`, s), 403);
  }
  if (p === '/hr/' || p === '/hr') {
    return send(res, layout('403', `<div class="page">
  <div class="kicker">403</div>
  <h2>HR 的目录喵</h2>
  <div class="say">早就搬空了喵，别在这儿耗着喵</div>
</div>`, s), 403);
  }

  // 登录
  if (p === '/login' && req.method === 'POST') {
    const b = await readBody(req);
    if (b.u === 'nomad' && b.p === 'neko2024') {
      s.user = 'nomad';
      grant(s, 1);
      res.writeHead(302, { Location: '/s2' });
      return res.end();
    }
    res.writeHead(302, { Location: '/lobby?msg=' + encodeURIComponent('工号或密码不对喵，再猜喵') });
    return res.end();
  }

  // 第 2 关
  if (p === '/s2') {
    if (!s.user) { res.writeHead(302, { Location: '/lobby' }); return res.end(); }
    const id = url.searchParams.get('id');
    let out = '';
    if (id !== null) {
      const rec = PAYSLIPS[id];
      if (rec) {
        out = JSON.stringify(rec, null, 2);
        if (Number(id) === 1 && rec.note.indexOf(PARTS[1]) !== -1) grant(s, 2);
      } else {
        out = JSON.stringify({ error: '没有这个工号喵' }, null, 2);
      }
    }
    return send(res, pagePayslip(s, out));
  }
  if (p === '/api/payslip') {
    const id = url.searchParams.get('id') || '';
    const rec = PAYSLIPS[id];
    if (rec && Number(id) === 1) grant(s, 2);
    return send(res, JSON.stringify(rec || { error: '没有这个工号喵' }, null, 2), rec ? 200 : 404,
      'application/json; charset=utf-8');
  }

  // 第 3 关
  if (p === '/s3') {
    if (!s.parts.has(2)) {
      return send(res, pageUpload(s, 'HR 的门还锁着喵（先把上一关的东西拿到手喵）', []));
    }
    return send(res, pageUpload(s, '', s.files.map((f) => f.name)));
  }
  if (p === '/s3/upload' && req.method === 'POST') {
    const b = await readBody(req);
    const name = String(b.name || '').trim();
    const content = String(b.content || '');
    if (!name) return send(res, pageUpload(s, '文件名呢喵', s.files.map((f) => f.name)));
    if (name.length > 64) {
      return send(res, pageUpload(s, '文件名太长了喵，64 字以内喵', s.files.map((f) => f.name)));
    }
    // 只挡小写 .php —— 单次判断，大小写能绕
    if (name.endsWith('.php')) {
      return send(res, pageUpload(s, '这个不行喵，本喵是懂安全的喵', s.files.map((f) => f.name)));
    }
    s.files.push({ name, content: content.slice(0, 4000) });
    const warn = content.length > FILE_KEEP ? `（内容超过 ${FILE_KEEP} 字，本喵只往回记了前 ${FILE_KEEP} 字喵）` : '';
    return send(res, pageUpload(s, `已上传：${name}${warn}`, s.files.map((f) => f.name)));
  }
  if (p === '/s3/file') {
    const name = url.searchParams.get('name') || '';
    const f = s.files.find((x) => x.name === name);
    if (!f) return send(res, 'file not found 喵', 404, 'text/plain; charset=utf-8');
    let body = f.content;
    // 渲染器：文件名匹配 .php（大小写不敏感）就当成模板执行
    if (/\.php$/i.test(f.name)) {
      body = body.replace(/\{\{\s*vault\s*\}\}/gi, PARTS[2]);
      if (body.indexOf(PARTS[2]) === -1) {
        body = `[模板已执行，但内容里没有 {{vault}} 喵]\n\n${body}`;
      }
      grant(s, 3);
      return send(res, `<html><body style="background:#0d0d0d;color:#ddd;font-family:monospace;padding:40px;white-space:pre-wrap">${esc(body)}</body></html>`);
    }
    return send(res, body, 200, 'text/plain; charset=utf-8');
  }

  // 第 4 关
  if (p === '/s4') {
    if (!s.parts.has(3)) return send(res, pagePreview(s, '这一层的门锁着喵（先拿到第 3 笔喵）', ''));
    const target = url.searchParams.get('url');
    if (!target) return send(res, pagePreview(s, '', ''));
    // 童叟无欺的黑名单
    if (/127\.0\.0\.1|localhost/i.test(target)) {
      return send(res, pagePreview(s, '内网地址不给看喵（本喵很严格的喵）', target));
    }
    const out = await new Promise((resolve) => {
      let u;
      try { u = new URL(target); } catch (_) { return resolve('这个地址本喵看不懂喵'); }
      if (u.protocol !== 'http:') return resolve('只支持 http 喵');
      const r = http.get({ hostname: u.hostname, port: u.port || 80, path: u.pathname + u.search, timeout: 2500 },
        (rr) => {
          let d = '';
          rr.on('data', (c) => { d += c; if (d.length > 20000) rr.destroy(); });
          rr.on('end', () => resolve(`HTTP ${rr.statusCode}\n\n${d.slice(0, 2000)}`));
        });
      r.on('timeout', () => { r.destroy(); resolve('超时了喵'); });
      r.on('error', (e) => resolve(`连不上喵：${e.message}`));
    });
    if (out.indexOf(PARTS[3]) !== -1) grant(s, 4);
    return send(res, pagePreview(s, out, target));
  }

  // 第 5 关
  if (p === '/s5') {
    if (!s.parts.has(4)) return send(res, pageConsole(s, '', '这一层的门锁着喵（先拿到第 4 笔喵）', ''));
    const q = url.searchParams.get('q');
    if (q === null) return send(res, pageConsole(s, '', '', ''));
    const cmd = `grep -i "${q}" /var/log/nomad/`;
    const out = fakeShell(cmd);
    if (out.indexOf(PARTS[4]) !== -1) grant(s, 5);
    return send(res, pageConsole(s, cmd, out, q));
  }

  if (p === '/end') return send(res, pageEnd(s));
  if (p === '/score') { res.writeHead(302, { Location: '/end' }); return res.end(); }

  send(res, layout('404', '<div class="page"><h2>这里没有东西喵</h2><div class="say">本喵也不知道你要找什么喵<br><span class="dim">文件被本喵藏起来了喵，桌面也擦干净了喵</span></div><div style="margin-top:24px"><a class="btn ghost" href="/">回首页喵</a></div></div>', s), 404);
}

/* 统一兜底：任何未预料的异常只影响这一个请求，不再把进程带走
 * （之前一个畸形编码就能让容器挂掉，对外表现为 502/504） */
const server = http.createServer((req, res) => {
  handle(req, res).catch((e) => {
    console.log(`[handler] ${req.method} ${req.url} → ${e && e.message}`);
    try {
      if (!res.headersSent) {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end('本喵看不懂这个请求喵\n');
      } else {
        res.end();
      }
    } catch (_) { /* 连接已断，忽略 */ }
  });
});

/* 畸形 HTTP 报文：回 400 后关连接，而不是让服务器报 clientError 崩 */
server.on('clientError', (err, socket) => {
  try { socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); } catch (_) {}
});

/* 最后一道防线：日志记下来，进程继续跑（题目容器不能因为一个请求就没了） */
process.on('unhandledRejection', (e) => console.log('[unhandledRejection]', e && e.message));
process.on('uncaughtException', (e) => console.log('[uncaughtException]', e && e.message));

startInner();
server.listen(PORT, HOST, () => {
  console.log(`残業 on ${HOST}:${PORT}`);
  console.log(`flag parts: ${PARTS.map((x, i) => (i + 1) + ':' + x.length).join(' ')}`);
});
