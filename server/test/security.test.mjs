import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { randomBytes, createHmac } from 'node:crypto';
import { mkdtemp, readFile, stat, rm, writeFile, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { WebSocket } from 'ws';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { nonce, proof, equalProof, frameProof } from '../../extension/auth.js';

const origin = `chrome-extension://${'a'.repeat(32)}`;
const secret = randomBytes(32).toString('hex');
const sockets = [];
function open(url, options = { origin }) {
  const ws = new WebSocket(url, options); sockets.push(ws); return ws;
}
async function rejectedUpgrade(url, options) {
  const ws = open(url, options);
  await new Promise((resolve, reject) => {
    ws.once('error', resolve);
    ws.once('open', () => reject(new Error('untrusted upgrade accepted')));
  });
}
async function auth(url, key = secret) {
  const ws = open(url);
  const [raw] = await once(ws, 'message');
  const challenge = JSON.parse(raw);
  const cn = nonce();
  const closed = once(ws, 'close');
  const next = key === secret ? once(ws, 'message') : null;
  ws.send(JSON.stringify({method:'authResponse', nonce:cn, proof:await proof(key,'client',challenge.nonce,cn)}));
  if (!next) { await closed; return; }
  const [ack] = await next;
  assert.equal(JSON.parse(ack).proof, await proof(secret,'server',challenge.nonce,cn));
  let sendSeq=0, recvSeq=0;
  ws.sendSigned=async message=>{
    const payload=JSON.stringify(message),seq=++sendSeq;
    ws.send(JSON.stringify({seq,payload,proof:await frameProof(key,'client',challenge.nonce,cn,seq,payload)}));
  };
  ws.decode=async raw=>{
    const msg=JSON.parse(raw);
    assert.equal(msg.seq,++recvSeq);
    assert.equal(msg.proof,await frameProof(key,'server',challenge.nonce,cn,msg.seq,msg.payload));
    return JSON.parse(msg.payload);
  };
  return ws;
}

test('role separation and tamper detection', async () => {
  const sn=nonce(), cn=nonce();
  const client = await proof(secret,'client',sn,cn);
  assert.equal(client, createHmac('sha256',secret).update(`ccb-v1:client:${sn}:${cn}`).digest('hex'));
  assert.ok(!equalProof(client, await proof(secret,'server',sn,cn)));
  assert.ok(!equalProof(client, await proof(secret,'client',nonce(),cn)));
  assert.ok(!equalProof(client, null));
});

test('real server rejects untrusted peers and confines artifact writes', { timeout: 30000 }, async t => {
  let stderr='';
  const transport = new StdioClientTransport({command:process.env.BUN || 'bun',args:['run','src/index.ts'],cwd:process.cwd(),env:{...process.env, BRIDGE_TOKEN:secret},stderr:'pipe'});
  transport.stderr.on('data', chunk => { stderr+=chunk; });
  const client = new Client({name:'security-test',version:'1.0.0'});
  const dir = await mkdtemp(join(tmpdir(),'ccb-security-'));
  try {
    await client.connect(transport);
    const port = /Server listening on port (\d+)/.exec(stderr)?.[1];
    assert.ok(port, 'server must report ready');
    const url=`ws://127.0.0.1:${port}`;
    await t.test('reject web origin, missing origin, and forged Host', async () => {
      await rejectedUpgrade(url,{origin:'https://evil.example'});
      await rejectedUpgrade(url,{});
      await rejectedUpgrade(url,{origin,headers:{Host:'evil.example'}});
      const response=await fetch(`http://127.0.0.1:${port}`);
      assert.equal(response.headers.get('access-control-allow-origin'),null);
    });
    await t.test('reject pre-auth commands and wrong token',async () => {
      const ws=open(url); await once(ws,'message');
      const closed=once(ws,'close'); ws.send(JSON.stringify({method:'extensionInfo'})); await closed;
      await auth(url,randomBytes(32).toString('hex'));
    });
    let ws=await auth(url);
    const forbidden=join(dir,'forbidden.txt');
    ws.on('message',async raw=>{
      const msg=await ws.decode(raw);
      if(msg.id) await ws.sendSigned({id:msg.id,result:{artifact:{data:'private artifact',encoding:'utf8',filePath:forbidden,filename:'result.txt'}}});
    });
    await t.test('rogue disconnect cannot kill authenticated pending commands',async()=>{
      await auth(url,randomBytes(32).toString('hex'));
      const result=await client.callTool({name:'export_har',arguments:{tabId:1}});
      assert.ok(!result.isError);
      const summary=JSON.parse(result.content[0].text);
      assert.notEqual(summary.path,forbidden);
      await assert.rejects(stat(forbidden),{code:'ENOENT'});
      assert.equal((await stat(summary.path)).mode & 0o777,0o600);
      await rm(summary.path);
      await rm(join(summary.path,'..'),{recursive:true,force:true});
    });
    await t.test('reject competing client and replayed proofs',async()=>{
      const competitor=open(url); const [raw]=await once(competitor,'message');
      const sn=JSON.parse(raw).nonce;const cn=nonce();
      const oldProof=await proof(secret,'client',nonce(),cn);
      const closed=once(competitor,'close');competitor.send(JSON.stringify({method:'authResponse',nonce:cn,proof:oldProof}));await closed;
      assert.ok(sn);
      const second=open(url);const [challenge]=await once(second,'message'); const secondSn=JSON.parse(challenge).nonce;
      const closed2=once(second,'close');second.send(JSON.stringify({method:'authResponse',nonce:cn,proof:await proof(secret,'client',secondSn,cn)}));await closed2;
    });
    await t.test('caller path is private, refuses overwrites and symlinks',async()=>{
      const dest=join(dir,'caller.txt');
      const result=await client.callTool({name:'export_har',arguments:{tabId:1,filePath:dest}});
      assert.ok(!result.isError);assert.equal(await readFile(dest,'utf8'),'private artifact');
      assert.equal((await stat(dest)).mode & 0o777,0o600);
      const again=await client.callTool({name:'export_har',arguments:{tabId:1,filePath:dest}});
      assert.equal(again.isError,true);
      const target=join(dir,'target.txt');await writeFile(target,'untouched');const link=join(dir,'link.txt');await symlink(target,link);
      const linked=await client.callTool({name:'export_har',arguments:{tabId:1,filePath:link}});
      assert.equal(linked.isError,true);assert.equal(await readFile(target,'utf8'),'untouched');
    });
  } finally {
    for(const ws of sockets) ws.terminate();
    await client.close();await rm(dir,{recursive:true,force:true});
  }
});

test('extension rejects forged servers before dispatching any command', async () => {
  const { runInNewContext } = await import('node:vm');
  const source = await readFile(new URL('../../extension/background.js', import.meta.url),'utf8');
  const connectSource = source.slice(source.indexOf('async function connectToPort('),source.indexOf('\nfunction scanPorts()',source.indexOf('async function connectToPort(')));
  let socket, dispatched=0;
  const connections=new Map();
  class FakeWebSocket {
    static OPEN=1;static CONNECTING=0;
    constructor(){socket=this;this.readyState=1;this.sent=[];}
    send(raw){this.sent.push(JSON.parse(raw));}
    close(){this.closed=true;this.readyState=3;this.onclose?.();}
  }
  const ctx={nonce,frameProof,validNonce:v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v),proof,equalProof,PORT_START:17890,PORT_END:17909,
    connections,WebSocket:FakeWebSocket,AbortSignal,fetch:async()=>({}),setTimeout,clearTimeout,
    chrome:{storage:{local:{get:async()=>({bridgeToken:secret})},session:{get:(_key,cb)=>cb({}),set:()=>{}}}},
    broadcastState:()=>{},handlers:{sensitive:async()=>{dispatched++;return {}; }},
    sendTo:(ws,data)=>ws.send(JSON.stringify(data))};
  runInNewContext(connectSource+'\nglobalThis.connect=connectToPort;',ctx);
  await ctx.connect(17890);
  await socket.onmessage({data:JSON.stringify({method:'sensitive',id:1})});
  assert.equal(dispatched,0);assert.ok(socket.closed);
  await ctx.connect(17890);
  const sn=nonce();
  await socket.onmessage({data:JSON.stringify({method:'authChallenge',nonce:sn})});
  await socket.onmessage({data:JSON.stringify({method:'authOk',proof:nonce()})});
  assert.ok(socket.closed);assert.equal(dispatched,0);
  await ctx.connect(17890);
  const sn2=nonce();
  await socket.onmessage({data:JSON.stringify({method:'authChallenge',nonce:sn2})});
  const response=socket.sent.find(msg=>msg.method==='authResponse');
  await socket.onmessage({data:JSON.stringify({method:'authOk',proof:await proof(secret,'server',sn2,response.nonce)})});
  const payload=JSON.stringify({method:'sensitive',id:2});
  const signed={seq:1,payload,proof:await frameProof(secret,'server',sn2,response.nonce,1,payload)};
  await socket.onmessage({data:JSON.stringify(signed)});
  assert.equal(dispatched,1);
  await socket.onmessage({data:JSON.stringify(signed)});
  assert.equal(dispatched,1);assert.ok(socket.closed);
  // Even after successful mutual auth, a relay cannot inject a command frame.
  await ctx.connect(17890);
  const sn3=nonce();await socket.onmessage({data:JSON.stringify({method:'authChallenge',nonce:sn3})});
  const response3=socket.sent.find(msg=>msg.method==='authResponse');
  await socket.onmessage({data:JSON.stringify({method:'authOk',proof:await proof(secret,'server',sn3,response3.nonce)})});
  await socket.onmessage({data:JSON.stringify({seq:1,payload,proof:nonce()})});
  assert.equal(dispatched,1);assert.ok(socket.closed);
});

 test('server rejects tampered application frames after authentication', {timeout:10000}, async()=>{
  let stderr='';
  const transport=new StdioClientTransport({command:process.env.BUN || 'bun',args:['run','src/index.ts'],cwd:process.cwd(),env:{...process.env,BRIDGE_TOKEN:secret},stderr:'pipe'});
  transport.stderr.on('data',chunk=>{stderr+=chunk;});
  const client=new Client({name:'frame-test',version:'1.0.0'});
  try {
    await client.connect(transport);
    const port=/Server listening on port (\d+)/.exec(stderr)[1];
    const ws=await auth(`ws://127.0.0.1:${port}`);
    const closed=once(ws,'close');
    ws.send(JSON.stringify({seq:1,payload:JSON.stringify({id:1,result:'forged'}),proof:nonce()}));
    await closed;
    const result=await client.callTool({name:'list_browser_tabs',arguments:{}});
    assert.equal(result.isError,true);
  } finally {await client.close();}
});

test('password-manager compatibility never replays partial input or hides fallback mode', async t => {
  const {runInNewContext}=await import('node:vm');
  const src=await readFile(new URL('../../extension/background.js',import.meta.url),'utf8');
  const helpers=src.slice(src.indexOf('function isForeignExtensionDenied('),src.indexOf('function codedError('));
  const typeMethod=src.slice(src.indexOf('  async typeText(params)'),src.indexOf('  // Fallback: native property descriptor setter'));
  const clickMethod=src.slice(src.indexOf('  async clickElement(params)'),src.indexOf('  // Fallback: synthetic DOM events (debugger unavailable'));
  const shotMethod=src.slice(src.indexOf('  async takeScreenshot(params)'),src.indexOf('  // Fallback: captureVisibleTab + OffscreenCanvas'));
  const forbidden=new Error('CDP command failed: Cannot access a chrome-extension:// URL of different extension');
  // Keep state in one context so each assertion can inspect whether DOM fallback ran.
  function harness(overrides={}){
    let fallbackCount=0;
    const ctx={countFallback:()=>fallbackCount++,ensureCdp:async()=>{},isCdpUnavailable:()=>false,getElementGeometry:async()=>({tagName:'input',inputType:'text',frameId:0}),inputTargetFor:()=>({x:1,y:1}),
      cdpSendTo:async()=>{},cdpSend:async()=>{},selectAllInElement:async()=>{},cdpPressKeyCombo:async()=>{},keyDefFor:()=>({code:'KeyA',vk:65}),MOUSE_BUTTONS:{left:{button:'left',buttons:1}},...overrides};
    runInNewContext(helpers+'\nconst handlers={'+typeMethod+clickMethod+shotMethod+`async typeTextSynthetic(){countFallback();return {value:'synthetic-value'};}, async clickElementSynthetic(){countFallback();return {};}, async takeScreenshotLegacy(){return {image:'test'};}};globalThis.h=handlers;`,ctx);
    return {h:ctx.h,count:()=>fallbackCount};
  }
  await t.test('native opt-in requests OS input instead of synthesizing DOM events',async()=>{
    const h=harness({cdpSendTo:async()=>{throw forbidden;}});
    const r=await h.h.typeText({tabId:1,text:'ab',clearFirst:true,nativeFallback:true});
    assert.equal(r.nativeInputRequired,true);assert.equal(h.count(),0);
  });
  await t.test('denied focus uses labeled DOM input',async()=>{
    const h=harness({cdpSendTo:async()=>{throw forbidden;}});
    const r=await h.h.typeText({tabId:1,text:'ab',clearFirst:true});assert.equal(r.inputMode,'synthetic');assert.equal(h.count(),1);
  });
  await t.test('denied first key uses DOM, but partial input is never replayed',async()=>{
    let h=harness({cdpSend:async()=>{throw forbidden;}});
    assert.equal((await h.h.typeText({tabId:1,text:'ab'})).inputMode,'synthetic');
    let calls=0;h=harness({cdpSend:async()=>{if(++calls===3)throw forbidden;}});
    await assert.rejects(h.h.typeText({tabId:1,text:'ab'}),/different extension/);assert.equal(h.count(),0);
  });
  await t.test('unrelated failures remain errors',async()=>{
    const h=harness({cdpSendTo:async()=>{throw new Error('renderer crashed');}});
    await assert.rejects(h.h.typeText({tabId:1,text:'ab'}),/renderer crashed/);assert.equal(h.count(),0);
  });
  await t.test('denied initial mouse move can fall back without a duplicate click',async()=>{
    const h=harness({cdpSendTo:async()=>{throw forbidden;}});
    assert.equal((await h.h.clickElement({tabId:1,selector:'#button'})).inputMode,'synthetic');assert.equal(h.count(),1);
  });
  await t.test('screenshot fallback identifies viewport capture',async()=>{
    const h=harness({ensureCdp:async()=>{throw forbidden;}});
    assert.equal((await h.h.takeScreenshot({tabId:1})).source,'captureVisibleTab');
  });
});


test('macOS helper rejects a mismatched page before posting events', {skip:process.platform !== 'darwin'}, async t=>{
  const {spawnSync}=await import('node:child_process');
  const {fileURLToPath}=await import('node:url');
  const binary=fileURLToPath(new URL('../native/.build/browser-native-input',import.meta.url));
  try {await stat(binary);} catch {t.skip('Build the native helper first');return;}
  const result=spawnSync(binary,[],{input:JSON.stringify({action:'text',expectedURL:'https://invalid.invalid/never-allowed',expectedDOMId:'not-the-focused-field',text:'must-not-be-sent'})+'\n',encoding:'utf8'});
  assert.notEqual(result.status,0);
  const reply=JSON.parse(result.stdout);assert.equal(reply.ok,false);assert.equal(reply.charactersSent,0);
  assert.match(reply.error,/NATIVE_INPUT_(TARGET_CHANGED|FOCUS_CHANGED|PERMISSION_REQUIRED)/);
});
