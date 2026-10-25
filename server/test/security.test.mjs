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
import { nonce, proof, equalProof } from '../../extension/auth.js';

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
    ws.on('message',raw=>{
      const msg=JSON.parse(raw);
      if(msg.id) ws.send(JSON.stringify({id:msg.id,result:{artifact:{data:'private artifact',encoding:'utf8',filePath:forbidden,filename:'result.txt'}}}));
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
  const ctx={nonce,validNonce:v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v),proof,equalProof,PORT_START:17890,PORT_END:17909,
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
  await socket.onmessage({data:JSON.stringify({method:'sensitive',id:2})});
  assert.equal(dispatched,1);socket.close();
});
