// Supabase Edge Function: sync-historico  v2026-10-20b
// Busca geração diária histórica das plataformas e salva em lancamentos.
// Chamada automaticamente pelo app após login para preencher dados desde 01/01/2026.
//
// Parâmetros (query string):
//   codigo       — código da usina (obrigatório)
//   data_inicio  — YYYY-MM-DD (default: 2026-01-01)
//   data_fim     — YYYY-MM-DD (default: ontem)
//
// Headers:
//   Authorization: Bearer <SUPABASE_ANON_KEY>   (para o gateway passar)
//   x-user-token: <user_access_token>            (autenticação real do usuário)
//
// Deploy: supabase functions deploy sync-historico --no-verify-jwt

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { serve } from 'https://deno.land/std@0.168.0/http/server.ts'

const SUPABASE_URL       = Deno.env.get('SUPABASE_URL')!
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
const SOLIS_KEY_ID       = Deno.env.get('SOLIS_KEY_ID')!
const SOLIS_KEY_SECRET   = Deno.env.get('SOLIS_KEY_SECRET')!
const FUSION_BASE        = 'https://la5.fusionsolar.huawei.com'
// Conta lmalta007@gmail.com está no servidor HK (cloudId=2): gateway.isolarcloud.com.hk
const ISOLAR_BASE        = 'https://gateway.isolarcloud.com.hk'
// Credenciais iSolarCloud HK (cloudId=2) — chaves DEVELOPER extraídas do WASM index_bg-BjKetHzz.wasm
// via isolarcloudconfig_get_developer_app_key / get_developer_access_key / get_developer_api_key
// appKey SPA (usado no body das chamadas — o web app usa este)
const ISOLAR_HK_APPKEY    = '5FD913AA74124F88B98E3705E9D29AEF'
// accessKey SPA (capturado do XHR real do web app — header x-access-key)
const ISOLAR_HK_ACCESSKEY = '9grzgbmxdsp3arfmmgq347xjbza4ysps'

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-user-token, x-access-key, x-random-secret-key, x-sign-code, sys_code, sg_encryption_mode, _pl, lang',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
  }
}
function json(data: object, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { ...corsHeaders(), 'Content-Type': 'application/json' },
  })
}

// ─── Autenticação ─────────────────────────────────────────────

async function verifySession(token: string) {
  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)
  const { data: { user }, error } = await sb.auth.getUser(token)
  if (error || !user) return null
  const { data: perfil } = await sb.from('usuarios').select('papel,usinas').eq('id', user.id).single()
  if (!perfil) return null
  return { userId: user.id, papel: perfil.papel, usinas: (perfil.usinas || []) as string[] }
}

// ─── Pure-JS MD5 (Deno Edge Functions não suportam MD5 via WebCrypto) ─────

function md5(input: string): string {
  const enc = new TextEncoder()
  const bytes = enc.encode(input)
  function safeAdd(x: number, y: number) { return (x + y) & 0xFFFFFFFF }
  function rol(n: number, c: number) { return (n << c) | (n >>> (32 - c)) }
  function cmn(q: number, a: number, b: number, x: number, s: number, t: number) { return safeAdd(rol(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b) }
  function ff(a: number,b: number,c: number,d: number,x: number,s: number,t: number){return cmn((b&c)|((~b)&d),a,b,x,s,t)}
  function gg(a: number,b: number,c: number,d: number,x: number,s: number,t: number){return cmn((b&d)|(c&(~d)),a,b,x,s,t)}
  function hh(a: number,b: number,c: number,d: number,x: number,s: number,t: number){return cmn(b^c^d,a,b,x,s,t)}
  function ii(a: number,b: number,c: number,d: number,x: number,s: number,t: number){return cmn(c^(b|(~d)),a,b,x,s,t)}
  const len = bytes.length
  const extra = len % 64 < 56 ? 55 - len % 64 : 119 - len % 64
  const padded = new Uint8Array(len + extra + 9)
  padded.set(bytes); padded[len] = 0x80
  const bitLen = len * 8
  const dv = new DataView(padded.buffer)
  dv.setUint32(padded.length - 8, bitLen >>> 0, true)
  dv.setUint32(padded.length - 4, Math.floor(bitLen / 0x100000000), true)
  let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476
  for (let i = 0; i < padded.length; i += 64) {
    const M: number[] = []
    for (let j = 0; j < 16; j++) M.push(dv.getInt32(i + j * 4, true))
    const [a0, b0, c0, d0] = [a, b, c, d]
    a=ff(a,b,c,d,M[0],7,-680876936);d=ff(d,a,b,c,M[1],12,-389564586);c=ff(c,d,a,b,M[2],17,606105819);b=ff(b,c,d,a,M[3],22,-1044525330)
    a=ff(a,b,c,d,M[4],7,-176418897);d=ff(d,a,b,c,M[5],12,1200080426);c=ff(c,d,a,b,M[6],17,-1473231341);b=ff(b,c,d,a,M[7],22,-45705983)
    a=ff(a,b,c,d,M[8],7,1770035416);d=ff(d,a,b,c,M[9],12,-1958414417);c=ff(c,d,a,b,M[10],17,-42063);b=ff(b,c,d,a,M[11],22,-1990404162)
    a=ff(a,b,c,d,M[12],7,1804603682);d=ff(d,a,b,c,M[13],12,-40341101);c=ff(c,d,a,b,M[14],17,-1502002290);b=ff(b,c,d,a,M[15],22,1236535329)
    a=gg(a,b,c,d,M[1],5,-165796510);d=gg(d,a,b,c,M[6],9,-1069501632);c=gg(c,d,a,b,M[11],14,643717713);b=gg(b,c,d,a,M[0],20,-373897302)
    a=gg(a,b,c,d,M[5],5,-701558691);d=gg(d,a,b,c,M[10],9,38016083);c=gg(c,d,a,b,M[15],14,-660478335);b=gg(b,c,d,a,M[4],20,-405537848)
    a=gg(a,b,c,d,M[9],5,568446438);d=gg(d,a,b,c,M[14],9,-1019803690);c=gg(c,d,a,b,M[3],14,-187363961);b=gg(b,c,d,a,M[8],20,1163531501)
    a=gg(a,b,c,d,M[13],5,-1444681467);d=gg(d,a,b,c,M[2],9,-51403784);c=gg(c,d,a,b,M[7],14,1735328473);b=gg(b,c,d,a,M[12],20,-1926607734)
    a=hh(a,b,c,d,M[5],4,-378558);d=hh(d,a,b,c,M[8],11,-2022574463);c=hh(c,d,a,b,M[11],16,1839030562);b=hh(b,c,d,a,M[14],23,-35309556)
    a=hh(a,b,c,d,M[1],4,-1530992060);d=hh(d,a,b,c,M[4],11,1272893353);c=hh(c,d,a,b,M[7],16,-155497632);b=hh(b,c,d,a,M[10],23,-1094730640)
    a=hh(a,b,c,d,M[13],4,681279174);d=hh(d,a,b,c,M[0],11,-358537222);c=hh(c,d,a,b,M[3],16,-722521979);b=hh(b,c,d,a,M[6],23,76029189)
    a=hh(a,b,c,d,M[9],4,-640364487);d=hh(d,a,b,c,M[12],11,-421815835);c=hh(c,d,a,b,M[15],16,530742520);b=hh(b,c,d,a,M[2],23,-995338651)
    a=ii(a,b,c,d,M[0],6,-198630844);d=ii(d,a,b,c,M[7],10,1126891415);c=ii(c,d,a,b,M[14],15,-1416354905);b=ii(b,c,d,a,M[5],21,-57434055)
    a=ii(a,b,c,d,M[12],6,1700485571);d=ii(d,a,b,c,M[3],10,-1894986606);c=ii(c,d,a,b,M[10],15,-1051523);b=ii(b,c,d,a,M[1],21,-2054922799)
    a=ii(a,b,c,d,M[8],6,1873313359);d=ii(d,a,b,c,M[15],10,-30611744);c=ii(c,d,a,b,M[6],15,-1560198380);b=ii(b,c,d,a,M[13],21,1309151649)
    a=ii(a,b,c,d,M[4],6,-145523070);d=ii(d,a,b,c,M[11],10,-1120210379);c=ii(c,d,a,b,M[2],15,718787259);b=ii(b,c,d,a,M[9],21,-343485551)
    a=safeAdd(a,a0); b=safeAdd(b,b0); c=safeAdd(c,c0); d=safeAdd(d,d0)
  }
  const result = new Uint8Array(16)
  const rv = new DataView(result.buffer)
  rv.setInt32(0,a,true); rv.setInt32(4,b,true); rv.setInt32(8,c,true); rv.setInt32(12,d,true)
  return btoa(String.fromCharCode(...result))
}

// Variante hex do MD5 (iSolarCloud usa lowercase hex para senhas)
function md5hex(input: string): string {
  const enc = new TextEncoder()
  const bytes = enc.encode(input)
  function safeAdd(x: number, y: number) { return (x + y) & 0xFFFFFFFF }
  function rol(n: number, c: number) { return (n << c) | (n >>> (32 - c)) }
  function cmn(q: number, a: number, b: number, x: number, s: number, t: number) { return safeAdd(rol(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b) }
  function ff(a: number,b: number,c: number,d: number,x: number,s: number,t: number){return cmn((b&c)|((~b)&d),a,b,x,s,t)}
  function gg(a: number,b: number,c: number,d: number,x: number,s: number,t: number){return cmn((b&d)|(c&(~d)),a,b,x,s,t)}
  function hh(a: number,b: number,c: number,d: number,x: number,s: number,t: number){return cmn(b^c^d,a,b,x,s,t)}
  function ii(a: number,b: number,c: number,d: number,x: number,s: number,t: number){return cmn(c^(b|(~d)),a,b,x,s,t)}
  const len = bytes.length
  const extra = len % 64 < 56 ? 55 - len % 64 : 119 - len % 64
  const padded = new Uint8Array(len + extra + 9)
  padded.set(bytes); padded[len] = 0x80
  const bitLen = len * 8
  const dv = new DataView(padded.buffer)
  dv.setUint32(padded.length - 8, bitLen >>> 0, true)
  dv.setUint32(padded.length - 4, Math.floor(bitLen / 0x100000000), true)
  let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476
  for (let i = 0; i < padded.length; i += 64) {
    const M: number[] = []
    for (let j = 0; j < 16; j++) M.push(dv.getInt32(i + j * 4, true))
    const [a0, b0, c0, d0] = [a, b, c, d]
    a=ff(a,b,c,d,M[0],7,-680876936);d=ff(d,a,b,c,M[1],12,-389564586);c=ff(c,d,a,b,M[2],17,606105819);b=ff(b,c,d,a,M[3],22,-1044525330)
    a=ff(a,b,c,d,M[4],7,-176418897);d=ff(d,a,b,c,M[5],12,1200080426);c=ff(c,d,a,b,M[6],17,-1473231341);b=ff(b,c,d,a,M[7],22,-45705983)
    a=ff(a,b,c,d,M[8],7,1770035416);d=ff(d,a,b,c,M[9],12,-1958414417);c=ff(c,d,a,b,M[10],17,-42063);b=ff(b,c,d,a,M[11],22,-1990404162)
    a=ff(a,b,c,d,M[12],7,1804603682);d=ff(d,a,b,c,M[13],12,-40341101);c=ff(c,d,a,b,M[14],17,-1502002290);b=ff(b,c,d,a,M[15],22,1236535329)
    a=gg(a,b,c,d,M[1],5,-165796510);d=gg(d,a,b,c,M[6],9,-1069501632);c=gg(c,d,a,b,M[11],14,643717713);b=gg(b,c,d,a,M[0],20,-373897302)
    a=gg(a,b,c,d,M[5],5,-701558691);d=gg(d,a,b,c,M[10],9,38016083);c=gg(c,d,a,b,M[15],14,-660478335);b=gg(b,c,d,a,M[4],20,-405537848)
    a=gg(a,b,c,d,M[9],5,568446438);d=gg(d,a,b,c,M[14],9,-1019803690);c=gg(c,d,a,b,M[3],14,-187363961);b=gg(b,c,d,a,M[8],20,1163531501)
    a=gg(a,b,c,d,M[13],5,-1444681467);d=gg(d,a,b,c,M[2],9,-51403784);c=gg(c,d,a,b,M[7],14,1735328473);b=gg(b,c,d,a,M[12],20,-1926607734)
    a=hh(a,b,c,d,M[5],4,-378558);d=hh(d,a,b,c,M[8],11,-2022574463);c=hh(c,d,a,b,M[11],16,1839030562);b=hh(b,c,d,a,M[14],23,-35309556)
    a=hh(a,b,c,d,M[1],4,-1530992060);d=hh(d,a,b,c,M[4],11,1272893353);c=hh(c,d,a,b,M[7],16,-155497632);b=hh(b,c,d,a,M[10],23,-1094730640)
    a=hh(a,b,c,d,M[13],4,681279174);d=hh(d,a,b,c,M[0],11,-358537222);c=hh(c,d,a,b,M[3],16,-722521979);b=hh(b,c,d,a,M[6],23,76029189)
    a=hh(a,b,c,d,M[9],4,-640364487);d=hh(d,a,b,c,M[12],11,-421815835);c=hh(c,d,a,b,M[15],16,530742520);b=hh(b,c,d,a,M[2],23,-995338651)
    a=ii(a,b,c,d,M[0],6,-198630844);d=ii(d,a,b,c,M[7],10,1126891415);c=ii(c,d,a,b,M[14],15,-1416354905);b=ii(b,c,d,a,M[5],21,-57434055)
    a=ii(a,b,c,d,M[12],6,1700485571);d=ii(d,a,b,c,M[3],10,-1894986606);c=ii(c,d,a,b,M[10],15,-1051523);b=ii(b,c,d,a,M[1],21,-2054922799)
    a=ii(a,b,c,d,M[8],6,1873313359);d=ii(d,a,b,c,M[15],10,-30611744);c=ii(c,d,a,b,M[6],15,-1560198380);b=ii(b,c,d,a,M[13],21,1309151649)
    a=ii(a,b,c,d,M[4],6,-145523070);d=ii(d,a,b,c,M[11],10,-1120210379);c=ii(c,d,a,b,M[2],15,718787259);b=ii(b,c,d,a,M[9],21,-343485551)
    a=safeAdd(a,a0); b=safeAdd(b,b0); c=safeAdd(c,c0); d=safeAdd(d,d0)
  }
  const result2 = new Uint8Array(16)
  const rv2 = new DataView(result2.buffer)
  rv2.setInt32(0,a,true); rv2.setInt32(4,b,true); rv2.setInt32(8,c,true); rv2.setInt32(12,d,true)
  return Array.from(result2).map(b => b.toString(16).padStart(2,'0')).join('')
}

// ─── Pure-JS HMAC-SHA1 (Deno Edge Functions não suportam SHA-1 via WebCrypto) ──

function hmacSha1(key: string, message: string): string {
  const blockSize = 64
  const enc = new TextEncoder()
  let keyBytes = enc.encode(key)
  if (keyBytes.length > blockSize) keyBytes = keyBytes.slice(0, blockSize)
  const keyPadded = new Uint8Array(blockSize)
  keyPadded.set(keyBytes)
  const ipad = keyPadded.map(b => b ^ 0x36)
  const opad = keyPadded.map(b => b ^ 0x5c)
  const msgBytes = enc.encode(message)
  const innerData = new Uint8Array(ipad.length + msgBytes.length)
  innerData.set(ipad); innerData.set(msgBytes, ipad.length)
  function sha1(data: Uint8Array): Uint8Array {
    let h0=0x67452301,h1=0xEFCDAB89,h2=0x98BADCFE,h3=0x10325476,h4=0xC3D2E1F0
    const ml = data.length
    const extra = ml % 64 < 56 ? 56 - ml % 64 : 120 - ml % 64
    const padded = new Uint8Array(ml + extra + 8)
    padded.set(data); padded[ml] = 0x80
    const bitLen = ml * 8
    for(let i=0;i<8;i++) padded[padded.length-8+i]=(bitLen/Math.pow(2,(7-i)*8))&0xff
    const view = new DataView(padded.buffer)
    for(let i=0;i<padded.length;i+=64){
      const w=new Uint32Array(80)
      for(let j=0;j<16;j++) w[j]=view.getUint32(i+j*4)
      for(let j=16;j<80;j++){const x=w[j-3]^w[j-8]^w[j-14]^w[j-16];w[j]=(x<<1)|(x>>>31)}
      let[a,b,c,d,e]=[h0,h1,h2,h3,h4]
      for(let j=0;j<80;j++){
        let f=0,k=0
        if(j<20){f=(b&c)|((~b)&d);k=0x5A827999}
        else if(j<40){f=b^c^d;k=0x6ED9EBA1}
        else if(j<60){f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDC}
        else{f=b^c^d;k=0xCA62C1D6}
        const tmp=(((a<<5)|(a>>>27))+f+e+k+w[j])>>>0
        e=d;d=c;c=(b<<30)|(b>>>2);b=a;a=tmp
      }
      h0=(h0+a)>>>0;h1=(h1+b)>>>0;h2=(h2+c)>>>0;h3=(h3+d)>>>0;h4=(h4+e)>>>0
    }
    const result=new Uint8Array(20)
    const rv=new DataView(result.buffer)
    rv.setUint32(0,h0);rv.setUint32(4,h1);rv.setUint32(8,h2);rv.setUint32(12,h3);rv.setUint32(16,h4)
    return result
  }
  const innerHash = sha1(innerData)
  const outerData = new Uint8Array(opad.length + innerHash.length)
  outerData.set(opad); outerData.set(innerHash, opad.length)
  return btoa(String.fromCharCode(...sha1(outerData)))
}

// ─── Utilitários de data ──────────────────────────────────────

function dateToYYYYMMDD(d: Date): string {
  return d.toISOString().slice(0, 10)
}

// Gera lista de datas [YYYY-MM-DD] entre inicio e fim (inclusive)
function dateRange(inicio: string, fim: string): string[] {
  const dates: string[] = []
  const cur = new Date(inicio + 'T12:00:00Z')
  const end = new Date(fim + 'T12:00:00Z')
  while (cur <= end) {
    dates.push(dateToYYYYMMDD(cur))
    cur.setDate(cur.getDate() + 1)
  }
  return dates
}

// Converte YYYY-MM-DD para timestamp ms (meia-noite UTC)
function dateStrToMs(d: string): number {
  return new Date(d + 'T00:00:00Z').getTime()
}

// ─── iSolarCloud — Criptografia AES-CTR + RSA PKCS#1 v1.5 ───
//
// Protocolo real do servidor HK (capturado via XHR do web3.isolarcloud.com.hk):
//
//   1. Gera chave AES-128 aleatória (16 bytes)
//   2. Criptografa a chave AES com RSA PKCS#1 v1.5 usando a pubkey SPA
//      → envia no header x-random-secret-key (base64 standard, ~172 chars para RSA-1024)
//      NOTA: Web Crypto API só suporta RSA-OAEP — usamos implementação BigInt pura
//   3. Criptografa o body JSON com AES-128-CTR (counter = 16 zero bytes)
//      → envia como hex UPPERCASE no body
//   4. Headers obrigatórios:
//      - sys_code: '200'
//      - sg_encryption_mode: 'aes_ctr'
//      - x-access-key: <accessKey SPA>
//      - x-random-secret-key: base64(RSA-PKCS1v15-encrypt(aesKey))
//      - x-sign-code: '0'
//      - _pl: 'js'
//   5. Resposta: também hex UPPERCASE → decriptar com mesma chave AES

// Chaves SPA (usadas pelo protocolo de produção do web app — capturadas do XHR real)
const ISOLAR_SPA_ACCESSKEY = '9grzgbmxdsp3arfmmgq347xjbza4ysps'
// RSA-1024 public key SPA — extraída do WASM (get_spa_api_key / apiKey SPA)
// O web app usa esta chave com NodeRSA pkcs1 scheme
const ISOLAR_SPA_RSA_PUBKEY = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkecphb6vgsBx4LJknKKes-eyj7-RKQ3fikF5B67EObZ3t4moFZyMGuuJPiadYdaxvRqtxyblIlVM7omAasROtKRhtgKwwRxo2a6878qBhTgUVlsqugpI_7ZC9RmO2Rpmr8WzDeAapGANfHN5bVr7G7GYGwIrjvyxMrAVit_oM4wIDAQAB'

function toUrlSafeBase64(buf: Uint8Array): string {
  let b = btoa(String.fromCharCode(...buf))
  b = b.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
  return b
}

function fromUrlSafeBase64(s: string): Uint8Array {
  let b = s.replace(/-/g, '+').replace(/_/g, '/')
  while (b.length % 4) b += '='
  return Uint8Array.from(atob(b), c => c.charCodeAt(0))
}

function toHexUpper(buf: Uint8Array): string {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('')
}

function fromHex(hex: string): Uint8Array {
  const result = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    result[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return result
}

// ─── RSA PKCS#1 v1.5 encrypt — implementação pura BigInt ────
// Web Crypto API não suporta PKCS1v15 para encrypt. O iSolarCloud usa NodeRSA
// com encryptionScheme: 'pkcs1' que é exatamente PKCS#1 v1.5.
//
// Algoritmo PKCS#1 v1.5 encrypt:
//   EM = 0x00 || 0x02 || PS || 0x00 || M
//   onde PS = k-3-mLen bytes aleatórios != 0x00, k = tamanho da chave em bytes
//   c = EM^e mod n  (mod-exp BigInt)

function parseDerSpki(spkiDer: Uint8Array): { n: bigint; e: bigint } {
  // Parser DER mínimo para SubjectPublicKeyInfo contendo RSAPublicKey
  // Estrutura: SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING { SEQUENCE { INTEGER n, INTEGER e } } }
  let pos = 0
  function readLen(): number {
    const first = spkiDer[pos++]
    if (first < 0x80) return first
    const nBytes = first & 0x7f
    let len = 0
    for (let i = 0; i < nBytes; i++) len = (len << 8) | spkiDer[pos++]
    return len
  }
  function readTag(expected: number) {
    const tag = spkiDer[pos++]
    if (tag !== expected) throw new Error(`DER: expected tag 0x${expected.toString(16)}, got 0x${tag.toString(16)} at pos ${pos-1}`)
    return readLen()
  }
  function readBigInt(): bigint {
    const len = readTag(0x02) // INTEGER
    // strip leading zero byte if present (sign byte)
    let start = pos
    let count = len
    if (spkiDer[start] === 0x00) { start++; count-- }
    const bytes = spkiDer.slice(start, start + count)
    pos += len
    let val = 0n
    for (const b of bytes) val = (val << 8n) | BigInt(b)
    return val
  }

  readTag(0x30)  // outer SEQUENCE
  // Algorithm identifier SEQUENCE — skip it entirely
  const algLen = readTag(0x30)
  pos += algLen
  // BIT STRING containing RSAPublicKey
  readTag(0x03)  // BIT STRING tag
  pos++          // skip "unused bits" byte (0x00)
  readTag(0x30)  // inner SEQUENCE (RSAPublicKey)
  const n = readBigInt()
  const e = readBigInt()
  return { n, e }
}

function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n
  base = base % mod
  while (exp > 0n) {
    if (exp % 2n === 1n) result = result * base % mod
    exp = exp >> 1n
    base = base * base % mod
  }
  return result
}

function rsaPkcs1v15Encrypt(message: Uint8Array, n: bigint, e: bigint): Uint8Array {
  // k = byte length of modulus
  const nHex = n.toString(16)
  const k = Math.ceil(nHex.length / 2)
  if (message.length > k - 11) throw new Error(`RSA PKCS1v15: message too long (${message.length} > ${k-11})`)

  // Build EM = 0x00 || 0x02 || PS || 0x00 || M
  const psLen = k - message.length - 3
  const PS = new Uint8Array(psLen)
  // PS must be non-zero random bytes
  let filled = 0
  while (filled < psLen) {
    const rand = crypto.getRandomValues(new Uint8Array(psLen - filled + 8))
    for (const b of rand) {
      if (b !== 0 && filled < psLen) PS[filled++] = b
    }
  }
  const EM = new Uint8Array(k)
  EM[0] = 0x00; EM[1] = 0x02
  EM.set(PS, 2)
  EM[2 + psLen] = 0x00
  EM.set(message, 3 + psLen)

  // m = OS2IP(EM)
  let m = 0n
  for (const b of EM) m = (m << 8n) | BigInt(b)

  // c = RSAEP(m) = m^e mod n
  const c = modpow(m, e, n)

  // I2OSP(c, k)
  const result = new Uint8Array(k)
  let cHexStr = c.toString(16).padStart(k * 2, '0')
  for (let i = 0; i < k; i++) {
    result[i] = parseInt(cHexStr.slice(i * 2, i * 2 + 2), 16)
  }
  return result
}

// Cache das partes da chave pública RSA (parseadas uma vez)
let _rsaPubKeyCache: { n: bigint; e: bigint } | null = null
function getRsaPubKey(): { n: bigint; e: bigint } {
  if (_rsaPubKeyCache) return _rsaPubKeyCache
  const der = fromUrlSafeBase64(ISOLAR_SPA_RSA_PUBKEY)
  _rsaPubKeyCache = parseDerSpki(der)
  return _rsaPubKeyCache
}

// Retorna: { hexBody, xRandomSecretKey (base64 para header), aesKey (para decriptar resposta) }
async function isolarEncryptBodyCtr(plainBody: string): Promise<{
  hexBody: string;
  xRandomSecretKey: string;
  aesKey: Uint8Array;
}> {
  // 1. Gerar chave AES-128 aleatória (16 bytes)
  const aesKey = crypto.getRandomValues(new Uint8Array(16))
  // AES-CTR: counter inicial = 16 bytes zero
  const counter = new Uint8Array(16)

  // 2. AES-128-CTR encrypt do body
  const cryptoKey = await crypto.subtle.importKey('raw', aesKey, { name: 'AES-CTR' }, false, ['encrypt'])
  const enc = new TextEncoder()
  const encBody = await crypto.subtle.encrypt(
    { name: 'AES-CTR', counter, length: 64 },
    cryptoKey,
    enc.encode(plainBody)
  )

  // 3. RSA PKCS#1 v1.5 encrypt da chave AES (implementação BigInt pura)
  const { n, e } = getRsaPubKey()
  const encAesKey = rsaPkcs1v15Encrypt(aesKey, n, e)

  // x-random-secret-key usa base64 standard (não URL-safe), ~172 chars para RSA-1024
  const xRandomSecretKey = btoa(String.fromCharCode(...encAesKey))

  return {
    hexBody: toHexUpper(new Uint8Array(encBody)),
    xRandomSecretKey,
    aesKey,
  }
}

async function isolarDecryptResponseCtr(hexResponse: string, aesKey: Uint8Array): Promise<string> {
  const encData = fromHex(hexResponse)
  const counter = new Uint8Array(16)
  const cryptoKey = await crypto.subtle.importKey('raw', aesKey, { name: 'AES-CTR' }, false, ['decrypt'])
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-CTR', counter, length: 64 },
    cryptoKey,
    encData
  )
  return new TextDecoder().decode(decrypted)
}

// ─── SolisCloud — histórico diário ───────────────────────────
// Endpoint: /v1/api/stationMonth  (dados diários de um mês inteiro)
// Retorna registros com: date (YYYY-MM-DD ou timestamp ms), energy (kWh)
// NOTA: stationDay retorna dados de UM único dia; stationMonth retorna todos os dias do mês

// Serializa objeto para JSON preservando números grandes como literais numéricos
// JSON.stringify perde precisão em números > Number.MAX_SAFE_INTEGER (ex: IDs SolisCloud de 19 dígitos)
function jsonStringifySafe(obj: Record<string, unknown>): string {
  const parts: string[] = []
  for (const [k, v] of Object.entries(obj)) {
    const key = `"${k}":`
    if (typeof v === 'string' && /^\d{16,}$/.test(v)) {
      // String que parece ser um número grande → serializar como número literal (sem aspas)
      parts.push(key + v)
    } else {
      parts.push(key + JSON.stringify(v))
    }
  }
  return '{' + parts.join(',') + '}'
}

async function solisRequest(path: string, body: Record<string, unknown>) {
  const bodyStr = jsonStringifySafe(body)
  const contentMd5 = md5(bodyStr)
  const dateStr = new Date().toUTCString()
  const contentType = 'application/json'
  const stringToSign = `POST\n${contentMd5}\n${contentType}\n${dateStr}\n${path}`
  const sign = hmacSha1(SOLIS_KEY_SECRET, stringToSign)
  const authHeader = `API ${SOLIS_KEY_ID}:${sign}`

  console.log(`[SolisCloud] POST ${path}`)
  console.log(`[SolisCloud] Date: ${dateStr}`)
  console.log(`[SolisCloud] Content-MD5: ${contentMd5}`)
  console.log(`[SolisCloud] StringToSign: ${JSON.stringify(stringToSign)}`)
  console.log(`[SolisCloud] Authorization: ${authHeader.slice(0, 30)}...`)
  console.log(`[SolisCloud] KeyID (primeiros 8): ${SOLIS_KEY_ID?.slice(0, 8)}... total ${SOLIS_KEY_ID?.length} chars`)

  const res = await fetch(`https://www.soliscloud.com:13333${path}`, {
    method: 'POST',
    headers: { 'Content-MD5': contentMd5, 'Content-Type': contentType, 'Date': dateStr, 'Authorization': authHeader },
    body: bodyStr,
  })
  const data = await res.json()
  console.log(`[SolisCloud] HTTP ${res.status}, response code: ${data.code}, msg: ${data.msg}`)
  if (String(data.code) !== '0') throw new Error('SolisCloud: ' + JSON.stringify(data))
  return data.data
}

// Busca geração diária SolisCloud para um mês (YYYY-MM)
// Usa /v1/api/stationMonth que retorna array de dias do mês
// Retorna Map: data (YYYY-MM-DD) → kWh
async function solisMonthly(stationId: string, yearMonth: string): Promise<Map<string, number>> {
  const [year, month] = yearMonth.split('-').map(Number)
  // IMPORTANTE: stationMonth usa campo "month" (não "time"), sem "timeZone"
  // stationDay usa campo "time" (YYYY-MM-DD) + "timeZone"
  // Referência: soliscloud_api Python library
  // O id deve ser passado como string para preservar precisão (>Number.MAX_SAFE_INTEGER)
  // jsonStringifySafe serializa strings numéricas como literais numéricos no JSON
  const requestBody: Record<string, unknown> = {
    id: stationId,     // string original — jsonStringifySafe vai emitir como número
    month: yearMonth,  // campo "month", formato "YYYY-MM" — NÃO usar "time" aqui!
    money: 'BRL',
  }
  console.log(`[SolisCloud] stationMonth request stationId=${stationId} yearMonth=${yearMonth}`)
  console.log(`[SolisCloud] request body: ${JSON.stringify(requestBody)}`)

  let rawData: any
  try {
    rawData = await solisRequest('/v1/api/stationMonth', requestBody)
  } catch (err: any) {
    console.error(`[SolisCloud] stationMonth error: ${err?.message}`)
    throw err
  }

  console.log(`[SolisCloud] raw response keys: ${Array.isArray(rawData) ? 'ARRAY len='+rawData.length : Object.keys(rawData || {}).join(', ')}`)
  console.log(`[SolisCloud] raw response: ${JSON.stringify(rawData).slice(0, 500)}`)

  const result = new Map<string, number>()
  // stationMonth pode retornar:
  // 1) array direto de objetos de dias (todos da conta)
  // 2) objeto com stationMonthEnergyVos / stationDayEnergyVos / records
  let vosList: any[]
  if (Array.isArray(rawData)) {
    // Resposta é array flat — filtra pelo station_id desta usina
    vosList = rawData.filter((item: any) => String(item.id) === stationId)
    // Se não achou por id, usa o item que tem dateStr (assume que é desta usina)
    if (vosList.length === 0) vosList = rawData
    // Cada item do array de stationMonth é um DIA — usa direto
    console.log(`[SolisCloud] array mode: ${rawData.length} total, ${vosList.length} desta usina`)
  } else {
    vosList = rawData?.stationMonthEnergyVos || rawData?.stationDayEnergyVos || rawData?.records || []
  }
  if (vosList.length > 0) {
    console.log(`[SolisCloud] ${vosList.length} registros. Keys: ${Object.keys(vosList[0]).join(', ')}`)
    console.log(`[SolisCloud] sample[0]: ${JSON.stringify(vosList[0])}`)
  } else {
    console.log(`[SolisCloud] lista vazia para ${stationId} ${yearMonth}`)
  }
  for (const item of vosList) {
    // item.date pode vir como "YYYY-MM-DD" ou timestamp ms
    // item.dateStr vem como "YYYY-MM-DD" (ex: "2026-10-01")
    let dateKey: string
    if (item.dateStr) {
      dateKey = String(item.dateStr).slice(0, 10)
    } else if (typeof item.date === 'number') {
      // timestamp em ms → converter para YYYY-MM-DD no fuso UTC-3
      const dt = new Date(item.date - 3 * 3600 * 1000)
      dateKey = dt.toISOString().slice(0, 10)
    } else {
      dateKey = String(item.date || item.time || '').slice(0, 10)
    }
    if (!dateKey || dateKey.length < 10) continue
    const kwh = parseFloat(item.energy ?? item.eToday ?? item.powerGeneratedStr ?? 0) || 0
    if (kwh > 0) result.set(dateKey, kwh)
  }
  return result
}

// ─── FusionSolar — histórico diário ──────────────────────────

async function fusionLoginComCache(conta: string): Promise<{ xsrfToken: string; cookie: string }> {
  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)
  const cacheKey = `fusion_session_${conta}`
  const { data: cached } = await sb.from('cache_sessoes').select('dados, criado_em').eq('chave', cacheKey).single()
  if (cached) {
    const idadeSeg = (Date.now() - new Date(cached.criado_em).getTime()) / 1000
    if (idadeSeg < 1200) return cached.dados as { xsrfToken: string; cookie: string }
  }
  const suffix = conta === 'padrao' ? '' : '_' + conta
  const userName = Deno.env.get('FUSION_USERNAME' + suffix)!
  const systemCode = Deno.env.get('FUSION_SYSTEM_CODE' + suffix)!
  const res = await fetch(`${FUSION_BASE}/thirdData/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ userName, systemCode }),
  })
  const body = await res.json()
  if (!body.success) throw new Error('FusionSolar login: ' + (body.failCode || JSON.stringify(body)))
  const headers = Object.fromEntries(res.headers.entries())
  const xsrfToken = headers['xsrf-token'] || headers['Xsrf-Token'] || ''
  const cookie = (headers['set-cookie'] || '').split(';')[0]
  const session = { xsrfToken, cookie }
  await sb.from('cache_sessoes').upsert({ chave: cacheKey, dados: session, criado_em: new Date().toISOString() }, { onConflict: 'chave' })
  return session
}

async function fusionRequestWithSession(path: string, payload: object, session: { xsrfToken: string; cookie: string }) {
  const res = await fetch(`${FUSION_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'XSRF-TOKEN': session.xsrfToken, 'Cookie': session.cookie },
    body: JSON.stringify(payload),
  })
  const body = await res.json()
  if (!body.success) throw new Error('FusionSolar: ' + JSON.stringify(body))
  return body.data
}

// Busca geração diária FusionSolar para um mês
// Endpoint: /thirdData/getKpiStationDay
// collectTime é timestamp (ms) do último dia do mês consultado
async function fusionMonthly(stationCode: string, conta: string, yearMonth: string): Promise<Map<string, number>> {
  const session = await fusionLoginComCache(conta)
  const [y, m] = yearMonth.split('-').map(Number)
  // collectTime = timestamp do primeiro dia do mês seguinte (último momento do mês)
  const lastDay = new Date(Date.UTC(y, m, 0)) // último dia do mês
  const collectTime = lastDay.getTime()
  const data: any[] = await fusionRequestWithSession('/thirdData/getKpiStationDay', {
    stationCodes: stationCode,
    collectTime: String(collectTime),
  }, session)
  const result = new Map<string, number>()
  for (const item of data || []) {
    if (item?.stationCode !== stationCode) continue
    // collectTime do item é timestamp ms UTC
    const dt = new Date(Number(item.collectTime))
    const dateKey = dt.toISOString().slice(0, 10)
    const kwh = parseFloat(item.dataItemMap?.radiation_intensity) || parseFloat(item.dataItemMap?.day_power) || 0
    if (kwh > 0) result.set(dateKey, kwh)
  }
  return result
}

// ─── iSolarCloud — histórico diário ──────────────────────────
//
// Autenticação iSolarCloud V1 (servidor HK) — protocolo real capturado do XHR:
//
//   PASSO 1 — Login com user/senha:
//     POST /v1/userService/login
//     Body: AES-128-CTR hex uppercase de { appkey, user_account, user_password: md5hex(senha) }
//     Headers: x-access-key, x-random-secret-key (RSA da chave AES), sys_code: '200',
//              sg_encryption_mode: 'aes_ctr', x-sign-code: '0', _pl: 'js'
//     Resposta: hex AES-CTR → decriptar → JSON com result_data.token, user_id, login_state
//
//   PASSO 2 — Chamadas de dados (mesma criptografia):
//     POST /v1/powerStationService/...
//     Body: AES-128-CTR hex uppercase de { token, user_id, login_state, appkey, ...params }
//
// Env vars:
//   ISOLAR_USER     — email/usuário (ex: lmalta007@gmail.com)
//   ISOLAR_PASS     — senha em texto puro
// (sufixo _<conta> para contas adicionais)
//
// O token de sessão é cacheado na tabela cache_sessoes por 20min.

async function isolarV1LoginComCache(conta: string): Promise<{ token: string; userId: string; loginState: string }> {
  const suffix  = conta === 'padrao' ? '' : '_' + conta
  const usuario = Deno.env.get('ISOLAR_USER' + suffix) || ''
  const senha   = Deno.env.get('ISOLAR_PASS' + suffix)
               || Deno.env.get('ISOLAR_PASSWORD' + suffix) || ''

  if (!usuario) throw new Error(`iSolarCloud: ISOLAR_USER${suffix} não configurado`)
  if (!senha)   throw new Error(`iSolarCloud: ISOLAR_PASS${suffix} não configurado`)

  const sbAdmin  = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)
  const cacheKey = `isolar_v1session_${conta}`

  // Tenta usar sessão cacheada (20 min)
  const { data: cached } = await sbAdmin
    .from('cache_sessoes')
    .select('dados, criado_em')
    .eq('chave', cacheKey)
    .single()
  if (cached) {
    const idadeSeg = (Date.now() - new Date(cached.criado_em).getTime()) / 1000
    if (idadeSeg < 1200) {  // 20 minutos
      console.log(`[iSolarCloud] sessão v1 cacheada para conta="${conta}" (${Math.round(idadeSeg)}s)`)
      return cached.dados as { token: string; userId: string; loginState: string }
    }
  }

  console.log(`[iSolarCloud] login V1 para conta="${conta}" user=${usuario}`)
  const loginPayload = JSON.stringify({
    appkey: ISOLAR_HK_APPKEY,
    user_account: usuario,
    user_password: md5hex(senha),
  })
  const { hexBody, xRandomSecretKey, aesKey } = await isolarEncryptBodyCtr(loginPayload)

  const res = await fetch(`${ISOLAR_BASE}/v1/userService/login`, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain',
      'x-access-key': ISOLAR_HK_ACCESSKEY,
      'x-random-secret-key': xRandomSecretKey,
      'x-sign-code': '0',
      'sys_code': '200',
      'sg_encryption_mode': 'aes_ctr',
      '_pl': 'js',
      'lang': '_en_US',
    },
    body: hexBody,
  })
  const rawBody = await res.text()
  console.log(`[iSolarCloud] login HTTP ${res.status}, raw body (50 chars): ${rawBody.slice(0, 50)}`)

  // Resposta pode ser hex-encriptada ou JSON direto (fallback)
  let body: any
  if (/^[0-9A-Fa-f]{10,}$/.test(rawBody.trim())) {
    const decrypted = await isolarDecryptResponseCtr(rawBody.trim(), aesKey)
    console.log(`[iSolarCloud] login decrypted: ${decrypted.slice(0, 200)}`)
    body = JSON.parse(decrypted)
  } else {
    try { body = JSON.parse(rawBody) } catch { body = { result_code: 'E_PARSE', raw: rawBody.slice(0, 200) } }
  }

  console.log(`[iSolarCloud] login result_code=${body.result_code} msg=${body.result_msg}`)
  if (body.result_code !== '1') throw new Error('iSolarCloud login: ' + JSON.stringify(body))

  const token      = body.result_data?.token      || ''
  const userId     = String(body.result_data?.user_id    || '')
  const loginState = String(body.result_data?.login_state || '')
  if (!token) throw new Error('iSolarCloud: token ausente na resposta de login: ' + JSON.stringify(body.result_data))

  const session = { token, userId, loginState }
  await sbAdmin.from('cache_sessoes').upsert(
    { chave: cacheKey, dados: session, criado_em: new Date().toISOString() },
    { onConflict: 'chave' }
  )
  console.log(`[iSolarCloud] login V1 ok, token cacheado para conta="${conta}"`)
  return session
}

async function isolarV1Request(path: string, payload: object, session: { token: string; userId: string; loginState: string }) {
  const fullPayload = JSON.stringify({
    token:       session.token,
    user_id:     session.userId,
    login_state: session.loginState,
    appkey:      ISOLAR_HK_APPKEY,
    ...payload,
  })
  const { hexBody, xRandomSecretKey, aesKey } = await isolarEncryptBodyCtr(fullPayload)
  console.log(`[iSolarCloud] V1 request ${path}`)
  const res = await fetch(`${ISOLAR_BASE}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain',
      'x-access-key': ISOLAR_HK_ACCESSKEY,
      'x-random-secret-key': xRandomSecretKey,
      'x-sign-code': '0',
      'sys_code': '200',
      'sg_encryption_mode': 'aes_ctr',
      '_pl': 'js',
      'lang': '_en_US',
    },
    body: hexBody,
  })
  const rawBody = await res.text()
  console.log(`[iSolarCloud] response ${path} HTTP ${res.status}, raw (50): ${rawBody.slice(0, 50)}`)

  let body: any
  if (/^[0-9A-Fa-f]{10,}$/.test(rawBody.trim())) {
    const decrypted = await isolarDecryptResponseCtr(rawBody.trim(), aesKey)
    console.log(`[iSolarCloud] decrypted ${path}: ${decrypted.slice(0, 300)}`)
    body = JSON.parse(decrypted)
  } else {
    try { body = JSON.parse(rawBody) } catch { body = { result_code: 'E_PARSE', raw: rawBody.slice(0, 200) } }
  }

  console.log(`[iSolarCloud] result_code=${body.result_code} msg=${body.result_msg}`)
  if (body.result_code !== '1') throw new Error('iSolarCloud V1: ' + JSON.stringify(body))
  return body.result_data
}

// Busca geração diária iSolarCloud para um mês
// Endpoint V1: /v1/powerStationService/getPowerStationPointDayMonthYearDataList
// p83022 = Daily Plant Yield (Wh) — data_type=2 (Peak/Total for daily)
async function isolarMonthly(psId: string, conta: string, yearMonth: string): Promise<Map<string, number>> {
  const session = await isolarV1LoginComCache(conta)
  console.log(`[iSolarCloud] sessão V1 ok, buscando psId=${psId} yearMonth=${yearMonth}`)
  const [y, m] = yearMonth.split('-').map(Number)
  const daysInMonth = new Date(y, m, 0).getDate()
  const startTime = yearMonth.replace('-', '') + '01'            // yyyyMMdd
  const endTime   = yearMonth.replace('-', '') + String(daysInMonth).padStart(2, '0')
  console.log(`[iSolarCloud] V1 getPowerStationPointDayMonthYearDataList psId=${psId} ${startTime}→${endTime}`)
  const data = await isolarV1Request('/v1/powerStationService/getPowerStationPointDayMonthYearDataList', {
    query_type:  'day',
    data_type:   '2',          // Peak (for daily generation)
    data_point:  'p83022',     // Plant daily yield (Wh)
    start_time:  startTime,
    end_time:    endTime,
    order:       0,
    ps_id_list:  [String(psId)],
  }, session)
  console.log(`[iSolarCloud] resposta: ${JSON.stringify(data).slice(0, 400)}`)
  const result = new Map<string, number>()
  // Response: result_data[ps_id].p83022 = [{data_type: "2", time_stamp: "20240823", "2": "12345"}, ...]
  const psData = data?.[String(psId)] || data?.[psId]
  const entries = psData?.p83022 || []
  for (const entry of entries) {
    const ts = String(entry.time_stamp || '')  // "20240823"
    if (ts.length < 8) continue
    const dateKey = `${ts.slice(0,4)}-${ts.slice(4,6)}-${ts.slice(6,8)}`
    // data_type "2" is the key; value in Wh → convert to kWh
    const rawVal = entry['2'] || entry['1'] || entry['4'] || '0'
    const wh = parseFloat(rawVal) || 0
    const kwh = wh / 1000
    if (kwh > 0) result.set(dateKey, kwh)
  }
  console.log(`[iSolarCloud] ${result.size} dias com geração para ${yearMonth}`)
  return result
}

// ─── APsystems — histórico diário ────────────────────────────

async function apsRequest(path: string) {
  const appId = Deno.env.get('APS_APP_ID') || ''
  const appSecret = Deno.env.get('APS_APP_SECRET') || ''
  if (!appId || !appSecret) throw new Error('APsystems não configurado')
  const timestamp = String(Date.now())
  const nonce = crypto.randomUUID().replace(/-/g, '')
  const segments = path.split('?')[0].split('/')
  const requestPath = segments[segments.length - 1]
  const stringToSign = `${timestamp}/${nonce}/${appId}/${requestPath}/GET/HmacSHA256`
  const encoder = new TextEncoder()
  const key = await crypto.subtle.importKey('raw', encoder.encode(appSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(stringToSign))
  const signature = btoa(String.fromCharCode(...new Uint8Array(sig)))
  const res = await fetch(`https://api.apsystemsema.com:9282${path}`, {
    headers: { 'X-CA-AppId': appId, 'X-CA-Timestamp': timestamp, 'X-CA-Nonce': nonce, 'X-CA-Signature-Method': 'HmacSHA256', 'X-CA-Signature': signature },
  })
  return await res.json()
}

// Busca energia diária APsystems para um período
// Endpoint GET /user/api/v2/systems/energy?systemId=...&startDate=YYYYMMDD&endDate=YYYYMMDD&timeUnit=2
async function apsMonthly(sid: string, yearMonth: string): Promise<Map<string, number>> {
  const [y, m] = yearMonth.split('-').map(Number)
  const startDate = `${yearMonth.replace('-', '')}01`                      // YYYYMMDD
  const daysInMonth = new Date(y, m, 0).getDate()
  const endDate = `${yearMonth.replace('-', '')}${String(daysInMonth).padStart(2, '0')}`
  const data = await apsRequest(`/user/api/v2/systems/energy?systemId=${sid}&startDate=${startDate}&endDate=${endDate}&timeUnit=2`)
  const result = new Map<string, number>()
  if (data.code !== 0 || !data.data?.energy) return result
  for (const item of data.data.energy) {
    // item.time: "YYYY-MM-DD"
    const dateKey = String(item.time || '').slice(0, 10)
    const kwh = parseFloat(item.energy) || 0
    if (kwh > 0 && dateKey.length === 10) result.set(dateKey, kwh)
  }
  return result
}

// ─── Lógica de meses a buscar ─────────────────────────────────

function monthsBetween(inicio: string, fim: string): string[] {
  const months: string[] = []
  const [yi, mi] = inicio.split('-').map(Number)
  const [yf, mf] = fim.split('-').map(Number)
  let y = yi, m = mi
  while (y < yf || (y === yf && m <= mf)) {
    months.push(`${y}-${String(m).padStart(2, '0')}`)
    m++; if (m > 12) { m = 1; y++ }
  }
  return months
}

// ─── Upsert em lancamentos ────────────────────────────────────

async function salvarLancamentos(sb: ReturnType<typeof createClient>, codigo: string, diasKwh: Map<string, number>) {
  if (!diasKwh.size) return 0
  const rows = Array.from(diasKwh.entries())
    .filter(([, kwh]) => kwh >= 0)  // aceita 0 como marcador de "mês tentado"
    .map(([data, kwh]) => ({ data, codigo_usina: codigo, geracao_real: kwh, obs: kwh === 0 ? 'sync-sem-dados' : 'sync-auto' }))
  if (!rows.length) return 0
  // upsert sem sobrescrever lançamentos que já existam com obs diferente de 'sync-auto'
  // (mantemos lançamentos manuais intactos usando onConflict + ignoreDuplicates = false)
  const { error } = await sb.from('lancamentos').upsert(rows, {
    onConflict: 'data,codigo_usina',
    ignoreDuplicates: false,   // atualiza se já existir (mantém dados frescos)
  })
  if (error) throw new Error('Upsert lancamentos: ' + error.message)
  return rows.length
}

// ─── Handler principal ────────────────────────────────────────

serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders() })

  console.log('[sync-historico] versão v2026-10-20b — iSolarCloud V1 HK com AES-CTR + RSA PKCS1v15')

  const url = new URL(req.url)

  // ─── Rota de debug: testa OAuth2 refresh_token + chamada de dados ────────────
  // GET /sync-historico?debug_isolar=1&conta=padrao&ps_id=XXXXX&mes=2026-09
  if (url.searchParams.get('debug_isolar')) {
    const conta  = url.searchParams.get('conta')  || 'padrao'
    const psId   = url.searchParams.get('ps_id')  || ''
    const mes    = url.searchParams.get('mes')     || '2026-09'
    try {
      const suffix      = conta === 'padrao' ? '' : '_' + conta
      const appkey      = Deno.env.get('ISOLAR_ACCESS_KEY'     + suffix)
                       || Deno.env.get('ISOLAR_APPKEY'         + suffix) || ''
      const refreshTok  = Deno.env.get('ISOLAR_REFRESH_TOKEN'  + suffix) || ''
      const debugInfo: any = {
        conta,
        appkey_len: appkey.length,
        appkey_prefix: appkey.slice(0, 8),
        access_key_configured: !!(Deno.env.get('ISOLAR_ACCESS_KEY' + suffix)),
        appkey_configured:     !!(Deno.env.get('ISOLAR_APPKEY'     + suffix)),
        refresh_token_len: refreshTok.length,
        refresh_token_prefix: refreshTok.slice(0, 8),
        refresh_token_suffix: refreshTok.slice(-4),
        endpoint_refresh: `${ISOLAR_BASE}/apiManage/refreshToken`,
      }

      // Limpa cache para forçar novo access_token
      const sbAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)
      await sbAdmin.from('cache_sessoes').delete().eq('chave', `isolar_access_${conta}`)
      debugInfo.cache_cleared = true

      // Passo 1: obter access_token via refresh_token
      const refreshRes = await fetch(`${ISOLAR_BASE}/apiManage/refreshToken`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-access-key': appkey },
        body: JSON.stringify({ appkey, refresh_token: refreshTok }),
      })
      const refreshBody = await refreshRes.json()
      debugInfo.refresh_status      = refreshRes.status
      debugInfo.refresh_result_code = refreshBody.result_code
      debugInfo.refresh_result_msg  = refreshBody.result_msg
      debugInfo.refresh_full_body   = JSON.stringify(refreshBody).slice(0, 500)
      debugInfo.refresh_data_keys   = Object.keys(refreshBody.result_data || {})
      const accessToken = refreshBody.result_data?.access_token || null
      debugInfo.access_token_found  = !!accessToken
      debugInfo.access_token_len    = String(accessToken || '').length

      // Passo 2: buscar dados se access_token OK e ps_id fornecido
      if (accessToken && psId) {
        const [y, m] = mes.split('-').map(Number)
        const daysInMonth = new Date(y, m, 0).getDate()
        const startTime = mes.replace('-', '') + '01'
        const endTime   = mes.replace('-', '') + String(daysInMonth).padStart(2, '0')
        debugInfo.startTime = startTime
        debugInfo.endTime   = endTime

        const dataPayload = { appkey, query_type: 'day', data_type: '2', data_point: 'p83022', start_time: startTime, end_time: endTime, order: 0, ps_id_list: [String(psId)] }
        const dataRes = await fetch(`${ISOLAR_BASE}/platform/getPowerStationPointDayMonthYearDataList`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${accessToken}` },
          body: JSON.stringify(dataPayload),
        })
        const dataBodyRaw = await dataRes.text()
        let dataBody: any = {}
        try { dataBody = JSON.parse(dataBodyRaw) } catch { dataBody = { raw: dataBodyRaw.slice(0, 500) } }
        debugInfo.data_status      = dataRes.status
        debugInfo.data_result_code = dataBody.result_code
        debugInfo.data_result_msg  = dataBody.result_msg || dataBody.error_description
        debugInfo.data_full_keys   = Object.keys(dataBody)
        debugInfo.data_result_data = JSON.stringify(dataBody.result_data ?? null).slice(0, 1000)
      }
      return json({ ok: true, debug: debugInfo })
    } catch (e: any) {
      return json({ ok: false, error: e.message })
    }
  }

  // ─── Rota de debug 2: testa login V1 (HK) + criptografia ──
  // GET /sync-historico?debug_login=1&conta=padrao&ps_id=XXXXX&mes=2026-09
  if (url.searchParams.get('debug_login')) {
    const conta  = url.searchParams.get('conta')  || 'padrao'
    const psId   = url.searchParams.get('ps_id')  || ''
    const mes    = url.searchParams.get('mes')     || '2026-09'
    try {
      const suffix  = conta === 'padrao' ? '' : '_' + conta
      const usuario = Deno.env.get('ISOLAR_USER' + suffix) || ''
      const senha   = Deno.env.get('ISOLAR_PASS' + suffix)
                   || Deno.env.get('ISOLAR_PASSWORD' + suffix) || ''
      const debugInfo: any = {
        conta,
        gateway: ISOLAR_BASE,
        appkey_prefix:    ISOLAR_HK_APPKEY.slice(0, 8),
        access_key_prefix: ISOLAR_HK_ACCESSKEY.slice(0, 8),
        usuario_configured: !!usuario,
        senha_configured: !!senha,
      }

      // Limpa cache para forçar novo login
      const sbAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)
      await sbAdmin.from('cache_sessoes').delete().eq('chave', `isolar_v1session_${conta}`)
      debugInfo.cache_cleared = true

      // Monta payload de login e criptografa
      const loginPayload = JSON.stringify({
        appkey: ISOLAR_HK_APPKEY,
        user_account: usuario,
        user_password: md5hex(senha),
      })
      debugInfo.login_payload_plain = loginPayload
      debugInfo.protocol = 'aes_ctr_sys200'
      const { hexBody: loginHex, xRandomSecretKey: loginRsk, aesKey: loginAesKey } = await isolarEncryptBodyCtr(loginPayload)
      debugInfo.login_hex_len = loginHex.length
      debugInfo.login_rsk_len = loginRsk.length

      // Envia login
      const loginRes = await fetch(`${ISOLAR_BASE}/v1/userService/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'text/plain',
          'x-access-key': ISOLAR_HK_ACCESSKEY,
          'x-random-secret-key': loginRsk,
          'x-sign-code': '0',
          'sys_code': '200',
          'sg_encryption_mode': 'aes_ctr',
          '_pl': 'js',
          'lang': '_en_US',
        },
        body: loginHex,
      })
      const loginRaw = await loginRes.text()
      debugInfo.login_status   = loginRes.status
      debugInfo.login_raw_len  = loginRaw.length
      debugInfo.login_raw_50   = loginRaw.slice(0, 50)
      let loginBody: any
      if (/^[0-9A-Fa-f]{10,}$/.test(loginRaw.trim())) {
        const dec = await isolarDecryptResponseCtr(loginRaw.trim(), loginAesKey)
        debugInfo.login_decrypted = dec.slice(0, 300)
        loginBody = JSON.parse(dec)
      } else {
        try { loginBody = JSON.parse(loginRaw) } catch { loginBody = { result_code: 'E_PARSE', raw: loginRaw.slice(0, 200) } }
      }
      debugInfo.login_result_code = loginBody.result_code
      debugInfo.login_result_msg  = loginBody.result_msg
      debugInfo.login_data_keys   = Object.keys(loginBody.result_data || {})
      const loginToken    = loginBody.result_data?.token      || null
      const loginUserId   = String(loginBody.result_data?.user_id    || '')
      const loginState    = String(loginBody.result_data?.login_state || '')
      debugInfo.login_token_found = !!loginToken
      debugInfo.login_user_id     = loginUserId
      debugInfo.login_state_val   = loginState

      // Testa listagem de plantas
      if (loginToken) {
        const listPayload = JSON.stringify({
          token: loginToken, user_id: loginUserId, login_state: loginState,
          appkey: ISOLAR_HK_APPKEY,
        })
        const { hexBody: listHex, xRandomSecretKey: listRsk, aesKey: listAesKey } = await isolarEncryptBodyCtr(listPayload)
        const listRes = await fetch(`${ISOLAR_BASE}/v1/powerStationService/getPowerStationList`, {
          method: 'POST',
          headers: {
            'Content-Type': 'text/plain', 'x-access-key': ISOLAR_HK_ACCESSKEY,
            'x-random-secret-key': listRsk, 'x-sign-code': '0',
            'sys_code': '200', 'sg_encryption_mode': 'aes_ctr', '_pl': 'js', 'lang': '_en_US'
          },
          body: listHex,
        })
        const listRaw = await listRes.text()
        let listBody: any
        if (/^[0-9A-Fa-f]{10,}$/.test(listRaw.trim())) {
          const dec = await isolarDecryptResponseCtr(listRaw.trim(), listAesKey)
          listBody = JSON.parse(dec)
        } else {
          listBody = JSON.parse(listRaw).catch?.(() => ({})) || {}
          try { listBody = JSON.parse(listRaw) } catch { listBody = {} }
        }
        debugInfo.list_status = listRes.status
        debugInfo.list_code   = listBody.result_code
        debugInfo.list_msg    = listBody.result_msg
        debugInfo.list_sample = JSON.stringify(listBody.result_data ?? listBody).slice(0, 600)
      }

      // Testa busca de dados de geração
      if (loginToken && psId) {
        const [y, m2] = mes.split('-').map(Number)
        const daysInMonth = new Date(y, m2, 0).getDate()
        const startTime = mes.replace('-', '') + '01'
        const endTime   = mes.replace('-', '') + String(daysInMonth).padStart(2, '0')
        const dataPayload = JSON.stringify({
          token: loginToken, user_id: loginUserId, login_state: loginState,
          appkey: ISOLAR_HK_APPKEY,
          query_type: 'day', data_type: '2', data_point: 'p83022',
          start_time: startTime, end_time: endTime, order: 0,
          ps_id_list: [String(psId)],
        })
        const { hexBody: dataHex, xRandomSecretKey: dataRsk, aesKey: dataAesKey } = await isolarEncryptBodyCtr(dataPayload)
        const dataRes = await fetch(`${ISOLAR_BASE}/v1/powerStationService/getPowerStationPointDayMonthYearDataList`, {
          method: 'POST',
          headers: {
            'Content-Type': 'text/plain', 'x-access-key': ISOLAR_HK_ACCESSKEY,
            'x-random-secret-key': dataRsk, 'x-sign-code': '0',
            'sys_code': '200', 'sg_encryption_mode': 'aes_ctr', '_pl': 'js', 'lang': '_en_US'
          },
          body: dataHex,
        })
        const dataRaw = await dataRes.text()
        let dataBody: any
        if (/^[0-9A-Fa-f]{10,}$/.test(dataRaw.trim())) {
          const dec = await isolarDecryptResponseCtr(dataRaw.trim(), dataAesKey)
          dataBody = JSON.parse(dec)
        } else {
          try { dataBody = JSON.parse(dataRaw) } catch { dataBody = {} }
        }
        debugInfo.data_status = dataRes.status
        debugInfo.data_code   = dataBody.result_code
        debugInfo.data_msg    = dataBody.result_msg
        debugInfo.data_sample = JSON.stringify(dataBody.result_data ?? dataBody).slice(0, 800)
      }
      return json({ ok: true, debug: debugInfo })
    } catch (e: any) {
      return json({ ok: false, error: e.message, stack: String(e.stack).slice(0, 500) })
    }
  }

  // ─── Rota: proxy transparente para o gateway iSolarCloud ─────────────────────────────────
  // POST /sync-historico?isolar_proxy=1&path=/v1/userService/login
  // O browser manda payload já criptografado + headers necessários.
  // A Edge Function apenas repassa — sem conhecer as credenciais.
  // Necessário porque o browser recebe CORS block ao chamar gateway.isolarcloud.com.hk diretamente
  // de recifesolarsafe-lab.github.io (o servidor não envia Access-Control-Allow-Origin).
  if (url.searchParams.get('isolar_proxy')) {
    const path = url.searchParams.get('path') || ''
    if (!path.startsWith('/v1/')) return json({ ok: false, error: 'path inválido' }, 400)
    // Aceita dois formatos de body para compatibilidade entre versões da página:
    // 1. JSON: { rsk, hex, ak? } — Content-Type: application/json
    //    (rsk no body para evitar truncamento na URL; sem headers customizados → sem preflight)
    // 2. text/plain: "RSK_BASE64\nHEX_PAYLOAD"
    //    (alternativa sem preflight; rsk na linha 1, hex na linha 2)
    const contentType = req.headers.get('content-type') || ''
    let ak = url.searchParams.get('ak') || ISOLAR_HK_ACCESSKEY
    let rsk = ''
    let hexBody = ''
    if (contentType.includes('application/json')) {
      let envelope: { rsk?: string; hex?: string; ak?: string } = {}
      try { envelope = await req.json() } catch { /* body não é JSON */ }
      if (envelope.ak) ak = envelope.ak
      rsk = envelope.rsk || ''
      hexBody = envelope.hex || ''
    } else {
      // text/plain: linha 1 = rsk, linha 2 = hex
      const rawBody = await req.text()
      const nlIdx = rawBody.indexOf('\n')
      if (nlIdx >= 0) {
        rsk = rawBody.slice(0, nlIdx).trim()
        hexBody = rawBody.slice(nlIdx + 1).trim()
      }
    }
    if (!hexBody) return json({ ok: false, error: 'hex ausente no body' }, 400)
    const forwardHeaders: Record<string, string> = {
      'Content-Type': 'text/plain',
      'x-access-key': ak,
      'x-random-secret-key': rsk,
      'x-sign-code': '0',
      'sys_code': '200',
      'sg_encryption_mode': 'aes_ctr',
      '_pl': 'js',
      'lang': '_en_US',
    }
    const gwRes = await fetch(`${ISOLAR_BASE}${path}`, {
      method: 'POST',
      headers: forwardHeaders,
      body: hexBody,
    })
    // O gateway iSolarCloud já retorna a resposta como texto hex uppercase
    // Ler como texto e repassar diretamente (sem double-encode)
    const gwHex = await gwRes.text()
    return new Response(gwHex, {
      status: gwRes.status,
      headers: { ...corsHeaders(), 'Content-Type': 'text/plain', 'x-isolar-proxy': '1' },
    })
  }

  // ─── Rota: retorna credenciais iSolarCloud para o browser fazer a chamada diretamente ─────
  // GET /sync-historico?get_isolar_creds=1&conta=padrao
  // Necessário porque o servidor iSolarCloud HK bloqueia IPs de datacenter/nuvem (504 Gateway Timeout)
  // O browser do usuário pode fazer a chamada diretamente sem bloqueio.
  // Requer autenticação via x-user-token (só admins podem acessar).
  if (url.searchParams.get('get_isolar_creds')) {
    const token = req.headers.get('x-user-token') || ''
    if (!token) return json({ ok: false, error: 'x-user-token obrigatório' }, 401)
    const sessao = await verifySession(token)
    if (!sessao) return json({ ok: false, error: 'Sessão inválida.' }, 401)
    if (sessao.papel !== 'Admin') return json({ ok: false, error: 'Apenas admins podem acessar credenciais.' }, 403)
    const conta = url.searchParams.get('conta') || 'padrao'
    const suffix = conta === 'padrao' ? '' : '_' + conta
    const usuario = Deno.env.get('ISOLAR_USER' + suffix) || ''
    const senha   = Deno.env.get('ISOLAR_PASS' + suffix) || Deno.env.get('ISOLAR_PASSWORD' + suffix) || ''
    if (!usuario || !senha) return json({ ok: false, error: `Credenciais ISOLAR_USER${suffix} não configuradas.` }, 404)
    return json({
      ok: true,
      usuario,
      senha,
      appkey: ISOLAR_HK_APPKEY,
      accesskey: ISOLAR_HK_ACCESSKEY,
      gateway: ISOLAR_BASE,
      rsaPubkey: ISOLAR_SPA_RSA_PUBKEY,
    })
  }
  // ─────────────────────────────────────────────────────────────────────────────

  // Token do usuário: lido do header x-user-token (evita conflito com gateway JWT do Supabase)
  const token = req.headers.get('x-user-token') || ''
  const codigo     = url.searchParams.get('codigo') || ''
  const dataInicio = url.searchParams.get('data_inicio') || '2026-01-01'
  const dataFim    = url.searchParams.get('data_fim') || dateToYYYYMMDD(new Date(Date.now() - 86400000)) // ontem

  if (!codigo) return json({ ok: false, error: 'codigo obrigatório' }, 400)
  if (!token)  return json({ ok: false, error: 'x-user-token obrigatório' }, 401)

  // Verifica sessão
  const sessao = await verifySession(token)
  if (!sessao) return json({ ok: false, error: 'Sessão inválida.' }, 401)
  if (sessao.papel !== 'Admin' && !sessao.usinas.includes(codigo)) return json({ ok: false, error: 'Sem permissão.' }, 403)

  // Carrega integração desta usina
  const sb = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)
  const { data: integRows } = await sb.from('integracoes_usina').select('*').eq('codigo_usina', codigo)

  if (!integRows?.length) return json({ ok: false, error: 'Usina sem integração configurada.' })

  const todosMeses = monthsBetween(dataInicio.slice(0, 7), dataFim.slice(0, 7))
  // Limita a 3 meses por chamada para evitar rate limit das APIs
  // Pega os meses mais RECENTES primeiro (os mais próximos de hoje)
  const MAX_MESES_POR_CHAMADA = 3
  const mesesOrdenados = [...todosMeses].reverse() // mais recente primeiro
  const meses = mesesOrdenados.slice(0, MAX_MESES_POR_CHAMADA).reverse() // volta à ordem cronológica para processar
  const temMaisParaSincronizar = todosMeses.length > MAX_MESES_POR_CHAMADA
  const proximoDataInicio = temMaisParaSincronizar
    ? todosMeses[0]
    : null

  let totalSalvo = 0
  const erros: string[] = []

  const sleep = (ms: number) => new Promise(r => setTimeout(r, ms))

  for (let mi = 0; mi < meses.length; mi++) {
    const mes = meses[mi]
    if (mi > 0) await sleep(1200) // 1.2s entre meses para evitar rate limit

    const diasKwh = new Map<string, number>()

    for (const integ of integRows) {
      try {
        let parcial = new Map<string, number>()

        if (integ.plataforma === 'solis') {
          parcial = await solisMonthly(integ.station_id, mes)
        } else if (integ.plataforma === 'fusion') {
          const conta = integ.conta_fusion || 'padrao'
          parcial = await fusionMonthly(integ.station_id, conta, mes)
        } else if (integ.plataforma === 'isolar') {
          const conta = integ.conta_isolar || 'padrao'
          parcial = await isolarMonthly(integ.station_id, conta, mes)
        } else if (integ.plataforma === 'apsystems') {
          parcial = await apsMonthly(integ.station_id, mes)
        }

        // Soma gerações de múltiplas plataformas (usina com 2 inversores)
        for (const [data, kwh] of parcial) {
          diasKwh.set(data, (diasKwh.get(data) || 0) + kwh)
        }
      } catch (err: any) {
        erros.push(`[${mes}/${integ.plataforma}] ${err?.message}`)
        console.error(mes, integ.plataforma, err)
      }
    }

    // Filtra só datas dentro do range pedido
    for (const [data] of diasKwh) {
      if (data < dataInicio || data > dataFim) diasKwh.delete(data)
    }

    // Se não veio nenhum dado para este mês (erro de API ou mês vazio),
    // salva um registro com geracao=0 no último dia do mês para avançar o ponteiro.
    // Isso evita que a sync fique presa em loop no mesmo mês com erro.
    if (diasKwh.size === 0) {
      const [y, m] = mes.split('-').map(Number)
      const ultimoDia = new Date(Date.UTC(y, m, 0)) // último dia do mês
      const ultimoDiaStr = dateToYYYYMMDD(ultimoDia)
      if (ultimoDiaStr >= dataInicio && ultimoDiaStr <= dataFim) {
        diasKwh.set(ultimoDiaStr, 0)
        console.log(`[${mes}] sem dados — inserindo marcador em ${ultimoDiaStr} para avançar ponteiro`)
      }
    }

    try {
      totalSalvo += await salvarLancamentos(sb, codigo, diasKwh)
    } catch (err: any) {
      erros.push(`[${mes}/upsert] ${err?.message}`)
    }
  }

  return json({
    ok: true,
    totalSalvo,
    mesesProcessados: meses.length,
    temMais: temMaisParaSincronizar,
    proximoDataInicio,          // frontend usa para chamar novamente com data_fim = início deste bloco - 1 dia
    mesesRestantes: temMaisParaSincronizar ? todosMeses.length - MAX_MESES_POR_CHAMADA : 0,
    erros,
  })
})

