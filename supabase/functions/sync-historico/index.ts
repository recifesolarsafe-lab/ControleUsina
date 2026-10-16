// Supabase Edge Function: sync-historico  v2026-10-16l
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
const ISOLAR_BASE        = 'https://gateway.isolarcloud.com.hk/openapi'

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-user-token',
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
// Autenticação iSolarCloud (API OAuth2 para endpoints /platform/):
//
//   PASSO 1 — Obter access_token:
//     POST /openapi/apiManage/refreshToken
//     Body: { appkey, refresh_token }
//     Resposta: result_data.access_token, result_data.refresh_token (novo, se rotacionado)
//
//   PASSO 2 — Chamadas de dados:
//     POST /openapi/platform/...
//     Header: Authorization: Bearer <access_token>
//     Body: { appkey, ...params }   ← SEM token no body
//
// Env vars:
//   ISOLAR_APPKEY            — App Key registrado no portal developer
//   ISOLAR_REFRESH_TOKEN     — Refresh token OAuth2 (obtido uma vez no portal)
// (sufixo _<conta> para contas adicionais)
//
// O access_token é cacheado na tabela cache_sessoes por 55min (expira em 60min).
// O refresh_token é salvo de volta se a API retornar um novo (rotação).

async function isolarOAuth2Token(conta: string): Promise<{ accessToken: string; appkey: string }> {
  const suffix   = conta === 'padrao' ? '' : '_' + conta
  // ISOLAR_ACCESS_KEY é o appkey real registrado no portal developer.isolarcloud.com
  // ISOLAR_APPKEY é fallback (pode ter sido configurado com valor incorreto em alguns ambientes)
  const appkey   = Deno.env.get('ISOLAR_ACCESS_KEY'     + suffix)
               || Deno.env.get('ISOLAR_APPKEY'          + suffix) || ''
  const refreshToken = Deno.env.get('ISOLAR_REFRESH_TOKEN' + suffix) || ''

  if (!appkey)       throw new Error(`iSolarCloud: ISOLAR_ACCESS_KEY${suffix} não configurado`)
  if (!refreshToken) throw new Error(`iSolarCloud: ISOLAR_REFRESH_TOKEN${suffix} não configurado`)

  const sbAdmin  = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)
  const cacheKey = `isolar_access_${conta}`

  // Tenta usar access_token cacheado (validade 55min, expira em 60min)
  const { data: cached } = await sbAdmin
    .from('cache_sessoes')
    .select('dados, criado_em')
    .eq('chave', cacheKey)
    .single()
  if (cached) {
    const idadeSeg = (Date.now() - new Date(cached.criado_em).getTime()) / 1000
    if (idadeSeg < 3300) {  // 55 minutos
      console.log(`[iSolarCloud] access_token cacheado para conta="${conta}" (${Math.round(idadeSeg)}s)`)
      return cached.dados as { accessToken: string; appkey: string }
    }
  }

  console.log(`[iSolarCloud] obtendo access_token via refresh para conta="${conta}", appkey_prefix=${appkey.slice(0,8)}`)
  const res = await fetch(`${ISOLAR_BASE}/apiManage/refreshToken`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-access-key': appkey },
    body: JSON.stringify({ appkey, refresh_token: refreshToken }),
  })
  const body = await res.json()
  console.log(`[iSolarCloud] refreshToken result_code=${body.result_code} msg=${body.result_msg}`)
  console.log(`[iSolarCloud] refreshToken result_data keys: ${Object.keys(body.result_data || {}).join(', ')}`)
  if (body.result_code !== '1') throw new Error('iSolarCloud refreshToken: ' + JSON.stringify(body))

  const accessToken = body.result_data?.access_token
  if (!accessToken) throw new Error('iSolarCloud: access_token ausente na resposta: ' + JSON.stringify(body.result_data))

  const session = { accessToken, appkey }
  await sbAdmin.from('cache_sessoes').upsert(
    { chave: cacheKey, dados: session, criado_em: new Date().toISOString() },
    { onConflict: 'chave' }
  )
  console.log(`[iSolarCloud] access_token obtido e cacheado para conta="${conta}"`)
  return session
}

async function isolarPlatformRequest(path: string, payload: object, session: { accessToken: string; appkey: string }) {
  console.log(`[iSolarCloud] platform request ${path}`)
  const res = await fetch(`${ISOLAR_BASE}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${session.accessToken}`,
    },
    // access_token vai no header Authorization; appkey vai no body
    body: JSON.stringify({ appkey: session.appkey, ...payload }),
  })
  const body = await res.json()
  console.log(`[iSolarCloud] response ${path}: result_code=${body.result_code} msg=${body.result_msg || body.error_description}`)
  if (body.result_code !== '1') throw new Error('iSolarCloud: ' + JSON.stringify(body))
  return body.result_data
}

// Busca geração diária iSolarCloud para um mês
// Endpoint: /platform/getPowerStationPointDayMonthYearDataList
// p83022 = Daily Plant Yield (Wh) — data_type=2 (Peak/Total for daily)
async function isolarMonthly(psId: string, conta: string, yearMonth: string): Promise<Map<string, number>> {
  const session = await isolarOAuth2Token(conta)
  console.log(`[iSolarCloud] token ok, buscando psId=${psId} yearMonth=${yearMonth}`)
  const [y, m] = yearMonth.split('-').map(Number)
  const daysInMonth = new Date(y, m, 0).getDate()
  const startTime = yearMonth.replace('-', '') + '01'            // yyyyMMdd
  const endTime   = yearMonth.replace('-', '') + String(daysInMonth).padStart(2, '0')
  console.log(`[iSolarCloud] getPowerStationPointDayMonthYearDataList psId=${psId} ${startTime}→${endTime}`)
  const data = await isolarPlatformRequest('/platform/getPowerStationPointDayMonthYearDataList', {
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

  console.log('[sync-historico] versão v2026-10-16l — debug: Bearer + x-access-key juntos')

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

  // ─── Rota de debug 2: testa login user/senha (APPKEY no body, ACCESS_KEY no header) ──
  // GET /sync-historico?debug_login=1&conta=padrao&ps_id=XXXXX&mes=2026-09
  if (url.searchParams.get('debug_login')) {
    const conta  = url.searchParams.get('conta')  || 'padrao'
    const psId   = url.searchParams.get('ps_id')  || ''
    const mes    = url.searchParams.get('mes')     || '2026-09'
    try {
      const suffix    = conta === 'padrao' ? '' : '_' + conta
      // IMPORTANTE: appkey vai no BODY, accessKey vai no HEADER x-access-key
      const appkey    = Deno.env.get('ISOLAR_APPKEY'      + suffix) || ''
      const accessKey = Deno.env.get('ISOLAR_ACCESS_KEY'  + suffix) || appkey
      const usuario   = Deno.env.get('ISOLAR_USER'        + suffix) || ''
      const senha     = Deno.env.get('ISOLAR_PASS'        + suffix)
                     || Deno.env.get('ISOLAR_PASSWORD'    + suffix) || ''
      const debugInfo: any = {
        conta,
        appkey_len:       appkey.length,
        appkey_prefix:    appkey.slice(0, 8),
        access_key_len:   accessKey.length,
        access_key_prefix: accessKey.slice(0, 8),
        access_key_same_as_appkey: appkey === accessKey,
        usuario_configured: !!usuario,
        senha_configured: !!senha,
      }

      // Passo 1: login — appkey no body, accessKey no header
      const loginRes = await fetch(`${ISOLAR_BASE}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-access-key': accessKey,
          'sys_code': '901',
          'lang': '_en_US',
        },
        body: JSON.stringify({ appkey, user_account: usuario, user_password: senha }),
      })
      const loginBody = await loginRes.json()
      debugInfo.login_status      = loginRes.status
      debugInfo.login_result_code = loginBody.result_code
      debugInfo.login_result_msg  = loginBody.result_msg
      debugInfo.login_full_body   = JSON.stringify(loginBody).slice(0, 300)
      debugInfo.login_data_keys   = Object.keys(loginBody.result_data || {})
      const loginToken = loginBody.result_data?.token || null
      debugInfo.login_token_found = !!loginToken
      debugInfo.login_token_len   = String(loginToken || '').length

      // Passo 2: se login OK, testa chamada de dados com token no BODY (não como Bearer)
      if (loginToken && psId) {
        const [y, m] = mes.split('-').map(Number)
        const daysInMonth = new Date(y, m, 0).getDate()
        const startTime = mes.replace('-', '') + '01'
        const endTime   = mes.replace('-', '') + String(daysInMonth).padStart(2, '0')

        // Variante A: token no body (conforme documentação original)
        const dataPayloadA = { token: loginToken, appkey, query_type: 'day', data_type: '2', data_point: 'p83022', start_time: startTime, end_time: endTime, order: 0, ps_id_list: [String(psId)] }
        const dataResA = await fetch(`${ISOLAR_BASE}/platform/getPowerStationPointDayMonthYearDataList`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-access-key': accessKey },
          body: JSON.stringify(dataPayloadA),
        })
        const dataBodyA = await dataResA.json().catch(() => ({}))
        debugInfo.data_tokenInBody_status = dataResA.status
        debugInfo.data_tokenInBody_code   = dataBodyA.result_code
        debugInfo.data_tokenInBody_msg    = dataBodyA.result_msg || dataBodyA.error_description

        // Variante B: token como Bearer + x-access-key no header
        const dataPayloadB = { appkey, query_type: 'day', data_type: '2', data_point: 'p83022', start_time: startTime, end_time: endTime, order: 0, ps_id_list: [String(psId)] }
        const dataResB = await fetch(`${ISOLAR_BASE}/platform/getPowerStationPointDayMonthYearDataList`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${loginToken}`,
            'x-access-key': accessKey,
          },
          body: JSON.stringify(dataPayloadB),
        })
        const dataBodyB = await dataResB.json().catch(() => ({}))
        debugInfo.data_tokenBearer_status = dataResB.status
        debugInfo.data_tokenBearer_code   = dataBodyB.result_code
        debugInfo.data_tokenBearer_msg    = dataBodyB.result_msg || dataBodyB.error_description
        debugInfo.data_tokenBearer_sample = dataBodyB.result_code === '1'
          ? JSON.stringify(dataBodyB.result_data).slice(0, 300)
          : JSON.stringify(dataBodyB).slice(0, 300)
      }
      return json({ ok: true, debug: debugInfo })
    } catch (e: any) {
      return json({ ok: false, error: e.message })
    }
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
