// ============================================================
// KRONOS-CB — núcleo compartido (Coinbase futuros + Vercel)
// Basado en la arquitectura de klaros2 (Kalshi/Netlify).
// Sin dependencias de npm: solo crypto y fetch nativos de Node.
// ============================================================
const crypto = require('crypto');

const BOT_VER = 'v1.5';
const SELLO = 'v1.5 · 2026-08-02 23-30ET'; // mismo sello que el nombre del zip
const MAX_CONTRATOS = 1; // tope duro: ninguna configuración puede pasar de aquí
const FOTO_VER = BOT_VER; // queda grabado en cada señal

const CB_HOST = 'api.coinbase.com';
const CB_BASE = '/api/v3/brokerage';

const CLAVE_PANEL = process.env.CLAVE_PANEL || process.env.ADMIN_PASSWORD || '';
const CRON_SECRET = process.env.CRON_SECRET || '';

const CB_KEY_NAME = process.env.COINBASE_KEY_NAME || process.env.COINBASE_API_KEY || '';
const CB_KEY_SECRET_RAW = process.env.COINBASE_KEY_SECRET || process.env.COINBASE_API_SECRET || '';

// ---------- Utilidades ----------
function ahoraISO() { return new Date(Date.now()).toISOString(); }
function nuevoId() { return crypto.randomBytes(8).toString('hex'); }
function centavos(usd) { return Math.round(Number(usd) * 100); }
function aUsd(cents) { return (Number(cents) / 100); }
function num(v, porDefecto) {
  const n = Number(v);
  return Number.isFinite(n) ? n : porDefecto;
}
function limita(v, min, max) { return Math.min(max, Math.max(min, v)); }

// ------------------------------------------------------------
// LLAVE PRIVADA — normalizador único.
// Lección de klaros1/2/3/5: había dos normalizadores conviviendo y el que
// se usaba al firmar fallaba si la variable llegaba entre comillas.
// Este acepta las cinco formas de estropearla:
//   1) PEM correcto
//   2) con \n literales
//   3) entre comillas simples o dobles
//   4) con los saltos convertidos en espacios
//   5) con \r\n
// Y además la forma base64 cruda (32 o 64 bytes) que da el portal CDP para Ed25519.
// ------------------------------------------------------------
function normalizaLlave(bruta) {
  if (!bruta || typeof bruta !== 'string') throw new Error('llave vacía');
  let s = bruta.trim();
  // comillas envolventes
  while ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    s = s.slice(1, -1).trim();
  }
  s = s.replace(/\\r/g, '').replace(/\\n/g, '\n').replace(/\r/g, '');

  if (s.includes('BEGIN')) {
    const m = s.match(/BEGIN ([A-Z0-9 ]+?)-----([\s\S]*?)-----END/);
    if (!m) throw new Error('PEM ilegible: no encuentro el cuerpo');
    const tipo = m[1].trim();
    const cuerpo = m[2].replace(/[^A-Za-z0-9+/=]/g, ''); // mata espacios, saltos y lo que sea
    if (!cuerpo) throw new Error('PEM ilegible: cuerpo vacío');
    const lineas = cuerpo.match(/.{1,64}/g).join('\n');
    return {
      pem: `-----BEGIN ${tipo}-----\n${lineas}\n-----END ${tipo}-----\n`,
      origen: 'pem',
    };
  }

  // base64 cruda -> Ed25519
  const limpia = s.replace(/[^A-Za-z0-9+/=]/g, '');
  let bytes;
  try { bytes = Buffer.from(limpia, 'base64'); } catch (e) { throw new Error('llave ilegible'); }
  if (bytes.length !== 32 && bytes.length !== 64) {
    throw new Error(`llave ilegible: ${bytes.length} bytes (esperaba PEM, 32 o 64)`);
  }
  const semilla = bytes.subarray(0, 32);
  // PKCS8 para Ed25519: prefijo fijo + los 32 bytes de la semilla
  const prefijo = Buffer.from('302e020100300506032b657004220420', 'hex');
  const der = Buffer.concat([prefijo, semilla]);
  const b64 = der.toString('base64').match(/.{1,64}/g).join('\n');
  return {
    pem: `-----BEGIN PRIVATE KEY-----\n${b64}\n-----END PRIVATE KEY-----\n`,
    origen: 'base64-ed25519',
  };
}

let LLAVE_CACHE = null;
function cargaLlave(bruta) {
  const fuente = bruta === undefined ? CB_KEY_SECRET_RAW : bruta;
  if (bruta === undefined && LLAVE_CACHE) return LLAVE_CACHE;
  const { pem, origen } = normalizaLlave(fuente);
  const objeto = crypto.createPrivateKey(pem);
  const tipo = objeto.asymmetricKeyType; // 'ec' | 'ed25519'
  let alg;
  if (tipo === 'ed25519') alg = 'EdDSA';
  else if (tipo === 'ec') alg = 'ES256';
  else throw new Error(`tipo de llave no soportado: ${tipo}`);
  const res = { objeto, alg, origen, tipo };
  if (bruta === undefined) LLAVE_CACHE = res;
  return res;
}

function b64url(buf) {
  return Buffer.from(buf).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// JWT de CDP: caduca en 120 s y va atado al método + ruta exactos.
function construyeJwt(metodo, ruta, opciones) {
  const o = opciones || {};
  const nombre = o.nombre !== undefined ? o.nombre : CB_KEY_NAME;
  if (!nombre) throw new Error('falta COINBASE_KEY_NAME');
  const llave = cargaLlave(o.secreto);
  const ahora = Math.floor(Date.now() / 1000);
  const rutaSinQuery = String(ruta).split('?')[0];
  const cabecera = {
    alg: llave.alg,
    kid: nombre,
    typ: 'JWT',
    nonce: crypto.randomBytes(16).toString('hex'),
  };
  const carga = {
    iss: 'cdp',
    sub: nombre,
    nbf: ahora,
    exp: ahora + 120,
    uri: `${metodo.toUpperCase()} ${CB_HOST}${rutaSinQuery}`,
  };
  const cuerpo = `${b64url(JSON.stringify(cabecera))}.${b64url(JSON.stringify(carga))}`;
  let firma;
  if (llave.alg === 'ES256') {
    firma = crypto.sign('sha256', Buffer.from(cuerpo), {
      key: llave.objeto,
      dsaEncoding: 'ieee-p1363', // JOSE quiere R||S crudo, no DER
    });
  } else {
    firma = crypto.sign(null, Buffer.from(cuerpo), llave.objeto);
  }
  return `${cuerpo}.${b64url(firma)}`;
}

// ------------------------------------------------------------
// ALMACENAMIENTO — Redis por REST (Upstash desde el Marketplace de Vercel).
// Por qué Redis y no Vercel Blob: el blob se sirve por CDN y puede devolver
// una copia vieja. Un bot que corre cada minuto leyendo estado viejo abre
// la posición dos veces. Redis es consistente y además da el cerrojo.
// Si no hay almacén configurado, el bot NO ordena (ver reglas de seguridad).
// ------------------------------------------------------------
const REDIS_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL || '';
const REDIS_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN || '';
const PREFIJO = process.env.PREFIJO_ALMACEN || 'kronos-cb';
const MEM = new Map(); // respaldo en memoria: solo para pruebas, se pierde entre llamadas

function hayAlmacen() { return Boolean(REDIS_URL && REDIS_TOKEN); }

function redisMem(comando) {
  const [op, clave, valor] = comando;
  if (op === 'GET') return MEM.has(clave) ? MEM.get(clave) : null;
  if (op === 'SET') { MEM.set(clave, valor); return 'OK'; }
  if (op === 'DEL') { MEM.delete(clave); return 1; }
  return null;
}

async function redis(comando) {
  if (!hayAlmacen()) return redisMem(comando);
  const r = await fetch(REDIS_URL, {
    method: 'POST',
    headers: { Authorization: `Bearer ${REDIS_TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify(comando),
  });
  const txt = await r.text();
  let j = null;
  try { j = JSON.parse(txt); } catch (e) { throw new Error(`almacén: respuesta ilegible (HTTP ${r.status})`); }
  if (!r.ok || (j && j.error)) throw new Error(`almacén: ${(j && j.error) || 'HTTP ' + r.status}`);
  return j.result;
}

const K = {
  estado: () => `${PREFIJO}:estado`,
  senales: () => `${PREFIJO}:senales`,            // clave antigua (v1.2 la migra a páginas)
  indice: () => `${PREFIJO}:senales:idx`,
  pagina: (n) => `${PREFIJO}:senales:p${n}`,
  cerrojo: () => `${PREFIJO}:cerrojo`,
};

// Varios comandos en una sola petición HTTP. Upstash limita el tamaño de cada
// petición, y por eso las señales van en páginas en vez de en un solo bloque:
// con 2.000 señales un único SET no cabría.
async function redisTanda(comandos) {
  if (!comandos.length) return [];
  if (!hayAlmacen()) return comandos.map((c) => redisMem(c));
  const r = await fetch(`${REDIS_URL}/pipeline`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${REDIS_TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify(comandos),
  });
  const txt = await r.text();
  let j = null;
  try { j = JSON.parse(txt); } catch (e) { throw new Error(`almacén: tanda ilegible (HTTP ${r.status})`); }
  if (!r.ok) throw new Error(`almacén: tanda HTTP ${r.status}`);
  return (Array.isArray(j) ? j : []).map((x) => (x && x.result !== undefined ? x.result : null));
}

async function leeJson(clave, porDefecto) {
  const v = await redis(['GET', clave]);
  if (v === null || v === undefined) return porDefecto;
  try { return JSON.parse(v); } catch (e) { return porDefecto; }
}
async function guardaJson(clave, valor) {
  await redis(['SET', clave, JSON.stringify(valor)]);
}

// Cerrojo: evita que dos corridas del cron se pisen (Vercel no impide solapamiento).
async function tomaCerrojo(segundos) {
  const marca = nuevoId();
  if (!hayAlmacen()) {
    if (MEM.get('cerrojo')) return null;
    MEM.set('cerrojo', marca);
    return marca;
  }
  const r = await redis(['SET', K.cerrojo(), marca, 'NX', 'EX', String(segundos || 55)]);
  return r === 'OK' ? marca : null;
}
async function sueltaCerrojo() {
  if (!hayAlmacen()) { MEM.delete('cerrojo'); return; }
  try { await redis(['DEL', K.cerrojo()]); } catch (e) { /* que expire solo */ }
}

// ------------------------------------------------------------
// ESTADO
// ------------------------------------------------------------
function ajustesDeFabrica() {
  return {
    prefijoProducto: 'BIP',   // BIP = nano perpetuo (no vence) · BIT = nano mensual
    contratos: 1,             // 1 contrato = 0,01 BTC. Tope duro, no se puede subir
    minutosAntes: 5,          // entra cuando falten ~N minutos para el cierre de la ventana
    tolMin: 1.0,              // tolerancia +/- en minutos
    momentumMin: 10,          // cuántos minutos de velas mira para medir la deriva
    umbralSigma: 1.6,         // v1.2: la deriva debe superar N veces el ruido típico
    minDerivaUsd: 300,        // v1.2 final: y además N dólares de movimiento de BTC
    minCoherencia: 0.6,       // v1.2: fracción de minutos que deben ir en la misma dirección
    comisionPct: 0.001,       // 0,1% por lado (lo que cobra Coinbase en el perpetuo nano)
    multiploCoste: 1.0,       // v1.2: suelo de no-pérdida; con 1.0 manda minDerivaUsd
    stopCents: 600,           // v1.2: cierra ya si pierde $6 sin realizar
    objetivoCents: 800,       // cierra ya si gana $8
    usarObjetivo: true,
    salirAlCierre: true,      // cierra siempre al terminar la ventana de 15'
    maxPerdidaDiaCents: 1200, // v1.2: $12 de pérdida en el día -> se apaga
    maxOperacionesDia: 4,     // v1.2
    deslizamientoCents: 0,    // reservado: por ahora entra a mercado (IOC)
    // v1.1 — horario de margen barato
    soloMargenBarato: true,   // no operar cuando Coinbase exige el margen alto
    colchonCierreMin: 20,     // no abrir en los N min previos a las 4pm ET
    // v1.1 — libro
    exigirLibro: true,        // sin poder leer el libro, no ordena
    maxDiferencialUsd: 25,    // diferencial máximo aceptable entre compra y venta
  };
}

function estadoDeFabrica() {
  return {
    ver: BOT_VER,
    creado: ahoraISO(),
    encendido: false,          // ARRANCA APAGADO a propósito: lo enciendes tú desde el panel
    modo: 'real',              // v1.3: arranca en dinero real. Sigue apagado hasta que tú lo enciendas
    ajustes: ajustesDeFabrica(),
    posicion: null,
    avisoTipo: null,           // 'lectura' | 'ajena' — para poder retirar el aviso al recuperarse
    producto: null,            // { id, caducidad, elegidoISO }
    diario: { fecha: null, operaciones: 0, plCents: 0, arriesgadoCents: 0, ganadas: 0, perdidas: 0 },
    corteContadorISO: null,
    ultimaCorrida: null,
    aviso: null,               // avisos en rojo para el panel (posición huérfana, credenciales, etc.)
    migraciones: { corte100: ahoraISO(), riesgo12: ahoraISO(), deriva300: ahoraISO(), modoReal13: ahoraISO() },
  };
}

function aplicaMigraciones(e) {
  e.migraciones = e.migraciones || {};
  e.migro = false;
  const base = ajustesDeFabrica();
  for (const k of Object.keys(base)) {
    if (e.ajustes[k] === undefined) e.ajustes[k] = base[k];
  }
  if (!e.migraciones.corte100) {
    e.corteContadorISO = e.corteContadorISO || ahoraISO();
    e.migraciones.corte100 = ahoraISO();
    e.migro = true;
  }
  // v1.2: los ajustes de riesgo se imponen una vez sobre el estado ya guardado.
  // Sin esto, un bot que ya venía corriendo se quedaría con el stop y los topes viejos.
  if (!e.migraciones.riesgo12) {
    e.ajustes.contratos = 1;
    e.ajustes.stopCents = 600;
    e.ajustes.maxPerdidaDiaCents = 1200;
    e.ajustes.maxOperacionesDia = 4;
    e.ajustes.umbralSigma = 1.6;
    e.ajustes.minDerivaUsd = 300;
    e.ajustes.minCoherencia = 0.6;
    e.ajustes.multiploCoste = 1.0;
    e.ajustes.comisionPct = 0.001;
    e.migraciones.riesgo12 = ahoraISO();
    e.migro = true;
  }
  // La v1.2 intermedia dejó minDerivaUsd en 150. Esta marca aparte hace que el
  // cambio a 300 llegue también a los bots que ya habían corrido aquella.
  if (!e.migraciones.deriva300) {
    if (e.ajustes.minDerivaUsd < 300) e.ajustes.minDerivaUsd = 300;
    e.migraciones.deriva300 = ahoraISO();
    e.migro = true;
  }
  // v1.3: el modo por defecto pasa a real. El estado ya guardado dice 'sombra',
  // así que hace falta imponerlo una vez — igual que con los ajustes de riesgo.
  // NO toca el interruptor: el bot sigue apagado hasta que lo enciendas.
  if (!e.migraciones.modoReal13) {
    if (!e.posicion) e.modo = 'real';
    e.migraciones.modoReal13 = ahoraISO();
    e.migro = true;
  }
  if (e.ajustes.contratos > MAX_CONTRATOS) e.ajustes.contratos = MAX_CONTRATOS;
  return e;
}

async function leeEstado() {
  const guardado = await leeJson(K.estado(), null);
  if (!guardado) return estadoDeFabrica();
  const e = Object.assign(estadoDeFabrica(), guardado);
  e.ajustes = Object.assign(ajustesDeFabrica(), guardado.ajustes || {});
  e.diario = Object.assign(estadoDeFabrica().diario, guardado.diario || {});
  const listo = aplicaMigraciones(e);
  if (listo.migro) {
    delete listo.migro;
    await guardaEstado(listo); // se persiste ya, si no vuelve a pisar los ajustes
  }
  delete listo.migro;
  return listo;
}
async function guardaEstado(e) {
  e.ver = BOT_VER;
  await guardaJson(K.estado(), e);
}

const TOPE_SENALES = 2000;   // v1.2: más del triple que antes (eran 600)
const TAM_PAGINA = 250;      // señales por página; cada página cabe de sobra en una petición

async function leeIndice() {
  const v = await redis(['GET', K.indice()]);
  if (v) {
    try {
      const j = JSON.parse(v);
      if (Number.isFinite(j.desde) && Number.isFinite(j.hasta)) return j;
    } catch (e) { /* índice ilegible: se reconstruye */ }
  }
  // Migración desde la clave única de v1.0/v1.1: se reparte en páginas y se borra.
  const antiguo = await redis(['GET', K.senales()]);
  if (antiguo) {
    let lista = [];
    try { lista = JSON.parse(antiguo) || []; } catch (e) { lista = []; }
    if (Array.isArray(lista) && lista.length) {
      const comandos = [];
      let n = 0;
      for (let i = 0; i < lista.length; i += TAM_PAGINA) {
        comandos.push(['SET', K.pagina(n), JSON.stringify(lista.slice(i, i + TAM_PAGINA))]);
        n += 1;
      }
      const idx = { desde: 0, hasta: n - 1 };
      comandos.push(['SET', K.indice(), JSON.stringify(idx)]);
      comandos.push(['DEL', K.senales()]);
      await redisTanda(comandos);
      return idx;
    }
  }
  return { desde: 0, hasta: 0 };
}

async function leePagina(n) {
  const v = await redis(['GET', K.pagina(n)]);
  if (!v) return [];
  try { const j = JSON.parse(v); return Array.isArray(j) ? j : []; } catch (e) { return []; }
}

// Devuelve las señales de más antigua a más nueva. Con `ultimas` solo abre las
// páginas necesarias, para no leer 2.000 filas cuando el panel muestra 60.
async function leeSenales(ultimas) {
  const idx = await leeIndice();
  let primera = idx.desde;
  if (ultimas) {
    const paginasNecesarias = Math.ceil(ultimas / TAM_PAGINA) + 1;
    primera = Math.max(idx.desde, idx.hasta - paginasNecesarias + 1);
  }
  const comandos = [];
  for (let n = primera; n <= idx.hasta; n++) comandos.push(['GET', K.pagina(n)]);
  const crudas = await redisTanda(comandos);
  const salida = [];
  for (const v of crudas) {
    if (!v) continue;
    try {
      const j = JSON.parse(v);
      if (Array.isArray(j)) salida.push(...j);
    } catch (e) { /* página ilegible: se salta, no se pierde el resto */ }
  }
  return ultimas ? salida.slice(-ultimas) : salida;
}

async function anadeSenal(s) {
  const idx = await leeIndice();
  let pagina = await leePagina(idx.hasta);
  const comandos = [];
  if (pagina.length >= TAM_PAGINA) {
    idx.hasta += 1;
    pagina = [];
  }
  pagina.push(s);
  comandos.push(['SET', K.pagina(idx.hasta), JSON.stringify(pagina)]);

  // Poda: se tira la página más vieja cuando se pasa del tope. Se guarda una
  // página de margen para que, justo después de podar, nunca queden menos de
  // TOPE_SENALES: si no, la capacidad real oscilaría entre 1.750 y 2.000.
  const cabenPaginas = Math.ceil(TOPE_SENALES / TAM_PAGINA) + 1;
  while (idx.hasta - idx.desde + 1 > cabenPaginas) {
    comandos.push(['DEL', K.pagina(idx.desde)]);
    idx.desde += 1;
  }
  comandos.push(['SET', K.indice(), JSON.stringify(idx)]);
  await redisTanda(comandos);
  return s;
}

// Se busca de la página más nueva hacia atrás: lo que se actualiza es siempre
// la señal abierta, que está al final.
async function actualizaSenal(id, cambios) {
  const idx = await leeIndice();
  for (let n = idx.hasta; n >= idx.desde; n--) {
    const pagina = await leePagina(n);
    const i = pagina.findIndex((x) => x.id === id);
    if (i >= 0) {
      pagina[i] = Object.assign({}, pagina[i], cambios);
      await redis(['SET', K.pagina(n), JSON.stringify(pagina)]);
      return pagina[i];
    }
  }
  return null;
}

// Reescritura completa. Solo la usa el borrado con triple cerrojo.
async function guardaSenales(lista) {
  const idx = await leeIndice();
  const comandos = [];
  for (let n = idx.desde; n <= idx.hasta; n++) comandos.push(['DEL', K.pagina(n)]);
  const cortada = (lista || []).slice(-TOPE_SENALES);
  let n = 0;
  if (cortada.length) {
    for (let i = 0; i < cortada.length; i += TAM_PAGINA) {
      comandos.push(['SET', K.pagina(n), JSON.stringify(cortada.slice(i, i + TAM_PAGINA))]);
      n += 1;
    }
    n -= 1;
  }
  comandos.push(['SET', K.indice(), JSON.stringify({ desde: 0, hasta: n })]);
  await redisTanda(comandos);
}

// ------------------------------------------------------------
// CLIENTE DE COINBASE
// ------------------------------------------------------------
// Un 502 de Coinbase llega como página HTML. Volcarla entera en el panel deja
// un aviso ilegible; y peor: si el fallo es pasajero, el bot se queda sin operar
// por un tropiezo de un segundo.
function limpiaError(txt, estado) {
  const s = String(txt || '').trim();
  if (/^\s*</.test(s) || /<html/i.test(s)) {
    return `Coinbase devolvió una página de error (HTTP ${estado}), no datos. Suele ser un tropiezo pasajero de su lado.`;
  }
  return `HTTP ${estado} ${s.slice(0, 160)}`;
}

const REINTENTOS = 3;
const ESPERA_MS = [400, 1200];

function esperar(ms) { return new Promise((r) => setTimeout(r, ms)); }

// Solo se reintenta lo que se puede repetir sin consecuencias: lecturas.
// Una orden JAMÁS se reintenta — un reintento a ciegas puede abrir dos posiciones.
function reintentable(metodo, estado) {
  return metodo === 'GET' && (estado === 0 || estado === 429 || estado >= 500);
}

async function cbPublico(ruta) {
  let ultimo = null;
  for (let intento = 0; intento < REINTENTOS; intento++) {
    let r = null;
    let txt = '';
    try {
      r = await fetch(`https://${CB_HOST}${CB_BASE}${ruta}`, {
        headers: { 'cache-control': 'no-cache', accept: 'application/json' },
      });
      txt = await r.text();
    } catch (err) {
      ultimo = new Error(`Coinbase ${ruta}: sin respuesta (${err.message})`);
      if (intento < REINTENTOS - 1) { await esperar(ESPERA_MS[intento]); continue; }
      throw ultimo;
    }
    if (r.ok) {
      try { return JSON.parse(txt); } catch (e) { return null; }
    }
    ultimo = new Error(`Coinbase ${ruta}: ${limpiaError(txt, r.status)}`);
    if (reintentable('GET', r.status) && intento < REINTENTOS - 1) {
      await esperar(ESPERA_MS[intento]);
      continue;
    }
    throw ultimo;
  }
  throw ultimo;
}

async function cbFirmado(metodo, ruta, cuerpo) {
  if (!CB_KEY_NAME || !CB_KEY_SECRET_RAW) {
    const e = new Error('faltan credenciales de Coinbase (COINBASE_KEY_NAME / COINBASE_KEY_SECRET)');
    e.credencial = true;
    throw e;
  }
  let jwt;
  try {
    jwt = construyeJwt(metodo, `${CB_BASE}${ruta}`);
  } catch (err) {
    const e = new Error(`llave ilegible: ${err.message}`);
    e.credencial = true;
    throw e;
  }
  const opciones = {
    method: metodo,
    headers: {
      Authorization: `Bearer ${jwt}`,
      'content-type': 'application/json',
      accept: 'application/json',
    },
  };
  if (cuerpo !== undefined) opciones.body = JSON.stringify(cuerpo);

  let r = null;
  let txt = '';
  try {
    r = await fetch(`https://${CB_HOST}${CB_BASE}${ruta}`, opciones);
    txt = await r.text();
  } catch (err) {
    throw new Error(`Coinbase ${metodo} ${ruta}: sin respuesta (${err.message})`);
  }
  let j = null;
  try { j = JSON.parse(txt); } catch (e) { /* deja j en null */ }
  if (r.status === 401 || r.status === 403) {
    const e = new Error(`Coinbase rechazó la credencial (HTTP ${r.status})`);
    e.credencial = true;
    throw e;
  }
  if (!r.ok) throw new Error(`Coinbase ${metodo} ${ruta}: ${limpiaError(txt, r.status)}`);
  return j;
}

// Envoltorio con reintentos SOLO para lecturas firmadas (posiciones, saldo,
// detalle de orden). Las escrituras pasan por cbFirmado a pelo, sin reintento.
async function cbFirmadoLee(ruta) {
  let ultimo = null;
  for (let intento = 0; intento < REINTENTOS; intento++) {
    try {
      return await cbFirmado('GET', ruta);
    } catch (err) {
      ultimo = err;
      if (err.credencial) throw err;
      const m = String(err.message).match(/HTTP (\d{3})/);
      const estado = m ? Number(m[1]) : (/sin respuesta|página de error/.test(err.message) ? 502 : 0);
      if (reintentable('GET', estado) && intento < REINTENTOS - 1) {
        await esperar(ESPERA_MS[intento]);
        continue;
      }
      throw err;
    }
  }
  throw ultimo;
}

// Lista de futuros y elección del contrato.
async function listaFuturos() {
  const j = await cbPublico('/market/products?product_type=FUTURE&limit=250');
  return (j && j.products) || [];
}

function caducidadDe(p) {
  const d = p.future_product_details || {};
  const s = d.contract_expiry || (d.contract_expiry_type === 'PERPETUAL' ? null : null);
  const t = s ? Date.parse(s) : NaN;
  return Number.isFinite(t) ? t : Infinity;
}

async function eligeProducto(prefijo) {
  const todos = await listaFuturos();
  const ahora = Date.now();
  const candidatos = todos.filter((p) => {
    const id = String(p.product_id || '');
    if (!id.startsWith(prefijo)) return false;
    if (p.trading_disabled || p.is_disabled) return false;
    if (p.status && String(p.status).toLowerCase() === 'offline') return false;
    const cad = caducidadDe(p);
    return cad === Infinity || cad > ahora + 60 * 60 * 1000; // no entres en algo que vence en menos de 1 h
  });
  if (!candidatos.length) {
    throw new Error(`no hay contrato disponible con prefijo ${prefijo}`);
  }
  candidatos.sort((a, b) => caducidadDe(a) - caducidadDe(b));
  const p = candidatos[0];
  return {
    id: p.product_id,
    caducidad: (p.future_product_details && p.future_product_details.contract_expiry) || null,
    elegidoISO: ahoraISO(),
  };
}

async function precioProducto(id) {
  const j = await cbPublico(`/market/products/${encodeURIComponent(id)}`);
  const p = Number(j && j.price);
  if (!Number.isFinite(p) || p <= 0) throw new Error(`precio ilegible de ${id}`);
  return p;
}

async function velasSpot(minutos) {
  const fin = Math.floor(Date.now() / 1000);
  const ini = fin - (minutos + 2) * 60;
  const j = await cbPublico(
    `/market/products/BTC-USD/candles?start=${ini}&end=${fin}&granularity=ONE_MINUTE&limit=${minutos + 5}`
  );
  const velas = ((j && j.candles) || []).map((c) => ({
    t: Number(c.start) * 1000,
    cierre: Number(c.close),
  })).filter((c) => Number.isFinite(c.t) && Number.isFinite(c.cierre));
  velas.sort((a, b) => a.t - b.t); // viejas primero
  return velas;
}

async function balanceFuturos() {
  const j = await cbFirmadoLee('/cfm/balance_summary');
  // Si no viene el envoltorio, se devuelve la respuesta entera: antes se
  // perdían los campos y el panel enseñaba un saldo vacío que no era real.
  return (j && (j.balance_summary || j)) || {};
}

async function posicionesFuturos() {
  const j = await cbFirmadoLee('/cfm/positions');
  return (j && j.positions) || [];
}

function contratosDePosicion(p) {
  const n = Number(p.number_of_contracts || p.net_size || 0);
  return Number.isFinite(n) ? Math.abs(n) : 0;
}
function ladoDePosicion(p) {
  const s = String(p.side || p.position_side || '').toUpperCase();
  if (s.includes('SHORT') || s.includes('SELL')) return 'corto';
  return 'largo';
}

async function creaOrden({ productId, lado, contratos, idCliente }) {
  const cuerpo = {
    client_order_id: idCliente || nuevoId() + nuevoId(),
    product_id: productId,
    side: lado === 'largo' ? 'BUY' : 'SELL',
    order_configuration: { market_market_ioc: { base_size: String(contratos) } },
  };
  const j = await cbFirmado('POST', '/orders', cuerpo);
  const exito = Boolean(j && j.success);
  const resp = (j && (j.success_response || j.order_response)) || {};
  const fallo = (j && (j.error_response || j.failure_reason)) || null;
  return {
    exito,
    ordenId: resp.order_id || (j && j.order_id) || null,
    idCliente: cuerpo.client_order_id,
    fallo: exito ? null : (typeof fallo === 'string' ? fallo : JSON.stringify(fallo || j)).slice(0, 300),
    crudo: j,
  };
}

async function detalleOrden(ordenId) {
  const j = await cbFirmadoLee(`/orders/historical/${encodeURIComponent(ordenId)}`);
  const o = (j && j.order) || {};
  return {
    estado: o.status || null,
    precio: Number(o.average_filled_price) || 0,
    llenado: Number(o.filled_size) || 0,
    comisionCents: centavos(Number(o.total_fees) || 0),
    crudo: o,
  };
}

// ------------------------------------------------------------
// VENTANAS DE 15 MINUTOS Y MOMENTUM
// ------------------------------------------------------------
const MS_VENTANA = 15 * 60 * 1000;
const BTC_POR_CONTRATO = 0.01; // nano: 1 contrato = 1/100 BTC

function cierreDeVentana(ts) {
  return Math.ceil((ts + 1) / MS_VENTANA) * MS_VENTANA;
}
function minutosParaCierre(ts) {
  return (cierreDeVentana(ts) - ts) / 60000;
}
function fechaET(d) {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/New_York', year: 'numeric', month: '2-digit', day: '2-digit',
  }).format(d || new Date(Date.now()));
}

// Deriva = cuánto se movió BTC en la ventana de momentum.
// Sigma = ruido típico por minuto. Solo entra si la deriva le gana al ruido
// Y además supera un mínimo en dólares. Sin las dos cosas, es fantasma.
function mideMomentum(velas) {
  if (!velas || velas.length < 3) return { valido: false, motivo: 'faltan velas' };
  const cierres = velas.map((v) => v.cierre);
  const deriva = cierres[cierres.length - 1] - cierres[0];
  const saltos = [];
  for (let i = 1; i < cierres.length; i++) saltos.push(cierres[i] - cierres[i - 1]);
  const media = saltos.reduce((a, b) => a + b, 0) / saltos.length;
  const varianza = saltos.reduce((a, b) => a + (b - media) * (b - media), 0) / Math.max(1, saltos.length - 1);
  const sigma = Math.sqrt(varianza);
  const ruidoEsperado = sigma * Math.sqrt(saltos.length);
  // Coherencia: qué fracción de los minutos fue en la misma dirección que la deriva.
  // Una deriva hecha de un solo salto y mucho vaivén es peor que una sostenida.
  const signo = deriva >= 0 ? 1 : -1;
  const aFavor = saltos.filter((x) => x * signo > 0).length;
  return {
    valido: true,
    deriva: Number(deriva.toFixed(2)),
    sigma: Number(sigma.toFixed(2)),
    ruidoEsperado: Number(ruidoEsperado.toFixed(2)),
    coherencia: Number((aFavor / saltos.length).toFixed(3)),
    ultimo: cierres[cierres.length - 1],
    velas: cierres.length,
  };
}

// Cuánto tiene que moverse BTC solo para pagar la comisión de ida y vuelta.
// Con 0,1% por lado son ~$130 a precios de agosto de 2026. Cualquier umbral
// por debajo de esto autoriza operaciones que pierden por aritmética.
function costeIdaVueltaBtc(precio, aj) {
  return precio * (aj.comisionPct || 0) * 2;
}

function decideDireccion(m, aj, precio) {
  if (!m.valido) return { lado: null, motivo: m.motivo };
  const coste = precio ? costeIdaVueltaBtc(precio, aj) : 0;
  const porCoste = coste * (aj.multiploCoste || 0);
  const exigido = Math.max(aj.umbralSigma * m.ruidoEsperado, aj.minDerivaUsd, porCoste);

  if (Math.abs(m.deriva) < exigido) {
    const quien = porCoste >= exigido ? 'no cubre el coste' : 'deriva corta';
    return {
      lado: null,
      motivo: `${quien} (deriva $${m.deriva.toFixed(2)}, exigido $${exigido.toFixed(2)})`,
      exigido,
    };
  }
  if (m.coherencia !== undefined && m.coherencia < (aj.minCoherencia || 0)) {
    return {
      lado: null,
      motivo: `movimiento incoherente (${Math.round(m.coherencia * 100)}% de los minutos a favor, exigido ${Math.round((aj.minCoherencia || 0) * 100)}%)`,
      exigido,
    };
  }
  return { lado: m.deriva > 0 ? 'largo' : 'corto', exigido, coste };
}

function plCentsDe(lado, entrada, salida, contratos) {
  const signo = lado === 'largo' ? 1 : -1;
  return Math.round(contratos * BTC_POR_CONTRATO * (salida - entrada) * signo * 100);
}

// ------------------------------------------------------------
// v1.1 — HORARIO DE MARGEN BARATO
// Coinbase solo da el apalancamiento intradía de 6pm ET a 4pm ET, entre semana.
// Fuera de esa franja el margen sube a ~25-33% del nocional. Un bot que corre
// 24/7 se mete solo en el tramo caro si nadie se lo impide.
// ------------------------------------------------------------
function relojET(d) {
  const partes = new Intl.DateTimeFormat('en-US', {
    timeZone: 'America/New_York', weekday: 'short',
    hour: '2-digit', minute: '2-digit', hour12: false,
  }).formatToParts(d || new Date(Date.now()));
  const busca = (t) => (partes.find((p) => p.type === t) || {}).value;
  const dias = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
  let hora = Number(busca('hour'));
  if (hora === 24) hora = 0; // el formateador devuelve 24 a medianoche
  return { dia: dias[busca('weekday')], hora, minuto: Number(busca('minute')) };
}

function margenBarato(aj, d) {
  const r = relojET(d);
  const minutos = r.hora * 60 + r.minuto;
  const cierre = 16 * 60 - Math.abs(aj.colchonCierreMin || 0);
  const apertura = 18 * 60;
  const nombres = ['domingo', 'lunes', 'martes', 'miércoles', 'jueves', 'viernes', 'sábado'];

  // tramo de tarde-noche: abre la sesión del día siguiente (dom a jue)
  if (minutos >= apertura && r.dia >= 0 && r.dia <= 4) return { ok: true };
  // tramo de madrugada-mañana: hasta el colchón antes de las 4pm ET (lun a vie)
  if (minutos < cierre && r.dia >= 1 && r.dia <= 5) return { ok: true };

  if (r.dia === 6 || r.dia === 0) {
    return { ok: false, motivo: `fin de semana (${nombres[r.dia]} ET): margen alto` };
  }
  if (minutos >= cierre && minutos < apertura) {
    return { ok: false, motivo: `cerca del corte de las 4pm ET (son las ${String(r.hora).padStart(2, '0')}:${String(r.minuto).padStart(2, '0')} ET)` };
  }
  return { ok: false, motivo: `fuera de la franja de margen barato (${nombres[r.dia]} ${r.hora}:${String(r.minuto).padStart(2, '0')} ET)` };
}

// ------------------------------------------------------------
// v1.1 — LIBRO
// La lección del "libro vacío" de Kalshi traducida: aquí el síntoma no son
// precios de 1¢, es un diferencial ancho. Entrar a mercado contra un libro
// delgado te llena peor de lo que creías y se come el stop antes de empezar.
// ------------------------------------------------------------
async function libroDe(productId) {
  const j = await cbPublico(`/market/product_book?product_id=${encodeURIComponent(productId)}&limit=1`);
  const pb = (j && (j.pricebook || j.price_book)) || {};
  const compra = ((pb.bids || [])[0]) || null;
  const venta = ((pb.asks || [])[0]) || null;
  const pc = Number(compra && compra.price);
  const pv = Number(venta && venta.price);
  if (!Number.isFinite(pc) || !Number.isFinite(pv) || pc <= 0 || pv <= 0) {
    throw new Error('libro ilegible: falta un lado');
  }
  return {
    compra: pc,
    venta: pv,
    medio: (pc + pv) / 2,
    diferencial: Number((pv - pc).toFixed(2)),
    tamCompra: Number(compra.size) || 0,
    tamVenta: Number(venta.size) || 0,
  };
}

// ------------------------------------------------------------
// v1.1 — INDICADORES DE OBSERVACIÓN
// Se calculan y se guardan en cada señal, pero NO deciden nada.
// Sirven para medirlos después, con muestra suficiente, sin que hoy
// contaminen el resultado. Ver la advertencia del README.
// ------------------------------------------------------------
function ema(valores, periodo) {
  if (valores.length < periodo) return null;
  const k = 2 / (periodo + 1);
  let e = valores.slice(0, periodo).reduce((a, b) => a + b, 0) / periodo;
  for (let i = periodo; i < valores.length; i++) e = valores[i] * k + e * (1 - k);
  return e;
}

function serieEma(valores, periodo) {
  if (valores.length < periodo) return [];
  const k = 2 / (periodo + 1);
  let e = valores.slice(0, periodo).reduce((a, b) => a + b, 0) / periodo;
  const salida = [e];
  for (let i = periodo; i < valores.length; i++) {
    e = valores[i] * k + e * (1 - k);
    salida.push(e);
  }
  return salida;
}

function rsi(cierres, periodo) {
  const n = periodo || 14;
  if (cierres.length < n + 1) return null;
  let subidas = 0;
  let bajadas = 0;
  for (let i = 1; i <= n; i++) {
    const d = cierres[i] - cierres[i - 1];
    if (d >= 0) subidas += d; else bajadas -= d;
  }
  let mediaSub = subidas / n;
  let mediaBaj = bajadas / n;
  for (let i = n + 1; i < cierres.length; i++) {
    const d = cierres[i] - cierres[i - 1];
    mediaSub = (mediaSub * (n - 1) + (d > 0 ? d : 0)) / n;
    mediaBaj = (mediaBaj * (n - 1) + (d < 0 ? -d : 0)) / n;
  }
  if (mediaBaj === 0) return 100;
  const rs = mediaSub / mediaBaj;
  return Number((100 - 100 / (1 + rs)).toFixed(2));
}

function macdHist(cierres) {
  if (cierres.length < 35) return null;
  const r12 = serieEma(cierres, 12);
  const r26 = serieEma(cierres, 26);
  if (!r12.length || !r26.length) return null;
  const desfase = r12.length - r26.length;
  const linea = r26.map((v, i) => r12[i + desfase] - v);
  const senal = ema(linea, 9);
  if (senal === null) return null;
  return Number((linea[linea.length - 1] - senal).toFixed(2));
}

function bbAncho(cierres, periodo) {
  const n = periodo || 20;
  if (cierres.length < n) return null;
  const ult = cierres.slice(-n);
  const media = ult.reduce((a, b) => a + b, 0) / n;
  const va = ult.reduce((a, b) => a + (b - media) * (b - media), 0) / n;
  const sd = Math.sqrt(va);
  if (!media) return null;
  return Number(((4 * sd) / media * 100).toFixed(3)); // ancho de las bandas en % del precio
}

function indicadores(cierres) {
  return {
    rsi: rsi(cierres, 14),
    macdHist: macdHist(cierres),
    bbAncho: bbAncho(cierres, 20),
    velasUsadas: cierres.length,
  };
}

// Las condiciones que hay que cumplir para abrir, en el mismo orden en que se
// comprueban. El panel las enseña tal cual: si una regla no se puede escribir
// en una frase, es que no está clara.
function reglasVigentes(e, precio) {
  const a = e.ajustes;
  const p = Number(precio) > 0 ? Number(precio) : null;
  const peaje = p ? costeIdaVueltaBtc(p, a) : null;
  const nocional = p ? p * BTC_POR_CONTRATO * a.contratos : null;
  return {
    entrada: [
      { regla: 'La deriva supera el ruido', valor: `${a.umbralSigma}× sigma` },
      { regla: 'La deriva llega al mínimo', valor: `$${a.minDerivaUsd}` },
      { regla: 'La deriva cubre el peaje',
        valor: peaje ? `${a.multiploCoste}× = $${(peaje * a.multiploCoste).toFixed(0)}` : `${a.multiploCoste}× el peaje` },
      { regla: 'El movimiento es coherente', valor: `${Math.round(a.minCoherencia * 100)}% de los minutos` },
      { regla: 'El libro no está ancho', valor: a.exigirLibro ? `≤ $${a.maxDiferencialUsd}` : 'sin comprobar' },
      { regla: 'Estamos en margen barato', valor: a.soloMargenBarato ? `6pm–4pm ET, lun a vie` : 'a cualquier hora' },
    ],
    riesgo: [
      { regla: 'Tamaño', valor: `${a.contratos} contrato${a.contratos > 1 ? 's' : ''}${nocional ? ` · $${nocional.toFixed(0)} de exposición` : ''}` },
      { regla: 'Stop por operación', valor: `−$${aUsd(a.stopCents).toFixed(2)}` },
      { regla: 'Objetivo', valor: a.usarObjetivo ? `+$${aUsd(a.objetivoCents).toFixed(2)}` : 'sin objetivo' },
      { regla: 'Salida obligatoria', valor: a.salirAlCierre ? 'al cerrar la ventana' : 'solo por stop u objetivo' },
      { regla: 'Tope de pérdida al día', valor: `−$${aUsd(a.maxPerdidaDiaCents).toFixed(2)} y se apaga` },
      { regla: 'Operaciones al día', valor: `${a.maxOperacionesDia}` },
    ],
    peaje: peaje ? {
      porOperacion: Number((peaje * BTC_POR_CONTRATO * a.contratos).toFixed(2)),
      movimientoParaEmpatar: Math.round(peaje),
    } : null,
  };
}

function fotoConfig(e) {
  const a = e.ajustes;
  return {
    ver: FOTO_VER,
    prefijoProducto: a.prefijoProducto,
    contratos: a.contratos,
    minutosAntes: a.minutosAntes,
    tolMin: a.tolMin,
    momentumMin: a.momentumMin,
    umbralSigma: a.umbralSigma,
    minDerivaUsd: a.minDerivaUsd,
    minCoherencia: a.minCoherencia,
    multiploCoste: a.multiploCoste,
    comisionPct: a.comisionPct,
    stopCents: a.stopCents,
    objetivoCents: a.objetivoCents,
    usarObjetivo: a.usarObjetivo,
    salirAlCierre: a.salirAlCierre,
    maxPerdidaDiaCents: a.maxPerdidaDiaCents,
    maxOperacionesDia: a.maxOperacionesDia,
    soloMargenBarato: a.soloMargenBarato,
    colchonCierreMin: a.colchonCierreMin,
    exigirLibro: a.exigirLibro,
    maxDiferencialUsd: a.maxDiferencialUsd,
    modo: e.modo,
  };
}

// Un aviso solo se retira solo si describía algo que ya no ocurre: no poder
// leer, o una posición ajena. Los demás (no se pudo cerrar, orden fallida,
// tope del día) se quedan hasta que el usuario actúe.
// Los avisos SIN tipo vienen de una versión anterior a la v1.3.2 y no tenían
// forma de retirarse: se quedaban en rojo para siempre. Se tratan como caducados.
function avisoCaducado(e) {
  if (!e.aviso) return false;
  if (!e.avisoTipo) return true;
  return e.avisoTipo === 'lectura' || e.avisoTipo === 'ajena';
}

function ruedaDiario(e) {
  const hoy = fechaET();
  if (e.diario.fecha !== hoy) {
    e.diario = { fecha: hoy, operaciones: 0, plCents: 0, arriesgadoCents: 0, ganadas: 0, perdidas: 0 };
  }
  return e;
}

// Fantasma: no se ordenó, pero queda registrado CON la foto de configuración.
// Es la única forma de medir cuánto cuesta cada filtro.
function nuevoFantasma(e, ctx, vetadaPor) {
  return {
    id: nuevoId(),
    creada: ahoraISO(),
    productId: (e.producto && e.producto.id) || null,
    ventanaCierre: ctx.ventanaCierreISO || null,
    estado: 'fantasma',
    modo: e.modo,
    lado: ctx.lado || null,
    contratos: 0,
    precioEntrada: ctx.precio || null,
    precioSalida: null,
    ordenEntradaId: null,
    ordenSalidaId: null,
    comisionCents: 0,
    plCents: 0,
    gano: null,
    motivoSalida: null,
    deriva: ctx.deriva !== undefined ? ctx.deriva : null,
    sigma: ctx.sigma !== undefined ? ctx.sigma : null,
    ruidoEsperado: ctx.ruidoEsperado !== undefined ? ctx.ruidoEsperado : null,
    coherencia: ctx.coherencia !== undefined ? ctx.coherencia : null,
    exigidoUsd: ctx.exigidoUsd !== undefined ? ctx.exigidoUsd : null,
    spotAlEntrar: ctx.spot || null,
    spotAlSalir: null,
    vetadaPor,
    nota: ctx.nota || null,
    diferencial: ctx.diferencial !== undefined ? ctx.diferencial : null,
    rsi: ctx.rsi !== undefined ? ctx.rsi : null,
    macdHist: ctx.macdHist !== undefined ? ctx.macdHist : null,
    bbAncho: ctx.bbAncho !== undefined ? ctx.bbAncho : null,
    nocionalUsd: null,
    roiPct: null,
    cfg: fotoConfig(e),
    ver: BOT_VER,
  };
}

// ------------------------------------------------------------
// EL CICLO — lo llama el cron cada minuto y el botón "correr ahora"
// ------------------------------------------------------------
async function cierraPosicion(e, motivo, precioMercado) {
  const pos = e.posicion;
  if (!pos) return null;
  const ladoContrario = pos.lado === 'largo' ? 'corto' : 'largo';
  let precioSalida = precioMercado;
  let ordenSalidaId = null;
  let comisionExtra = 0;
  let nota = null;

  let comisionEstimada = false;
  if (pos.modo === 'sombra') {
    // La sombra no manda órdenes, así que Coinbase no le cobra nada. Si no se
    // le imputa el peaje, su curva miente por omisión — y el peaje es justo lo
    // que decide si esta estrategia gana o pierde.
    const nocional = pos.precioEntrada * BTC_POR_CONTRATO * pos.contratos;
    comisionExtra = Math.round(nocional * (e.ajustes.comisionPct || 0) * 2 * 100);
    comisionEstimada = true;
  }

  if (pos.modo === 'real') {
    const r = await creaOrden({
      productId: pos.productId, lado: ladoContrario, contratos: pos.contratos,
    });
    if (!r.exito) {
      // No se pudo cerrar: la posición SIGUE abierta. Se avisa en rojo y se reintenta
      // el minuto siguiente. Nunca se marca cerrada una posición que sigue viva.
      e.aviso = `⚠️ NO se pudo cerrar la posición (${motivo}): ${r.fallo}`;
      e.avisoTipo = 'cierre';
      return { fallo: r.fallo };
    }
    ordenSalidaId = r.ordenId;
    if (ordenSalidaId) {
      try {
        const d = await detalleOrden(ordenSalidaId);
        if (d.precio > 0) precioSalida = d.precio;
        comisionExtra = d.comisionCents;
      } catch (err) {
        nota = `salida enviada pero no pude leer el detalle: ${err.message}`;
      }
    }
  }

  const plBruto = plCentsDe(pos.lado, pos.precioEntrada, precioSalida, pos.contratos);
  const comisionTotal = (pos.comisionCents || 0) + comisionExtra;
  const plNeto = plBruto - comisionTotal;
  const nocionalCents = Math.round(pos.precioEntrada * BTC_POR_CONTRATO * pos.contratos * 100);

  await actualizaSenal(pos.senalId, {
    estado: 'cerrada',
    precioSalida,
    ordenSalidaId,
    comisionCents: comisionTotal,
    plCents: plNeto,
    nocionalUsd: Number((nocionalCents / 100).toFixed(2)),
    roiPct: nocionalCents ? Number((plNeto / nocionalCents * 100).toFixed(4)) : null,
    plPorContratoCents: pos.contratos ? Math.round(plNeto / pos.contratos) : plNeto,
    gano: plNeto > 0,
    motivoSalida: motivo,
    cerrada: ahoraISO(),
    comisionEstimada,
    nota: nota || null,
  });

  if (pos.modo === 'real') {
    e.diario.plCents += plNeto;
    if (plNeto > 0) e.diario.ganadas += 1; else e.diario.perdidas += 1;
  }
  e.posicion = null;
  e.aviso = null;
  return { plNeto, precioSalida, motivo };
}

async function corre(opciones) {
  const o = opciones || {};
  const informe = { ISO: ahoraISO(), ver: BOT_VER, pasos: [], acciones: [] };
  const marca = await tomaCerrojo(55);
  if (!marca) { informe.saltado = 'otra corrida sigue en curso'; return informe; }

  try {
    const e = await leeEstado();
    ruedaDiario(e);
    informe.modo = e.modo;
    informe.encendido = e.encendido;

    // --- 1. contrato ---
    try {
      const cad = e.producto && e.producto.caducidad ? Date.parse(e.producto.caducidad) : Infinity;
      const viejo = !e.producto || (Number.isFinite(cad) && cad < Date.now() + 60 * 60 * 1000);
      if (viejo) {
        e.producto = await eligeProducto(e.ajustes.prefijoProducto);
        informe.pasos.push(`contrato elegido: ${e.producto.id}`);
      }
    } catch (err) {
      informe.error = `no pude elegir contrato: ${err.message}`;
      e.aviso = informe.error;
      e.avisoTipo = 'lectura';
      await guardaEstado(e);
      return informe;
    }
    informe.producto = e.producto.id;

    // --- 2. precio ---
    let precio;
    try {
      precio = await precioProducto(e.producto.id);
    } catch (err) {
      informe.error = `sin precio: ${err.message}`;
      await guardaEstado(e);
      return informe;
    }
    informe.precio = precio;

    // --- 3. reconciliación contra Coinbase (la lección de klaros5) ---
    // Si la consulta de posiciones falla, NO se ordena, y el motivo real queda
    // escrito. Nunca un motivo inventado encima del verdadero.
    let posBolsa = null;
    let posLegible = false;
    if (e.modo === 'real' && CB_KEY_NAME && CB_KEY_SECRET_RAW) {
      try {
        const lista = await posicionesFuturos();
        posBolsa = lista.find((p) => String(p.product_id) === String(e.producto.id)) || null;
        posLegible = true;
      } catch (err) {
        posLegible = false;
        e.aviso = `⚠️ No pude leer tus posiciones en Coinbase: ${err.message} El bot no ordena a ciegas.`;
        e.avisoTipo = 'lectura';
        informe.pasos.push('posiciones ilegibles -> no se ordena');
      }
    } else {
      posLegible = true; // en sombra no hay nada que reconciliar
    }

    if (e.modo === 'real' && posLegible) {
      const contratosBolsa = posBolsa ? contratosDePosicion(posBolsa) : 0;
      if (e.posicion && contratosBolsa === 0) {
        // desapareció: la cerraste a mano, o te liquidaron
        await actualizaSenal(e.posicion.senalId, {
          estado: 'cerrada',
          precioSalida: precio,
          plCents: plCentsDe(e.posicion.lado, e.posicion.precioEntrada, precio, e.posicion.contratos) - (e.posicion.comisionCents || 0),
          motivoSalida: 'la posición ya no está en Coinbase (cerrada fuera del bot o liquidada)',
          aproximado: true,
          cerrada: ahoraISO(),
        });
        e.posicion = null;
        e.aviso = 'La posición desapareció de Coinbase sin pasar por el bot. El P&L de esa señal es aproximado.';
        e.avisoTipo = 'huerfana';
        informe.pasos.push('posición huérfana en el estado -> conciliada');
      } else if (!e.posicion && contratosBolsa > 0) {
        // NUNCA adoptar una posición que el bot no abrió
        e.aviso = `⚠️ Hay ${contratosBolsa} contrato(s) abiertos en ${e.producto.id} que este bot NO abrió. No ordeno nada hasta que se cierre.`;
        e.avisoTipo = 'ajena';
        informe.pasos.push('posición ajena detectada -> bot en pausa');
        await guardaEstado(e);
        return informe;
      }
      // Coinbase volvió a responder: un aviso de lectura o de posición ajena ya
      // no describe la realidad. Se retira, o se queda pegado en rojo para siempre.
      if (avisoCaducado(e)) { e.aviso = null; e.avisoTipo = null; }
    } else if (posLegible && avisoCaducado(e)) {
      e.aviso = null;
      e.avisoTipo = null;
    }

    // --- 4. gestionar la posición abierta (esto ocurre AUNQUE el bot esté apagado) ---
    if (e.posicion) {
      const pos = e.posicion;
      const plAbierto = plCentsDe(pos.lado, pos.precioEntrada, precio, pos.contratos);
      informe.posicion = { lado: pos.lado, entrada: pos.precioEntrada, plAbierto };
      const venceVentana = Date.parse(pos.ventanaCierreISO) <= Date.now();
      let motivo = null;
      if (plAbierto <= -Math.abs(e.ajustes.stopCents)) motivo = `stop ($${aUsd(plAbierto).toFixed(2)})`;
      else if (e.ajustes.usarObjetivo && plAbierto >= Math.abs(e.ajustes.objetivoCents)) motivo = `objetivo ($${aUsd(plAbierto).toFixed(2)})`;
      else if (venceVentana && e.ajustes.salirAlCierre) motivo = 'cierre de ventana';
      else if (!e.encendido) motivo = 'bot apagado: se cierra lo que quedaba abierto';

      if (motivo) {
        if (!posLegible && pos.modo === 'real') {
          informe.pasos.push('toca cerrar pero no puedo leer posiciones; reintento el minuto siguiente');
        } else {
          const r = await cierraPosicion(e, motivo, precio);
          informe.acciones.push({ tipo: 'cierre', motivo, resultado: r });
        }
      }
      await guardaEstado(e);
      return informe;
    }

    // --- 5. evaluar entrada ---
    const minutos = minutosParaCierre(Date.now());
    const cierreISO = new Date(cierreDeVentana(Date.now())).toISOString();
    informe.minutosParaCierre = Number(minutos.toFixed(2));

    const aj = e.ajustes;
    const enVentana = Math.abs(minutos - aj.minutosAntes) <= aj.tolMin;
    if (!enVentana) { informe.pasos.push('fuera de la ventana de entrada'); await guardaEstado(e); return informe; }
    if (e.ultimaVentana === cierreISO) { informe.pasos.push('esta ventana ya se evaluó'); await guardaEstado(e); return informe; }
    e.ultimaVentana = cierreISO;

    const ctxBase = { ventanaCierreISO: cierreISO, precio, spot: precio };

    if (!e.encendido) {
      await anadeSenal(nuevoFantasma(e, ctxBase, 'bot apagado'));
      await guardaEstado(e); informe.pasos.push('apagado'); return informe;
    }
    if (e.diario.operaciones >= aj.maxOperacionesDia) {
      await anadeSenal(nuevoFantasma(e, ctxBase, `tope de ${aj.maxOperacionesDia} operaciones al día`));
      await guardaEstado(e); return informe;
    }
    if (e.diario.plCents <= -Math.abs(aj.maxPerdidaDiaCents)) {
      e.encendido = false;
      e.aviso = `Se alcanzó el tope de pérdida del día ($${aUsd(Math.abs(aj.maxPerdidaDiaCents)).toFixed(2)}). El bot se apagó solo.`;
      e.avisoTipo = 'tope';
      await anadeSenal(nuevoFantasma(e, ctxBase, 'tope de pérdida diaria'));
      await guardaEstado(e); return informe;
    }
    if (e.modo === 'real' && !hayAlmacen()) {
      await anadeSenal(nuevoFantasma(e, ctxBase, 'sin almacén: en real no se ordena sin memoria'));
      e.aviso = 'No hay Redis configurado. En real el bot no ordena, porque sin memoria podría abrir la misma posición muchas veces.';
      e.avisoTipo = 'almacen';
      await guardaEstado(e); return informe;
    }
    if (e.modo === 'real' && !posLegible) {
      await anadeSenal(nuevoFantasma(e, ctxBase, 'no pude leer posiciones en Coinbase'));
      await guardaEstado(e); return informe;
    }
    if (e.modo === 'real' && aj.soloMargenBarato) {
      const franja = margenBarato(aj);
      if (!franja.ok) {
        await anadeSenal(nuevoFantasma(e, ctxBase, franja.motivo));
        informe.pasos.push(franja.motivo);
        await guardaEstado(e); return informe;
      }
    }

    let m;
    let cierresVelas = [];
    try {
      const velas = await velasSpot(Math.max(aj.momentumMin, 60));
    cierresVelas = velas.map((v) => v.cierre);
    m = mideMomentum(velas.slice(-Math.max(3, aj.momentumMin)));
    } catch (err) {
      await anadeSenal(nuevoFantasma(e, ctxBase, `sin velas: ${err.message}`));
      await guardaEstado(e); return informe;
    }
    const ctx = Object.assign({}, ctxBase, {
      deriva: m.deriva, sigma: m.sigma, ruidoEsperado: m.ruidoEsperado,
      coherencia: m.coherencia, spot: m.ultimo || precio,
    });
    const ind = indicadores(cierresVelas);
    Object.assign(ctx, { rsi: ind.rsi, macdHist: ind.macdHist, bbAncho: ind.bbAncho });

    const d = decideDireccion(m, aj, precio);
    informe.momentum = m;
    informe.indicadores = ind;
    if (d.exigido !== undefined) ctx.exigidoUsd = Number(d.exigido.toFixed(2));
    if (!d.lado) {
      await anadeSenal(nuevoFantasma(e, ctx, d.motivo));
      informe.pasos.push(d.motivo);
      await guardaEstado(e); return informe;
    }

    // El libro: un diferencial ancho se come el stop antes de empezar.
    let libro = null;
    if (aj.exigirLibro) {
      try {
        libro = await libroDe(e.producto.id);
      } catch (err) {
        await anadeSenal(nuevoFantasma(e, ctx, `libro ilegible: ${err.message}`));
        informe.pasos.push('libro ilegible -> no se ordena');
        await guardaEstado(e); return informe;
      }
      ctx.diferencial = libro.diferencial;
      if (libro.diferencial > Math.abs(aj.maxDiferencialUsd)) {
        const motivo = `diferencial ancho ($${libro.diferencial.toFixed(2)}, máximo $${aj.maxDiferencialUsd})`;
        await anadeSenal(nuevoFantasma(e, ctx, motivo));
        informe.pasos.push(motivo);
        await guardaEstado(e); return informe;
      }
      const tamLado = d.lado === 'largo' ? libro.tamVenta : libro.tamCompra;
      if (tamLado > 0 && tamLado < aj.contratos) {
        const motivo = `libro delgado (${tamLado} contrato(s) al mejor precio, hacen falta ${aj.contratos})`;
        await anadeSenal(nuevoFantasma(e, ctx, motivo));
        informe.pasos.push(motivo);
        await guardaEstado(e); return informe;
      }
      informe.libro = libro;
    }

    // --- 6. entrar ---
    const senal = {
      id: nuevoId(),
      creada: ahoraISO(),
      productId: e.producto.id,
      ventanaCierre: cierreISO,
      estado: 'abierta',
      modo: e.modo,
      lado: d.lado,
      contratos: Math.min(aj.contratos, MAX_CONTRATOS),
      precioEntrada: precio,
      precioSalida: null,
      ordenEntradaId: null,
      ordenSalidaId: null,
      comisionCents: 0,
      plCents: 0,
      gano: null,
      motivoSalida: null,
      deriva: m.deriva,
      sigma: m.sigma,
      ruidoEsperado: m.ruidoEsperado,
      coherencia: m.coherencia,
      exigidoUsd: Number(d.exigido.toFixed(2)),
      spotAlEntrar: m.ultimo || precio,
      spotAlSalir: null,
      vetadaPor: null,
      nota: null,
      diferencial: libro ? libro.diferencial : null,
      compra: libro ? libro.compra : null,
      venta: libro ? libro.venta : null,
      rsi: ind.rsi,
      macdHist: ind.macdHist,
      bbAncho: ind.bbAncho,
      nocionalUsd: Number((precio * BTC_POR_CONTRATO * aj.contratos).toFixed(2)),
      roiPct: null,
      cfg: fotoConfig(e),
      ver: BOT_VER,
    };

    if (e.modo === 'real') {
      const r = await creaOrden({ productId: e.producto.id, lado: d.lado, contratos: Math.min(aj.contratos, MAX_CONTRATOS) });
      if (!r.exito) {
        senal.estado = 'error';
        senal.vetadaPor = null;
        senal.nota = `⚠️ ERROR al ordenar: ${r.fallo}`;
        await anadeSenal(senal);
        e.aviso = senal.nota;
        e.avisoTipo = 'orden';
        await guardaEstado(e);
        informe.acciones.push({ tipo: 'orden', exito: false, fallo: r.fallo });
        return informe;
      }
      senal.ordenEntradaId = r.ordenId;
      if (r.ordenId) {
        try {
          const det = await detalleOrden(r.ordenId);
          if (det.precio > 0) senal.precioEntrada = det.precio;
          senal.comisionCents = det.comisionCents;
          senal.llenado = det.llenado;
        } catch (err) {
          senal.nota = `orden enviada, detalle ilegible: ${err.message}`;
        }
      }
      e.diario.operaciones += 1;
      e.diario.arriesgadoCents += Math.abs(aj.stopCents);
    }

    await anadeSenal(senal);
    e.posicion = {
      senalId: senal.id,
      productId: senal.productId,
      lado: senal.lado,
      contratos: senal.contratos,
      precioEntrada: senal.precioEntrada,
      comisionCents: senal.comisionCents,
      modo: senal.modo,
      abiertaISO: senal.creada,
      ventanaCierreISO: cierreISO,
      ordenId: senal.ordenEntradaId,
    };
    informe.acciones.push({ tipo: 'entrada', lado: senal.lado, precio: senal.precioEntrada, modo: senal.modo });
    e.ultimaCorrida = { ISO: ahoraISO(), resumen: `entrada ${senal.lado} a ${senal.precioEntrada}` };
    await guardaEstado(e);
    return informe;
  } catch (err) {
    informe.error = err.message;
    return informe;
  } finally {
    await sueltaCerrojo();
  }
}

// ------------------------------------------------------------
// CONTADORES — el número grande es SOLO dinero real.
// El corte filtra al CONTAR; jamás borra señales.
// ------------------------------------------------------------
function cuenta(senales, filtro) {
  const s = senales.filter(filtro);
  const cerradas = s.filter((x) => x.estado === 'cerrada');
  const plCents = cerradas.reduce((a, b) => a + (b.plCents || 0), 0);
  const ganadas = cerradas.filter((x) => (x.plCents || 0) > 0).length;
  return {
    operaciones: s.filter((x) => x.estado === 'cerrada' || x.estado === 'abierta').length,
    liquidadas: cerradas.length,
    plCents,
    ganadas,
    perdidas: cerradas.length - ganadas,
    comisionCents: cerradas.reduce((a, b) => a + (b.comisionCents || 0), 0),
    roiPctMedio: cerradas.length
      ? Number((cerradas.reduce((a, b) => a + (b.roiPct || 0), 0) / cerradas.length).toFixed(4))
      : null,
  };
}

// Los motivos llevan cifras dentro ("deriva corta (deriva $412, exigido $300)").
// Para contarlos hay que quedarse con la causa y tirar los números, o cada veto
// sería único y la lista no diría nada.
function normalizaMotivo(m) {
  if (!m) return 'sin motivo';
  return String(m)
    .replace(/\([^)]*\)/g, '')
    .replace(/\$[\d.,]+/g, '')
    .replace(/\d+/g, '')
    .replace(/\s+/g, ' ')
    .replace(/\s+([:,])/g, '$1')
    .replace(/[:,.]\s*$/, '')
    .trim()
    .toLowerCase() || 'sin motivo';
}

// Por qué NO operó, ordenado. Es la pregunta que de verdad se hace mirando
// un bot que lleva días sin abrir nada.
function cuentaMotivos(senales, tope) {
  const mapa = new Map();
  for (const s of senales) {
    if (s.estado !== 'fantasma') continue;
    const m = normalizaMotivo(s.vetadaPor);
    mapa.set(m, (mapa.get(m) || 0) + 1);
  }
  return [...mapa.entries()]
    .map(([motivo, n]) => ({ motivo, n }))
    .sort((a, b) => b.n - a.n)
    .slice(0, tope || 8);
}

// Curva acumulada del dinero, punto por operación liquidada.
function curvaDe(senales, modo, tope) {
  const cerradas = senales
    .filter((s) => s.modo === modo && s.estado === 'cerrada')
    .slice(-(tope || 150));
  let suma = 0;
  return cerradas.map((s) => {
    suma += s.plCents || 0;
    return { creada: s.creada, plCents: suma, punto: s.plCents || 0 };
  });
}

// Las últimas ventanas, en orden, para la cinta del panel.
function cintaDe(senales, cuantas) {
  return senales.slice(-(cuantas || 48)).map((s) => ({
    estado: s.estado,
    modo: s.modo,
    lado: s.lado,
    plCents: s.plCents || 0,
    creada: s.creada,
    motivo: s.estado === 'fantasma' ? normalizaMotivo(s.vetadaPor) : (s.motivoSalida || null),
  }));
}

// El precio de BTC que vio el bot en cada ventana, con lo que decidió en ella.
// No hace falta pedir nada a Coinbase: cada señal ya guarda el spot del momento,
// también las vetadas. Así se puede ver si un veto se ahorró un movimiento o se
// lo perdió.
function serieSpotDe(senales, tope) {
  return senales
    .filter((s) => Number(s.spotAlEntrar) > 0)
    .slice(-(tope || 160))
    .map((s) => ({
      creada: s.creada,
      spot: Number(s.spotAlEntrar),
      estado: s.estado,
      lado: s.lado || null,
      modo: s.modo,
      plCents: s.plCents || 0,
      motivo: s.estado === 'fantasma' ? normalizaMotivo(s.vetadaPor) : (s.motivoSalida || null),
    }));
}

function estadisticas(e, senales) {
  const corte = e.corteContadorISO ? Date.parse(e.corteContadorISO) : 0;
  const desdeCorte = (x) => !corte || Date.parse(x.creada) >= corte;
  const hoy = fechaET();
  const esHoy = (x) => fechaET(new Date(x.creada)) === hoy;
  return {
    hoyReal: cuenta(senales, (x) => x.modo === 'real' && desdeCorte(x) && esHoy(x)),
    acumuladoReal: cuenta(senales, (x) => x.modo === 'real' && desdeCorte(x)),
    sombra: cuenta(senales, (x) => x.modo === 'sombra' && desdeCorte(x)),
    fantasmas: senales.filter((x) => x.estado === 'fantasma' && desdeCorte(x)).length,
    errores: senales.filter((x) => x.estado === 'error' && desdeCorte(x)).length,
    total: senales.length,
    corte: e.corteContadorISO || null,
    motivos: cuentaMotivos(senales.filter(desdeCorte), 8),
    curvaReal: curvaDe(senales.filter(desdeCorte), 'real', 150),
    curvaSombra: curvaDe(senales.filter(desdeCorte), 'sombra', 150),
    cinta: cintaDe(senales.filter(desdeCorte), 48),
    serieSpot: serieSpotDe(senales.filter(desdeCorte), 160),
  };
}

// ------------------------------------------------------------
// EXPORTADOR CSV — mismas columnas siempre, lo que no existe va vacío
// ------------------------------------------------------------
const COLUMNAS = [
  ['bot', () => 'kronos-cb'],
  ['id', (s) => s.id],
  ['contrato', (s) => s.productId],
  ['creada', (s) => s.creada],
  ['cerrada', (s) => s.cerrada],
  ['ventana_cierre', (s) => s.ventanaCierre],
  ['estado', (s) => s.estado],
  ['modo', (s) => s.modo],
  ['lado', (s) => s.lado],
  ['contratos', (s) => s.contratos],
  ['precio_entrada', (s) => s.precioEntrada],
  ['precio_salida', (s) => s.precioSalida],
  ['orden_entrada', (s) => s.ordenEntradaId],
  ['orden_salida', (s) => s.ordenSalidaId],
  ['llenado', (s) => s.llenado],
  ['comision_usd', (s) => (s.comisionCents != null ? (s.comisionCents / 100).toFixed(2) : '')],
  ['comision_estimada', (s) => (s.comisionEstimada ? 'si' : '')],
  ['pl_usd', (s) => (s.plCents != null ? (s.plCents / 100).toFixed(2) : '')],
  ['pl_por_contrato_usd', (s) => (s.plPorContratoCents != null ? (s.plPorContratoCents / 100).toFixed(2) : '')],
  ['nocional_usd', (s) => s.nocionalUsd],
  ['roi_pct', (s) => s.roiPct],
  ['gano', (s) => (s.gano === null || s.gano === undefined ? '' : (s.gano ? 'si' : 'no'))],
  ['motivo_salida', (s) => s.motivoSalida],
  ['aproximado', (s) => (s.aproximado ? 'si' : '')],
  ['diferencial_usd', (s) => s.diferencial],
  ['mejor_compra', (s) => s.compra],
  ['mejor_venta', (s) => s.venta],
  ['coherencia', (s) => s.coherencia],
  ['exigido_usd', (s) => s.exigidoUsd],
  ['obs_rsi14', (s) => s.rsi],
  ['obs_macd_hist', (s) => s.macdHist],
  ['obs_bb_ancho_pct', (s) => s.bbAncho],
  ['deriva_usd', (s) => s.deriva],
  ['sigma_usd', (s) => s.sigma],
  ['ruido_esperado_usd', (s) => s.ruidoEsperado],
  ['spot_al_entrar', (s) => s.spotAlEntrar],
  ['spot_al_salir', (s) => s.spotAlSalir],
  ['vetada_por', (s) => s.vetadaPor],
  ['nota', (s) => s.nota],
  ['cfg_prefijo', (s) => (s.cfg || {}).prefijoProducto],
  ['cfg_contratos', (s) => (s.cfg || {}).contratos],
  ['cfg_minutos_antes', (s) => (s.cfg || {}).minutosAntes],
  ['cfg_tol_min', (s) => (s.cfg || {}).tolMin],
  ['cfg_momentum_min', (s) => (s.cfg || {}).momentumMin],
  ['cfg_umbral_sigma', (s) => (s.cfg || {}).umbralSigma],
  ['cfg_min_deriva_usd', (s) => (s.cfg || {}).minDerivaUsd],
  ['cfg_min_coherencia', (s) => (s.cfg || {}).minCoherencia],
  ['cfg_multiplo_coste', (s) => (s.cfg || {}).multiploCoste],
  ['cfg_comision_pct', (s) => (s.cfg || {}).comisionPct],
  ['cfg_stop_usd', (s) => ((s.cfg || {}).stopCents != null ? ((s.cfg || {}).stopCents / 100).toFixed(2) : '')],
  ['cfg_objetivo_usd', (s) => ((s.cfg || {}).objetivoCents != null ? ((s.cfg || {}).objetivoCents / 100).toFixed(2) : '')],
  ['cfg_usar_objetivo', (s) => ((s.cfg || {}).usarObjetivo ? 'si' : 'no')],
  ['cfg_salir_al_cierre', (s) => ((s.cfg || {}).salirAlCierre ? 'si' : 'no')],
  ['cfg_max_perdida_dia_usd', (s) => ((s.cfg || {}).maxPerdidaDiaCents != null ? ((s.cfg || {}).maxPerdidaDiaCents / 100).toFixed(2) : '')],
  ['cfg_max_operaciones_dia', (s) => (s.cfg || {}).maxOperacionesDia],
  ['cfg_solo_margen_barato', (s) => ((s.cfg || {}).soloMargenBarato ? 'si' : 'no')],
  ['cfg_colchon_cierre_min', (s) => (s.cfg || {}).colchonCierreMin],
  ['cfg_exigir_libro', (s) => ((s.cfg || {}).exigirLibro ? 'si' : 'no')],
  ['cfg_max_diferencial_usd', (s) => (s.cfg || {}).maxDiferencialUsd],
  ['cfg_modo', (s) => (s.cfg || {}).modo],
  ['version', (s) => (s.cfg || {}).ver || s.ver],
];

function escapaCsv(v) {
  if (v === null || v === undefined) return '';
  const s = String(v);
  return /[",\n;]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function aCsv(senales) {
  const lineas = [COLUMNAS.map((c) => c[0]).join(',')];
  for (const s of senales) {
    lineas.push(COLUMNAS.map((c) => {
      let v;
      try { v = c[1](s); } catch (e) { v = ''; }
      return escapaCsv(v);
    }).join(','));
  }
  return lineas.join('\n');
}

module.exports = {
  BOT_VER, SELLO, FOTO_VER, MAX_CONTRATOS, costeIdaVueltaBtc, CB_HOST, CB_BASE, CLAVE_PANEL, CRON_SECRET,
  CB_KEY_NAME, CB_KEY_SECRET_RAW, BTC_POR_CONTRATO,
  ahoraISO, nuevoId, centavos, aUsd, num, limita, fechaET,
  normalizaLlave, cargaLlave, construyeJwt, b64url,
  hayAlmacen, redis, redisTanda, K, TOPE_SENALES, TAM_PAGINA, leeIndice, leeJson, guardaJson, tomaCerrojo, sueltaCerrojo,
  ajustesDeFabrica, estadoDeFabrica, leeEstado, guardaEstado,
  leeSenales, guardaSenales, anadeSenal, actualizaSenal,
  cbPublico, cbFirmado, cbFirmadoLee, limpiaError, REINTENTOS, listaFuturos, eligeProducto, precioProducto, velasSpot,
  balanceFuturos, posicionesFuturos, creaOrden, detalleOrden,
  contratosDePosicion, ladoDePosicion,
  cierreDeVentana, minutosParaCierre, mideMomentum, decideDireccion,
  relojET, margenBarato, libroDe, indicadores, rsi, macdHist, bbAncho, ema, serieEma,
  plCentsDe, fotoConfig, reglasVigentes, serieSpotDe, avisoCaducado, ruedaDiario, nuevoFantasma, cierraPosicion, corre,
  estadisticas, cuenta, normalizaMotivo, cuentaMotivos, curvaDe, cintaDe, aCsv, COLUMNAS,
};
