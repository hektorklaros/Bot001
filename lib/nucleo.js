// ============================================================
// KRONOS-CB — núcleo compartido (Coinbase futuros + Vercel)
// Basado en la arquitectura de klaros2 (Kalshi/Netlify).
// Sin dependencias de npm: solo crypto y fetch nativos de Node.
// ============================================================
const crypto = require('crypto');

const BOT_VER = 'v1.0';
const SELLO = 'v1.0 · 2026-08-02 08-30ET'; // mismo sello que el nombre del zip
const FOTO_VER = BOT_VER; // queda grabado en cada señal

const CB_HOST = 'api.coinbase.com';
const CB_BASE = '/api/v3/brokerage';

const CLAVE_PANEL = process.env.CLAVE_PANEL || process.env.ADMIN_PASSWORD || '';
const CRON_SECRET = process.env.CRON_SECRET || '';

const CB_KEY_NAME = process.env.COINBASE_KEY_NAME || process.env.COINBASE_API_KEY || '';
const CB_KEY_SECRET_RAW = process.env.COINBASE_KEY_SECRET || process.env.COINBASE_API_SECRET || '';

// ---------- Utilidades ----------
function ahoraISO() { return new Date().toISOString(); }
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

async function redis(comando) {
  if (!hayAlmacen()) {
    // modo memoria (degradado)
    const [op, clave, valor] = comando;
    if (op === 'GET') return MEM.has(clave) ? MEM.get(clave) : null;
    if (op === 'SET') { MEM.set(clave, valor); return 'OK'; }
    if (op === 'DEL') { MEM.delete(clave); return 1; }
    if (op === 'SET_NX') { if (MEM.has(clave)) return null; MEM.set(clave, valor); return 'OK'; }
    return null;
  }
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
  senales: () => `${PREFIJO}:senales`,
  cerrojo: () => `${PREFIJO}:cerrojo`,
};

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
    contratos: 1,             // 1 contrato = 0,01 BTC. Es el mínimo: no hay tickets de $1
    minutosAntes: 5,          // entra cuando falten ~N minutos para el cierre de la ventana
    tolMin: 1.0,              // tolerancia +/- en minutos
    momentumMin: 10,          // cuántos minutos de velas mira para medir la deriva
    umbralSigma: 1.0,         // la deriva debe superar N veces el ruido típico
    minDerivaUsd: 25,         // y además N dólares de movimiento (equivale a minDistUsd)
    stopCents: 800,           // cierra ya si pierde $8 sin realizar
    objetivoCents: 800,       // cierra ya si gana $8
    usarObjetivo: true,
    salirAlCierre: true,      // cierra siempre al terminar la ventana de 15'
    maxPerdidaDiaCents: 2000, // $20 de pérdida en el día -> se apaga
    maxOperacionesDia: 8,
    deslizamientoCents: 0,    // reservado: por ahora entra a mercado (IOC)
  };
}

function estadoDeFabrica() {
  return {
    ver: BOT_VER,
    creado: ahoraISO(),
    encendido: false,          // ARRANCA APAGADO a propósito: lo enciendes tú desde el panel
    modo: 'sombra',            // 'sombra' | 'real'
    ajustes: ajustesDeFabrica(),
    posicion: null,
    producto: null,            // { id, caducidad, elegidoISO }
    diario: { fecha: null, operaciones: 0, plCents: 0, arriesgadoCents: 0, ganadas: 0, perdidas: 0 },
    corteContadorISO: null,
    ultimaCorrida: null,
    aviso: null,               // avisos en rojo para el panel (posición huérfana, credenciales, etc.)
    migraciones: {},
  };
}

function aplicaMigraciones(e) {
  e.migraciones = e.migraciones || {};
  const base = ajustesDeFabrica();
  for (const k of Object.keys(base)) {
    if (e.ajustes[k] === undefined) e.ajustes[k] = base[k];
  }
  if (!e.migraciones.corte100) {
    e.corteContadorISO = e.corteContadorISO || ahoraISO();
    e.migraciones.corte100 = ahoraISO();
  }
  return e;
}

async function leeEstado() {
  const guardado = await leeJson(K.estado(), null);
  if (!guardado) return estadoDeFabrica();
  const e = Object.assign(estadoDeFabrica(), guardado);
  e.ajustes = Object.assign(ajustesDeFabrica(), guardado.ajustes || {});
  e.diario = Object.assign(estadoDeFabrica().diario, guardado.diario || {});
  return aplicaMigraciones(e);
}
async function guardaEstado(e) {
  e.ver = BOT_VER;
  await guardaJson(K.estado(), e);
}

const TOPE_SENALES = 600;
async function leeSenales() {
  const s = await leeJson(K.senales(), []);
  return Array.isArray(s) ? s : [];
}
async function guardaSenales(lista) {
  // NUNCA se filtra al guardar. El corte del contador se aplica solo al contar.
  const cortada = lista.slice(-TOPE_SENALES);
  await guardaJson(K.senales(), cortada);
}
async function anadeSenal(s) {
  const lista = await leeSenales();
  lista.push(s);
  await guardaSenales(lista);
  return s;
}
async function actualizaSenal(id, cambios) {
  const lista = await leeSenales();
  const i = lista.findIndex((x) => x.id === id);
  if (i < 0) return null;
  lista[i] = Object.assign({}, lista[i], cambios);
  await guardaSenales(lista);
  return lista[i];
}

// ------------------------------------------------------------
// CLIENTE DE COINBASE
// ------------------------------------------------------------
async function cbPublico(ruta) {
  const r = await fetch(`https://${CB_HOST}${CB_BASE}${ruta}`, {
    headers: { 'cache-control': 'no-cache', accept: 'application/json' },
  });
  const txt = await r.text();
  let j = null;
  try { j = JSON.parse(txt); } catch (e) { /* deja j en null */ }
  if (!r.ok) throw new Error(`Coinbase ${ruta}: HTTP ${r.status} ${txt.slice(0, 160)}`);
  return j;
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
  const r = await fetch(`https://${CB_HOST}${CB_BASE}${ruta}`, opciones);
  const txt = await r.text();
  let j = null;
  try { j = JSON.parse(txt); } catch (e) { /* deja j en null */ }
  if (r.status === 401 || r.status === 403) {
    const e = new Error(`Coinbase rechazó la credencial (HTTP ${r.status})`);
    e.credencial = true;
    throw e;
  }
  if (!r.ok) throw new Error(`Coinbase ${metodo} ${ruta}: HTTP ${r.status} ${txt.slice(0, 200)}`);
  return j;
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
  const j = await cbFirmado('GET', '/cfm/balance_summary');
  return (j && j.balance_summary) || {};
}

async function posicionesFuturos() {
  const j = await cbFirmado('GET', '/cfm/positions');
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
  const j = await cbFirmado('GET', `/orders/historical/${encodeURIComponent(ordenId)}`);
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
  }).format(d || new Date());
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
  return {
    valido: true,
    deriva: Number(deriva.toFixed(2)),
    sigma: Number(sigma.toFixed(2)),
    ruidoEsperado: Number(ruidoEsperado.toFixed(2)),
    ultimo: cierres[cierres.length - 1],
    velas: cierres.length,
  };
}

function decideDireccion(m, aj) {
  if (!m.valido) return { lado: null, motivo: m.motivo };
  const exigido = Math.max(aj.umbralSigma * m.ruidoEsperado, aj.minDerivaUsd);
  if (Math.abs(m.deriva) < exigido) {
    return {
      lado: null,
      motivo: `sin dirección clara (deriva $${m.deriva.toFixed(2)}, exigido $${exigido.toFixed(2)})`,
      exigido,
    };
  }
  return { lado: m.deriva > 0 ? 'largo' : 'corto', exigido };
}

function plCentsDe(lado, entrada, salida, contratos) {
  const signo = lado === 'largo' ? 1 : -1;
  return Math.round(contratos * BTC_POR_CONTRATO * (salida - entrada) * signo * 100);
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
    stopCents: a.stopCents,
    objetivoCents: a.objetivoCents,
    usarObjetivo: a.usarObjetivo,
    salirAlCierre: a.salirAlCierre,
    maxPerdidaDiaCents: a.maxPerdidaDiaCents,
    maxOperacionesDia: a.maxOperacionesDia,
    modo: e.modo,
  };
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
    spotAlEntrar: ctx.spot || null,
    spotAlSalir: null,
    vetadaPor,
    nota: ctx.nota || null,
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

  if (pos.modo === 'real') {
    const r = await creaOrden({
      productId: pos.productId, lado: ladoContrario, contratos: pos.contratos,
    });
    if (!r.exito) {
      // No se pudo cerrar: la posición SIGUE abierta. Se avisa en rojo y se reintenta
      // el minuto siguiente. Nunca se marca cerrada una posición que sigue viva.
      e.aviso = `⚠️ NO se pudo cerrar la posición (${motivo}): ${r.fallo}`;
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

  await actualizaSenal(pos.senalId, {
    estado: 'cerrada',
    precioSalida,
    ordenSalidaId,
    comisionCents: comisionTotal,
    plCents: plNeto,
    gano: plNeto > 0,
    motivoSalida: motivo,
    cerrada: ahoraISO(),
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
        e.aviso = `⚠️ No pude leer tus posiciones en Coinbase: ${err.message}. El bot no ordena a ciegas.`;
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
        informe.pasos.push('posición huérfana en el estado -> conciliada');
      } else if (!e.posicion && contratosBolsa > 0) {
        // NUNCA adoptar una posición que el bot no abrió
        e.aviso = `⚠️ Hay ${contratosBolsa} contrato(s) abiertos en ${e.producto.id} que este bot NO abrió. No ordeno nada hasta que se cierre.`;
        informe.pasos.push('posición ajena detectada -> bot en pausa');
        await guardaEstado(e);
        return informe;
      }
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
      await anadeSenal(nuevoFantasma(e, ctxBase, 'tope de pérdida diaria'));
      await guardaEstado(e); return informe;
    }
    if (e.modo === 'real' && !hayAlmacen()) {
      await anadeSenal(nuevoFantasma(e, ctxBase, 'sin almacén: en real no se ordena sin memoria'));
      e.aviso = 'No hay Redis configurado. En real el bot no ordena, porque sin memoria podría abrir la misma posición muchas veces.';
      await guardaEstado(e); return informe;
    }
    if (e.modo === 'real' && !posLegible) {
      await anadeSenal(nuevoFantasma(e, ctxBase, 'no pude leer posiciones en Coinbase'));
      await guardaEstado(e); return informe;
    }

    let m;
    try {
      m = mideMomentum(await velasSpot(aj.momentumMin));
    } catch (err) {
      await anadeSenal(nuevoFantasma(e, ctxBase, `sin velas: ${err.message}`));
      await guardaEstado(e); return informe;
    }
    const ctx = Object.assign({}, ctxBase, {
      deriva: m.deriva, sigma: m.sigma, ruidoEsperado: m.ruidoEsperado, spot: m.ultimo || precio,
    });
    const d = decideDireccion(m, aj);
    informe.momentum = m;
    if (!d.lado) {
      await anadeSenal(nuevoFantasma(e, ctx, d.motivo));
      informe.pasos.push(d.motivo);
      await guardaEstado(e); return informe;
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
      contratos: aj.contratos,
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
      spotAlEntrar: m.ultimo || precio,
      spotAlSalir: null,
      vetadaPor: null,
      nota: null,
      cfg: fotoConfig(e),
      ver: BOT_VER,
    };

    if (e.modo === 'real') {
      const r = await creaOrden({ productId: e.producto.id, lado: d.lado, contratos: aj.contratos });
      if (!r.exito) {
        senal.estado = 'error';
        senal.vetadaPor = null;
        senal.nota = `⚠️ ERROR al ordenar: ${r.fallo}`;
        await anadeSenal(senal);
        e.aviso = senal.nota;
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
  };
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
  ['pl_usd', (s) => (s.plCents != null ? (s.plCents / 100).toFixed(2) : '')],
  ['gano', (s) => (s.gano === null || s.gano === undefined ? '' : (s.gano ? 'si' : 'no'))],
  ['motivo_salida', (s) => s.motivoSalida],
  ['aproximado', (s) => (s.aproximado ? 'si' : '')],
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
  ['cfg_stop_usd', (s) => ((s.cfg || {}).stopCents != null ? ((s.cfg || {}).stopCents / 100).toFixed(2) : '')],
  ['cfg_objetivo_usd', (s) => ((s.cfg || {}).objetivoCents != null ? ((s.cfg || {}).objetivoCents / 100).toFixed(2) : '')],
  ['cfg_usar_objetivo', (s) => ((s.cfg || {}).usarObjetivo ? 'si' : 'no')],
  ['cfg_salir_al_cierre', (s) => ((s.cfg || {}).salirAlCierre ? 'si' : 'no')],
  ['cfg_max_perdida_dia_usd', (s) => ((s.cfg || {}).maxPerdidaDiaCents != null ? ((s.cfg || {}).maxPerdidaDiaCents / 100).toFixed(2) : '')],
  ['cfg_max_operaciones_dia', (s) => (s.cfg || {}).maxOperacionesDia],
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
  BOT_VER, SELLO, FOTO_VER, CB_HOST, CB_BASE, CLAVE_PANEL, CRON_SECRET,
  CB_KEY_NAME, CB_KEY_SECRET_RAW, BTC_POR_CONTRATO,
  ahoraISO, nuevoId, centavos, aUsd, num, limita, fechaET,
  normalizaLlave, cargaLlave, construyeJwt, b64url,
  hayAlmacen, redis, K, leeJson, guardaJson, tomaCerrojo, sueltaCerrojo,
  ajustesDeFabrica, estadoDeFabrica, leeEstado, guardaEstado,
  leeSenales, guardaSenales, anadeSenal, actualizaSenal,
  cbPublico, cbFirmado, listaFuturos, eligeProducto, precioProducto, velasSpot,
  balanceFuturos, posicionesFuturos, creaOrden, detalleOrden,
  contratosDePosicion, ladoDePosicion,
  cierreDeVentana, minutosParaCierre, mideMomentum, decideDireccion,
  plCentsDe, fotoConfig, ruedaDiario, nuevoFantasma, cierraPosicion, corre,
  estadisticas, cuenta, aCsv, COLUMNAS,
};
