'use strict';
// ══════════════════════════════════════════════════════════════════════════
//  PERSISTENCIA OHLCV · las velas que Darvas necesita para existir
//  Informe técnico del 19 ago 2026, §8.3
//
//  POR QUÉ HACE FALTA: el motor Darvas ya estaba escrito y probado, pero
//  consumía velas que NADIE grababa. Sin esto, `darvas_6h_v1` y `darvas_8h_v1`
//  devuelven VETO_HISTORIAL_INSUFICIENTE para siempre y no acumulan ni una
//  observación. Es la pieza que separa "el motor funciona" de "el motor mide".
//
//  DE DÓNDE SALEN: la API pública de velas de Coinbase, la misma que ya usaba
//  `velasSpot` para el minuto a minuto. No hace falta ninguna fuente nueva ni
//  ninguna llave.
//
//  LA REGLA QUE LO GOBIERNA TODO: `is_complete`. Una vela solo está completa
//  cuando su ventana ya cerró del todo. Darvas rechaza las incompletas, así que
//  marcarlas mal sería mirar el futuro sin darse cuenta — el error más caro que
//  se puede cometer en un backtest, porque no falla: solo miente.
// ══════════════════════════════════════════════════════════════════════════

const MS_15M = 15 * 60 * 1000;

// Coinbase nombra las granularidades así, no en minutos.
const GRANULARIDAD = { 15: 'FIFTEEN_MINUTE', 60: 'ONE_HOUR' };

// Techo de velas guardadas. Con 15 minutos, 1.500 velas son unos 15 días —
// suficiente para la caja de 8 h (32 velas) con muchísimo margen, y para
// revisar a mano lo que pasó.
const MAX_VELAS = 1500;

// El inicio de la ventana de 15 minutos que contiene ese instante.
function inicioVentana(ms, minutos) {
  const paso = minutos * 60 * 1000;
  return Math.floor(ms / paso) * paso;
}

// ── ¿Está cerrada esta vela? ─────────────────────────────────────────────
// Solo si su ventana terminó ANTES de ahora. El margen de gracia existe porque
// Coinbase puede tardar unos segundos en consolidar la última vela: sin él, se
// grabaría como completa una vela que todavía puede cambiar.
function estaCompleta(inicioMs, minutos, ahoraMs, graciaMs) {
  const fin = inicioMs + minutos * 60 * 1000;
  return (ahoraMs - (graciaMs == null ? 20000 : graciaMs)) >= fin;
}

// ── Traer velas OHLCV de Coinbase ────────────────────────────────────────
// Devuelve los campos que pide el informe. `volume` y `trade_count` se guardan
// como OBSERVACIÓN: el filtro de volumen empieza apagado y no debe activarse
// sin un backtest propio.
async function traeVelas(cbPublico, { producto, minutos, cuantas, ahoraMs }) {
  const gran = GRANULARIDAD[minutos];
  if (!gran) throw new Error('granularidad no soportada: ' + minutos);
  const ahora = ahoraMs || Date.now();
  const fin = Math.floor(ahora / 1000);
  const ini = fin - (cuantas + 3) * minutos * 60;
  const j = await cbPublico(
    `/market/products/${encodeURIComponent(producto)}/candles`
    + `?start=${ini}&end=${fin}&granularity=${gran}&limit=${Math.min(cuantas + 5, 350)}`
  );
  const crudas = (j && j.candles) || [];
  const velas = crudas.map((c) => {
    const inicioMs = Number(c.start) * 1000;
    const o = Number(c.open), h = Number(c.high), l = Number(c.low), cl = Number(c.close);
    if (![inicioMs, o, h, l, cl].every(Number.isFinite)) return null;
    // vwap: Coinbase no lo da en este endpoint. Se aproxima con el típico
    // (alto+bajo+cierre)/3 y se DEJA DICHO que es una aproximación, para que
    // nadie lo confunda con el vwap real ponderado por operación.
    const vol = Number(c.volume);
    return {
      bar_open_time: new Date(inicioMs).toISOString(),
      bar_close_time: new Date(inicioMs + minutos * 60 * 1000).toISOString(),
      open: o, high: h, low: l, close: cl,
      volume: Number.isFinite(vol) ? vol : null,
      trade_count: Number.isFinite(Number(c.trade_count)) ? Number(c.trade_count) : null,
      vwap: Number(((h + l + cl) / 3).toFixed(2)),
      vwap_es_aproximado: true,
      best_bid_at_close: null,     // se rellena al cerrar, con el libro en vivo
      best_ask_at_close: null,
      spread_at_close: null,
      is_complete: estaCompleta(inicioMs, minutos, ahora),
      source: 'coinbase_candles',
      _t: inicioMs,
    };
  }).filter(Boolean);
  velas.sort((a, b) => a._t - b._t);   // viejas primero, como espera Darvas
  return velas;
}

// ── Fundir lo nuevo con lo guardado ──────────────────────────────────────
// Una vela ya marcada completa NO se reescribe: si Coinbase devolviera un valor
// distinto más tarde, cambiaría el pasado y el backtest dejaría de ser
// reproducible (§11.3). Las incompletas sí se actualizan, que para eso lo son.
function fusiona(guardadas, nuevas, max) {
  const porT = new Map();
  for (const v of guardadas || []) porT.set(v._t, v);
  for (const n of nuevas || []) {
    const vieja = porT.get(n._t);
    if (vieja && vieja.is_complete) continue;          // el pasado no se toca
    porT.set(n._t, vieja ? Object.assign({}, vieja, n) : n);
  }
  const todas = Array.from(porT.values()).sort((a, b) => a._t - b._t);
  return todas.slice(-(max || MAX_VELAS));
}

// Al cerrar una vela se le pega el libro de ese momento. Darvas veta por
// spread, así que sin esto no puede aplicar su propio filtro.
function selloDeLibro(vela, libro) {
  if (!vela || !libro) return vela;
  vela.best_bid_at_close = libro.compra != null ? libro.compra : null;
  vela.best_ask_at_close = libro.venta != null ? libro.venta : null;
  vela.spread_at_close = (libro.compra != null && libro.venta != null)
    ? Number((libro.venta - libro.compra).toFixed(2)) : null;
  return vela;
}

// ── El ciclo: traer, sellar y guardar ────────────────────────────────────
// Se llama una vez por corrida. Es barato: dos peticiones públicas.
async function actualiza(io, opciones) {
  const o = opciones || {};
  const producto = o.producto || 'BTC-USD';
  const ahora = o.ahoraMs || Date.now();
  const salida = { velas15m: [], velas1h: [], error: null };
  try {
    const guardadas = (await io.lee()) || { v15: [], v60: [] };
    const n15 = await traeVelas(io.cbPublico, { producto, minutos: 15, cuantas: 40, ahoraMs: ahora });
    const n60 = await traeVelas(io.cbPublico, { producto, minutos: 60, cuantas: 6, ahoraMs: ahora });

    // sellar con el libro SOLO la última vela recién cerrada
    if (io.libroDe && o.productoFuturo) {
      const ultimaCerrada = [...n15].reverse().find(v => v.is_complete);
      if (ultimaCerrada && !ultimaCerrada.best_bid_at_close) {
        try { selloDeLibro(ultimaCerrada, await io.libroDe(o.productoFuturo)); }
        catch (e) { /* sin libro la vela sigue siendo útil, solo sin spread */ }
      }
    }

    const v15 = fusiona(guardadas.v15, n15, MAX_VELAS);
    const v60 = fusiona(guardadas.v60, n60, 400);
    await io.guarda({ v15, v60, actualizado: new Date(ahora).toISOString() });
    salida.velas15m = v15;
    salida.velas1h = v60;
  } catch (err) {
    // Sin velas, Darvas no decide nada — que es lo correcto. No se inventa
    // historial ni se reutiliza el viejo como si fuera fresco.
    salida.error = err.message;
  }
  return salida;
}

module.exports = { traeVelas, fusiona, selloDeLibro, actualiza,
  estaCompleta, inicioVentana, GRANULARIDAD, MAX_VELAS, MS_15M };
