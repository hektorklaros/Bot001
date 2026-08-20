'use strict';
// ══════════════════════════════════════════════════════════════════════════
//  MOTOR DARVAS · darvas_6h_v1 y darvas_8h_v1
//  Informe técnico del 19 de agosto de 2026 · KRONOS-CB
//
//  QUÉ ES: Nicolas Darvas compraba cuando el precio rompía por arriba una
//  "caja" — un rango en el que llevaba un tiempo encerrado — y ponía el stop
//  justo debajo de la caja. Aquí la caja son las últimas N velas de 15 minutos.
//
//  LO QUE ESTE MOTOR **NO** HACE, y es deliberado:
//    · NO opera en corto. La simulación bajista dio −$26,15 (caja de 6 h) y
//      −$19,60 (8 h). Los cortos quedan desactivados.
//    · NO piramida ni promedia posiciones perdedoras.
//    · NO usa objetivo fijo de $8 — el original no lo tiene.
//    · NO cierra al terminar la ventana de 15 minutos. Eso es del baseline.
//    · NO puede operar en real. `real_trading_allowed` es false y hay una
//      comprobación explícita que lo impide.
//
//  ADVERTENCIA HONESTA SOBRE LOS NÚMEROS QUE LO JUSTIFICAN:
//  en la simulación, UNA SOLA operación (19 ago, 11:09→17:09 UTC, ~+$37,25)
//  explicó el 100% del resultado de la caja de 6 h y el 94% de la de 8 h. Sin
//  ella, las dos quedan en cero o negativo. Esto NO demuestra rentabilidad: es
//  motivo suficiente para MEDIR en sombra, y nada más.
// ══════════════════════════════════════════════════════════════════════════

const CONFIGS = {
  darvas_6h_v1: {
    strategy_id: 'darvas_6h_v1', enabled: true, mode: 'shadow',
    contract_prefix: 'BIP', contracts: 1,
    bar_interval_minutes: 15, box_lookback_bars: 24, box_confirmation_bars: 3,
    higher_timeframe_minutes: 60, direction: 'LONG_ONLY',
    breakout_buffer_ticks: 1, tick_size_index_points: 5,
    maximum_spread_index_points: 10, maximum_total_initial_risk_usd: 6,
    initial_stop_buffer_ticks: 1, trailing_swing_confirmation_bars: 3,
    fixed_take_profit_enabled: false, forced_15m_window_exit_enabled: false,
    pyramiding_enabled: false, shorts_enabled: false,
    volume_filter_enabled: false, real_trading_allowed: false,
  },
  darvas_8h_v1: {
    strategy_id: 'darvas_8h_v1', enabled: true, mode: 'shadow',
    contract_prefix: 'BIP', contracts: 1,
    bar_interval_minutes: 15, box_lookback_bars: 32, box_confirmation_bars: 3,
    higher_timeframe_minutes: 60, direction: 'LONG_ONLY',
    breakout_buffer_ticks: 1, tick_size_index_points: 5,
    maximum_spread_index_points: 10, maximum_total_initial_risk_usd: 6,
    initial_stop_buffer_ticks: 1, trailing_swing_confirmation_bars: 3,
    fixed_take_profit_enabled: false, forced_15m_window_exit_enabled: false,
    pyramiding_enabled: false, shorts_enabled: false,
    volume_filter_enabled: false, real_trading_allowed: false,
  },
};

const BTC_POR_CONTRATO = 0.01;

// ── VELAS · solo las CERRADAS cuentan ────────────────────────────────────
// El informe insiste: una vela incompleta nunca participa en una caja, y la
// vela que se está evaluando nunca participa en su propio umbral de ruptura.
// Es la diferencia entre un backtest honesto y uno que mira el futuro.
function velasCerradas(velas) {
  return (velas || []).filter(v => v && v.is_complete === true);
}

// Un extremo está CONFIRMADO si, desde la última vela que lo tocó, han cerrado
// al menos `confirm` velas más sin romperlo. Sin esto, cualquier máximo
// reciente valdría como techo de caja y la ruptura sería un espejismo.
function extremoConfirmado(barras, confirm, cual) {
  if (!barras.length) return false;
  const val = cual === 'top'
    ? Math.max(...barras.map(b => b.high))
    : Math.min(...barras.map(b => b.low));
  let ultimoToque = -1;
  barras.forEach((b, i) => {
    const v = cual === 'top' ? b.high : b.low;
    if (v === val) ultimoToque = i;
  });
  if (ultimoToque < 0) return false;
  const posteriores = barras.length - 1 - ultimoToque;
  if (posteriores < confirm) return false;
  // y ninguna de las posteriores lo rompió
  for (let i = ultimoToque + 1; i < barras.length; i++) {
    if (cual === 'top' && barras[i].high > val) return false;
    if (cual === 'bottom' && barras[i].low < val) return false;
  }
  return true;
}

// Tendencia horaria, solo con velas de una hora YA CERRADAS.
function tendenciaHorariaPositiva(velasHora) {
  const c = velasCerradas(velasHora);
  if (c.length < 2) return null;             // null = no se sabe, NO es "sí"
  return c[c.length - 1].close > c[c.length - 2].close;
}

// El riesgo se calcula ENTERO antes de entrar: distancia al stop más las dos
// comisiones y la fricción. Si pasa de $6, se veta la caja. El informe lo dice
// expresamente: NO estrechar el stop artificialmente para que quepa.
function riesgoTotalUsd(entrada, stop, contratos, costes) {
  const c = costes || {};
  const precio = (entrada - stop) * BTC_POR_CONTRATO * contratos;
  return precio + (c.comisionEntrada || 0.15) + (c.comisionSalida || 0.15)
       + (c.friccion || 0.10);
}

// ── LA DECISIÓN ──────────────────────────────────────────────────────────
// Devuelve siempre un objeto con `action` y `reason`, nunca lanza. Las razones
// son las del pseudocódigo del informe, para que el panel las pueda listar.
function evalua(cfg, snapshot, state) {
  const st = state || {};
  const snap = snapshot || {};

  if (snap.brokerEstadoDesconocido) {
    return { action: 'VETO', reason: 'ERROR_RECONCILIACION_REQUERIDA', strategyId: cfg.strategy_id };
  }

  // ── con posición abierta: solo se sube el stop, nunca se baja ──────────
  if (st.posicion) {
    const minAsc = minimoAscendenteConfirmado(velasCerradas(snap.velas15m), cfg.trailing_swing_confirmation_bars);
    if (minAsc != null) {
      const candidato = minAsc - cfg.initial_stop_buffer_ticks * cfg.tick_size_index_points;
      if (candidato > st.stopVigente) {
        return { action: 'HOLD', reason: 'SUBIR_STOP', nuevoStop: candidato, strategyId: cfg.strategy_id };
      }
    }
    return { action: 'HOLD', reason: 'POSICION_ABIERTA', strategyId: cfg.strategy_id };
  }

  const cerradas = velasCerradas(snap.velas15m);
  // la vela en curso NO entra en la caja: se toman las N ANTERIORES
  const hist = cerradas.slice(-cfg.box_lookback_bars);
  if (hist.length < cfg.box_lookback_bars) {
    return { action: 'VETO', reason: 'VETO_HISTORIAL_INSUFICIENTE', strategyId: cfg.strategy_id };
  }

  const boxTop = Math.max(...hist.map(b => b.high));
  const boxBottom = Math.min(...hist.map(b => b.low));

  if (!extremoConfirmado(hist, cfg.box_confirmation_bars, 'top')
   || !extremoConfirmado(hist, cfg.box_confirmation_bars, 'bottom')) {
    return { action: 'VETO', reason: 'VETO_CAJA_NO_CONFIRMADA', boxTop, boxBottom, strategyId: cfg.strategy_id };
  }

  const tend = tendenciaHorariaPositiva(snap.velas1h);
  if (tend !== true) {
    return { action: 'VETO', reason: 'VETO_TENDENCIA_HORARIA', boxTop, boxBottom, strategyId: cfg.strategy_id };
  }

  if (snap.spread == null || snap.spread > cfg.maximum_spread_index_points) {
    return { action: 'VETO', reason: 'VETO_SPREAD', spread: snap.spread, strategyId: cfg.strategy_id };
  }

  const tick = cfg.tick_size_index_points;
  const entrada = boxTop + cfg.breakout_buffer_ticks * tick;
  const stop = boxBottom - cfg.initial_stop_buffer_ticks * tick;
  const riesgo = riesgoTotalUsd(entrada, stop, cfg.contracts, snap.costes);
  if (riesgo > cfg.maximum_total_initial_risk_usd) {
    return { action: 'VETO', reason: 'VETO_CAJA_DEMASIADO_ANCHA', riesgoUsd: Number(riesgo.toFixed(2)),
             boxTop, boxBottom, strategyId: cfg.strategy_id };
  }

  if (snap.askEjecutable == null || snap.askEjecutable < entrada) {
    return { action: 'HOLD', reason: 'ESPERANDO_RUPTURA', intendedEntry: entrada,
             initialStop: stop, boxTop, boxBottom, strategyId: cfg.strategy_id };
  }

  return {
    action: 'ENTER_LONG', reason: 'RUPTURA_CONFIRMADA',
    strategyId: cfg.strategy_id, configId: cfg.strategy_id,
    requestedContracts: cfg.contracts,
    intendedEntry: entrada, initialStop: stop,
    boxTop, boxBottom, riesgoUsd: Number(riesgo.toFixed(2)),
  };
}

// Último mínimo ASCENDENTE confirmado por `confirm` velas cerradas posteriores.
function minimoAscendenteConfirmado(barras, confirm) {
  if (!barras || barras.length < confirm + 2) return null;
  for (let i = barras.length - 1 - confirm; i >= 1; i--) {
    const m = barras[i].low;
    if (m >= barras[i - 1].low) continue;          // tiene que ser un mínimo local
    let vale = true;
    for (let j = i + 1; j <= i + confirm; j++) if (barras[j].low < m) { vale = false; break; }
    if (vale) return m;
  }
  return null;
}

// ── CANDADO DE DINERO REAL ───────────────────────────────────────────────
// Ninguna ruta de Darvas puede ordenar en real. Esto no depende del panel ni
// del estado guardado: está en el código y hay una prueba que lo vigila.
function puedeOperarReal(cfg) { return false; }

module.exports = { CONFIGS, evalua, velasCerradas, extremoConfirmado,
  tendenciaHorariaPositiva, riesgoTotalUsd, minimoAscendenteConfirmado,
  puedeOperarReal, BTC_POR_CONTRATO };
