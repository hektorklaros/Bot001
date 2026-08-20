// ============================================================
// KRONOS-CB · lib/panel-extra.js — 20 ago 2026
//
// POR QUÉ EXISTE ESTE ARCHIVO
// El front (index.html) pide seis cosas que el nucleo v1.6 no construye:
//   stats.curvaReal · stats.curvaSombra · stats.cinta · stats.serieSpot
//   stats.motivos   · reglas  (por N.reglasVigentes, que no existía)
// Sin ellas, tres tarjetas del panel salen vacías aunque el contador de
// vetadas suba, y la llamada a reglasVigentes reventaba el panel entero
// antes de validar la clave.
//
// Se pone aparte a propósito: nucleo.js no se toca, así que un fallo aquí
// no puede tumbar el motor que ordena. Esto solo lo lee el panel.
// ============================================================

// El corte del contador NO borra señales: solo marca desde cuándo se cuenta.
function filtroCorte(e) {
  const corte = e && e.corteContadorISO ? Date.parse(e.corteContadorISO) : 0;
  return (s) => {
    if (!corte) return true;
    const t = Date.parse(s.creada);
    return !Number.isFinite(t) || t >= corte;
  };
}

// ---------- curvas acumuladas ----------
// El front dibuja real en línea sólida y sombra tenue detrás. Cada punto es
// el acumulado DESPUÉS de esa operación, así que la curva arranca en la
// primera liquidada y no en cero.
function curvaDe(senales, modo, dentro) {
  let acumulado = 0;
  const puntos = [];
  for (const s of senales) {
    if (s.estado !== 'cerrada') continue;
    if (s.modo !== modo) continue;
    if (!dentro(s)) continue;
    acumulado += Number(s.plCents) || 0;
    puntos.push({ plCents: acumulado, creada: s.creada });
  }
  return puntos;
}

// ---------- la cinta de ventanas ----------
// Una barra por señal reciente. El alto lo pone el front; aquí solo va lo
// que necesita para elegir color y texto al tocarla.
function cintaDe(senales, dentro, cuantas) {
  const n = cuantas || 60;
  return senales
    .filter(dentro)
    .slice(-n)
    .map((s) => ({
      estado: s.estado,
      plCents: s.estado === 'cerrada' ? (Number(s.plCents) || 0) : 0,
      modo: s.modo,
      motivo: s.vetadaPor || s.motivoSalida || s.nota || s.estado,
      creada: s.creada,
    }));
}

// ---------- el precio que vio el bot ----------
// Punto grande = entró (ámbar largo, azul corto). Punto pequeño gris = vetó.
// Solo entran señales con precio guardado: un cero inventado deformaría la
// escala del gráfico entero.
function serieSpotDe(senales, dentro, cuantas) {
  const n = cuantas || 80;
  const salida = [];
  for (const s of senales) {
    if (!dentro(s)) continue;
    const spot = Number(s.spotAlEntrar);
    if (!Number.isFinite(spot) || spot <= 0) continue;
    salida.push({
      spot,
      estado: s.estado,
      lado: s.lado || null,
      creada: s.creada,
    });
  }
  return salida.slice(-n);
}

// ---------- por qué no operó ----------
// Se agrupan los motivos de veto tal cual los escribió el motor. Los motivos
// llevan cifras dentro ("deriva corta (deriva $12.40, exigido $126.00)"), así
// que se recorta la parte variable para que no salgan mil grupos de uno.
function normalizaMotivo(txt) {
  return String(txt || 'sin motivo')
    .replace(/\([^)]*\)/g, '')      // fuera los paréntesis con cifras
    .replace(/\$-?[\d.,]+/g, '$')   // fuera los importes sueltos
    .replace(/\s+/g, ' ')
    .trim() || 'sin motivo';
}

function motivosDe(senales, dentro, cuantos) {
  const cuenta = new Map();
  for (const s of senales) {
    if (s.estado !== 'fantasma') continue;
    if (!dentro(s)) continue;
    const clave = normalizaMotivo(s.vetadaPor);
    cuenta.set(clave, (cuenta.get(clave) || 0) + 1);
  }
  return [...cuenta.entries()]
    .map(([motivo, n]) => ({ motivo, n }))
    .sort((a, b) => b.n - a.n)
    .slice(0, cuantos || 8);
}

// ---------- las cinco series juntas ----------
function extras(e, senales) {
  const dentro = filtroCorte(e);
  return {
    curvaReal: curvaDe(senales, 'real', dentro),
    curvaSombra: curvaDe(senales, 'sombra', dentro),
    cinta: cintaDe(senales, dentro),
    serieSpot: serieSpotDe(senales, dentro),
    motivos: motivosDe(senales, dentro),
  };
}

// ============================================================
// REGLAS VIGENTES
// Lo que el bot exige AHORA para abrir, y los límites que se ha puesto.
// Se leen de los ajustes guardados, no de los de fábrica: si tú cambiaste
// algo en el panel, aquí sale lo que cambiaste.
// ============================================================
const pct = (x) => Math.round((Number(x) || 0) * 100) + '%';
const dol = (cents) => '$' + ((Number(cents) || 0) / 100).toFixed(2);

function reglasVigentes(N, e, spot) {
  const a = (e && e.ajustes) || {};
  const contratos = Number(a.contratos) || 1;

  // El peaje: lo que cuesta abrir y cerrar una vez, y cuánto tiene que
  // moverse BTC solo para empatar. Si el bot exige menos que esto, autoriza
  // operaciones que pierden por aritmética aunque acierte la dirección.
  let peaje = null;
  if (Number.isFinite(spot) && spot > 0) {
    const btcPorContrato = N.BTC_POR_CONTRATO;
    const nocional = spot * btcPorContrato * contratos;
    const comisiones = nocional * (Number(a.comisionPct) || 0) * 2;
    peaje = {
      porOperacion: comisiones,
      movimientoParaEmpatar: N.costeIdaVueltaBtc(spot, a).toFixed(0),
      nocional: Number(nocional.toFixed(2)),
    };
  }

  const entrada = [
    { regla: 'Contrato', valor: (a.prefijoProducto || '—') + (a.prefijoProducto === 'BIP' ? ' · perpetuo' : ' · mensual') },
    { regla: 'Momento de entrada', valor: `a ${a.minutosAntes} min del cierre · ±${a.tolMin}` },
    { regla: 'Ventana de momentum', valor: `${a.momentumMin} min de velas` },
    { regla: 'Deriva exigida', valor: `la mayor de: ${a.umbralSigma}σ · $${a.minDerivaUsd} · ${a.multiploCoste}× peaje` },
    { regla: 'Coherencia mínima', valor: `${pct(a.minCoherencia)} de los minutos a favor` },
    {
      regla: 'Libro',
      valor: a.exigirLibro
        ? `diferencial máximo $${a.maxDiferencialUsd} · sin libro no ordena`
        : 'no se mira (riesgo de llenado malo)',
    },
    {
      regla: 'Horario',
      valor: a.soloMargenBarato
        ? `solo margen barato · para ${a.colchonCierreMin} min antes de las 4pm ET`
        : 'a cualquier hora (margen caro incluido)',
    },
  ];

  const riesgo = [
    { regla: 'Contratos por operación', valor: `${contratos} · tope duro ${N.MAX_CONTRATOS}` },
    {
      regla: 'Exposición',
      valor: peaje ? `$${peaje.nocional.toFixed(2)} de BTC por operación` : 'sin precio todavía',
    },
    { regla: 'Peaje de ida y vuelta', valor: peaje ? `$${peaje.porOperacion.toFixed(2)}` : '—' },
    { regla: 'Stop', valor: dol(a.stopCents) },
    { regla: 'Objetivo', valor: a.usarObjetivo ? dol(a.objetivoCents) : 'sin objetivo' },
    { regla: 'Cierre de ventana', valor: a.salirAlCierre ? 'cierra siempre a los 15 min' : 'aguanta más allá de la ventana' },
    { regla: 'Tope de pérdida del día', valor: `${dol(a.maxPerdidaDiaCents)} · se apaga solo` },
    { regla: 'Máximo de operaciones al día', valor: String(a.maxOperacionesDia) },
    { regla: 'Modo', valor: e.modo === 'real' ? 'DINERO REAL' : 'sombra · no se ordena nada' },
    {
      regla: 'Almacén',
      valor: N.hayAlmacen() ? 'Redis conectado' : 'SIN almacén · en real no ordena',
    },
  ];

  return { entrada, riesgo, peaje };
}

module.exports = { extras, reglasVigentes, filtroCorte, normalizaMotivo };
