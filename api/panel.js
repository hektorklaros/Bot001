// API del panel. Todo pasa por clave.
const N = require('../lib/nucleo.js');

function claveDe(req) {
  const h = (req.headers && (req.headers['x-clave'] || req.headers['X-Clave'])) || '';
  const q = (req.query && (req.query.clave || req.query.key)) || '';
  const b = (req.body && req.body.clave) || '';
  return String(h || q || b || '');
}
function autorizado(req) {
  if (!N.CLAVE_PANEL) return false; // sin clave configurada el panel no abre
  return claveDe(req) === N.CLAVE_PANEL;
}

function limpiaAjustes(entrada, actuales) {
  const a = Object.assign({}, actuales);
  const e = entrada || {};
  const enteros = {
    contratos: [1, 5],
    minutosAntes: [1, 14],
    momentumMin: [3, 60],
    stopCents: [50, 10000],
    objetivoCents: [50, 10000],
    maxPerdidaDiaCents: [100, 50000],
    maxOperacionesDia: [1, 96],
    minDerivaUsd: [0, 5000],
  };
  for (const [k, [min, max]] of Object.entries(enteros)) {
    if (e[k] !== undefined) a[k] = Math.round(N.limita(N.num(e[k], a[k]), min, max));
  }
  if (e.tolMin !== undefined) a.tolMin = N.limita(N.num(e.tolMin, a.tolMin), 0.25, 5);
  if (e.umbralSigma !== undefined) a.umbralSigma = N.limita(N.num(e.umbralSigma, a.umbralSigma), 0, 6);
  if (e.usarObjetivo !== undefined) a.usarObjetivo = Boolean(e.usarObjetivo);
  if (e.salirAlCierre !== undefined) a.salirAlCierre = Boolean(e.salirAlCierre);
  if (e.prefijoProducto !== undefined) {
    const p = String(e.prefijoProducto).toUpperCase().trim();
    if (p === 'BIP' || p === 'BIT') a.prefijoProducto = p;
  }
  return a;
}

async function paquete() {
  const e = await N.leeEstado();
  const senales = await N.leeSenales();
  return {
    ver: N.BOT_VER,
    sello: N.SELLO,
    ahora: N.ahoraISO(),
    estado: {
      encendido: e.encendido,
      modo: e.modo,
      producto: e.producto,
      posicion: e.posicion,
      diario: e.diario,
      aviso: e.aviso,
      corteContadorISO: e.corteContadorISO,
      ultimaCorrida: e.ultimaCorrida,
    },
    ajustes: e.ajustes,
    entorno: {
      almacen: N.hayAlmacen(),
      credenciales: Boolean(N.CB_KEY_NAME && N.CB_KEY_SECRET_RAW),
      cronSecret: Boolean(N.CRON_SECRET),
    },
    stats: N.estadisticas(e, senales),
    senales: senales.slice(-60).reverse(),
  };
}

module.exports = async (req, res) => {
  const q = req.query || {};
  const accion = String(q.accion || (req.body && req.body.accion) || '').trim();

  if (!N.CLAVE_PANEL) {
    res.status(500).json({ ok: false, error: 'falta la variable CLAVE_PANEL en Vercel' });
    return;
  }
  if (!autorizado(req)) {
    res.status(401).json({ ok: false, error: 'clave incorrecta' });
    return;
  }

  try {
    // ---------- GET ----------
    if (req.method === 'GET') {
      if (accion === 'export') {
        const senales = await N.leeSenales();
        const nombre = `senales-kronos-cb-${N.fechaET().replace(/-/g, '')}.csv`;
        res.setHeader('content-type', 'text/csv; charset=utf-8');
        res.setHeader('content-disposition', `attachment; filename="${nombre}"`);
        res.status(200).send(N.aCsv(senales));
        return;
      }
      if (accion === 'prueba') {
        const salida = { almacen: null, llave: null, coinbase: null, contrato: null, balance: null };
        try {
          await N.redis(['SET', `${N.K.estado()}:ping`, String(Date.now())]);
          salida.almacen = N.hayAlmacen() ? 'ok (Redis responde)' : 'SIN ALMACÉN: memoria volátil, en real no se ordena';
        } catch (err) { salida.almacen = `falla: ${err.message}`; }
        try {
          const l = N.cargaLlave();
          salida.llave = `ok (${l.alg}, leída como ${l.origen})`;
        } catch (err) { salida.llave = `falla: ${err.message}`; }
        try {
          const j = await N.cbFirmado('GET', '/key_permissions');
          salida.coinbase = `ok (puede ver: ${j && j.can_view}, puede operar: ${j && j.can_trade})`;
        } catch (err) { salida.coinbase = `falla: ${err.message}`; }
        try {
          const e = await N.leeEstado();
          const p = await N.eligeProducto(e.ajustes.prefijoProducto);
          const precio = await N.precioProducto(p.id);
          salida.contrato = `${p.id} a ${precio} (exposición por contrato: $${(precio * N.BTC_POR_CONTRATO).toFixed(2)})`;
        } catch (err) { salida.contrato = `falla: ${err.message}`; }
        try {
          const b = await N.balanceFuturos();
          const saldo = (b.cfm_usd_balance && b.cfm_usd_balance.value) || (b.total_usd_balance && b.total_usd_balance.value);
          salida.balance = saldo !== undefined ? `$${saldo}` : JSON.stringify(b).slice(0, 200);
        } catch (err) { salida.balance = `falla: ${err.message}`; }
        res.status(200).json({ ok: true, prueba: salida });
        return;
      }
      if (accion && accion !== 'estado') {
        res.status(400).json({ ok: false, error: `acción desconocida: ${accion}` });
        return;
      }
      res.status(200).json(Object.assign({ ok: true }, await paquete()));
      return;
    }

    // ---------- POST ----------
    if (req.method !== 'POST') { res.status(405).json({ ok: false, error: 'método no permitido' }); return; }
    const cuerpo = req.body || {};
    const e = await N.leeEstado();

    if (accion === 'ajustes') {
      e.ajustes = limpiaAjustes(cuerpo.ajustes, e.ajustes);
      await N.guardaEstado(e);
      res.status(200).json(Object.assign({ ok: true }, await paquete()));
      return;
    }

    if (accion === 'encender' || accion === 'apagar') {
      e.encendido = accion === 'encender';
      if (e.encendido) e.aviso = null;
      await N.guardaEstado(e);
      res.status(200).json(Object.assign({ ok: true }, await paquete()));
      return;
    }

    if (accion === 'modo') {
      const m = String(cuerpo.modo || '').toLowerCase();
      if (m !== 'real' && m !== 'sombra') { res.status(400).json({ ok: false, error: 'modo inválido' }); return; }
      if (e.posicion) { res.status(400).json({ ok: false, error: 'hay una posición abierta: ciérrala antes de cambiar de modo' }); return; }
      if (m === 'real' && !N.hayAlmacen()) { res.status(400).json({ ok: false, error: 'no puedo pasar a real sin Redis configurado' }); return; }
      if (m === 'real' && cuerpo.confirmo !== 'DINERO REAL') { res.status(400).json({ ok: false, error: 'para pasar a real hay que escribir DINERO REAL' }); return; }
      e.modo = m;
      await N.guardaEstado(e);
      res.status(200).json(Object.assign({ ok: true }, await paquete()));
      return;
    }

    if (accion === 'correr') {
      const informe = await N.corre({ origen: 'panel' });
      res.status(200).json(Object.assign({ ok: true, informe }, await paquete()));
      return;
    }

    if (accion === 'panico') {
      // cierra lo que haya y apaga
      let cierre = null;
      if (e.posicion) {
        try {
          const precio = await N.precioProducto(e.posicion.productId);
          cierre = await N.cierraPosicion(e, 'botón de pánico', precio);
        } catch (err) { cierre = { fallo: err.message }; }
      }
      e.encendido = false;
      await N.guardaEstado(e);
      res.status(200).json(Object.assign({ ok: true, cierre }, await paquete()));
      return;
    }

    if (accion === 'reiniciar-contador') {
      // NO borra nada: solo mueve el corte desde el que se cuenta
      e.corteContadorISO = N.ahoraISO();
      await N.guardaEstado(e);
      res.status(200).json(Object.assign({ ok: true }, await paquete()));
      return;
    }

    if (accion === 'borrar-historial') {
      if (cuerpo.confirmo !== 'BORRAR') { res.status(400).json({ ok: false, error: 'hay que escribir BORRAR en mayúsculas' }); return; }
      const cuantas = (await N.leeSenales()).length;
      if (Number(cuerpo.cuantas) !== cuantas) {
        res.status(400).json({ ok: false, error: `descuadre: el panel dice ${cuerpo.cuantas} y el almacén tiene ${cuantas}. No borro nada.` });
        return;
      }
      await N.guardaSenales([]);
      res.status(200).json(Object.assign({ ok: true, borradas: cuantas }, await paquete()));
      return;
    }

    res.status(400).json({ ok: false, error: `acción desconocida: ${accion}` });
  } catch (err) {
    res.status(200).json({ ok: false, error: err.message });
  }
};
