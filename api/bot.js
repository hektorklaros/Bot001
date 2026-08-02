// Cron de Vercel: entra por GET cada minuto (vercel.json).
// Vercel manda "Authorization: Bearer <CRON_SECRET>" si la variable existe.
const N = require('../lib/nucleo.js');

function autorizado(req) {
  const cab = String((req.headers && (req.headers.authorization || req.headers.Authorization)) || '');
  const q = (req.query && (req.query.clave || req.query.key)) || '';
  if (N.CRON_SECRET && cab === `Bearer ${N.CRON_SECRET}`) return true;
  if (N.CLAVE_PANEL && (q === N.CLAVE_PANEL || cab === `Bearer ${N.CLAVE_PANEL}`)) return true;
  // Sin CRON_SECRET ni CLAVE_PANEL configurados no hay nada que proteger todavía:
  // el bot arranca apagado y en sombra.
  if (!N.CRON_SECRET && !N.CLAVE_PANEL) return true;
  return false;
}

module.exports = async (req, res) => {
  if (!autorizado(req)) {
    res.status(401).json({ ok: false, error: 'no autorizado' });
    return;
  }
  try {
    const informe = await N.corre({ origen: 'cron' });
    res.status(200).json({ ok: !informe.error, informe });
  } catch (err) {
    res.status(200).json({ ok: false, error: err.message });
  }
};
