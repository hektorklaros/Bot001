# Kronos-CB v1.0 — futuros nano de BTC en Coinbase, corriendo en Vercel

`v1.0 · 2026-08-02 08-30ET`

Traducción de **klaros2** (Kalshi/Netlify) a Coinbase Advanced (futuros de EE.UU.) sobre Vercel.
Arranca **apagado y en sombra**. Nada se ordena hasta que tú lo enciendes.

---

## Lo primero: los números que cambian respecto a Kalshi

| | klaros2 (Kalshi) | Kronos-CB |
|---|---|---|
| Ticket mínimo | $1 | 1 contrato = 0,01 BTC ≈ **$630** de exposición con BTC a $63.000 |
| Peor caso por operación | pierdes el ticket | lo pone el mercado — por eso el **stop** es obligatorio, no opcional |
| Dirección | solo comprar el favorito | **largo y corto** |
| Llenado | "sin vendedores en rango" | libro profundo, entra a mercado |

Con el stop de fábrica en **$8** y el tope diario en **$20**, el peor día previsto son
$20 sobre una cuenta de ~$160. El stop es lo único que convierte esto en una apuesta
acotada, así que **no lo apagues**.

Ojo con el margen: mientras la posición se abre y se cierra dentro del mismo cuarto de
hora aplica el margen intradía (~10% del nocional). Si una posición sobrevive a la
ventana de margen intradía de Coinbase, el requisito sube bastante. El bot cierra al
final de cada ventana justamente por eso.

---

## Qué hace, minuto a minuto

1. Elige el contrato (`BIP` perpetuo por defecto; `BIT` mensual si lo prefieres).
2. Cuando faltan ~5 minutos para el cierre del cuarto de hora, mide el momentum de BTC
   con velas de 1 minuto: **deriva** (cuánto se movió) contra **sigma** (el ruido típico).
3. Entra largo o corto **solo si** la deriva le gana al ruido *y* supera un mínimo en dólares.
   Si no, deja un **fantasma** con el motivo — igual que en tus otros bots.
4. Cierra por **stop**, por **objetivo**, o al terminar la ventana. Lo que ocurra primero.
5. Guarda la señal con la **foto de configuración** completa, para poder medir después
   cuánto cuesta cada filtro.

---

## Reglas de seguridad que ya están dentro

Estas salieron de los fallos reales de tus bots de Kalshi:

- **Nunca adopta una posición que no abrió.** Si encuentra contratos abiertos que no son
  suyos, se pone en pausa y avisa. (El segundo bug de klaros5.)
- **Si no puede leer tus posiciones, no ordena** — y el motivo que queda escrito es el
  verdadero, no un "sin vendedores en rango" tapando el error real. (El primer bug de klaros5.)
- **Si el cierre falla, la posición sigue marcada como abierta** y reintenta al minuto
  siguiente. Jamás marca cerrada una posición que sigue viva.
- **Un error al ordenar sale como `⚠️ ERROR`, no como `👻 vetada`**: el bot no decidió, falló.
- **Cerrojo entre corridas**: Vercel no impide que dos crons se solapen; el cerrojo sí.
- **Sin memoria no opera**: en real, si Redis no responde, no ordena. Sin memoria podría
  abrir la misma posición sesenta veces por hora.
- **Apagado sigue cerrando** lo que quedó abierto. Apagar no es abandonar una posición.
- **El número grande del panel es solo dinero real.** La sombra va chica y gris debajo.
- **Reiniciar contador ≠ borrar**: el corte solo se aplica al contar, el historial completo
  sigue guardado y exportable. Borrar de verdad exige tres cerrojos.

---

## Despliegue (recomendado: GitHub, para que la URL no cambie)

1. Crea un repositorio en GitHub y sube estos archivos (desde Safari: *Add file → Upload files*).
2. En Vercel: **Add New → Project → Import** ese repositorio. Framework: *Other*. Deploy.
3. **Storage → Upstash Redis** (Marketplace) y conéctalo al proyecto. Eso inyecta solo
   `KV_REST_API_URL` y `KV_REST_API_TOKEN`.
4. **Settings → Environment Variables**, añade:

| Variable | Qué es |
|---|---|
| `CLAVE_PANEL` | la clave con la que abres el panel. Sin esto el panel no abre. |
| `COINBASE_KEY_NAME` | el nombre de tu llave CDP: `organizations/…/apiKeys/…` |
| `COINBASE_KEY_SECRET` | la llave privada. Pégala como te la dé Coinbase: el bot la endereza sola. |
| `CRON_SECRET` | cualquier texto largo. Evita que un extraño dispare tu ciclo. |
| `PREFIJO_ALMACEN` | opcional. Cámbialo solo si montas un segundo bot en el mismo Redis. |

5. Redeploy. El cron de `vercel.json` corre `/api/bot` **cada minuto** (necesita Pro; en
   Hobby el despliegue falla porque el plan gratis solo admite un cron al día).
6. Abre la URL, entra con tu clave y pulsa **Probar conexión con Coinbase**. Las cinco
   líneas tienen que decir `ok` antes de encender nada.

> Si prefieres arrastrar el zip a `vercel.com/drop`: funciona, pero cada arrastre crea un
> **proyecto nuevo** con URL nueva, y hay que volver a poner variables, Redis y cron. Para
> un bot que vas a tocar varias veces al día, GitHub te ahorra ese trabajo.

**No pegues la llave privada en ningún archivo de este repositorio.** A diferencia de tus
bots de Netlify, aquí no hay credencial embebida: todo va por variables de entorno.

---

## Archivos

```
vercel.json          cron cada minuto + duración máxima de las funciones
package.json         sin dependencias de npm
public/index.html    el panel
api/bot.js           lo que llama el cron
api/panel.js         el API del panel (estado, ajustes, herramientas, CSV)
lib/nucleo.js        todo lo demás: llave, almacén, Coinbase, estrategia, ciclo, CSV
pruebas/             el simulacro y las tres suites
```

## Pruebas

```
node pruebas/p1-llave.js      firma JWT con la llave estropeada de cinco formas
node pruebas/p2-ciclo.js      ciclo completo contra una Coinbase y un Redis falsos
node pruebas/p3-estatico.js   identificadores fantasma, duplicados, cron, acciones del panel
```

**50 en verde, 0 fallidas.** Las de ciclo invocan los handlers de verdad (`api/bot.js`,
`api/panel.js`) por el mismo método que usan el cron y el panel — no las funciones sueltas.

---

## Lo que este bot todavía NO sabe

- **No tiene ventaja demostrada.** El momentum de 15 minutos es la traducción más fiel de
  lo que ya hacías, no un hallazgo. Igual que en Kalshi, hasta tener señales suficientes
  no se puede afirmar que gane.
- No mira el *funding* del perpetuo (se paga cada hora; en posiciones de 15 minutos suele
  ser centavos, pero no está modelado).
- No usa órdenes stop nativas de Coinbase: el stop lo vigila el bot cada minuto. Si Vercel
  se salta un minuto, el stop puede ejecutarse tarde.
- No reparte entre varios contratos ni hace escalones de tamaño.
