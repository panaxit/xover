# Scope, peticiones, eventos y render

- El scope puede ser documento, elemento o atributo. Resuelve su documento con `xover.references.scopeDocument.call(self)`; `self.ownerDocument` suele ser el HTML anfitrión. Un widget hereda su contexto a menos que declare otro con las referencias de XOver. Filtra sus eventos por contexto; no busques todas las instancias ni recurras al documento activo global.
- `source.url` identifica el origen lógico; `request.url` pertenece a la petición. Un fetch del source crea otro request. Para reenviar uno existente, conserva su URL y su target concreto, recuperándolo cuando proceda con `xover.requests.get(target)`. El target puede ser un nodo o comentario, no solo un documento.
- Delega la selección de la transformación y su destino al store/documento, por ejemplo con `store.render({ target })`. Conserva la relación que XOver establece entre el resultado y su nodo XML; no generes identificadores de scope por tu cuenta.
- Consume eventos del framework con `xover.listener.on`. Conserva `urlchange` y la relación de `SearchParams` con su URL: en `set`, `null` elimina y `undefined` representa un valor vacío. Una URL de request también emite cambios. Cada URL calcula su propio `dirty`; un fetch exitoso actualiza su referencia sin emitir otro cambio de URL.
- Si una mutación debe conservar su evento pero posponer el render, marca el atributo con `this.inert = true` dentro de su listener y antes del primer `await`. El observer consume esa marca. No desactives la reactividad global. Conserva la deduplicación textual de listeners; para distinguir instancias, usa una clave estable como `{ key: self }` cuando la API de esa versión lo admita.
- Los parámetros XSLT `session:*` declaran dependencias de sesión de la vista. No dupliques la sincronización copiando valores al DOM. En listeners nativos, recibe el evento explícitamente y usa `currentTarget` para identificar el control registrado.
- Si el shell intercepta enlaces para navegar por hash, limita esa interceptación a su navegación interna. Conserva el comportamiento nativo de descargas, ventanas nuevas, enlaces a otras páginas y clics con modificadores. Para diálogos que el framework cierra y reabre como modales, comprueba que sigan cerrados antes de retirarlos en el evento `close`.

Reproduce el caso con las instancias o documentos relevantes. Comprueba tanto el evento y su contexto como el efecto en la vista; una transformación aislada no valida el flujo reactivo.

## Peticiones y transformaciones de una vista

Empieza por la ruta del manifest y sigue su resolución en `sources` y `settings`. Configura allí los headers y las credenciales que requiere la petición. Si el flujo necesita una llamada explícita, usa `xo.server` para un alias de servidor o `source.fetch()` cuando necesites recargar una fuente existente. Mantén la transformación a cargo de XOver con la XSLT declarada y su destino. Si falla la carga, revisa en Network la respuesta, su código y su tipo de contenido. Si llega el XML pero falta la vista, revisa la XSLT resuelta, el destino y el scope en vez de añadir otra implementación de carga o render.

## Trackers por petición

En XOver `v20260707`, cada `xo.Request` tiene su propio `request.trackers` (un `Set`). Al actualizar el avance, XOver emite `progress` con la petición en `detail.request` y actualiza los elementos `<progress>` dentro de los contenedores registrados. Los eventos de avance de esos nodos también pueden llegar al listener. Registra un solo indicador por petición y retíralo en los tres eventos terminales. Si el proyecto declara `trackers` o un `label` en el manifest, su widget interpreta esa configuración y resuelve el texto en el idioma de la interfaz.

```js
const indicators = new WeakMap();

window.addEventListener('progress', ({ detail }) => {
  const { request, percent } = detail ?? {};
  if (!(request instanceof xo.Request) || percent !== 0 || indicators.has(request)) return;

  const tracker = document.createElement('div');
  const progress = document.createElement('progress');
  progress.max = 100;
  progress.setAttribute('aria-label', 'Cargando reporte');
  tracker.append(progress);

  indicators.set(request, tracker);
  request.trackers.add(tracker);
  document.body.append(tracker);
});

for (const type of ['success', 'failure', 'abort']) {
  window.addEventListener(type, ({ detail }) => {
    const request = detail?.request;
    const tracker = indicators.get(request);
    if (!tracker) return;
    request.trackers.delete(tracker);
    indicators.delete(request);
    tracker.remove();
  });
}
```

## Eventos del shell

El control despacha una intención con `this.dispatch` y el shell registra el listener que cambia su estado. Usa un nombre con prefijo como `shell:sitemap`. La versión `v20260707` intenta resolver primero el nombre como función. Registra el listener al inicializar el shell para que atienda el evento aunque el reporte todavía esté cargando.

```html
<button type="button" aria-controls="sitemap" aria-expanded="false"
        onclick="this.dispatch('shell:sitemap')">Menú</button>
```

```js
xo.listener.on('shell:sitemap', function ({ target, open }) {
  const shell = target.closest('#shell');
  const sitemap = shell?.querySelector(':scope > #sitemap');
  if (!sitemap) return;

  const nextOpen = open ?? sitemap.hidden;
  sitemap.hidden = !nextOpen;
  shell.querySelector('[aria-controls="sitemap"]')
    ?.setAttribute('aria-expanded', String(nextOpen));
});
```

El ejemplo parte de un `#sitemap` con `hidden`. Para cerrar explícitamente, despacha `this.dispatch('shell:sitemap', { open: false })`. En un atributo literal de XSLT, escapa las llaves del objeto con `{{ open: false }}`.

## Integración con IIS Panax

En este backend, `request.asp` entrega datos. `FROM` identifica el objeto consultado y los demás parámetros de consulta especifican los datos pedidos, según el contrato del servidor. Usa los headers para opciones HTTP como `Accept`. Un parámetro como `view=balance-mxn` puede identificar un conjunto de datos si el servidor lo acepta. Confirma en el backend si esa clave se interpreta como filtro o como argumento y conserva el prefijo `@` cuando lo exija el contrato.

En este ejemplo, el backend recibe la consulta y XOver selecciona la XSLT y su destino a partir de la ruta del cliente. Cambia el alias y los parámetros según el backend desplegado.

```json
{
  "server": { "balances": "https://api.example.com/request.asp" },
  "sources": {
    "#balance-mxn": {
      "server:balances": { "FROM": "fin.GetBalances", "view": "balance-mxn" }
    }
  },
  "settings": {
    "#server:balances": {
      "credentials": "include",
      "headers": { "Accept": "application/xml" }
    },
    "#balance-mxn||#balance-usd": {
      "stylesheets": [{ "href": "balance.xslt", "target": "@#shell main" }]
    }
  }
}
```

En `v20260707`, `||` permite que varios selectores compartan un bloque de `manifest.settings`. Cada ruta conserva su propia definición en `sources`. Para otros backends, usa su contrato HTTP con el mismo flujo de fuentes y vistas de XOver.
