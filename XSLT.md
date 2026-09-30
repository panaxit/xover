# XSLT sin extensiones

## Flujo existente y decisión

Todo el procesamiento de XOver está en `xo.js`:

- `xover.init()` espera `xover.modernize()` antes de Observer, manifest y render.
- `xo.js` también inicia `modernize()` durante su evaluación. Manifest.init y
  los iframes vuelven a llamarlo. Ahora todas esas llamadas comparten una promesa
  por ventana, incluidos sus errores. Se corrigió la precedencia de la selección
  de `targetWindow` para respetar también el argumento explícito.
- `Response.processBody` identifica XML/XSLT y usa `xml.createDocument`.
  `sources.ready` conduce a `xml.initialize`, que espera dependencias y llama a
  `XMLDocument.consolidate`. Este código existente integra imports/includes.
- Las propiedades `stylesheets` y el wrapper `ProcessingInstruction` resuelven
  `<?xml-stylesheet?>`, su href, role, target y otras opciones de XOver.
- `Node.transform` crea el único procesador activo del flujo normal, aplica
  parámetros, llama a `importStylesheet` y utiliza `transformToFragment` o
  `transformToDocument`. Los otros ejemplos de creación están comentados.
- `modernize` extiende `importStylesheet`, `setParameter` y `asyncTransform`.
  El último usa el worker .NET de `wasm/` cuando se solicita `async: true`;
  es un camino opcional existente, no el reemplazo de la API síncrona.

Se conservan esos flujos, el procesamiento de PI, los imports y las APIs públicas.
La carga del motor ocurre desde `modernize`. Las extensiones DOM se instalan
sin esperar la red, como antes; las extensiones del procesador se instalan cuando
está disponible, y `modernize` no se completa antes de ese momento.

## Detección y despliegue

La detección importa una hoja mínima, establece un parámetro y verifica un
atributo calculado en un documento y un fragmento. No basta con que exista el
constructor. Usar un atributo evita interpretar el aviso de retirada que algunos
Chromium insertan en el resultado como una avería del motor.

Si funciona, no se solicita ningún archivo de `polyfills/`. En caso contrario
se carga `polyfills/xslt.js` relativo a la URL real de `xo.js` y después la copia
local de xslt-polyfill. Se espera `xsltPolyfillReady()` y se repite la comprobación
funcional antes de continuar. El motor conserva `XSLTProcessor` como API.

Publicar junto a `xo.js` el directorio `polyfills/` completo. Servir JavaScript
como UTF-8. Si hay CSP, debe permitir los scripts locales y WebAssembly
(`wasm-unsafe-eval` donde corresponda); se propaga el nonce del script original.
No se modifica automáticamente la política del sitio. Actualizar la caché del
service worker del proyecto consumidor si mantiene copias de estos recursos.

Los errores de descarga, inicialización o comprobación rechazan la promesa.
La carga del motor tiene un límite de 30 segundos y la espera desde XOver uno
de 35 segundos, incluyendo el cargador. No se reinicia una modernización parcial:
tras corregir un despliegue fallido, recargar la página. `init` conserva su rechazo,
establece status `error` y no emite `xover-initialized` en ese caso.

## XML público abierto directamente

Una PI por sí sola no puede instalar JavaScript. Si `xo.js` solamente aparece
en el resultado de la transformación, no llegará a ejecutarse sin XSLT nativo.
Agregar este elemento dentro de la raíz del XML público (ajustar la ruta):

```xml
<?xml version="1.0"?>
<?xml-stylesheet type="text/xsl" href="pagina.xsl"?>
<pagina>
  <script xmlns="http://www.w3.org/1999/xhtml"
          src="/xover/polyfills/xslt.js"></script>
  <contenido>Ejemplo</contenido>
</pagina>
```

El cargador comprueba el motor y usa el procesamiento de PI del propio polyfill;
no añade un segundo motor ni interpretación de XSLT a XOver. Espera el DOM antes
de entregar el XML al polyfill. Los errores se muestran en la página y la consola.
La hoja debe excluir ese script auxiliar de su salida cuando corresponda.
Un XML que no pueda incorporar scripts necesita una entrada HTML o transformación
en servidor. Este repositorio no contiene los XML públicos de las aplicaciones,
por lo que aquí se proporciona el cargador, no una modificación de esos archivos.

## Límites que deben revisarse en la aplicación

- El API síncrono del polyfill no descarga dependencias durante la transformación.
  Los imports/includes resueltos por el flujo normal de XOver siguen pasando por
  `consolidate`; llamadas directas al procesador con imports pendientes y
  `document()` con recursos externos no quedan cubiertas automáticamente.
- El modo de XML público del polyfill sí tiene carga asíncrona de recursos,
  sometida a CORS. Puede haber diferencias de orden de scripts, eventos y layout
  respecto a una transformación nativa del navegador.
- El polyfill es XSLT 1.0 y su `setParameter` ignora namespaceURI (XOver ya pasa
  null con nombres cualificados). Uso directo de parámetros con namespaceURI,
  extensiones específicas y hojas complejas requieren validación propia.
- No se cambia el worker .NET opcional ni sus limitaciones.
- Código externo que transforma inmediatamente después de incluir `xo.js` debe
  esperar `xover.modernize()` o `xover.ready` cuando no exista motor nativo.

## Pruebas

La suite `node --test tests/xslt-browser.cjs` requiere Playwright accesible para
Node y Chrome instalado. Lanza un navegador aislado con extensiones deshabilitadas.
Comprueba motor nativo sin descargas, API ausente/rota, ambas transformaciones,
el flujo real `Node.transform`, espera de init, concurrencia, iframes, XML público
y errores de descarga, Wasm, timeout y procesador inválido.

Para probar una aplicación manualmente:

1. Deshabilitar/desinstalar la extensión XSLT y desplegar estos archivos juntos.
2. Con XSLT nativo habilitado, abrir `#login`: no debe haber descargas de
   `polyfills/` en Network. Probar vistas, cambios de parámetros y renderizados.
3. Deshabilitar XSLT en `chrome://flags/#xslt` si esa versión ofrece la opción y
   reiniciar. La suite también simula su ausencia antes de cargar `xo.js`.
4. Abrir de nuevo la aplicación: deben descargarse el cargador y el bundle local.
   `await xover.modernize()` debe completarse y el login debe renderizar.
5. Bloquear el bundle en Network y recargar: `await xover.init()` debe rechazar,
   con `xover.init.status === 'error'`, sin iniciar manifest ni render.
6. Abrir un XML público que incluya el script mostrado arriba y su PI; repetir
   con recursos importados y las políticas CORS/CSP reales del despliegue.

No se ha desplegado ningún cambio en produceteam.panax.io.
