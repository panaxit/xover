---
name: xover-development
description: Integrar XOver en un proyecto web y desarrollar o depurar sus vistas XML/XSLT y componentes XHTML. Usar al configurar el manifest, conectar datos y vistas, o trabajar con scope, eventos y reactividad de XOver.
---

# Desarrollo con XOver

Para una integración nueva, usa el [ejemplo mínimo](references/getting-started.md) para conectar una fuente XML y una vista XSLT. Comprueba ese recorrido antes de introducir componentes o datos remotos.

En un proyecto existente, identifica la versión del framework y sigue la ruta concreta: interacción, nodo o atributo en scope, evento, consumidor y render. Lee el componente comparable y busca los símbolos relevantes en `xo.js`. Antes de editar un widget, verifica qué recurso resuelve el manifest; puede haber copias locales y recursos compartidos con el mismo nombre.

Para cargar y renderizar datos de una vista XOver, declara la fuente, la XSLT y su destino en el manifest o en los atributos de XOver que ya usa el proyecto. Si necesitas iniciar una petición desde JavaScript, usa la API de XOver. Evita crear una ruta paralela con `window.fetch`, `DOMParser`, `XSLTProcessor` o inserción manual del HTML del reporte. Así la petición y el render conservan su contexto, eventos y reactividad.

- Para componer widgets o generar componentes desde XSLT, consulta [componentes y vistas](references/components.md).
- Para depurar contexto, peticiones, eventos o render, consulta [scope y reactividad](references/runtime.md).

Conserva la relación entre los datos XML, la vista XSLT y el host XHTML. Valida la salida de la transformación y, cuando haya componentes, la instancia compuesta con su scope real. Distingue una comprobación estática de una prueba ejecutada en el navegador.
