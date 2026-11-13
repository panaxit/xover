# Componentes y vistas

Registra los web components en `manifest.sources`, por ejemplo `"px-value": "/widgets/value.xhtml"`. XOver resuelve el recurso y registra la etiqueta: no declares otra clase ni llames de nuevo a `customElements.define`.

```xml
<template value="">
  <script>
    constructor.extend({
      init() {
        parts.content.textContent = this.value;
      },
      value: {
        set(input) {
          parts.content.textContent = input ?? '';
          return input;
        }
      }
    });
  </script>
  <span part="content"></span>
</template>
```

El script interno dispone de `self` (host), `parts` y `constructor.extend`. Los atributos del template aportan valores predeterminados; la instancia puede declarar otros. Haz `init` repetible: la recomposición puede volver a ejecutarlo. Comprueba si un cambio llega por propiedad o atributo; no supongas que el setter observa ambos. Conserva los slots y usa `shadowrootmode="open"` solo cuando necesites encapsulación. Un template con `role="behavior"` se aplica con `is`; no registra una etiqueta nueva.

En XSLT, usa el namespace XHTML y conserva el nodo de origen al generar, por ejemplo, `<px-value value="{@nombre}"/>`. Las expresiones de atributos se evalúan en XSLT, no en el template XHTML del widget. Reutiliza imports, modos, parámetros y claves de la transformación. Una sección puede declarar `xo-source` y `xo-stylesheet` para asociar datos y vista. Si una vista necesita la raíz de su propio XML, usa `xo-scope="/*"` en ese contexto, sin imponerlo a todas las instancias.

Agrupa un widget XSLT nuevo y sus archivos auxiliares en una carpeta propia si el proyecto no tiene otra convención. Un componente autocontenido puede quedar en un solo XHTML. Conserva las rutas que consume el manifest.
