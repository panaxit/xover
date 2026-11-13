# Primera vista con XOver

Usa una versión concreta de XOver. Sirve los archivos por HTTP desde el mismo origen y coloca `xo.js` bajo `vendor/xover/`. Si tu versión incluye recursos auxiliares, conserva sus rutas relativas al script.

`index.html`:

```html
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Primera vista XOver</title>
  <link rel="xover-manifest" href="./manifest.json">
  <script src="./vendor/xover/xo.js"></script>
</head>
<body>
  <main xo-source="#catalogo" xo-stylesheet="./catalogo.xslt"></main>
</body>
</html>
```

`manifest.json`:

```json
{
  "sources": { "#catalogo": "./catalogo.xml" },
  "start": ["#catalogo"]
}
```

`catalogo.xml`:

```xml
<catalogo><producto nombre="Cuaderno"/></catalogo>
```

`catalogo.xslt`:

```xml
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns="http://www.w3.org/1999/xhtml">
  <xsl:output method="xml" omit-xml-declaration="yes"/>
  <xsl:template match="/">
    <ul>
      <xsl:for-each select="catalogo/producto">
        <li><xsl:value-of select="@nombre"/></li>
      </xsl:for-each>
    </ul>
  </xsl:template>
</xsl:stylesheet>
```

Abre la página y comprueba que se muestra «Cuaderno». Si la vista queda vacía, revisa en la consola y en la pestaña de red que se hayan cargado el script, el manifest, el XML y el XSLT. Si el XML ya define una instrucción `xml-stylesheet`, comprueba su ruta y destino antes de añadir otra transformación. Una instrucción en un XML abierto directamente no carga por sí sola el JavaScript de XOver.
