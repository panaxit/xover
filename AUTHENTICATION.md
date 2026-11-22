# Reanudación de solicitudes después del login

Cuando una petición reanudable recibe un `401` y el manifiesto configura
`authentication: "#login"` u otro store de acceso, XOver muestra ese store y
deja la petición en espera. El store presenta el formulario. El ciclo de
reintento pertenece a la petición original.

Al completar el acceso, XOver actualiza la sesión y emite `login`.
`event.detail.request` identifica la petición de autenticación. El listener
recorre `xover.requests.suspended` y selecciona las peticiones de autenticación
reanudables que recibieron un `401`. Compara el `.origin` de la petición
pendiente y el de su respuesta con el `.origin` de la petición de login. La
comparación incluye protocolo, host y puerto. Las rutas del login y de la
consulta pueden ser distintas.

Antes de llamar a `request.resume()`, el listener espera a que termine el
intento anterior y confirma que la petición sigue suspendida con la misma
respuesta y sin señal de cancelación. La petición original vuelve a intentar
la consulta con la sesión activa.

## Cancelar la reanudación automática

El listener de XOver se registra con `{ priority: -1 }`. El dispatcher
ejecuta primero los listeners de mayor prioridad y omite los de prioridad
negativa si el evento ya fue cancelado. Un listener de aplicación con
prioridad normal puede llamar a `event.preventDefault()`. La sesión conserva
el estado `authorized` y la petición original sigue en `suspended`.

```js
xover.listener.on('login', function ({ event }) {
    event.preventDefault();
});
```

## Pruebas con Google en Autofactura de desarrollo

Se usó una página temporal en `autofactura.panax.io` que cargó el XOver
modificado. En cada prueba, la consulta original `autofactura.portalTickets`
de Factura Global recibió un `401` de `server.autofactura.io` antes de
iniciar sesión con Google mediante `uriel@panax.io`.

| Caso | Resultado observado |
| --- | --- |
| Un listener de la aplicación llamó a `preventDefault()`. | La sesión quedó en `authorized` y la petición original siguió en `suspended`, sin evento de éxito. |
| Acceso normal sin cancelar el evento. | La sesión quedó en `authorized`. La misma instancia de la petición se reanudó y emitió el evento de éxito. |
