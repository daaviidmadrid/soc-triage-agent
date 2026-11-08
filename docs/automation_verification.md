# Verificación de la automatización

## Actualización: subida e inicio explícito

El nuevo recorrido se comprobó con `demo_alertas_comunes.jsonl`, sin cambiar reglas,
prompts ni criterios de política a partir de sus alertas. El archivo contiene diez
alertas y se usa solo como entrada de integración. Las herramientas consultan una
copia local de la API simulada; las respuestas LLM son genéricas y falsas, sin
evaluar veredictos ni entrenar sobre alertas reservadas.

- La subida deja diez trabajos `staged`, sin runs ni llamadas al proveedor.
- «Iniciar flujo» comprueba la API y libera la cola. El orden mostrado coincide con
  el orden de los diez runs de triaje, usando prioridad y orden de encolado.
- El lote produjo diez tickets y nueve informes con los proveedores falsos. Se
  verificó que se genera un informe por caso final, sin repetir investigaciones
  de las versiones intermedias del lote.
- La prueba reproduce `ConnectError` de contexto: no inicia investigaciones a
  partir del análisis fallido. El inicio comprueba conectividad antes de reclamar.
- El botón puede reintentar el bloqueo de fallos consecutivos, manteniendo llamadas
  consumidas y época de presupuesto; no limpia cuota ni presupuesto gastado.
- Un fallo histórico que ya tiene una ejecución posterior correcta no se reintenta
  al empezar otro lote.
- Firefox: subida desde dashboard, inicio, cola, procesamiento completo y tamaños
  de 390, 768, 1024 y 1440 px, sin errores de consola ni scroll vertical anidado.
- El nuevo `python scripts/dev.py` arrancó mock, backend y Vite en puertos de QA;
  mostró una cola vacía esperando Start y cerró los tres servicios limpiamente.
- Suite completa con el JSON opcional: **805 pruebas superadas**. Pruebas frontend
  y build de producción superados. Las acciones individuales no adelantan trabajos
  preparados o pendientes fuera del orden de la cola.

La suite puede repetir la integración del archivo mediante
`TARVIA_IMPORT_TEST_FILE=/ruta/al/archivo.jsonl pytest`. Sin esa variable, esa prueba
opcional se omite; las pruebas sintéticas del inicio siempre se ejecutan. Los
artefactos de esta sesión quedan bajo `runs/flow-start-verification/`.

No se hicieron llamadas reales al LLM. No se aprobaron ni ejecutaron acciones de
contención. La configuración privada de `.env` no se abrió ni imprimió.

## Verificación anterior

Comprobación local del 8 de noviembre de 2026. Backend con SQLite temporal, alertas
sintéticas y proveedores falsos. La suite existente usa una copia temporal de la API
simulada para que sus escrituras no afecten a `data/`.

| Comprobación | Resultado |
|---|---|
| Suite Python completa | 797 pruebas superadas; último run completo: 109,06 s |
| Presupuesto tras el último ajuste de motivo de parada | 48 pruebas de automatización superadas |
| Frontend | Tres archivos de pruebas Node superados: dashboard/model, dashboard/interaction y queue/model |
| Producción | `npm run build` superado, sin nuevas dependencias |
| Diff | `git diff --check` sin errores |
| Importación en Firefox | Archivo sintético recibido; triaje, correlación e informe avanzan sin solicitudes a `/api/triage/` |
| Streams | Máximo de una conexión SSE simultánea en el flujo; al navegar se cierran las anteriores |
| Cierre y revisión | Regla sin LLM, disposición automática y revisión humana se muestran por separado |
| Borrador | Conservado entre pestañas y al salir y volver al ticket |
| Relaciones | Motivos guardados, enlace al informe y diagrama limitado con lista completa |
| Cronología | Dos días, separación real de 26 horas, selección por modelo/código e ID que abre el paso de recuperación |
| Tamaños de viewport | 390, 768, 1024 y 1440 px; sin desbordamiento horizontal ni paneles con scroll vertical anidado |
| Tooltip | Puntero inmediato, una sola fila resaltada, `pointer-events: none`, transición de 0 s y cierre con Escape |
| Menú móvil | Apertura y cierre con Escape comprobados |
| Movimiento reducido | Firefox con `prefers-reduced-motion: reduce`; cero animaciones compartidas y transiciones de botón de 0 s |
| Caída y recuperación | Se interrumpe solo el backend sintético con un trabajo activo; la UI muestra reconexión, recupera el trabajo y conserva run interrumpido y época de presupuesto |

La prueba de caída también cubrió un proxy que conserva el socket SSE abierto tras
perder el upstream. Al recuperarse la API de polling, el hook reabre la suscripción
desde `after=2`, cierra la anterior y reconcilia el nuevo run recuperado. No se
necesitó iniciar de nuevo el triaje.

Los artefactos locales de esta sesión se guardan en `runs/automation-verification/`
(directorio ignorado por Git): informes JSON y capturas de cola, actividad,
relaciones, cronología y movimiento reducido.

## Límites comprobables

- No se hicieron llamadas reales al LLM ni se evaluó su calidad, latencia o cuota real.
- Firefox headless devolvió `document.hasFocus() === false`; el foco nativo y la
  aparición del tooltip por `:focus-visible` requieren comprobación en una ventana
  interactiva. Se mantuvo el comportamiento existente; Escape y el menú sí se probaron.
- Los tamaños móviles fueron viewports emulados de Firefox. No se probaron gestos
  en teléfonos físicos, Safari ni Chromium.
- No se implementan notificaciones reales a N2, responsable SOC o CISO. El escalado
  es un estado/recomendación, no una notificación enviada.
- La prueba de caída usa un backend y datos sintéticos. No demuestra rendimiento
  bajo el volumen diario del SOC ni seguridad de un despliegue remoto; la API
  conserva su ámbito exclusivamente local.
