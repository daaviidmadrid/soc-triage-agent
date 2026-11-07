# Colores e interacción de gráficos

El nombre del archivo se conserva por compatibilidad con referencias anteriores.
La paleta vigente es azul y neutra. React, CSS y SVG nativo; sin paquetes nuevos.

```css
:root {
  --deloitte-green: #758BFD; /* Acento y CTA */
  --deloitte-black: #08022C;
  --deloitte-gray: #27187E;
  --deloitte-white: #F1F2F6;
  --deloitte-border: #AEB8FE;
  --deloitte-navy: #08022C;
  --deloitte-blue: #758BFD;
  --deloitte-sky: #AEB8FE;
}
```

Los nombres de tokens son históricos. Las superficies, texto, series y sombras
usan la paleta indicada y transparencias derivadas.

- KPIs: valores y navegación al filtro; sin elevación ni tooltip.
- Severidad: escala rojiza compartida con los badges mediante `--sev-*`.
- Fuentes: barras azules con recuento permanente; sin detalles redundantes
  al pasar el cursor. Conservan la acción de filtrar.
- Cobertura: porcentaje y desglose visibles; sin hover.
- Donut: cuatro azules y una trama para fallos, separación entre sectores y
  leyenda con cantidades y porcentajes. Legible sin interacción.
- Evolución temporal: detalle exacto, comparación diaria, foco y dimming de puntos.
- Prioridad: detalle individual de cada alerta al pasar el cursor o enfocar un
  botón de su fila. La descripción se obtiene con el GET de alerta existente.

`src/dashboard/ChartTooltip.jsx` exporta `useChartFocus()` y el tooltip. La fila
usa `interaction.bind('alert:' + id)`; su contenido tiene esta estructura:

```js
{
  kind: 'alert',
  label: row.alert_id,
  title: row.rule_name,
  fields: [['Producto', row.source_product], ['Estado', stateLabel]],
  description: alert.description,
}
```

El componente usa un portal en `document.body`, posición fija limitada al viewport
y seguimiento del puntero sin transición. Se sitúa 14 px arriba y pasa debajo
cuando no cabe. Tiene `pointer-events: none`. Hover y foco son independientes;
el foco ancla el tooltip al control y Escape lo cierra. Los datos se renderizan como texto React, nunca
como HTML ni enlaces. Las etiquetas y cifras conservan contraste; el movimiento
reducido elimina escalado y transiciones.

`dayComparison()` solo compara días UTC consecutivos. Una base cero no produce
un porcentaje ficticio. Los porcentajes del donut son proporciones de la cola.

Verificación:

```bash
node --test ui/src/dashboard/model.test.js ui/src/dashboard/interaction.test.js
npm --prefix ui run build
```
