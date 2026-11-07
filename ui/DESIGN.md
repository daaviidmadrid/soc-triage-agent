# Sistema visual · Tarvia

Consola operativa clara, con énfasis en lectura rápida y continuidad entre
dashboard, cola y ticket. La dirección visual usa la paleta azul y neutra indicada por el usuario. Los nombres históricos de los tokens se conservan.
La marca del producto sigue siendo Tarvia y el dashboard mantiene su jerarquía operativa.

## Tokens

Los tokens implementados están en `src/styles.css`.

| Uso | Valor |
|---|---|
| Acento y CTA | `--deloitte-green: #758BFD` |
| Títulos | `--deloitte-black: #08022C` |
| Texto secundario | `--deloitte-gray: #27187E` |
| Fondo y paneles | `--deloitte-white: #F1F2F6` |
| Bordes y separadores | `--deloitte-border: #AEB8FE` |
| Datos principales | `--deloitte-navy: #08022C` |
| Tendencia e interfaz | `--deloitte-blue: #758BFD` |
| Datos de soporte | `--deloitte-sky: #AEB8FE` |

Tipografía: familia sans del sistema, cifras tabulares para métricas, monoespaciada
solo para IDs y datos. Títulos de pantalla de 25 px y KPIs de 43 px en escritorio.
Ritmo de 4, 8, 12, 16, 24 y 32 px. Separadores neutros derivados de la paleta azul. El bloque de prioridad tiene un
borde discreto; los gráficos secundarios se separan mediante espacio y una línea superior.
Los colores de severidad siempre llevan una etiqueta textual. Son una excepción
semántica a la identidad azul: informativa blanca, baja casi blanca con tinte rojo,
media roja suave, alta más marcada y crítica intensa. Los tokens `--sev-*`,
`--sev-*-bg`, `--sev-*-border` y `--sev-*-ink` centralizan marca, fondo, borde y texto.
Se aplican a badges y barras sin cambiar los estados operativos azules.

## Composición y navegación

La entrada sin fragmento abre el dashboard; `#/dashboard` lo identifica
explícitamente. Se conservan `#/` y `#/?...` para la cola y sus filtros, y
`#/alerta/<id>` para el ticket. `#/incidentes` muestra los incidentes del nivel 2.
El menú lateral enlaza dashboard, cola, revisión y resueltas mediante los filtros
existentes, e incidentes como pantalla propia.

La barra lateral ocupa 224 px en escritorio (se reduce en anchos intermedios) y
puede contraerse a 76 px mediante el botón de la cabecera. Los iconos conservan
nombre accesible y etiqueta visible al enfocar o pasar el puntero. En móvil es
un diálogo con fondo inerte, cierre con Escape y restauración del foco al botón.
La cabecera es clara y el lateral Prussian Blue conserva la marca principal.
No hay avatar decorativo ni rótulos redundantes. Un indicador lateral sigue la sección
seleccionada; el fondo seleccionado y el texto conservan contraste durante todo el movimiento.

Dashboard, cola y triaje comparten el scroll vertical de página, sin paneles
anidados con scroll. La cola conserva seis columnas y páginas de ocho alertas;
en móvil, cola y prioridad presentan filas sin scroll horizontal. La cola incluye una distribución proporcional de estados y filtros con iconos,
etiquetas y recuentos. Los indicadores de posible inyección se mantienen separados
del reparto porque pueden coincidir con cualquier estado. Las etiquetas de campo
se alinean a la izquierda.

El triaje tiene siete pestañas: Análisis y evidencias, Contexto, Política y acciones,
Resolución, Actividad, Datos originales e Historial y avisos. Dentro de cada bloque
las listas y los textos son completos, sin selectores de campos ni páginas de caracteres.
Solo los argumentos técnicos y el ticket original usan desplegables secundarios.
El formulario permanece montado al cambiar de pestaña para conservar el borrador.
En escritorio, el análisis muestra los metadatos en una columna lateral; en tablet y móvil
vuelven al flujo de lectura. Las pestañas permanecen accesibles al desplazarse en escritorio.
Los avisos importantes se mantienen encima del bloque de trabajo, incluido el que
indica que la alerta forma parte de un incidente, con enlace a Incidentes.

Política y acciones incluye la contención del nivel 4: cada acción que el código
construye a partir de una sugerencia del LLM, su impacto, quién debe aprobarla,
la aprobación con nombre por cada papel, la ejecución en la API simulada solo
cuando todos han aprobado, las sugerencias que no se proponen y por qué, y el
registro de la API simulada. El LLM nunca aprueba ni ejecuta.

Incidentes usa la misma cabecera de página que la cola. Cada incidente es un panel
con su severidad, veredicto, escalado, alertas y qué comparte cada enlace. El ruido
se cuenta en una tabla aparte. Las tablas se ajustan al panel en escritorio.

## Jerarquía operativa

Los cuatro KPIs conservan sus valores grandes y sus acciones de filtro, agrupados
en una banda con separadores en lugar de cuatro cajas con iconos repetidos.
Prioridad de atención aparece justo después, antes de los gráficos: la tarea del
analista precede a las estadísticas descriptivas. No se elimina ningún gráfico ni métrica.

Los productos son texto sencillo; los badges se reservan para severidad y estados.
Se conservan fecha, fuente, regla e ID. Los textos de tabla y los títulos de gráfico
suben de tamaño. Los fondos de las barras son discretos para que un valor cero no
se confunda con una barra llena. El cálculo de cifras y proporciones permanece intacto.

## Datos del dashboard

- Alertas totales: tamaño de la cola devuelta por la API.
- Prioridad alta: severidad efectiva alta o crítica; su tarjeta abre ese filtro.
- En revisión: estado pendiente según el mismo modelo usado por la cola.
- Resueltas: decisiones según el estado calculado por la cola.
- Volumen: fechas UTC de las alertas, con días vacíos explícitos en rangos cortos.
- Distribución: severidad final cuando existe; severidad de regla en otro caso.
- Fuentes: recuentos por producto. Se muestran las seis fuentes con más alertas.
- Cobertura: alertas con ticket respecto al total.
- Duración media: solo la última ejecución real terminada de cada alerta. Las
  reproducciones de ejemplo y los fallos no cuentan como rendimiento real.

No se inventan tendencias, incrementos, objetivos ni resultados. Las fechas sin
formato válido se excluyen del gráfico temporal y se mantienen en el total.

## Texto, estados y accesibilidad

Usar etiquetas breves: Actividad, Análisis, Severidad y escalado, Resolución.
Conservar avisos de cuota, errores, evidencias truncadas, aprobaciones pendientes
y procedencia simulada. Eliminar leyendas de roles y explicaciones redundantes.

Foco visible azul, controles nativos, menú con Escape y foco contenido, estados
de carga/error/vacío, texto largo expandible y reducción de movimiento. Las
interacciones frecuentes son inmediatas; las transiciones de color y presión
son breves. No hay efectos de entrada orquestados ni animación de las cifras.

## Movimiento y continuidad

Implementación compartida en `src/motion.js`, con CSS y Web Animations API; sin librerías nuevas.

- Menú: indicador lateral de selección y adaptación del contenido con FLIP, 220 ms.
- Filtros y páginas: las identidades de las filas guían su recolocación, 180 ms; entrada
  de nuevas filas con un desfase máximo de 72 ms. La primera carga permanece inmediata.
- Triaje: indicador de pestaña, transición de bloque de 150 ms y llegada de nuevos pasos
  únicamente cuando la cronología está visible. Las colecciones siguen completas.
- Procesamiento: el icono gira solo mientras el estado estructurado es `running`;
  el resultado terminado conserva su etiqueta y señal de cambio. No se inventa progreso.
- Interrupción: nuevas selecciones retoman la posición actual y cancelan movimientos anteriores.
- Teclado: los cambios de navegación, panel y lista son inmediatos. Al cerrar el menú se
  devuelve el foco al botón; al navegar desde él, pasa al contenido. Quitar filtros por
  teclado devuelve el foco al buscador.
- `prefers-reduced-motion` elimina el movimiento; los textos y estados siguen informando.
  Las animaciones de actividad se pausan con la página oculta.

La curva de llegada es `cubic-bezier(.23, 1, .32, 1)`. Se animan transformaciones y
opacidad, sin interpolar dimensiones ni cifras. El tooltip de prioridad sigue el puntero
sin animación, como corresponde a un detalle de consulta.


## Interacción de gráficos

Los KPIs, barras de severidad, fuentes y cobertura no abren tooltips ni se elevan.
Los KPIs y barras conservan su navegación a los filtros. La severidad usa la misma
escala semántica que los badges; las etiquetas y recuentos aportan el detalle.

El donut usa cuatro azules y una trama para el estado fallido, con separación entre
sectores y una leyenda permanente de cantidades y porcentajes. No depende de hover.

La evolución temporal mantiene el detalle exacto y la comparación entre días
consecutivos. En prioridad, cada fila ofrece un tooltip de esa alerta: producto,
fecha UTC, estado, severidad, regla, veredicto cuando existe y descripción. Reutiliza
GET de la alerta bajo demanda y mantiene los datos como texto plano.

El tooltip se monta con un portal en document.body. Sigue el puntero sin transición,
14 px por encima; cambia debajo si falta espacio y se limita a los bordes del viewport.
No intercepta eventos del puntero. El resaltado depende del puntero sobre esa fila
y se elimina inmediatamente al salir. El foco de teclado usa un contorno propio y
ancla el tooltip al control enfocado; Escape lo cierra. Las flechas recorren la serie
temporal. Se respeta el modo de movimiento reducido.

Configuración: `docs/deloitte-charts.md` (nombre histórico).
