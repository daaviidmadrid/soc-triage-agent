# Tarvia · Consola SOC

Modo de uso: Operate. Analistas de seguridad que revisan, priorizan y resuelven
alertas en una herramienta de trabajo habitual.

La aplicación muestra la cola, el estado del triaje, las consultas y evidencias,
la severidad, el escalado recomendado y la resolución registrada, los incidentes
que agrupa el código (nivel 2) y la contención que aprueban personas (nivel 4). El dashboard
resume los datos que devuelve la misma cola; no introduce endpoints ni métricas
de reputación externas. Los resultados de ejemplo se identifican como simulados.

Compromisos del encargo: consola clara con paleta azul y neutra, navegación
lateral, KPIs grandes y gráficos legibles sin hover. Detalle emergente por alerta
y en la evolución temporal. Cola sin scroll horizontal y triaje con bloques de trabajo
legibles de forma continua, siete pestañas y un único scroll de página. Reducir explicaciones sobre la arquitectura, conservando
información técnica y avisos que afecten a la revisión. Mantener todas las
conexiones y contratos del backend.

La identidad sigue siendo Tarvia. No se usan logotipos ni recursos de SOCRadar.
No se añaden paquetes, fuentes remotas, imágenes externas ni llamadas al LLM.
La contención se aprueba y ejecuta solo desde Política y acciones, a través de los
endpoints del backend. Cada papel lo aprueba una persona con su nombre, y solo
entonces se llama a la API simulada, una vez. El LLM nunca aprueba ni ejecuta.
