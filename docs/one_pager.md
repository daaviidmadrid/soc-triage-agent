# Revisión de alertas de seguridad con IA

Para el comité de dirección de Tarvia · David, Alex y Francesco · 8 de noviembre de 2026

**En una frase:** un programa reúne y comprueba los hechos, la IA los valora y una persona decide. Es un prototipo probado solo con datos ficticios, aún no listo para usarse en real.

## El problema
Llegan unas 4.000 alertas al día antes de quitar duplicados, y el equipo son 6 personas de 8:00 a 20:00 de lunes a viernes. De noche y en fin de semana nadie mira la consola: solo hay una guardia localizable por teléfono. En campaña, cada hora de tienda online caída cuesta unos 120.000 €.

## Qué hace el sistema
Por cada alerta, la IA valora los datos que reúne el programa, y este comprueba las pruebas y calcula la gravedad según la política de Tarvia. Sale una propuesta razonada: cerrar o escalar a un analista superior. También agrupa las alertas de un mismo ataque, redacta el informe y propone medidas para frenarlo. Trata lo que lee como dato, no como orden, porque parte lo escriben los atacantes.

## Qué siguen decidiendo las personas
- **Cerrar o escalar:** una persona, con su nombre, acepta cada propuesta o la cambia dando un motivo.
- **Excepción, con el modo automático encendido:** los cierres de gravedad baja que cumplen todas las condiciones no los revisa nadie, salvo una muestra del 5%. Un error así puede pasar inadvertido.
- **Frenar un ataque** (aislar un equipo, por ejemplo): lo aprueban y ejecutan personas, nunca la IA.

## Resultados (versión v8)
| Qué se midió | Resultado | Frente a qué |
|---|---|---|
| Alertas de práctica con veredicto, gravedad y escalado iguales a la clave | 77 y 76 de 80, en dos pruebas | Acuerdo con la clave de respuestas |
| Ataques pasados por alto | 0 en ambas pruebas | La misma clave y alertas |
| Alertas que dos reglas fijas proponen cerrar sin IA | 43% (4.735 de 11.057) | Muestra de Deloitte, no las 4.000 diarias. No dice si aciertan |
| Prueba final: 40 alertas reservadas | **[PENDIENTE]** | La misma clave |
| Las 10 alertas de Deloitte | **[PENDIENTE]** | Valoración de Deloitte |

**Estas cifras son optimistas.** Miden acuerdo con la clave, no acierto real. La redactó otra IA (Claude); el equipo revisó solo las 20 de sus 120 respuestas más dudosas y no cambió ninguna. Esas 80 alertas también se usaron para ajustar el sistema.

## Límites y riesgos
- **Noches y fines de semana, solo en parte:** el modo automático viene apagado y un presupuesto de consultas a la IA limita lo que cubre. Ningún aviso sale de la aplicación: nadie recibe una llamada y un problema de noche no se ve hasta que alguien abre la consola.
- **Se equivoca y varía:** dos pruebas de la misma versión difieren en unas pocas alertas.
- **Es lento:** unos 2,5 minutos por consulta a la IA; en modo rápido, segundos, pero puntúa peor.
- **Es un prototipo:** las medidas solo se ejecutan en un entorno simulado, los aprobadores escriben su nombre sin iniciar sesión y no consulta fuentes externas de reputación.

## Qué haría falta para usarlo de verdad
Una clave de respuestas revisada entera por personas; conexión real con los sistemas de Tarvia y fuentes externas, con avisos que lleguen a la guardia; aprobadores que entren con su cuenta; y un piloto junto a los analistas para comparar sus decisiones con las propuestas.
