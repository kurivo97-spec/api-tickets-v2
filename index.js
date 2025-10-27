// index.js

// 1. IMPORTAR LAS LIBRERÍAS
require('dotenv').config(); // Carga las variables del .env (la llave de Aiven)



const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise'); // Usamos la versión con "promesas"
const bcrypt = require('bcryptjs'); // Para comparar contraseñas
const jwt = require('jsonwebtoken'); // Para crear tokens de sesión
// Nuevas importaciones para Hito 6
const multer = require('multer');
const cloudinary = require('cloudinary').v2;



// 2. CONFIGURACIÓN INICIAL
const app = express();
const PORT = process.env.PORT || 3001; // El puerto donde correrá la API

// 3. CONFIGURAR CLOUDINARY (AHORA SÍ, DESPUÉS DE IMPORTARLO)
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// 4. MIDDLEWARE (Funciones intermedias)
app.use(cors()); // Permite que el frontend se conecte a esta API
app.use(express.json()); // Permite a la API entender datos en formato JSON

// Configurar Multer para subida de archivos en memoria (NUEVO)
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// 4. CONEXIÓN A LA BASE DE DATOS (AIVEN)
const pool = mysql.createPool({
    connectionLimit: 10,
    uri: process.env.DATABASE_URL, // Usa la "llave" del archivo .env
    ssl: {
        rejectUnauthorized: false // Aiven requiere SSL
    }
});

console.log("Intentando conectar a la base de datos...");
// Probamos la conexión al iniciar
pool.getConnection()
    .then(connection => {
        console.log('✅ ¡Conexión a Aiven (MySQL) exitosa!');
        connection.release(); // Soltamos la conexión de prueba
    })
    .catch(err => {
        console.error('❌ Error al conectar a la base de datos:', err);
    });

// 5. RUTAS (LOS ENDPOINTS DE LA API)
// 5. RUTAS (LOS ENDPOINTS DE LA API)

// ----- Middleware Guardián (para proteger rutas) -----
const protegerRuta = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato "Bearer TOKEN"

    if (token == null) {
        return res.status(401).json({ error: 'No token provided' }); // No hay token
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, userPayload) => {
        if (err) {
            return res.status(403).json({ error: 'Token is not valid' }); // Token inválido
        }
        
        // ¡Token válido! Adjuntamos los datos del usuario a la solicitud
        req.usuario = userPayload; 
        next(); // Continúa hacia el endpoint real
    });
};


/**
 * @endpoint POST /login
 * @desc Autentica a un usuario y devuelve un token.
 */
app.post('/login', async (req, res) => {
    
    // 1. Obtener datos del cuerpo (body)
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
    }

    let connection;
    try {
        // 2. Obtener una conexión del Pool
        connection = await pool.getConnection();

        // 3. Buscar al usuario en la BD
        // (Recuerda que tu usuario de prueba es 'admin')
        const sqlQuery = 'SELECT * FROM Usuarios WHERE username = ?';
        const [users] = await connection.execute(sqlQuery, [username]);

        if (users.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        const user = users[0];

        // 4. Comparar la contraseña recibida con el hash de la BD
        // (La contraseña de 'admin' es '123456')
        const isPasswordCorrect = await bcrypt.compare(password, user.password_hash);

        if (!isPasswordCorrect) {
            return res.status(401).json({ error: 'Contraseña incorrecta' });
        }

        // 5. ¡ÉXITO! Crear un Token de Sesión (JWT)
        const payload = {
            id: user.id_usuario,
            rol: user.id_rol,
            area_servicio: user.id_area_servicio
        };
        
        const token = jwt.sign(payload, process.env.JWT_SECRET, {
            expiresIn: '1d' // El token dura 1 día
        });

        // 6. Enviar la respuesta
        res.status(200).json({
            message: 'Login exitoso',
            token: token,
            usuario: {
                id_usuario: user.id_usuario,
                nombre: user.nombre_completo,
                id_rol: user.id_rol,
                datos_actualizados: user.datos_actualizados
            }
        });

    } catch (error) {
        console.error("Error en /login:", error);
        res.status(500).json({ error: 'Error interno del servidor' });
    } finally {
        // 7. Siempre liberar la conexión al final
        if (connection) connection.release();
    }
}); // <--- AQUÍ TERMINA EL LOGIN


// ========================================================
// ==== AQUÍ EMPIEZA EL NUEVO CÓDIGO DE ACTUALIZAR PERFIL ====
// ========================================================

/**
 * @endpoint PUT /usuarios/actualizar-perfil
 * @desc Actualiza el perfil del usuario logueado (Ruta Protegida).
 */
app.put('/usuarios/actualizar-perfil', protegerRuta, async (req, res) => {
    
    // 1. Gracias al middleware 'protegerRuta', ya sabemos quién es el usuario.
    //    El ID del usuario está en 'req.usuario.id'
    const idUsuarioLogueado = req.usuario.id;

    // 2. Obtener los datos a actualizar del cuerpo (body)
    const { nombre_completo, id_sede, id_area_usuario, cargo, password } = req.body;

    if (!nombre_completo || !id_sede || !id_area_usuario || !cargo) {
        return res.status(400).json({ error: 'Nombre, sede, área y cargo son requeridos' });
    }

    let connection;
    try {
        connection = await pool.getConnection();

        let passwordHash = null;
        // 3. Si el usuario mandó una nueva contraseña, la encriptamos
        if (password && password.length > 0) {
            const salt = await bcrypt.genSalt(10);
            passwordHash = await bcrypt.hash(password, salt);
        }

        // 4. Construir la consulta SQL
        let sqlQuery;
        let queryParams;

        if (passwordHash) {
            // Si actualiza contraseña
            sqlQuery = `
                UPDATE Usuarios 
                SET nombre_completo = ?, id_sede = ?, id_area_usuario = ?, cargo = ?, password_hash = ?, datos_actualizados = 1
                WHERE id_usuario = ?
            `;
            queryParams = [nombre_completo, id_sede, id_area_usuario, cargo, passwordHash, idUsuarioLogueado];
        } else {
            // Si NO actualiza contraseña
            sqlQuery = `
                UPDATE Usuarios 
                SET nombre_completo = ?, id_sede = ?, id_area_usuario = ?, cargo = ?, datos_actualizados = 1
                WHERE id_usuario = ?
            `;
            queryParams = [nombre_completo, id_sede, id_area_usuario, cargo, idUsuarioLogueado];
        }

        // 5. Ejecutar la actualización
        const [result] = await connection.execute(sqlQuery, queryParams);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado para actualizar' });
        }

        // 6. Éxito
        res.status(200).json({ message: 'Perfil actualizado correctamente' });

    } catch (error) {
        console.error("Error en /usuarios/actualizar-perfil:", error);
        res.status(500).json({ error: 'Error interno del servidor' });
    } finally {
        if (connection) connection.release();
    }
});
// ========================================================
// ==== HITO 3: GESTIÓN DE TICKETS (SOLICITANTE) ====
// ========================================================

/**
 * @endpoint GET /configuracion
 * @desc Obtiene todas las listas necesarias para los formularios.
 */
app.get('/configuracion', async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        
        // Hacemos todas las consultas a la vez
        const [areas] = await connection.execute('SELECT * FROM Areas');
        const [sedes] = await connection.execute('SELECT * FROM Sedes');
        const [subcategorias] = await connection.execute('SELECT * FROM SubCategorias');

        // Devolvemos todo en un solo objeto
        res.status(200).json({
            areas: areas,
            sedes: sedes,
            subcategorias: subcategorias
        });

    } catch (error) {
        console.error("Error en /configuracion:", error);
        res.status(500).json({ error: 'Error interno del servidor' });
    } finally {
        if (connection) connection.release();
    }
});

/**
 * @endpoint POST /tickets/crear
 * @desc Crea un nuevo ticket (Ruta Protegida).
 */
app.post('/tickets/crear', protegerRuta, async (req, res) => {
    
    // 1. Obtenemos el ID del usuario que crea el ticket (gracias al token)
    const idSolicitante = req.usuario.id;

    // 2. Obtenemos los datos del formulario
    const { titulo, descripcion, prioridad, id_area, id_subcategoria } = req.body;

    if (!titulo || !descripcion || !prioridad || !id_area) {
        return res.status(400).json({ error: 'Título, descripción, prioridad y área son requeridos' });
    }

    let connection;
    try {
        connection = await pool.getConnection();

        // 3. Buscamos el ID del estado "Recibido"
        // (En nuestro script de SCRIPT 2, "Recibido" es el ID 1)
        const [estados] = await connection.execute('SELECT id_estado FROM Estados_Ticket WHERE nombre_estado = ?', ['Recibido']);
        if (estados.length === 0) {
            throw new Error('Estado "Recibido" no encontrado en la base de datos');
        }
        const idEstadoRecibido = estados[0].id_estado;
        
        // 4. Creamos la consulta SQL para insertar el ticket
        const sqlQuery = `
            INSERT INTO Tickets (titulo, descripcion, prioridad, id_solicitante, id_area, id_subcategoria, id_estado)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        
        // El id_subcategoria puede ser 'null' (ej: para Mantenimiento)
        const params = [titulo, descripcion, prioridad, idSolicitante, id_area, id_subcategoria || null, idEstadoRecibido];

        // 5. Ejecutamos la inserción
        const [result] = await connection.execute(sqlQuery, params);
        
        const nuevoTicketId = result.insertId;

        // 6. Éxito
        res.status(201).json({ 
            message: 'Ticket creado exitosamente', 
            id_ticket: nuevoTicketId // Devolvemos el ID del nuevo ticket
        });

    } catch (error) {
        console.error("Error en /tickets/crear:", error);
        res.status(500).json({ error: 'Error interno del servidor' });
    } finally {
        if (connection) connection.release();
    }
});

/**
 * @endpoint GET /mis-tickets
 * @desc Obtiene todos los tickets creados por el usuario logueado (Ruta Protegida).
 */
// index.js (API Backend)

// index.js (API Backend)

app.get('/mis-tickets', protegerRuta, async (req, res) => { 

    const idSolicitante = req.usuario.id; // ¡Esta línea es necesaria!

    let connection;
    try {
        connection = await pool.getConnection();

        // ESTA ES LA CONSULTA SQL CORRECTA (limpia, sin comentarios extra)
        const sqlQuery = `
            SELECT 
                t.id_ticket,
                t.titulo,
                t.prioridad,
                t.fecha_creacion,
                a.nombre_area,
                e.nombre_estado
            FROM 
                Tickets AS t
            JOIN 
                Areas AS a ON t.id_area = a.id_area
            JOIN 
                Estados_Ticket AS e ON t.id_estado = e.id_estado
            WHERE 
                t.id_solicitante = ?
            ORDER BY 
                t.fecha_creacion DESC
        `;

        // Ejecuta la consulta PASANDO el idSolicitante
        const [tickets] = await connection.execute(sqlQuery, [idSolicitante]);

        res.status(200).json(tickets);

    } catch (error) {
        console.error("Error en /mis-tickets (protegido):", error); 
        res.status(500).json({ error: 'Error interno del servidor al obtener mis tickets' });
    } finally {
        if (connection) connection.release();
    }
});

// ========================================================
// ==== HITO 4: PANEL DE CONTROL DEL TÉCNICO ====
// ========================================================

/**
 * @endpoint GET /tecnico/dashboard
 * @desc Obtiene la cola de tickets activos para el área del técnico logueado.
 */
app.get('/tecnico/dashboard', protegerRuta, async (req, res) => {

    // 1. Obtenemos los datos del técnico (gracias al token)
    const idAreaServicio = req.usuario.area_servicio;
    const idRol = req.usuario.rol;

    // 2. Verificamos que sea un técnico o admin (Rol 2 o 3)
    if (idRol < 2) {
        return res.status(403).json({ error: 'Acceso denegado. Se requiere rol de técnico o administrador.' });
    }
    if (!idAreaServicio) {
        return res.status(400).json({ error: 'El usuario no tiene un área de servicio asignada.' });
    }

    let connection;
    try {
        connection = await pool.getConnection();

        // 3. Consulta compleja para el dashboard
        const sqlQuery = `
            SELECT 
                t.id_ticket,
                t.titulo,
                t.prioridad,
                t.fecha_creacion,
                u.nombre_completo AS solicitante_nombre,
                s.nombre_sede,
                e.nombre_estado,
                sc.nombre_subcategoria
            FROM 
                Tickets AS t
            JOIN 
                Usuarios AS u ON t.id_solicitante = u.id_usuario
            JOIN 
                Sedes AS s ON u.id_sede = s.id_sede
            JOIN 
                Estados_Ticket AS e ON t.id_estado = e.id_estado
            LEFT JOIN -- Usamos LEFT JOIN por si Mantenimiento no tiene sub-categoría
                SubCategorias AS sc ON t.id_subcategoria = sc.id_subcategoria
            WHERE 
                t.id_area = ? 
            AND 
                (e.nombre_estado = 'Recibido' OR e.nombre_estado = 'En Proceso')
            ORDER BY
                -- Ordenamos por prioridad (Alta, Media, Baja) y luego por fecha (el más antiguo primero)
                FIELD(t.prioridad, 'Alta', 'Media', 'Baja'),
                t.fecha_creacion ASC;
        `;

        // 4. Ejecutamos la consulta pasando el área del técnico
        const [tickets] = await connection.execute(sqlQuery, [idAreaServicio]);

        // 5. Devolvemos la lista de tickets
        res.status(200).json(tickets);

    } catch (error) {
        console.error("Error en /tecnico/dashboard:", error);
        res.status(500).json({ error: 'Error interno del servidor' });
    } finally {
        if (connection) connection.release();
    }
});

/**
 * @endpoint PUT /tickets/:id/asignar
 * @desc El técnico se asigna un ticket (cambia a "En Proceso").
 */
app.put('/tickets/:id/asignar', protegerRuta, async (req, res) => {
    
    // 1. Obtenemos el ID del ticket (de la URL) y el ID del técnico (del token)
    const idTicket = req.params.id;
    const idTecnico = req.usuario.id;

    let connection;
    try {
        connection = await pool.getConnection();

        // 2. Buscamos el ID del estado "En Proceso"
        const [estados] = await connection.execute('SELECT id_estado FROM Estados_Ticket WHERE nombre_estado = ?', ['En Proceso']);
        if (estados.length === 0) {
            throw new Error('Estado "En Proceso" no encontrado');
        }
        const idEstadoEnProceso = estados[0].id_estado;

        // 3. Actualizamos el ticket
        const sqlQuery = `
            UPDATE Tickets 
            SET 
                id_tecnico_asignado = ?,
                id_estado = ?
            WHERE 
                id_ticket = ?
        `;
        
        const [result] = await connection.execute(sqlQuery, [idTecnico, idEstadoEnProceso, idTicket]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Ticket no encontrado' });
        }

        // 4. Éxito
        res.status(200).json({ message: 'Ticket asignado correctamente' });

    } catch (error) {
        console.error("Error en /tickets/:id/asignar:", error);
        res.status(500).json({ error: 'Error interno del servidor' });
    } finally {
        if (connection) connection.release();
    }
});


/**
 * @endpoint PUT /tickets/:id/resolver
 * @desc El técnico marca un ticket como "Resuelto".
 */
app.put('/tickets/:id/resolver', protegerRuta, async (req, res) => {
    
    const idTicket = req.params.id;

    let connection;
    try {
        connection = await pool.getConnection();

        // 1. Buscamos el ID del estado "Resuelto"
        const [estados] = await connection.execute('SELECT id_estado FROM Estados_Ticket WHERE nombre_estado = ?', ['Resuelto']);
        if (estados.length === 0) {
            throw new Error('Estado "Resuelto" no encontrado');
        }
        const idEstadoResuelto = estados[0].id_estado;

        // 2. Actualizamos el ticket
        const sqlQuery = `
            UPDATE Tickets 
            SET 
                id_estado = ?,
                fecha_resolucion = NOW() 
            WHERE 
                id_ticket = ?
        `;
        // NOW() pone la fecha y hora actual

        const [result] = await connection.execute(sqlQuery, [idEstadoResuelto, idTicket]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Ticket no encontrado' });
        }

        // 3. Éxito
        // (Aquí es donde, en el futuro, dispararíamos el correo de notificación)
        res.status(200).json({ message: 'Ticket marcado como Resuelto' });

    } catch (error) {
        console.error("Error en /tickets/:id/resolver:", error);
        res.status(500).json({ error: 'Error interno del servidor' });
    } finally {
        if (connection) connection.release();
    }
});

// ========================================================
// ==== HITO 5: CALIFICACIÓN Y CIERRE DE TICKET ====
// ========================================================

/**
 * @endpoint POST /tickets/:id/calificar
 * @desc El usuario solicitante califica un ticket resuelto.
 */
app.post('/tickets/:id/calificar', protegerRuta, async (req, res) => {
    
    // 1. Obtenemos el ID del ticket (de la URL) y el ID del usuario (del token)
    const idTicket = req.params.id;
    const idUsuario = req.usuario.id;

    // 2. Obtenemos la puntuación del cuerpo (body)
    const { puntuacion } = req.body;

    if (!puntuacion || puntuacion < 1 || puntuacion > 5) {
        return res.status(400).json({ error: 'La puntuación debe ser un número entre 1 y 5' });
    }

    let connection;
    try {
        connection = await pool.getConnection();
        // Iniciamos una transacción para hacer dos cosas a la vez de forma segura
        await connection.beginTransaction();

        // 3. Buscamos el ID del estado "Cerrado"
        const [estados] = await connection.execute('SELECT id_estado FROM Estados_Ticket WHERE nombre_estado = ?', ['Cerrado']);
        if (estados.length === 0) {
            throw new Error('Estado "Cerrado" no encontrado');
        }
        const idEstadoCerrado = estados[0].id_estado;

        // 4. Insertamos la calificación
        const sqlInsertCalificacion = `
            INSERT INTO Calificaciones_Ticket (id_ticket, id_usuario, puntuacion)
            VALUES (?, ?, ?)
        `;
        await connection.execute(sqlInsertCalificacion, [idTicket, idUsuario, puntuacion]);
        
        // 5. Actualizamos el ticket a "Cerrado"
        const sqlUpdateTicket = `
            UPDATE Tickets 
            SET 
                id_estado = ?,
                fecha_cierre = NOW()
            WHERE 
                id_ticket = ? 
            AND 
                id_solicitante = ?
        `;
        // Nos aseguramos que solo el solicitante original pueda cerrar su ticket
        const [result] = await connection.execute(sqlUpdateTicket, [idEstadoCerrado, idTicket, idUsuario]);

        if (result.affectedRows === 0) {
            // Si no se actualizó, es porque el ticket no existe o no le pertenece
            throw new Error('El ticket no se pudo actualizar, no existe o no pertenece al usuario');
        }

        // 6. Si todo salió bien, confirmamos la transacción
        await connection.commit();

        res.status(200).json({ message: 'Ticket calificado y cerrado exitosamente' });

    } catch (error) {
        // Si algo falló, revertimos todo
        if (connection) await connection.rollback();
        
        // Manejamos el error de "calificación duplicada" (llave única)
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Este ticket ya ha sido calificado' });
        }

        console.error("Error en /tickets/:id/calificar:", error);
        res.status(500).json({ error: 'Error interno del servidor' });
    } finally {
        if (connection) connection.release();
    }
});// ========================================================
// ==== HITO 6: SUBIDA DE FOTOS Y EVIDENCIAS ====
// ========================================================

/**
 * @endpoint POST /tickets/:id/adjuntar-foto
 * @desc El USUARIO adjunta una foto a su ticket (Ruta Protegida).
 * El frontend debe enviar el archivo bajo el nombre 'foto'
 */
app.post('/tickets/:id/adjuntar-foto', protegerRuta, upload.single('foto'), async (req, res) => {
    
    const idTicket = req.params.id;
    const idUsuario = req.usuario.id;
    const tipoAdjunto = 'Solicitud'; // Es una foto del problema

    if (!req.file) {
        return res.status(400).json({ error: 'No se subió ningún archivo.' });
    }

    let connection;
    try {
        // 1. Subir el archivo a Cloudinary
        // Convertimos el buffer (archivo en memoria) a un string base64 que Cloudinary entiende
        const b64 = Buffer.from(req.file.buffer).toString("base64");
        let dataURI = "data:" + req.file.mimetype + ";base64," + b64;
        
        const cloudinaryResponse = await cloudinary.uploader.upload(dataURI, {
            resource_type: "auto",
            folder: "tickets-app/solicitudes" // Carpeta en Cloudinary
        });

        // 2. Guardar la URL segura de Cloudinary en nuestra BD (Aiven)
        connection = await pool.getConnection();
        const sqlInsert = `
            INSERT INTO Adjuntos_Ticket (id_ticket, id_usuario_sube, tipo_adjunto, url_archivo)
            VALUES (?, ?, ?, ?)
        `;
        await connection.execute(sqlInsert, [idTicket, idUsuario, tipoAdjunto, cloudinaryResponse.secure_url]);

        // 3. Éxito
        res.status(201).json({ 
            message: 'Foto adjuntada exitosamente', 
            url: cloudinaryResponse.secure_url 
        });

    } catch (error) {
        console.error("Error en /tickets/:id/adjuntar-foto:", error);
        res.status(500).json({ error: 'Error al subir la imagen' });
    } finally {
        if (connection) connection.release();
    }
});


/**
 * @endpoint POST /tickets/:id/adjuntar-evidencia
 * @desc El TÉCNICO adjunta una foto como evidencia de resolución.
 * El frontend debe enviar el archivo bajo el nombre 'evidencia'
 */
app.post('/tickets/:id/adjuntar-evidencia', protegerRuta, upload.single('evidencia'), async (req, res) => {
    
    const idTicket = req.params.id;
    const idTecnico = req.usuario.id;
    const tipoAdjunto = 'Evidencia'; // Es una foto del trabajo hecho

    if (req.usuario.rol < 2) { // Solo Técnicos o Admins
         return res.status(403).json({ error: 'Acceso denegado.' });
    }
    if (!req.file) {
        return res.status(400).json({ error: 'No se subió ningún archivo.' });
    }

    let connection;
    try {
        // 1. Subir a Cloudinary
        const b64 = Buffer.from(req.file.buffer).toString("base64");
        let dataURI = "data:" + req.file.mimetype + ";base64," + b64;
        
        const cloudinaryResponse = await cloudinary.uploader.upload(dataURI, {
            resource_type: "auto",
            folder: "tickets-app/evidencias" // Carpeta diferente
        });

        // 2. Guardar URL en Aiven
        connection = await pool.getConnection();
        const sqlInsert = `
            INSERT INTO Adjuntos_Ticket (id_ticket, id_usuario_sube, tipo_adjunto, url_archivo)
            VALUES (?, ?, ?, ?)
        `;
        await connection.execute(sqlInsert, [idTicket, idTecnico, tipoAdjunto, cloudinaryResponse.secure_url]);

        // 3. Éxito
        res.status(201).json({ 
            message: 'Evidencia adjuntada exitosamente', 
            url: cloudinaryResponse.secure_url 
        });

    } catch (error)
    {
        console.error("Error en /tickets/:id/adjuntar-evidencia:", error);
        res.status(500).json({ error: 'Error al subir la imagen' });
    } finally {
        if (connection) connection.release();
    }
});



// 6. INICIAR EL SERVIDOR
app.listen(PORT, () => {
    console.log(`🚀 Servidor API corriendo en http://localhost:${PORT}`);
});