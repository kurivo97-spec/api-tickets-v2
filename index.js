// index.js (API Backend - VERSIÓN LIMPIA Y COMPLETA)

// 1. IMPORTAR LIBRERÍAS
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;

// 2. CONFIGURACIÓN INICIAL
const app = express();
const PORT = process.env.PORT || 10000; // Render usa el puerto 10000 por defecto

// 3. CONFIGURAR CLOUDINARY
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// 4. MIDDLEWARE
app.use(cors()); // Considera opciones más específicas para producción
app.use(express.json());
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// 5. CONEXIÓN A BASE DE DATOS (AIVEN)
let pool; // Definimos pool fuera para poder reintentar si falla
function connectDB() {
    try {
        pool = mysql.createPool({
            connectionLimit: 10,
            uri: process.env.DATABASE_URL,
            ssl: {
                rejectUnauthorized: false
            }
        });

        // Probar conexión inicial
        pool.getConnection()
            .then(connection => {
                console.log('✅ ¡Conexión inicial a Aiven (MySQL) exitosa!');
                connection.release();
            })
            .catch(err => {
                console.error('❌ Error en la conexión inicial a la base de datos:', err);
                // Podrías intentar reconectar o salir
            });
    } catch (err) {
        console.error('❌ Error creando el pool de conexiones:', err);
    }
}
connectDB(); // Llama a la función para conectar

// ----- Middleware Guardián (para proteger rutas) -----
const protegerRuta = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        return res.status(401).json({ error: 'No token provided' });
    }

    // Verificar JWT_SECRET antes de verificar el token
    if (!process.env.JWT_SECRET) {
        console.error('ERROR FATAL en protegerRuta: JWT_SECRET no definido');
        return res.status(500).json({ error: 'Error de configuración del servidor' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, userPayload) => {
        if (err) {
            console.warn('Token inválido recibido:', err.message); // Log de advertencia
            return res.status(403).json({ error: 'Token is not valid' });
        }
        req.usuario = userPayload;
        next();
    });
};


// 6. RUTAS (ENDPOINTS)

// --- Login ---
app.post('/login', async (req, res) => {
    console.log('==== INTENTO DE LOGIN RECIBIDO ====');
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });

    let connection;
    try {
        console.log(`Buscando usuario: ${username}`);
        connection = await pool.getConnection();
        const sqlQuery = 'SELECT * FROM Usuarios WHERE username = ?';
        const [users] = await connection.execute(sqlQuery, [username]);

        if (users.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        const user = users[0];

        const isPasswordCorrect = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordCorrect) return res.status(401).json({ error: 'Contraseña incorrecta' });

        if (!process.env.JWT_SECRET) throw new Error('JWT_SECRET no configurado');
        const payload = { id: user.id_usuario, rol: user.id_rol, area_servicio: user.id_area_servicio };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1d' });

        const responseData = {
            message: 'Login exitoso', token,
            usuario: {
                id_usuario: user.id_usuario, nombre: user.nombre_completo,
                id_rol: user.id_rol, datos_actualizados: user.datos_actualizados
            }
        };
        console.log('Enviando respuesta JSON login...');
        res.status(200).json(responseData);
        console.log('Respuesta login enviada.');

    } catch (error) {
        console.error("Error DETALLADO en /login:", error);
        if (!res.headersSent) res.status(500).json({ error: 'Error interno servidor login' });
    } finally {
        if (connection) connection.release();
    }
});

// --- Actualizar Perfil ---
app.put('/usuarios/actualizar-perfil', protegerRuta, async (req, res) => {
    const idUsuarioLogueado = req.usuario.id;
    const { nombre_completo, id_sede, id_area_usuario, cargo, password } = req.body;
    if (!nombre_completo || !id_sede || !id_area_usuario || !cargo) {
        return res.status(400).json({ error: 'Nombre, sede, área y cargo requeridos' });
    }

    let connection;
    try {
        connection = await pool.getConnection();
        let passwordHash = null;
        if (password && password.length > 0) {
            const salt = await bcrypt.genSalt(10);
            passwordHash = await bcrypt.hash(password, salt);
        }

        let sqlQuery, queryParams;
        if (passwordHash) {
            sqlQuery = `UPDATE Usuarios SET nombre_completo = ?, id_sede = ?, id_area_usuario = ?, cargo = ?, password_hash = ?, datos_actualizados = 1 WHERE id_usuario = ?`;
            queryParams = [nombre_completo, id_sede, id_area_usuario, cargo, passwordHash, idUsuarioLogueado];
        } else {
            sqlQuery = `UPDATE Usuarios SET nombre_completo = ?, id_sede = ?, id_area_usuario = ?, cargo = ?, datos_actualizados = 1 WHERE id_usuario = ?`;
            queryParams = [nombre_completo, id_sede, id_area_usuario, cargo, idUsuarioLogueado];
        }

        const [result] = await connection.execute(sqlQuery, queryParams);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        res.status(200).json({ message: 'Perfil actualizado' });

    } catch (error) {
        console.error("Error en /usuarios/actualizar-perfil:", error);
        res.status(500).json({ error: 'Error interno servidor actualizar perfil' });
    } finally {
        if (connection) connection.release();
    }
});

// --- Obtener Configuración (Áreas, Sedes, Subcategorías) ---
app.get('/configuracion', async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [areas] = await connection.execute('SELECT * FROM Areas ORDER BY nombre_area');
        const [sedes] = await connection.execute('SELECT * FROM Sedes ORDER BY nombre_sede');
        const [subcategorias] = await connection.execute('SELECT * FROM SubCategorias ORDER BY nombre_subcategoria');
        res.status(200).json({ areas, sedes, subcategorias });
    } catch (error) {
        console.error("Error en /configuracion:", error);
        res.status(500).json({ error: 'Error interno servidor config' });
    } finally {
        if (connection) connection.release();
    }
});

// --- Crear Ticket ---
app.post('/tickets/crear', protegerRuta, async (req, res) => {
    const idSolicitante = req.usuario.id;
    const { titulo, descripcion, prioridad, id_area, id_subcategoria } = req.body;
    if (!titulo || !descripcion || !prioridad || !id_area) {
        return res.status(400).json({ error: 'Título, descripción, prioridad y área requeridos' });
    }

    let connection;
    try {
        connection = await pool.getConnection();
        const [estados] = await connection.execute('SELECT id_estado FROM Estados_Ticket WHERE nombre_estado = ?', ['Recibido']);
        if (estados.length === 0) throw new Error('Estado "Recibido" no encontrado');
        const idEstadoRecibido = estados[0].id_estado;

        const sqlQuery = `INSERT INTO Tickets (titulo, descripcion, prioridad, id_solicitante, id_area, id_subcategoria, id_estado) VALUES (?, ?, ?, ?, ?, ?, ?)`;
        const params = [titulo, descripcion, prioridad, idSolicitante, id_area, id_subcategoria || null, idEstadoRecibido];
        const [result] = await connection.execute(sqlQuery, params);
        res.status(201).json({ message: 'Ticket creado', id_ticket: result.insertId });

    } catch (error) {
        console.error("Error en /tickets/crear:", error);
        res.status(500).json({ error: 'Error interno servidor crear ticket' });
    } finally {
        if (connection) connection.release();
    }
});

// --- Obtener Mis Tickets ---
app.get('/mis-tickets', protegerRuta, async (req, res) => {
    const idSolicitante = req.usuario.id;
    let connection;
    try {
        connection = await pool.getConnection();
        const sqlQuery = `
            SELECT t.id_ticket, t.titulo, t.prioridad, t.fecha_creacion, a.nombre_area, e.nombre_estado
            FROM Tickets AS t
            JOIN Areas AS a ON t.id_area = a.id_area
            JOIN Estados_Ticket AS e ON t.id_estado = e.id_estado
            WHERE t.id_solicitante = ? ORDER BY t.fecha_creacion DESC`;
        const [tickets] = await connection.execute(sqlQuery, [idSolicitante]);
        res.status(200).json(tickets);
    } catch (error) {
        console.error("Error en /mis-tickets:", error);
        res.status(500).json({ error: 'Error interno servidor mis tickets' });
    } finally {
        if (connection) connection.release();
    }
});

// --- Dashboard Técnico ---
app.get('/tecnico/dashboard', protegerRuta, async (req, res) => {
    const { idRol, area_servicio: idAreaServicio } = req.usuario;
    if (idRol < 2) return res.status(403).json({ error: 'Acceso denegado (no técnico/admin)' });
    if (!idAreaServicio) return res.status(400).json({ error: 'Usuario sin área de servicio' });

    let connection;
    try {
        connection = await pool.getConnection();
        const sqlQuery = `
            SELECT t.id_ticket, t.titulo, t.prioridad, t.fecha_creacion, u.nombre_completo AS solicitante_nombre,
                   s.nombre_sede, e.nombre_estado, sc.nombre_subcategoria
            FROM Tickets AS t
            JOIN Usuarios AS u ON t.id_solicitante = u.id_usuario
            JOIN Sedes AS s ON u.id_sede = s.id_sede
            JOIN Estados_Ticket AS e ON t.id_estado = e.id_estado
            LEFT JOIN SubCategorias AS sc ON t.id_subcategoria = sc.id_subcategoria
            WHERE t.id_area = ? AND e.nombre_estado IN ('Recibido', 'En Proceso')
            ORDER BY FIELD(t.prioridad, 'Alta', 'Media', 'Baja'), t.fecha_creacion ASC`;
        const [tickets] = await connection.execute(sqlQuery, [idAreaServicio]);
        res.status(200).json(tickets);
    } catch (error) {
        console.error("Error en /tecnico/dashboard:", error);
        res.status(500).json({ error: 'Error interno servidor dashboard técnico' });
    } finally {
        if (connection) connection.release();
    }
});

// --- Asignar Ticket ---
app.put('/tickets/:id/asignar', protegerRuta, async (req, res) => {
    const idTicket = req.params.id;
    const idTecnico = req.usuario.id;
    if (req.usuario.rol < 2) return res.status(403).json({ error: 'Acceso denegado' });

    let connection;
    try {
        connection = await pool.getConnection();
        const [estados] = await connection.execute('SELECT id_estado FROM Estados_Ticket WHERE nombre_estado = ?', ['En Proceso']);
        if (estados.length === 0) throw new Error('Estado "En Proceso" no encontrado');
        const idEstadoEnProceso = estados[0].id_estado;

        const sqlQuery = `UPDATE Tickets SET id_tecnico_asignado = ?, id_estado = ? WHERE id_ticket = ?`;
        const [result] = await connection.execute(sqlQuery, [idTecnico, idEstadoEnProceso, idTicket]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Ticket no encontrado' });
        res.status(200).json({ message: 'Ticket asignado' });
    } catch (error) {
        console.error("Error en /tickets/:id/asignar:", error);
        res.status(500).json({ error: 'Error interno servidor asignar' });
    } finally {
        if (connection) connection.release();
    }
});

// --- Resolver Ticket ---
app.put('/tickets/:id/resolver', protegerRuta, async (req, res) => {
    const idTicket = req.params.id;
    if (req.usuario.rol < 2) return res.status(403).json({ error: 'Acceso denegado' });

    let connection;
    try {
        connection = await pool.getConnection();
        const [estados] = await connection.execute('SELECT id_estado FROM Estados_Ticket WHERE nombre_estado = ?', ['Resuelto']);
        if (estados.length === 0) throw new Error('Estado "Resuelto" no encontrado');
        const idEstadoResuelto = estados[0].id_estado;

        const sqlQuery = `UPDATE Tickets SET id_estado = ?, fecha_resolucion = NOW() WHERE id_ticket = ?`;
        const [result] = await connection.execute(sqlQuery, [idEstadoResuelto, idTicket]);
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Ticket no encontrado' });
        res.status(200).json({ message: 'Ticket resuelto' });
    } catch (error) {
        console.error("Error en /tickets/:id/resolver:", error);
        res.status(500).json({ error: 'Error interno servidor resolver' });
    } finally {
        if (connection) connection.release();
    }
});

// --- Calificar Ticket ---
app.post('/tickets/:id/calificar', protegerRuta, async (req, res) => {
    const idTicket = req.params.id;
    const idUsuario = req.usuario.id;
    const { puntuacion } = req.body;
    if (!puntuacion || puntuacion < 1 || puntuacion > 5) {
        return res.status(400).json({ error: 'Puntuación inválida (1-5)' });
    }

    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();
        const [estados] = await connection.execute('SELECT id_estado FROM Estados_Ticket WHERE nombre_estado = ?', ['Cerrado']);
        if (estados.length === 0) throw new Error('Estado "Cerrado" no encontrado');
        const idEstadoCerrado = estados[0].id_estado;

        const sqlInsert = `INSERT INTO Calificaciones_Ticket (id_ticket, id_usuario, puntuacion) VALUES (?, ?, ?)`;
        await connection.execute(sqlInsert, [idTicket, idUsuario, puntuacion]);

        const sqlUpdate = `UPDATE Tickets SET id_estado = ?, fecha_cierre = NOW() WHERE id_ticket = ? AND id_solicitante = ?`;
        const [result] = await connection.execute(sqlUpdate, [idEstadoCerrado, idTicket, idUsuario]);
        if (result.affectedRows === 0) throw new Error('Ticket no actualizable (no existe o no pertenece)');

        await connection.commit();
        res.status(200).json({ message: 'Ticket calificado y cerrado' });
    } catch (error) {
        if (connection) await connection.rollback();
        if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Ticket ya calificado' });
        console.error("Error en /tickets/:id/calificar:", error);
        res.status(500).json({ error: 'Error interno servidor calificar' });
    } finally {
        if (connection) connection.release();
    }
});

// --- Adjuntar Foto (Solicitud) ---
app.post('/tickets/:id/adjuntar-foto', protegerRuta, upload.single('foto'), async (req, res) => {
    const idTicket = req.params.id;
    const idUsuario = req.usuario.id;
    const tipoAdjunto = 'Solicitud';
    if (!req.file) return res.status(400).json({ error: 'No se subió archivo' });

    let connection;
    try {
        const b64 = Buffer.from(req.file.buffer).toString("base64");
        const dataURI = `data:${req.file.mimetype};base64,${b64}`;
        const cloudinaryResponse = await cloudinary.uploader.upload(dataURI, {
            resource_type: "auto", folder: "tickets-app/solicitudes"
        });

        connection = await pool.getConnection();
        const sqlInsert = `INSERT INTO Adjuntos_Ticket (id_ticket, id_usuario_sube, tipo_adjunto, url_archivo) VALUES (?, ?, ?, ?)`;
        await connection.execute(sqlInsert, [idTicket, idUsuario, tipoAdjunto, cloudinaryResponse.secure_url]);
        res.status(201).json({ message: 'Foto adjuntada', url: cloudinaryResponse.secure_url });
    } catch (error) {
        console.error("Error en /tickets/:id/adjuntar-foto:", error);
        res.status(500).json({ error: 'Error al subir imagen' });
    } finally {
        if (connection) connection.release();
    }
});

// --- Adjuntar Evidencia (Técnico) ---
app.post('/tickets/:id/adjuntar-evidencia', protegerRuta, upload.single('evidencia'), async (req, res) => {
    const idTicket = req.params.id;
    const idTecnico = req.usuario.id;
    const tipoAdjunto = 'Evidencia';
    if (req.usuario.rol < 2) return res.status(403).json({ error: 'Acceso denegado' });
    if (!req.file) return res.status(400).json({ error: 'No se subió archivo' });

    let connection;
    try {
        const b64 = Buffer.from(req.file.buffer).toString("base64");
        const dataURI = `data:${req.file.mimetype};base64,${b64}`;
        const cloudinaryResponse = await cloudinary.uploader.upload(dataURI, {
            resource_type: "auto", folder: "tickets-app/evidencias"
        });

        connection = await pool.getConnection();
        const sqlInsert = `INSERT INTO Adjuntos_Ticket (id_ticket, id_usuario_sube, tipo_adjunto, url_archivo) VALUES (?, ?, ?, ?)`;
        await connection.execute(sqlInsert, [idTicket, idTecnico, tipoAdjunto, cloudinaryResponse.secure_url]);
        res.status(201).json({ message: 'Evidencia adjuntada', url: cloudinaryResponse.secure_url });
    } catch (error) {
        console.error("Error en /tickets/:id/adjuntar-evidencia:", error);
        res.status(500).json({ error: 'Error al subir imagen' });
    } finally {
        if (connection) connection.release();
    }
});

// --- Obtener Detalles de Ticket ---
app.get('/tickets/:id', protegerRuta, async (req, res) => {
    const idTicket = req.params.id;
    const { id: idUsuarioLogueado, rol: rolUsuarioLogueado } = req.usuario;

    let connection;
    try {
        connection = await pool.getConnection();
        const sqlTicket = `
            SELECT t.*, a.nombre_area, e.nombre_estado, sc.nombre_subcategoria,
                   sol.nombre_completo AS solicitante_nombre, sed.nombre_sede AS solicitante_sede, sol.cargo AS solicitante_cargo,
                   tec.nombre_completo AS tecnico_nombre, cal.puntuacion AS calificacion
            FROM Tickets AS t
            JOIN Areas AS a ON t.id_area = a.id_area
            JOIN Estados_Ticket AS e ON t.id_estado = e.id_estado
            LEFT JOIN SubCategorias AS sc ON t.id_subcategoria = sc.id_subcategoria
            JOIN Usuarios AS sol ON t.id_solicitante = sol.id_usuario
            JOIN Sedes AS sed ON sol.id_sede = sed.id_sede
            LEFT JOIN Usuarios AS tec ON t.id_tecnico_asignado = tec.id_usuario
            LEFT JOIN Calificaciones_Ticket AS cal ON t.id_ticket = cal.id_ticket
            WHERE t.id_ticket = ?`;
        const [ticketResult] = await connection.execute(sqlTicket, [idTicket]);
        if (ticketResult.length === 0) return res.status(404).json({ error: 'Ticket no encontrado' });
        const ticket = ticketResult[0];

        if (ticket.id_solicitante !== idUsuarioLogueado && rolUsuarioLogueado < 2) {
             return res.status(403).json({ error: 'No tienes permiso' });
        }

        const sqlAdjuntos = `SELECT id_adjunto, tipo_adjunto, url_archivo, fecha_subida FROM Adjuntos_Ticket WHERE id_ticket = ? ORDER BY fecha_subida ASC`;
        const [adjuntosResult] = await connection.execute(sqlAdjuntos, [idTicket]);
        
        // Mapeo final
        const ticketDetallado = {
            id_ticket: ticket.id_ticket, titulo: ticket.titulo, descripcion: ticket.descripcion, prioridad: ticket.prioridad,
            fecha_creacion: ticket.fecha_creacion, fecha_resolucion: ticket.fecha_resolucion, fecha_cierre: ticket.fecha_cierre,
            area: ticket.nombre_area, estado: ticket.nombre_estado, subcategoria: ticket.nombre_subcategoria,
            solicitante_nombre: ticket.solicitante_nombre, solicitante_sede: ticket.solicitante_sede, solicitante_cargo: ticket.solicitante_cargo,
            tecnico_nombre: ticket.tecnico_nombre, calificacion: ticket.calificacion,
            adjuntos: adjuntosResult
        };
        res.status(200).json(ticketDetallado);

    } catch (error) {
        console.error(`Error en GET /tickets/${idTicket}:`, error);
        res.status(500).json({ error: 'Error interno servidor detalle ticket' });
    } finally {
        if (connection) connection.release();
    }
});

// --- Reportes Admin ---
app.get('/admin/reportes', protegerRuta, async (req, res) => {
    if (req.usuario.rol !== 3) return res.status(403).json({ error: 'Acceso denegado (Admin)' });

    let connection;
    try {
        connection = await pool.getConnection();
        const sqlEstado = `SELECT e.nombre_estado, COUNT(t.id_ticket) AS total FROM Estados_Ticket e LEFT JOIN Tickets t ON e.id_estado = t.id_estado GROUP BY e.nombre_estado ORDER BY e.id_estado`;
        const sqlArea = `SELECT a.nombre_area, COUNT(t.id_ticket) AS total FROM Areas a LEFT JOIN Tickets t ON a.id_area = t.id_area GROUP BY a.nombre_area ORDER BY a.nombre_area`;
        const sqlCalif = `SELECT AVG(puntuacion) AS promedio_general FROM Calificaciones_Ticket`;
        const sqlTecnico = `SELECT u.nombre_completo AS tecnico, COUNT(t.id_ticket) AS total_resueltos FROM Tickets t JOIN Usuarios u ON t.id_tecnico_asignado = u.id_usuario WHERE t.id_estado IN (SELECT id_estado FROM Estados_Ticket WHERE nombre_estado IN ('Resuelto','Cerrado')) GROUP BY u.nombre_completo ORDER BY total_resueltos DESC LIMIT 5`;

        const [[estados], [areas], [calif], [tecnicos]] = await Promise.all([
            connection.execute(sqlEstado), connection.execute(sqlArea),
            connection.execute(sqlCalif), connection.execute(sqlTecnico)
        ]);

        res.status(200).json({
            ticketsPorEstado: estados, ticketsPorArea: areas,
            calificacionPromedio: calif[0].promedio_general || 0,
            topTecnicos: tecnicos
        });
    } catch (error) {
        console.error("Error en /admin/reportes:", error);
        res.status(500).json({ error: 'Error interno servidor reportes' });
    } finally {
        if (connection) connection.release();
    }
});


// 7. INICIAR EL SERVIDOR (AL FINAL DE TODO)
app.listen(PORT, () => {
    console.log(`🚀 Servidor API corriendo en puerto ${PORT}`);
});