import { MongoClient, ObjectId } from "mongodb";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import swaggerJsdoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";

// ---------- Configuración ----------

const PORT = process.env.PORT ?? 5000;
const DB_URL = process.env.MONGODB_URI ?? "mongodb://localhost:27017";
const DB_NAME = process.env.DB_NAME ?? "api";
const SECRET_KEY = process.env.JWT_SECRET ?? "secreto";
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET ?? "secreto_refresh";

const USERS = "usuariosMascota";
const MASCOTAS = "mascotas";
const TOKENS = "refreshTokens";

const ACCESS_EXPIRES = "5m";
const REFRESH_EXPIRES = "7d";
const REFRESH_SECONDS = 7 * 24 * 3600;

const app = express();
app.use(express.json());
app.use(cors());

const client = new MongoClient(DB_URL);
await client.connect();

// Índice TTL: Mongo borra solo los refresh tokens caducados
await client
    .db(DB_NAME)
    .collection(TOKENS)
    .createIndex({ createdAt: 1 }, { expireAfterSeconds: REFRESH_SECONDS });

// ---------- Rate Limit ----------

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    limit: 100, // 100 peticiones por IP en esa ventana
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: "Demasiadas peticiones, inténtalo más tarde" },
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5, // 5 intentos de login cada 15 minutos
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: "Demasiados intentos de login, espera 15 minutos" },
});

app.use(globalLimiter);
app.use("/api/login", loginLimiter);

// ---------- Swagger ----------

const swaggerSpec = swaggerJsdoc({
    definition: {
        openapi: "3.0.0",
        info: { title: "API Mascotas", version: "1.0.0" },
        servers: [{ url: `http://localhost:${PORT}` }],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: "http",
                    scheme: "bearer",
                    bearerFormat: "JWT",
                },
            },
            schemas: {
                Mascota: {
                    type: "object",
                    properties: {
                        nombreDueño: { type: "string", example: "Ana" },
                        nombre: { type: "string", example: "Toby" },
                        edad: { type: "integer", example: 3 },
                        especie: { type: "string", example: "perro" },
                    },
                },
            },
        },
    },
    apis: ["./index.js"],
});

app.use("/api/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// ---------- Autenticación JWT ----------

function generarTokens(user) {
    const payload = { id: user._id.toString(), nombre: user.nombre };
    const accessToken = jwt.sign(payload, SECRET_KEY, {
        expiresIn: ACCESS_EXPIRES,
    });
    const refreshToken = jwt.sign(payload, REFRESH_SECRET, {
        expiresIn: REFRESH_EXPIRES,
    });
    return { accessToken, refreshToken };
}

function verifyToken(request, response, next) {
    const token = request.headers.authorization?.split(" ")[1];

    if (!token)
        return response.status(403).json({ message: "Token requerido" });

    try {
        request.user = jwt.verify(token, SECRET_KEY);
        next();
    } catch (err) {
        const expirado = err.name === "TokenExpiredError";
        // 401 = caducado (el cliente debe usar /api/refresh), 403 = inválido
        return response.status(expirado ? 401 : 403).json({
            message: expirado ? "Token expirado" : "Token inválido",
        });
    }
}

function validarId(request, response, next) {
    if (!ObjectId.isValid(request.params.id))
        return response.status(400).json({ message: "Id no válido" });
    next();
}

/**
 * @openapi
 * /api/login:
 *   post:
 *     summary: Iniciar sesión
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               nombre: { type: string }
 *               contraseña: { type: string }
 *     responses:
 *       200:
 *         description: Devuelve accessToken y refreshToken
 *       401:
 *         description: Credenciales incorrectas
 *       429:
 *         description: Demasiados intentos
 */
app.post("/api/login", async (request, response) => {
    if (!request.is("json"))
        return response
            .status(400)
            .json({ message: "Debes proporcionar datos JSON" });

    const { nombre, contraseña } = request.body;
    if (!nombre || !contraseña)
        return response
            .status(400)
            .json({ message: "Nombre y contraseña requeridos" });

    const db = client.db(DB_NAME);
    const user = await db.collection(USERS).findOne({ nombre });

    if (!user)
        return response
            .status(401)
            .json({ message: "Credenciales incorrectas" });

    const correctPassword = await bcrypt.compare(contraseña, user.contraseña);
    if (!correctPassword)
        return response
            .status(401)
            .json({ message: "Credenciales incorrectas" });

    const { accessToken, refreshToken } = generarTokens(user);
    await db.collection(TOKENS).insertOne({
        token: refreshToken,
        userId: user._id,
        createdAt: new Date(),
    });

    response.json({ accessToken, refreshToken });
});

/**
 * @openapi
 * /api/refresh:
 *   post:
 *     summary: Obtener un nuevo accessToken con el refreshToken
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               refreshToken: { type: string }
 *     responses:
 *       200:
 *         description: Nuevo accessToken y nuevo refreshToken
 *       401:
 *         description: Refresh token requerido
 *       403:
 *         description: Refresh token no válido o expirado
 */
app.post("/api/refresh", async (request, response) => {
    const { refreshToken } = request.body;
    if (!refreshToken)
        return response
            .status(401)
            .json({ message: "Refresh token requerido" });

    const db = client.db(DB_NAME);
    const guardado = await db
        .collection(TOKENS)
        .findOne({ token: refreshToken });

    if (!guardado)
        return response
            .status(403)
            .json({ message: "Refresh token no válido" });

    try {
        const payload = jwt.verify(refreshToken, REFRESH_SECRET);

        // Rotación: se borra el refresh viejo y se emite uno nuevo
        await db.collection(TOKENS).deleteOne({ token: refreshToken });

        const tokens = generarTokens({
            _id: payload.id,
            nombre: payload.nombre,
        });
        await db.collection(TOKENS).insertOne({
            token: tokens.refreshToken,
            userId: new ObjectId(payload.id),
            createdAt: new Date(),
        });

        response.json(tokens);
    } catch {
        await db.collection(TOKENS).deleteOne({ token: refreshToken });
        response.status(403).json({ message: "Refresh token expirado" });
    }
});

/**
 * @openapi
 * /api/logout:
 *   post:
 *     summary: Cerrar sesión (invalida el refreshToken)
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               refreshToken: { type: string }
 *     responses:
 *       200:
 *         description: Sesión cerrada
 */
app.post("/api/logout", async (request, response) => {
    const { refreshToken } = request.body;
    if (refreshToken)
        await client
            .db(DB_NAME)
            .collection(TOKENS)
            .deleteOne({ token: refreshToken });

    response.json({ message: "Sesión cerrada" });
});

// ---------- Endpoints de mascotas ----------

/**
 * @openapi
 * /api/mascotas:
 *   get:
 *     summary: Listar todas las mascotas
 *     tags: [Mascotas]
 *     responses:
 *       200:
 *         description: Lista de mascotas
 *   post:
 *     summary: Crear una mascota
 *     tags: [Mascotas]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Mascota'
 *     responses:
 *       200:
 *         description: Mascota creada
 *       401:
 *         description: Token expirado
 *       403:
 *         description: Token requerido o inválido
 */
app.get("/api/mascotas", async (request, response) => {
    const collection = client.db(DB_NAME).collection(MASCOTAS);
    const results = await collection.find({}).toArray();
    response.status(200).json(results);
});

app.post("/api/mascotas", verifyToken, async (request, response) => {
    if (!request.is("json"))
        return response
            .status(400)
            .json({ message: "Debes proporcionar datos JSON" });

    const collection = client.db(DB_NAME).collection(MASCOTAS);

    const { nombreDueño, nombre, edad, especie } = request.body;
    const results = await collection.insertOne({
        nombreDueño,
        nombre,
        edad,
        especie,
    });

    response.status(200).json(results);
});

/**
 * @openapi
 * /api/mascotas/{id}:
 *   get:
 *     summary: Obtener una mascota por id
 *     tags: [Mascotas]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200:
 *         description: Mascota encontrada
 *       400:
 *         description: Id no válido
 *   put:
 *     summary: Actualizar una mascota
 *     tags: [Mascotas]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/Mascota'
 *     responses:
 *       200:
 *         description: Mascota actualizada
 *       400:
 *         description: Id no válido
 *       401:
 *         description: Token expirado
 *       403:
 *         description: Token requerido o inválido
 *   delete:
 *     summary: Eliminar una mascota
 *     tags: [Mascotas]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema: { type: string }
 *     responses:
 *       200:
 *         description: Mascota eliminada
 *       400:
 *         description: Id no válido
 *       401:
 *         description: Token expirado
 *       403:
 *         description: Token requerido o inválido
 */
app.get("/api/mascotas/:id", validarId, async (request, response) => {
    const collection = client.db(DB_NAME).collection(MASCOTAS);
    const { id } = request.params;
    const results = await collection.find({ _id: new ObjectId(id) }).toArray();
    response.status(200).json(results);
});

app.put(
    "/api/mascotas/:id",
    verifyToken,
    validarId,
    async (request, response) => {
        if (!request.is("json"))
            return response
                .status(400)
                .json({ message: "Debes proporcionar datos JSON" });

        const collection = client.db(DB_NAME).collection(MASCOTAS);

        const { id } = request.params;
        const { nombreDueño, nombre, edad, especie } = request.body;
        const results = await collection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { nombreDueño, nombre, edad, especie } },
        );

        response.status(200).json(results);
    },
);

app.delete(
    "/api/mascotas/:id",
    verifyToken,
    validarId,
    async (request, response) => {
        const collection = client.db(DB_NAME).collection(MASCOTAS);
        const { id } = request.params;
        const results = await collection.deleteOne({ _id: new ObjectId(id) });
        response.status(200).json(results);
    },
);

app.listen(PORT, () =>
    console.log(`Servidor web iniciado en puerto: ${PORT} (docs en /api/docs)`),
);
