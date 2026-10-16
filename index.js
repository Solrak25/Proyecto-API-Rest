import { MongoClient, ObjectId } from "mongodb";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import swaggerUi from "swagger-ui-express";
import swaggerDocument from "./openapi.json" with { type: "json" };

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

// ---------- MongoDB ----------

const client = new MongoClient(DB_URL);
const db = client.db(DB_NAME);

// ---------- Limitación de peticiones ----------

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Demasiadas peticiones, inténtalo más tarde",
    },
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 5,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        message: "Demasiados intentos de login, espera 15 minutos",
    },
});

app.use(globalLimiter);
app.use("/api/login", loginLimiter);

// ---------- Swagger ----------

app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.get("/", (request, response) => {
    response.redirect("/api-docs/");
});

// ---------- Autenticación JWT ----------

function generarTokens(user) {
    const payload = {
        id: user._id.toString(),
        nombre: user.nombre,
    };

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

    if (!token) {
        return response.status(403).json({
            message: "Token requerido",
        });
    }

    try {
        request.user = jwt.verify(token, SECRET_KEY);
        next();
    } catch (error) {
        const expirado = error.name === "TokenExpiredError";

        return response.status(expirado ? 401 : 403).json({
            message: expirado ? "Token expirado" : "Token inválido",
        });
    }
}

// ---------- Login ----------

app.post("/api/login", async (request, response) => {
    if (!request.is("json")) {
        return response.status(400).json({
            message: "Debes proporcionar datos JSON",
        });
    }

    const { nombre, contraseña } = request.body;

    if (!nombre || !contraseña) {
        return response.status(400).json({
            message: "Nombre y contraseña requeridos",
        });
    }

    const user = await db.collection(USERS).findOne({ nombre });

    if (!user) {
        return response.status(401).json({
            message: "Credenciales incorrectas",
        });
    }

    const correctPassword = await bcrypt.compare(contraseña, user.contraseña);

    if (!correctPassword) {
        return response.status(401).json({
            message: "Credenciales incorrectas",
        });
    }

    const { accessToken, refreshToken } = generarTokens(user);

    await db.collection(TOKENS).insertOne({
        token: refreshToken,
        userId: user._id,
        createdAt: new Date(),
    });

    response.json({ accessToken, refreshToken });
});

// ---------- Renovar tokens ----------

app.post("/api/refresh", async (request, response) => {
    const { refreshToken } = request.body ?? {};

    if (!refreshToken) {
        return response.status(401).json({
            message: "Refresh token requerido",
        });
    }

    const tokensCollection = db.collection(TOKENS);

    const guardado = await tokensCollection.findOne({
        token: refreshToken,
    });

    if (!guardado) {
        return response.status(403).json({
            message: "Refresh token no válido",
        });
    }

    try {
        const payload = jwt.verify(refreshToken, REFRESH_SECRET);

        await tokensCollection.deleteOne({ token: refreshToken });

        const tokens = generarTokens({
            _id: new ObjectId(payload.id),
            nombre: payload.nombre,
        });

        await tokensCollection.insertOne({
            token: tokens.refreshToken,
            userId: new ObjectId(payload.id),
            createdAt: new Date(),
        });

        response.json(tokens);
    } catch {
        await tokensCollection.deleteOne({ token: refreshToken });

        response.status(403).json({
            message: "Refresh token expirado",
        });
    }
});

// ---------- Logout ----------

app.post("/api/logout", async (request, response) => {
    const { refreshToken } = request.body ?? {};

    if (refreshToken) {
        await db.collection(TOKENS).deleteOne({
            token: refreshToken,
        });
    }

    response.json({ message: "Sesión cerrada" });
});

// ---------- Endpoints de mascotas ----------

// Listar mascotas
app.get("/api/mascotas", async (request, response) => {
    const results = await db.collection(MASCOTAS).find({}).toArray();

    response.status(200).json(results);
});

// Crear mascota (requiere JWT)
app.post("/api/mascotas", verifyToken, async (request, response) => {
    if (!request.is("json")) {
        return response.status(400).json({
            message: "Debes proporcionar datos JSON",
        });
    }

    const { nombreDueño, nombre, edad, especie } = request.body;

    const results = await db.collection(MASCOTAS).insertOne({
        nombreDueño,
        nombre,
        edad,
        especie,
    });

    response.status(201).json(results);
});

// Obtener mascota por ID
app.get("/api/mascotas/:id", async (request, response) => {
    const { id } = request.params;

    const results = await db
        .collection(MASCOTAS)
        .find({ _id: new ObjectId(id) })
        .toArray();

    response.status(200).json(results);
});

// Actualizar mascota (requiere JWT)
app.put("/api/mascotas/:id", verifyToken, async (request, response) => {
    if (!request.is("json")) {
        return response.status(400).json({
            message: "Debes proporcionar datos JSON",
        });
    }

    const { id } = request.params;
    const { nombreDueño, nombre, edad, especie } = request.body;

    const results = await db.collection(MASCOTAS).updateOne(
        { _id: new ObjectId(id) },
        {
            $set: {
                nombreDueño,
                nombre,
                edad,
                especie,
            },
        },
    );

    response.status(200).json(results);
});

// Eliminar mascota (requiere JWT)
app.delete("/api/mascotas/:id", verifyToken, async (request, response) => {
    const { id } = request.params;

    const results = await db
        .collection(MASCOTAS)
        .deleteOne({ _id: new ObjectId(id) });

    response.status(200).json(results);
});

// ---------- Crear índice de caducidad ----------

db.collection(TOKENS)
    .createIndex({ createdAt: 1 }, { expireAfterSeconds: REFRESH_SECONDS })
    .catch((error) => {
        console.error(
            "No se pudo crear el índice de refresh tokens:",
            error.message,
        );
    });

// ---------- Inicio del servidor ----------

app.listen(PORT, () => {
    console.log(`Servidor en puerto: ${PORT}`);
});

export default app;
