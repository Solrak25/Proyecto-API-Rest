import { MongoClient, ObjectId } from "mongodb";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";

const SECRET_KEY = process.env.JWT_SECRET ?? "secreto";

const app = express();
app.use(express.json());
app.use(cors());
app.use(globalLimiter);
app.use("/api/login", loginLimiter);

const PORT = process.env.PORT ?? 5000;
const DB_URL = process.env.MONGODB_URI ?? "mongodb://localhost:27017";
const DB_NAME = process.env.DB_NAME ?? "api";
const USERS = "usuariosMascota";
const MASCOTAS = "mascotas";

const client = new MongoClient(DB_URL);

// Autenficacion en JWT

function verifyToken(request, response, next) {
    const token = request.headers.authorization?.split(" ")[1];

    if (!token)
        return response.status(403).json({ message: "Token requerido" });

    try {
        request.user = jwt.verify(token, SECRET_KEY);
        next();
    } catch (err) {
        return response.status(403).json({ message: "Token inválido" });
    }
}

app.post("/api/login", async (request, response) => {
    if (!request.is("json"))
        return response.json({ message: "Debes proporcionar datos JSON" });

    const { nombre, contraseña } = request.body;

    const database = client.db(DB_NAME);
    const collection = database.collection(USERS);

    const Users = await collection.find({}).toArray();

    const user = Users.find((u) => u.nombre == nombre);

    if (user == undefined) {
        return response.json({ message: "Usuario no encontrado" });
    }

    const correctPassword = await bcrypt.compare(contraseña, user.contraseña);

    if (!correctPassword) {
        return response.json({ message: "Contraseña incorrecta" });
    }

    const token = jwt.sign({ id: user.id, nombre: user.nombre }, SECRET_KEY, {
        expiresIn: "5m",
    });

    response.json({ token });
});

// Rate limit

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
    message: { message: "Demasiados intentos de login, espera 15 minutos" },
});

// EndPoints

app.get("/api/mascotas", async (request, response) => {
    const database = client.db(DB_NAME);
    const collection = database.collection(MASCOTAS);

    const results = await collection.find({}).toArray();

    response.status(200).json(results);
});

app.post("/api/mascotas", verifyToken, async (request, response) => {
    if (!request.is("json"))
        return response.json({ message: "Debes proporcionar datos JSON" });

    const database = client.db(DB_NAME);
    const collection = database.collection(MASCOTAS);

    const { nombreDueño, nombre, edad, especie } = request.body;
    const results = await collection.insertOne({
        nombreDueño,
        nombre,
        edad,
        especie,
    });

    return response.status(200).json(results);
});

app.get("/api/mascotas/:id", async (request, response) => {
    const database = client.db(DB_NAME);
    const collection = database.collection(MASCOTAS);

    const { id } = request.params;
    const results = await collection.find({ _id: new ObjectId(id) }).toArray();

    response.status(200).json(results);
});

app.put("/api/mascotas/:id", verifyToken, async (request, response) => {
    if (!request.is("json"))
        return response.json({ message: "Debes proporcionar datos JSON" });

    const database = client.db(DB_NAME);
    const collection = database.collection(MASCOTAS);

    const { id } = request.params;
    const { nombreDueño, nombre, edad, especie } = request.body;
    const results = await collection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { nombreDueño, nombre, edad, especie } },
    );

    response.status(200).json(results);
});

app.delete("/api/mascotas/:id", verifyToken, async (request, response) => {
    const database = client.db(DB_NAME);
    const collection = database.collection(MASCOTAS);

    const { id } = request.params;
    const results = await collection.deleteOne({ _id: new ObjectId(id) });
    response.status(200).json(results);
});

app.listen(PORT, () => console.log(`Servidor web iniciado en puerto: ${PORT}`));
