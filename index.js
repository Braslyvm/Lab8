// -------------------------
// index.js
// -------------------------
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;


app.use(express.json());
const users = JSON.parse(fs.readFileSync("./User.json", "utf8")).users;


//ver apikey
function checkApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== process.env.API_KEY) {
    return res.status(401).json({ status: "error", message: "API Key inválida o ausente" });
  }
  next();
}

//jwt
function jwtAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ status: "error", message: "Falta Authorization Bearer token" });
  }
  const token = auth.split(' ')[1];
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || "mi-secreto");
    req.user = payload; 
    next();
  } catch (err) {
    return res.status(401).json({ status: "error", message: "Token inválido o expirado" });
  }
}

//chequea el login del usuario validnado credenciales token y apikey
app.post('/auth/login', checkApiKey, (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ status: "error", message: "username y password requeridos" });
  }
  const user = users.find(u => u.username === username && u.password === password);
    if (!user) {
    return res.status(401).json({ status: "error", message: "Credenciales inválidas" });
  }

  // Generar JWT
  const payload = { id: user.id, username: user.username, role: user.role };
  const token = jwt.sign(payload, process.env.JWT_SECRET || "mi-secreto", { expiresIn: "1h" });

  res.json({ status: "success", token });
});




// -------------------------
// Iniciar servidor
// -------------------------
app.listen(PORT, () => console.log(`Servidor escuchando en http://localhost:${PORT}`));
