// intentionally vulnerable app.js (for learning purposes only)

const express = require("express");
const fs = require("fs");
const { exec } = require("child_process");
const sqlite3 = require("sqlite3").verbose();

const app = express();
app.use(express.urlencoded({ extended: true }));

const db = new sqlite3.Database(":memory:");

// init DB
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER, username TEXT, password TEXT)");
    db.run("INSERT INTO users VALUES (1, 'admin', 'admin123')");
});

// login route
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    db.get(query, (err, row) => {
        if (row) {
            res.send("Welcome " + username);
        } else {
            res.send("Login failed");
        }
    });
});

// file read route
app.get("/file", (req, res) => {
    const file = req.query.name;

    fs.readFile("./files/" + file, "utf8", (err, data) => {
        if (err) return res.send("Error");
        res.send(data);
    });
});

// command execution
app.get("/ping", (req, res) => {
    const host = req.query.host;

    exec("ping -c 1 " + host, (err, stdout) => {
        res.send(stdout);
    });
});

// template rendering (XSS)
app.get("/hello", (req, res) => {
    const name = req.query.name;
    res.send(`<h1>Hello ${name}</h1>`);
});

// insecure deserialization simulation
app.post("/deserialize", (req, res) => {
    const obj = JSON.parse(req.body.data);
    eval(obj.code); // VERY BAD
    res.send("done");
});

app.listen(3000, () => console.log("Running on port 3000"));