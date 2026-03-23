const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/run1', (req, res) => {
    const cmd = req.query.cmd;

    // Command Injection
    exec("ls " + cmd, (err, stdout) => {
        res.send(stdout);
    });
});

app.get('/user1', (req, res) => {
    const user = req.query.user;

    // SQL Injection
    const query = "SELECT * FROM users WHERE name = '" + user + "'";
    res.send(query);
});

app.listen(3000);
