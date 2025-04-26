#!/usr/bin/env node
const express = require('express');
const cors = require('cors');
const path = require('path');
const http = require('http');

const rootDir = __dirname;

const app = express();
const server = http.createServer(app);

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use('/fuzzer', express.static(path.join(rootDir, 'fuzzer')));
app.use(express.static(rootDir));

const port = 1337;
let testData = null;
let serverReady = false;

app.post('/current-config', (req, res) => {
    testData = req.body;
    res.type('json').send(JSON.stringify({ success: true }));
});

app.get('/current-config', (req, res) => {
    res.type('json').send(JSON.stringify(testData || {}));
});

app.get('/health', (req, res) => {
    res.type('json').send(JSON.stringify({ 
        status: serverReady ? 'ok' : 'initializing' 
    }));
});

app.get('/', (req, res) => {
    res.sendFile(path.join(rootDir, 'fuzzer', 'test-environment.html'));
});

server.listen(port, '0.0.0.0', () => {
    console.log(`Server running on port ${port}`);
    serverReady = true;
    console.log('Server fully initialized');
});
