const express = require('express');
const app = express();
const jose = require('node-jose');
const fs = require('fs');
const ms = require('ms');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const health = require('@cloudnative/health-connect');
let healthcheck = new health.HealthChecker();

const shutdownPromise = () => new Promise(function (resolve, _reject) {
    setTimeout(function () {
      console.log('DONE!');
      resolve();
    }, 10);
  });
let shutdownCheck = new health.ShutdownCheck("shutdownCheck", shutdownPromise);

healthcheck.registerShutdownCheck(shutdownCheck);
app.use('/live', health.LivenessEndpoint(healthcheck));
app.use('/ready', health.ReadinessEndpoint(healthcheck));

process.on('unhandledRejection', error => {
    console.error('unhandledRejection', error);
    process.exit(1);
  });

(async () => {
    const ks = JSON.parse(fs.readFileSync('secrets/keys.json'));
    const config = JSON.parse(fs.readFileSync('config/config.json'));

    const ttl = Math.floor(ms(config.ttl) / 1000);

    const keyStore = await jose.JWK.asKeyStore(JSON.stringify(ks));
    const [enc_key] = keyStore.all({ use: 'enc' });

    app.use(cookieParser());

    app.get('/tokens', async function (req, res) {
        const now = Math.floor(Date.now() / 1000);
        const key = req.query.key;
        // creds if defined from the cookie
        const creds = req.cookies.tokenId !== undefined ? jwt.decode(req.cookies.tokenId, {complete: true}).payload : {
            sub: 'test',
            user_id: 'test',
            preferred_username: 'test' 
        };

        const payload = JSON.stringify({ 
            sub: creds.preferred_username,
            exp: now + ttl,
            iat: now,
            key
        });

        const enc_token = await jose.JWE.createEncrypt({ format: 'compact', zip: true }, enc_key)
        .update(payload)
        .final();

        res.set('Content-Type', 'text/plain');
        res.send(enc_token);
    });
    app.listen(3000);    
})();