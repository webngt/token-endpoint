const express = require('express');
const app = express();
const jose = require('node-jose');
const fs = require('fs');
const ms = require('ms');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');


(async () => {
    const ks = fs.readFileSync('config/secret.json');
    const config = JSON.parse(fs.readFileSync('config/config.json'));

    const ttl = Math.floor(ms(config.ttl) / 1000);

    try {
        const keyStore = await jose.JWK.asKeyStore(ks.toString());
        const [key] = keyStore.all({ use: 'sig' });
        const opt = { compact: true, jwk: key, fields: { typ: 'jwt' } };

        app.use(cookieParser());
    
        app.get('/tokens', async function (req, res) {
            try {
                const now = Math.floor(Date.now() / 1000);
                
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
                    iss: config.checklistIss
                });
                const token = await jose.JWS.createSign(opt, key)
                .update(payload)
                .final();
                res.set('Content-Type', 'text/plain');
                res.send(token);
            } catch(err) {
                console.error(err);
                process.exit(1);
            }
        });
        app.listen(3000);    
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
})();