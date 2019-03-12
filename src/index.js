const https = require('https');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const auth = require('./auth');

const app = express();
const http_port = 3000;
const https_port = 3443;
const ip = '127.0.1.2';

const KEY_DIR = process.env.KEY_DIR || 'keys';
const CRT = process.env.CRT_NAME || 'rs.acme.com.crt';
const CA_CRT = process.env.CA_CRT_NAME || 'ca.crt';
const HOSTNAME = process.env.HOSTNAME || 'rs.acme.com';

const options = {
    key: fs.readFileSync(`${__dirname}/../${KEY_DIR}/rs.acme.com.pem`),
    cert: fs.readFileSync(`${__dirname}/../${KEY_DIR}/${CRT}`),
    requestCert: true,
    rejectUnauthorized: false,
    ca: [ fs.readFileSync(`${__dirname}/../${KEY_DIR}/${CA_CRT}`) ]
};

// HTTPS Only
// Will only work if we listen on HTTP
const requireHTTPS = (req, res, next) => {
    if (!req.secure) {
        console.log(`redirect to https://${HOSTNAME}:${https_port}${req.url}`);
        return res.redirect(`https://${HOSTNAME}:${https_port}${req.url}`);
    }
    next();
}

const upload = (file, dest, filename, overwrite = true) => {
    const basepath = `${__dirname}/../resources/`;
    const dirpath = basepath + dest;
    if (!fs.existsSync(dirpath)){
        fs.mkdirSync(dirpath, {recursive:true});
    }
    if (fs.existsSync(dirpath + filename) && !overwrite) {
        throw "File already exits!"
    }
    fs.writeFileSync(dirpath + filename, file);
};

const download = (dest, filename) => {
    const basepath = `${__dirname}/../resources/`;
    const path = basepath + dest + filename;
    if (fs.existsSync(path)) {
        return fs.readFileSync(path, "utf8")
    }
    throw "File not found";
};

const listdir = (dest) => {
    const basepath = `${__dirname}/../resources/`;
    const path = basepath + dest
    if (fs.existsSync(path)) {
        return fs.readdirSync(path)
    }
    return [];
}

/**
 * Handle uploaded files
 */
const upload_handler = (res, options, onSuccess) => {
    try {
        let decoded_token = auth.verify_token(token, options);
        const hash = decoded_token.payload.filehash;
        const correct = auth.verify_file(hash, payload);
        if (correct) {
            onSuccess();
            res.send();
        }
        else {
            res.status(400)
                .send("Invalid file sha \n");
        }
    }

    catch(error) {
        console.log(error);
        res.status(400)
            .send("Invalid Token\n");
    }
}


app.use(requireHTTPS);
app.use(bodyParser.json());

app.get('/:userId/pubkey', (req, res) => {
    const id = req.params.userId;
    const token = auth.get_token(req);

    const options = {
        aud: HOSTNAME,
        issuer: "auth.acme.com"
    };
    try {
        auth.verify_token(token, options);
        const key = download('pubkeys/', id);
        res.setHeader('Content-Type', 'application/json');
        res.send({key:key});
    }
    catch(error) {
        res.status(400)
            .send(`${error}\n`);
    }
});

/**
 * Add a public key.
 * Only the owner is allowed to upload a public key.
 */
app.put('/:userId/pubkey', (req, res) => {
    const id = req.params.userId;

        const token = req.body.token;
        const payload = req.body.file;
        const options = {
            aud: HOSTNAME,
            issuer: "auth.acme.com",
            subject: id
        }

        upload_handler(req, res, () =>
            upload(payload,'pubkeys/', id)
        );
});

app.get('/:userId/files', (req, res) => {
    const id = req.params.userId;
    const token = auth.get_token(req);

    const options = {
        aud: HOSTNAME,
        issuer: "auth.acme.com",
        subject: id
    };
    try {
        auth.verify_token(token, options);
        const files = listdir(`files/${id}`);
        res.setHeader('Content-Type', 'application/json');
        res.send(files);
    }
    catch(error) {
        res.status(400)
            .send(`${error}\n`);
    }
});

app.get('/:userId/files/:filename', (req, res) => {
    const id = req.params.userId;
    const filename = req.params.filename;
    const token = auth.get_token(req);

    const options = {
        aud: HOSTNAME,
        issuer: "auth.acme.com",
        subject: id
    };
    try {
        auth.verify_token(token, options);
        const file = download(`files/${id}/`, filename);
        res.setHeader('Content-Type', 'application/json');
        res.send({file:file});
    }
    catch(error) {
        res.status(400)
            .send(`${error}\n`);
    }
});


/**
 * File upload.
 *  AC: All authed are allowed to upload files.
 *  Only the owner is allowed to overwrite.
 */
app.put('/:userId/files/:filename', (req, res) => {
    const id = req.params.userId;
    const filename = req.params.filename;

    const token = req.body.token;
    const payload = req.body.file;
    const options = {
        aud: HOSTNAME,
        issuer: "auth.acme.com",
    }

    const d_token = auth.decode_token(token);

    if (d_token.sub != id) {
        upload_handler(res, options, () =>
            upload(payload,`files/${id}/`, filename, false)
        );
    } else {
        upload_handler(res, options, () =>
            upload(payload,`files/${id}/`, filename)
        );
    }
});

/**
 * Retrieve the TOTP key
 * AC: Only the owner is allowed to retreieve it.
 */
app.get('/:userId/key', (req, res) => {
    const id = req.params.userId;
    const token = auth.get_token(req);

    const options = {
        aud: HOSTNAME,
        issuer: "auth.acme.com",
        subject: id
    };
    try {
        auth.verify_token(token, options);
        const key = download('keys/', id);
        res.setHeader('Content-Type', 'application/json');
        res.send({key:key});
    }
    catch(error) {
        res.status(400)
            .send(`${error}\n`);
    }

});

/**
 * Add a TOTP key.
 * AC: Only the owner is allowed to upload.
 */
app.put('/:userId/key', (req, res) => {
    const id = req.params.userId;

    const token = req.body.token;
    const payload = req.body.file;
    const options = {
        aud: HOSTNAME,
        issuer: "auth.acme.com",
        subject: id
    }
    upload_handler(req, res, () =>
        upload(payload,'keys/', id)
    );
});

app.listen(http_port, ip, () => console.log(`HTTP on ${ip}:${http_port}`));
https.createServer(options, app).listen(https_port, ip, () => console.log(`HTTPS on ${ip}:${https_port}`));
