const express = require('express');
const crypto = require('crypto');

const app = express();
const port = 3000;
const cipherAlgorithm = 'aes-256-cbc'


/* `app.use(express.json())` is setting up middleware in the Express application to parse incoming
requests with JSON payloads. This middleware function parses incoming request bodies and makes the
parsed data available on the `req.body` property of the request object. This allows the application
to easily work with JSON data sent in the request body. */
app.use(express.json())

function validateKey(key){
    return [16, 24, 32].includes(key.length);
}

function validateHex(key){
    const hexRegEx = /^[0-9a-fA-F]+$/;
    return hexRegEx.test(key);
}

function generateEncryptionKey(){
    return crypto.randomBytes(32)
}


app.post('/encrypt', (req, res) => {
    const outputEncoding = 'hex';
    const inputEncoding = 'utf8';
    const {data} = req.body;
    const encryptionKey = generateEncryptionKey()
    if(!validateKey(encryptionKey)){
        return res.status(400).json({
            code: 400,
            message: 'Invalid Key'
        })
    }
    const iv = crypto.randomBytes(16)
    const cipher = crypto.createCipheriv(cipherAlgorithm, encryptionKey, iv );
    let encryptedData = cipher.update(data, inputEncoding, outputEncoding);
    encryptedData += cipher.final(outputEncoding);
    res.json({
        data: encryptedData,
        key: encryptionKey.toString(outputEncoding),
        iv: iv.toString(outputEncoding)
    })
});

app.post('/decrypt', (req, res) => {
    const outputEncoding = 'utf8';
    const inputEncoding = 'hex';
    const { data, key, iv } = req.body;
    if(!validateHex(key)){
        return res.status(400).json({
            code: 400,
            message: 'Invalid Key'
        })
    }
    const decipher = crypto.createDecipheriv(cipherAlgorithm, Buffer.from(key, inputEncoding), Buffer.from(iv, inputEncoding));
    let decryptedData = decipher.update(data, inputEncoding, outputEncoding);
    decryptedData += decipher.final(outputEncoding);
    res.json({
        data: decryptedData
    })
})


/* The `app.listen(port, () => { console.log(`Server rendered at http://localhost:`) })` code
snippet is starting the Express application by making it listen on a specific port for incoming HTTP
requests. */
app.listen(port, () => {
    console.log(`Server rendered at http://localhost:${port}`)
})