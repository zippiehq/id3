import express from 'express'
import cors from 'cors'
import bodyParser from 'body-parser'
import Router from 'express-promise-router'
import fs from 'fs'
import winston from 'winston'
import crypto from 'crypto'
import expressWinston from 'express-winston'
import BLS from 'bls-wasm'

let publicKey, privateKey
let logger

const app = express()
const router = new Router()

app.use(cors())
app.use(bodyParser.json()) // support json encoded bodies

router.get('/get_attestation', async (req, res) => {
    res.send({publicKey: Buffer.from(publicKey.serialize()).toString('hex')})
})

router.post('/signup', async (req, res) => {
    if (!req.body.login) {
        return res.status(500).send({error: 'No login'})
    }
    if (!req.body.password) {
        return res.status(500).send({error: 'No password'})
    }
    let hash = crypto.createHash('sha256').update(req.body.login).digest()
    if (fs.existsSync('logins/' + hash.toString('hex'))) {
        return res.status(500).send({error: 'User already exists'})
    }
    let phashp = crypto.createHash('sha256').update(req.body.password).digest('hex')
    fs.writeFileSync('logins/' + hash.toString('hex'), phashp, {flag: 'w+'})
    return res.send({ok: true})
})

router.post('/login', async (req, res) => {
    if (!req.body.login) {
        return res.status(500).send({error: 'No login'})
    }
    if (!req.body.password) {
        return res.status(500).send({error: 'No password'})
    }
    if (!req.body.linkage_blinded) {
        return res.status(500).send({error: 'No blinded linkage'})
    }
    
    let hx = crypto.createHash('sha256').update(req.body.login).digest()
    if (!fs.existsSync('logins/' + hx.toString('hex'))) {
        return res.status(500).send({error: 'No such user'})
    }
    // XXX should PBDKF2
    let phashp = crypto.createHash('sha256').update(req.body.password).digest('hex')
    let phashf = fs.readFileSync('logins/' + hx.toString('hex')).toString('utf8')
    if (phashp !== phashf) {
        return res.status(500).send({error: 'Password mismatch'})
    }

    // we need to give:
    // x, H(x)*k_t, H(condition|initialiser)*r * k_t
    // XXX: g*k_t attestation (later)

    const hx_kt = privateKey.sign(hx)
    const linkage_blinded = new BLS.Signature()
    linkage_blinded.deserialize(Buffer.from(req.body.linkage_blinded, 'hex'))

    const linkage_blinded_kt = privateKey.blindSign(linkage_blinded, false)
    const ret = {
        x: req.body.login, 
        hx: hx.toString('hex'),
        hx_kt: Buffer.from(hx_kt.serialize()).toString('hex'),
        linkage_blinded_kt: Buffer.from(linkage_blinded_kt.serialize()).toString('hex')
    }
    res.send(ret)
})

async function init() {
    console.log('STARTING...')
    await BLS.init(BLS.BLS12_381)
    logger = winston.createLogger({
        level: 'info',
        defaultMeta: { service: 'enclave_oracle' },
        format: winston.format.combine(winston.format.timestamp(), winston.format.splat(), winston.format.json()),
        transports: [new winston.transports.Console()],
    })

    if (!fs.existsSync('private.json')) {
        privateKey = new BLS.SecretKey()
        privateKey.setByCSPRNG()

        publicKey = privateKey.getPublicKey()
        fs.writeFileSync('private.json', Buffer.from(JSON.stringify({privateKey: Buffer.from(privateKey.serialize()).toString('hex')}), 'utf8'), { flag: 'w+'})
    } else {
        privateKey = new BLS.SecretKey()
        privateKey.deserialize(Buffer.from(JSON.parse(fs.readFileSync('private.json')).privateKey, 'hex'))
        publicKey = privateKey.getPublicKey()
    }

    expressWinston.requestWhitelist.push('body')
    app.use(
        expressWinston.logger({
          winstonInstance: logger,
          transports: [new winston.transports.Console()],
          format: winston.format.combine(winston.format.timestamp(), winston.format.json(), winston.format.splat()),
          meta: true, // optional: control whether you want to log the meta data about the request (default to true)
          expressFormat: true, // Use the default Express/morgan request formatting. Enabling this will override any msg if true. Will only output colors with colorize set to true
          colorize: false, // Color the text and status code, using the Express/morgan color palette (text: gray, status: default green, 3XX cyan, 4XX yellow, 5XX red).
          ignoreRoute: function (req, res) {
            return req.url == '/health'
          }, // optional: allows to skip some log messages based on request and/or response
        }),
    )
    
    app.use(router)

    app.get('/health', function (req, res) {
      res.send(JSON.stringify({ notdead: true }))
    })
  
    const port = process.env.APP_LISTEN_PORT || 8099
  
    const server = app.listen(port, '0.0.0.0', function () {
      logger.info('ENCLAVE_ORACLE listening at http://%s:%s', server.address().address, server.address().port)
    })
}

init()

