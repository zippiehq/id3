import express from 'express'
import cors from 'cors'
import bodyParser from 'body-parser'
import Router from 'express-promise-router'
import fs from 'fs'
import winston from 'winston'
import crypto from 'crypto'
import expressWinston from 'express-winston'

import { validate, ValidationError, Joi } from 'express-validation'
import opaque from './opaque-login.mjs'
import * as utils from './utils.mjs'

let logger

const app = express()
const router = new Router()

app.use(cors())
app.use(bodyParser.json()) // support json encoded bodies

const signupValidation = {
    body: Joi.object({
      login: Joi.string()
        .email()
        .required(),
      password: Joi.string()
        .regex(/[a-zA-Z0-9]{3,30}/)
        .required(),
    }),
  }

  const loginValidation = {
    body: Joi.object({
      login: Joi.string()
        .email()
        .required(),
      password: Joi.string()
        .regex(/[a-zA-Z0-9]{3,30}/)
        .required(),
      linkage_blinded: Joi.string()
        .required()
    }),
  }
  
router.use(function(err, req, res, next) {
    if (err instanceof ValidationError) {
      return res.status(err.statusCode).json(err)
    }
  
    return res.status(500).json(err)
  })

router.get('/get_attestation', async (req, res) => {
    res.send({publicKey: utils.getPublicKey()})
})

router.post('/signup', validate(signupValidation), async (req, res) => {
    let hash = crypto.createHash('sha256').update(req.body.login).digest()

    if (fs.existsSync('logins/' + hash.toString('hex'))) {
        return res.status(500).send({error: 'User already exists'})
    }

    let phashp = crypto.createHash('sha256').update(req.body.password).digest('hex')
    fs.writeFileSync('logins/' + hash.toString('hex'), phashp, {flag: 'w+'})

    return res.send({ok: true})
})

router.post('/login', validate(loginValidation), async (req, res) => {
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

    const ret = utils.getLoginAttestation(req.body.login, req.body.linkage_blinded)

    res.send(ret)
})

async function init() {
    console.log('STARTING...')

    logger = winston.createLogger({
        level: 'info',
        defaultMeta: { service: 'enclave_oracle' },
        format: winston.format.combine(winston.format.timestamp(), winston.format.splat(), winston.format.json()),
        transports: [new winston.transports.Console()],
    })

    await utils.initPrivateKey()

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
    app.use('/opaque', opaque)

    app.get('/health', function (req, res) {
      res.send(JSON.stringify({ notdead: true }))
    })
  
    const port = process.env.APP_LISTEN_PORT || 8099
  
    const server = app.listen(port, '0.0.0.0', function () {
      logger.info('ENCLAVE_ORACLE listening at http://%s:%s', server.address().address, server.address().port)
    })
}

init()

