import express from 'express'
import cors from 'cors'
import bodyParser from 'body-parser'
import Router from 'express-promise-router'
import fs from 'fs'
import path from 'path'
import winston from 'winston'
import crypto from 'crypto'
import expressWinston from 'express-winston'
import BLS from '@zippie/bls-wasm'
import toml from 'toml'

let logger
let k_i
let k_i_index 
let k_commits

const app = express()
const router = new Router()

app.use(cors())
app.use(bodyParser.json()) // support json encoded bodies
/* body: JSON.stringify({ 
      precredential: { 
        hx_v_kt: Buffer.from(hx_v_kt.serialize()).toString('hex'),
        HconditionInitialiserGv_v_kt: Buffer.from(HconditionInitialiserGv_v_kt.serialize()).toString('hex'), 
        g_kt: Buffer.from(g_kt.serialize()).toString('hex'),
        g_v: Buffer.from(g_v.serialize()).toString('hex'),
      },
      condition,
      initialiser,
      // XXX missing attestation 
      hx_v: Buffer.from(hx_v.serialize()).toString('hex'),
      HconditionInitialiser_v: Buffer.from(HconditionInitialiser_v.serialize()).toString('hex'),
      HconditionInitialiserGv_v: Buffer.from(HconditionInitialiserGv_v.serialize()).toString('hex'),
    })
    */


router.post('/execute', async (req, res) => {
  if (!req.body.precredential) {
    return res.status(500).send({error: 'No precredential'})
  }
  if (!req.body.precredential.hx_v_kt) {
    return res.status(500).send({error: 'No precredential.hx_v_kt'})
  }
  if (!req.body.precredential.HconditionInitialiserGv_v_kt) {
    return res.status(500).send({error: 'No precredential.HconditionInitialiserGv_v_kt'})
  }
  if (!req.body.precredential.g_kt) {
    return res.status(500).send({error: 'No precredential.g_kt'})
  }
  if (!req.body.precredential.g_v) {
    return res.status(500).send({error: 'No precredential.g_v'})
  }
  if (!req.body.condition) {
    return res.status(500).send({error: 'No condition'})
  }
  if (!req.body.initialiser) {
    return res.status(500).send({error: 'No initialiser'})
  }
  if (!req.body.hx_v) {
    return res.status(500).send({error: 'No hx_v'})
  }
  if (!req.body.HconditionInitialiser_v) {
    return res.status(500).send({error: 'No HconditionInitialiser_v'})    
  }
  if (!req.body.HconditionInitialiserGv_v) {
    return res.status(500).send({error: 'No HconditionInitialiser_v'})    
  }

  const conditionInitialiser = Buffer.from(JSON.stringify({ condition: req.body.condition, initialiser: req.body.initialiser }), 'utf8')
  const conditionInitialiserGv = Buffer.from(JSON.stringify({ condition: req.body.condition, initialiser: req.body.initialiser, gv: req.body.precredential.g_v }), 'utf8')

  const g_v = new BLS.PublicKey()
  g_v.deserialize(Buffer.from(req.body.precredential.g_v, 'hex'))

  const HconditionInitialiser_v = new BLS.Signature()
  HconditionInitialiser_v.deserialize(Buffer.from(req.body.HconditionInitialiser_v, 'hex'))

  if (!g_v.verify(HconditionInitialiser_v, conditionInitialiser)) {
    return res.status(500).send({error: 'H(condition|initialiser)*v not a sig by g*v over H(condition|initialiser)'})
  }

  const HconditionInitialiserGv_v = new BLS.Signature()
  HconditionInitialiserGv_v.deserialize(Buffer.from(req.body.HconditionInitialiserGv_v, 'hex'))

  if (!g_v.verify(HconditionInitialiserGv_v, conditionInitialiserGv)) {
    return res.status(500).send({error: 'H(condition|initialiser|g*v)*v not a sig by v over H(condition|initialiser|g*v)'})    
  }

  // XXX check attestation

  const g_kt = new BLS.PublicKey()
  g_kt.deserialize(Buffer.from(req.body.precredential.g_kt, 'hex'))

  const hx_v_kt = new BLS.Signature()
  hx_v_kt.deserialize(Buffer.from(req.body.precredential.hx_v_kt, 'hex'))
 
  const hx_v = new BLS.Signature()
  hx_v.deserialize(Buffer.from(req.body.hx_v, 'hex'))

  if (!g_kt.verifyBlind(hx_v_kt, hx_v)) {
    return res.status(500).send({error: 'H(x)*v*k_t is not a sig of H(x)*v by k_t'})
  }

  const HconditionInitialiserGv_v_kt = new BLS.Signature()
  HconditionInitialiserGv_v_kt.deserialize(Buffer.from(req.body.precredential.HconditionInitialiserGv_v_kt, 'hex'))

  if (!g_kt.verifyBlind(HconditionInitialiserGv_v_kt, HconditionInitialiserGv_v)) {
    return res.status(500).send({error: 'H(condition|initialiser|g*v)*v*k_t is not a sig of H(condition|initialiser|g*v)*v by k_t'})
  }
  
  // generate H(x)*v*k_i + H(condition|initialiser)*v_k_i
  const response1 = k_i.blindSign(hx_v, false)
  const response2 = k_i.blindSign(HconditionInitialiser_v, false)
  response2.add(response1)

  return res.send({response: Buffer.from(response2.serialize()).toString('hex')})

})

async function init() {
    console.log('STARTING...')
    await BLS.init(BLS.BLS12_381)

    let dist_key = toml.parse(fs.readFileSync(path.join(process.env.HOME, '.drand/groups/dist_key.private')))

    k_i_index = dist_key.Index
    k_commits = dist_key.Commits
    k_i = new BLS.SecretKey()
    k_i.deserialize(Buffer.from(dist_key.Share, 'hex'))

    logger = winston.createLogger({
        level: 'info',
        defaultMeta: { service: 'recovery_node' },
        format: winston.format.combine(winston.format.timestamp(), winston.format.splat(), winston.format.json()),
        transports: [new winston.transports.Console()],
    })


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
  
    const port = process.env.APP_LISTEN_PORT || 8098
  
    const server = app.listen(port, '0.0.0.0', function () {
      logger.info('RECOVERY_NODE listening at http://%s:%s', server.address().address, server.address().port)
    })
}

init()

