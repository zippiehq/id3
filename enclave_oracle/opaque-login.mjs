import Router from 'express-promise-router'
import ExpressValidation from 'express-validation'
import Opaque from '@zippie/opaque-wasm/opaque_wasm.js'
import crypto from 'crypto'
import fs from 'fs'
import * as utils from './utils.mjs'
const { validate, Joi } = ExpressValidation
const { HandleRegistration, HandleLogin } = Opaque

const server_privatekey = 'c95843d9c67f7ba7f1231af10e1a88dc' // XXX: get this from env?? Use same as BLS??

const router = new Router()
const reg_state = []
const login_state = []
const login_sessionKeys = []

const validation = {
    body: Joi.object({
        username: Joi.string().email().required(),
        message: Joi.string().required()
    })
}

router.post('/register_user', validate(validation), async (req,res) => {

    const registration_tx = Buffer.from(req.body.message, 'base64')
    console.log(registration_tx)
    const user = req.body.username

    let user_hash = crypto.createHash('sha256').update(user).digest('hex')

    if (fs.existsSync('logins/' + user_hash)) {
        return res.status(500).send({error: 'User already registered'})
    }

    const serverRegistration = new HandleRegistration()
    let response = serverRegistration.start(Uint8Array.from(registration_tx), server_privatekey)

    reg_state[user] = serverRegistration

    res.send({message: Buffer.from(response).toString('base64')})

})

router.post('/finish_user_registration', validate(validation), async(req,res) => {

    const user = req.body.username
    const registration_tx = Buffer.from(req.body.message, 'base64')
    console.log(registration_tx)

    const serverRegistration = reg_state[user]

    const passwordFile = serverRegistration.finish(Uint8Array.from(registration_tx))

    let user_hash = crypto.createHash('sha256').update(user).digest('hex')
    fs.writeFileSync('./logins/' +user_hash, Buffer.from(passwordFile).toString('base64'), {flag: 'w+'})

    res.send({status: 'registered'})

})

router.post('/login_start', validate(validation), async(req,res) => {
    const user = req.body.username
    const login_tx = Buffer.from(req.body.message, 'base64')

    let user_hash = crypto.createHash('sha256').update(user).digest('hex')

    if (!fs.existsSync('logins/' + user_hash)) {
        return res.status(500).send({error: 'No such user'})
    }

    const password_file = fs.readFileSync('./logins/' + user_hash.toString('hex')).toString('utf8')
    const pw_buf = Buffer.from(password_file, 'base64')

    const serverLogin = new HandleLogin()
    const challenge = serverLogin.start(Uint8Array.from(pw_buf), Uint8Array.from(login_tx), server_privatekey)

    login_state[user] = serverLogin

    res.send({message: Buffer.from(challenge).toString('base64')})
})

router.post('/login_finish', validate(validation), async(req,res) => {
    const user = req.body.username
    const login_tx = Buffer.from(req.body.message, 'base64')

    const serverLogin = login_state[user]

    const sessionKey = serverLogin.finish(Uint8Array.from(login_tx))
    login_sessionKeys[user] = Buffer.from(sessionKey).toString('base64')

    res.send({status: 'ok'})
})

router.post('/get_login_attestation', async(req,res) => {
    const user = req.body.username
    const sessionKey = req.body.sessionKey
    const linkage_blinded = req.body.linkage_blinded


    const serverKey = login_sessionKeys[user]

    if(sessionKey === serverKey) {
        // all good, send attestation
        const attestation = utils.getLoginAttestation(user, linkage_blinded)
        res,send(attestation)
    } else {
        console.log('serverKey', serverKey)
        console.log('userKey', sessionKey)
        res.status(401).send({message: 'Unauthorised'})
    }
})

export default router