import Router from 'express-promise-router'
import { validate, Joi } from 'express-validation'
import crypto from 'crypto'
import fs from 'fs'
import * as utils from './utils.mjs'
import {
    generateAttestationOptions,
    verifyAttestationResponse,
    generateAssertionOptions,
    verifyAssertionResponse
  } from '@simplewebauthn/server'

const router = new Router()
const reg_state = []
const login_state = []

// Human-readable title for your website
const rpName = 'Zippie DID webauthn';
// A unique identifier for your website
const rpID = 'localhost';
// The URL at which attestations and assertions should occur
const origin = `https://localhost:8444`;

router.post('/attestation_options', async(req,res) => {
    const user = req.body.username

    const options = generateAttestationOptions({
        rpName,
        rpID,
        userID: user,
        userName: user,
        attestationType: 'indirect',
    })

    reg_state[user] = options.challenge

    res.send({options})
})

router.post('/verify_attestation', async(req,res) => {
    const user = req.body.username
    const response = req.body.challenge_response

    const expectedChallenge = reg_state[user]

    if(!expectedChallenge) {
        return res.status(400).send({message: 'no stored challenge, set attestation_options first'})
    }

    let verification

    verification = await verifyAttestationResponse({
        credential: JSON.parse(response),
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
    })


    const { verified, attestationInfo } = verification

    console.log(attestationInfo)

    // store attestationInfo to password file
    let user_hash = crypto.createHash('sha256').update(user).digest('hex')
    fs.writeFileSync('./logins/' +user_hash, Buffer.from(JSON.stringify(attestationInfo)).toString('base64'), {flag: 'w+'})


    return res.send({verified})
})

router.post('/assertion_options', async (req,res) => {
    const user = req.body.username
    let user_hash = crypto.createHash('sha256').update(user).digest('hex')

    const attestationInfo = JSON.parse(fs.readFileSync('./logins/' + user_hash.toString('hex')).toString('utf8'))

    if(!attestationInfo) {
        res.status(400).send({message: 'no stored authenticators for this user'})
    }

    const options = generateAssertionOptions({
        allowCredentials: {
            id: attestationInfo.credentialID,
            type: "public-key"
        },
        userVerification: 'preferred',
    })

    login_state[user] = options.challenge

    res.send({options})
})

router.post('/verify_assertion', async (req,res) => {
    const user = req.body.username
    const challenge_response = req.body.challenge_response
    let user_hash = crypto.createHash('sha256').update(user).digest('hex')

    const expectedChallenge = login_state[user]
    const attestationInfo = JSON.parse(fs.readFileSync('./logins/' + user_hash.toString('hex')).toString('utf8'))

    if(!expectedChallenge || !attestationInfo) {
        return res.status(400).send({message: 'no stored challenge, set assertion_options first'})
    }

    let verification;
    try {
      verification = await verifyAssertionResponse({
        credential: challenge_response,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        attestationInfo,
      });
    } catch (error) {
      console.error(error);
      return res.status(400).send({ error: error.message });
    }

    const { verified, assertionInfo } = verification;

    attestationInfo.counter = assertionInfo.newCounter
    fs.writeFileSync('./logins/' +user_hash, Buffer.from(JSON.stringify(attestationInfo)).toString('base64'), {flag: 'w+'})

    // XXX: Sign the thing

    return res.send({verified})
})

export default router