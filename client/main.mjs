import fetch from 'isomorphic-fetch'
import crypto from 'crypto'
import fs from 'fs'
import BLS from '@zippie/bls-wasm'

let login = crypto.randomBytes(32).toString('hex')
let password = crypto.randomBytes(32).toString('hex')

async function init() {
  await BLS.init(BLS.BLS12_381)

  // generate random r for blinding
  const r = new BLS.SecretKey()
  r.setByCSPRNG()

  // generate random v for blinding and generate public key
  const v = new BLS.SecretKey()
  v.setByCSPRNG()
  const g_v = v.getPublicKey()
  const condition = 'x'
  const initialiser = 'z'
  const conditionInitialiserGv = Buffer.from(JSON.stringify({ condition, initialiser, gv: Buffer.from(g_v.serialize()).toString('hex') }), 'utf8')
  const conditionInitialiser = Buffer.from(JSON.stringify({ condition, initialiser }), 'utf8')

  // blind H(condition|initialiser) with r
  const HconditionInitialiserGvR = r.sign(conditionInitialiserGv)

  let attestation1_response = await fetch('http://localhost:8099/get_attestation')
  let attestation1_json = await attestation1_response.json()

  const g_kt = new BLS.PublicKey()
  g_kt.deserialize(Buffer.from(attestation1_json.publicKey, 'hex'))


  
  const login = 'test@test.com'
  const password = 'test'

  let response1 = await fetch('http://localhost:8099/signup', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ login, password })
  }
  )
  let json1 = await response1.json()
  console.log(json1)

  let response2 = await fetch('http://localhost:8099/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ login, password, linkage_blinded: Buffer.from(HconditionInitialiserGvR.serialize()).toString('hex') })
  }
  )
  let json = await response2.json()
  console.log(json)

  const HconditionInitialiserGvR_kt = new BLS.Signature()
  HconditionInitialiserGvR_kt.deserialize(Buffer.from(json.linkage_blinded_kt, 'hex'))

  // unblind H(condition|initialiser|g*v)*r*k_t with r
  const HconditionInitialiserGv_kt = r.blindSign(HconditionInitialiserGvR_kt, true)

  if (!g_kt.verify(HconditionInitialiserGv_kt, conditionInitialiserGv)) {
    throw new Error('Was unable to succesfully unblind HconditionInitialiserGv_kt')
  } else {
    console.log('Succesfully unblinded HconditionInitialiserGv_kt')
  }

  const HconditionInitialiserGv_v_kt = v.blindSign(HconditionInitialiserGv_kt, false)
  const HconditionInitialiser_v = v.sign(conditionInitialiser)
  const HconditionInitialiserGv_v = v.sign(conditionInitialiserGv)

  const hx_kt = new BLS.Signature()
  hx_kt.deserialize(Buffer.from(json.hx_kt, 'hex'))

  const hx_v_kt = v.blindSign(hx_kt, false)
  const hx_v = v.sign(Buffer.from(json.hx, 'hex'))

  let response3 = await fetch('http://localhost:8098/execute', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ 
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
  }
  )
  let json2 = await response3.json()
  console.log(json2)

  const node_response = new BLS.Signature()
  node_response.deserialize(Buffer.from(json2.response, 'hex'))

  const unblinded_response2 = v.blindSign(node_response, true).serialize()

  const secret = crypto.createHash('sha256').update(json.x).update(unblinded_response2).digest('hex')
  console.log(secret)

  // XXX verify secret is indeed a sig over (H(x)+H(condition|initialiser) by k_i

}


init().catch((err) => {
  console.log(err)
})