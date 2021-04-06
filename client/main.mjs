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

  let attestation1_response = await fetch('http://localhost:9000/get_attestation')
  let attestation1_json = await attestation1_response.json()

  const g_kt = new BLS.PublicKey()
  g_kt.deserialize(Buffer.from(attestation1_json.publicKey, 'hex'))


  
  const login = 'test@test.com'
  const password = 'test'

  let response1 = await fetch('http://localhost:9000/signup', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ login, password })
  }
  )
  let json1 = await response1.json()
  console.log(json1)

  let response2 = await fetch('http://localhost:9000/login', {
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

  const group_key = new BLS.PublicKey()
  group_key.deserialize(Buffer.from('8d70536f669c48e3ac9e08fd59d652d2ecd3af728b4320b0cf31f188b451e38218366ee0c4d976430072f8d298cf16a3', 'hex'))


  const vvec = [new BLS.PublicKey(), new BLS.PublicKey()]
  vvec[0].deserialize(Buffer.from('8d70536f669c48e3ac9e08fd59d652d2ecd3af728b4320b0cf31f188b451e38218366ee0c4d976430072f8d298cf16a3', 'hex'))
  vvec[1].deserialize(Buffer.from('80e26003e90d7373b47f1229a80fe199aebbb3afb928fccd027ca7b60f31a2b352a76a19cc27bc08576291c64f20e558', 'hex'))

  let responses = []
  const members = [1, 2].map(id => {
    const sk = new BLS.Id()
    sk.setInt(id)
    return sk
  })

  const message = hx_v.clone()
  message.add(HconditionInitialiser_v)

  for (let i = 1; i < 3; i++) {
    let response3 = await fetch('http://localhost:' + (8900 + i) + '/execute', {
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
    })

    let json2 = await response3.json()
    console.log(json2)
  
    const node_response = new BLS.Signature()
    node_response.deserialize(Buffer.from(json2.response, 'hex'))

    
    let expected_pubkey = new BLS.PublicKey()
    expected_pubkey.share(vvec, members[i-1])
    
    if (!expected_pubkey.verifyBlind(node_response, message)) {
      throw new Error('Failed from ' + i)
    } else {
      console.log('Public key match of node ' + i)
    }
  
    //const unblinded_response2 = v.blindSign(node_response, true)
    responses.push(node_response)
  }

  const p = new BLS.Signature()
  p.recover(responses, members)

  if (!group_key.verifyBlind(p, message)) {
    throw new Error('Group key verification of message failed')
  } else {
    console.log('Group key verification of message passed')
  }

  const unblinded_version = v.blindSign(p, true)
  const hx_point = new BLS.Signature()
  hx_point.setHashOf(Buffer.from(json.hx, 'hex'))
  const conditionInitialiser_point = new BLS.Signature()
  conditionInitialiser_point.setHashOf(conditionInitialiser)
  const original_message = hx_point.clone()
  original_message.add(conditionInitialiser_point)

  if (!group_key.verifyBlind(unblinded_version, original_message)) {
    throw new Error('Failed to verify unblinded / original message against group key')
  } else {
    console.log('Passed group key verification of original message')
  }

  const secret = crypto.createHash('sha256').update(json.x).update(original_message.serialize()).update(unblinded_version.serialize()).digest('hex')
  console.log('generated private key: ', secret)
}


init().catch((err) => {
  console.log(err)
})