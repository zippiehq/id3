import fetch from 'isomorphic-fetch'
import crypto from 'crypto'
import fs from 'fs'
import BLS from 'bls-wasm'

let login = crypto.randomBytes(32).toString('hex')
let password = crypto.randomBytes(32).toString('hex')

async function testStuff() {
  await BLS.init(BLS.BLS12_381)

  // generate random r
  const r = new BLS.SecretKey()
  r.setByCSPRNG()

  // generate random v
  const v = new BLS.SecretKey()
  v.setByCSPRNG()
  const g_v = v.getPublicKey()

  const conditionInitialiserGv = Buffer.from(JSON.stringify({ condition: 'x', initialiser: 'y', gv: g_v.serialize() }), 'utf8')
  const conditionInitialiser = Buffer.from(JSON.stringify({ condition: 'x', initialiser: 'y', gv: g_v.serialize() }), 'utf8')

  // blind H(condition|initialiser) with r
  const HconditionInitialiserGvR = r.sign(conditionInitialiserGvR)

  const x = Buffer.from('z', 'utf8')
  const kt = new BLS.SecretKey()
  kt.setByCSPRNG()

  const g_kt = kt.getPublicKey()

  // H(x) * k_t
  const hx_kt = kt.sign(x)

  // H(condition|initialiser) * r * k_t
  const HconditionInitialiserR_kt = kt.blindSign(HconditionInitialiserR, false)

  // unblind H(condition|initialiser)*r*k_t with r
  const HconditionInitialiser_kt = r.blindSign(HconditionInitialiserR_kt, true)


  // blind H(condition|initialiser)*k_t with v
  // blind H(x)*k_t with v
  const HconditionInitialiser_v_kt = v.blindSign(HconditionInitialiser_kt, false)

  const hx_v_kt = v.blindSign(hx_kt, false)

  const hx_v = v.sign(x)

  const HconditionInitialiser_v = v.sign(conditionInitialiser)


  // Verify H(condition|initialiser) * v is a sig over H(condition|initialiser) by g*v
  console.log(g_v.verify(HconditionInitialiser_v, conditionInitialiser))

  // CONDITION:
  // XXX check attestation of g_k_t

  // check that H(x)*v*k_t is sig of H(x)*v by g*k_t
  console.log(g_kt.verifyBlind(hx_v_kt, hx_v))
  // check this H(condition|initialiser)*v*k_t is sig over H(condition|initialiser)*v by g*k_t 
  console.log(g_kt.verifyBlind(HconditionInitialiser_v_kt, HconditionInitialiser_v))
  // CONDITION END

  const k_i = new BLS.SecretKey()
  k_i.deserialize(Buffer.from('30f80a85c9f43434b9a3947fe4113488be10ae2070c17f147b84e0d149d61327', 'hex'))
  //k_i.setByCSPRNG()
  console.log(Buffer.from(k_i.serialize()).toString('hex'))

  // generate H(x)*v*k_i + H(condition|initialiser)*v_k_i
  const response1 = k_i.blindSign(hx_v, false)
  const response2 = k_i.blindSign(HconditionInitialiser_v)
  response2.add(response1)

  // we can verify (H(x)+H(condition|initialiser))*v*k_i is a sig over (H(x)+H(condition|initialiser))*v by g*k_i
  const unblinded_response2 = v.blindSign(response2, true).serialize()

  const secret = crypto.createHash('sha256').update(x).update(unblinded_response2).digest('hex')
  console.log(secret)
  /* 
  const kidp = new BLS.SecretKey()
  kidp.setByCSPRNG();

  const hx = new BLS.Signature()
  hx.setHashOf(Buffer.from('foo', 'utf8'))
  const hgv = new BLS.Signature()
  hgv.setHashOf(Buffer.from('foo1', 'utf8'))
  
  const combined = new BLS.Signature()
  combined.add(hx)
  combined.add(hgv)

  const sig = kidp.blindSign(combined, false)

  
  const removed = new BLS.Signature()
  removed.add(sig)
  const hgv_sign = kidp.blindSign(hgv)

  removed.sub(hgv_sign)

  const pubNode = kidp.getPublicKey();

  console.log(pubNode.verifyBlind(sig, combined))
  console.log(pubNode.verifyBlind(removed, hx))
  */
}


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

  const login = 'test'
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

  /*    
  
      let id = Buffer.from(json.id, 'hex')
      let pkhash = crypto.createHash('sha256').update(pk).digest()
      let id_and_pk = pedersenHash.hash(Buffer.concat([id, pkhash]))
      let jws2 = json.id_and_pk.split('.')
      let verification2 = await flattenedVerify({protected: jws2[0], signature: jws2[2], payload: jws2[1]}, publicKey)
      console.log(verification2)
      console.log(Buffer.compare(id_and_pk, verification2.payload))
  
      
      const blinder = crypto.randomBytes(32)
      console.log(blinder)
      const id_buf = Buffer.from(json.id, 'hex')
      const idup1 = bigIntBuffer.toBigIntLE(id_buf.slice(0,16))
      const idup2 = bigIntBuffer.toBigIntLE(id_buf.slice(16, 32))
  
      const blinder1 = bigIntBuffer.toBigIntLE(blinder.slice(0,16))
      const blinder2 = bigIntBuffer.toBigIntLE(blinder.slice(16,32))
  
      const pk1 = bigIntBuffer.toBigIntLE(pkhash.slice(0,16))
      const pk2 = bigIntBuffer.toBigIntLE(pkhash.slice(16,32))
      console.log(pk1, pk2)
  
      console.log('generating proof..')
      let inputs = {
        both: [idup1, idup2], 
        rs: [blinder1, blinder2], 
        bs: [pk1, pk2]
      }
      console.log(inputs)
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, 
          "../zkp/twos_pedersen.wasm", "../zkp/twos_pedersen_final.zkey")
      console.log('done')
      console.log(publicSignals)
      console.log(proof)
  
      let id_and_pkH = babyJub.unpackPoint(id_and_pk)
      console.log(id_and_pkH)
      console.log(id_and_pkH[0].toString() === publicSignals[2])
      console.log(id_and_pkH[1].toString() === publicSignals[3])
      let id_and_blinder = pedersenHash.hash(Buffer.concat([id, blinder]))
      console.log('blinded ID: ' + id_and_blinder.toString('hex'))
      let id_and_blinderH = babyJub.unpackPoint(id_and_blinder)
      console.log(id_and_blinderH[0].toString() === publicSignals[0])
      console.log(id_and_blinderH[1].toString() === publicSignals[1])
      console.log('verifying:')
      const vKey = JSON.parse(fs.readFileSync("../zkp/twos_pedersen_verification.json"));
      console.log(await snarkjs.groth16.verify(vKey, publicSignals, proof))
  */
  /*
  let output_ = JSON.parse(output)
  const idup_and_pk_from_witness1 = new BN(output_[1][0], 10)
  const idup_and_pk_from_witness2 = new BN(output_[1][1], 10) 
  const idup_and_pk_from_witness = Buffer.concat([idup_and_pk_from_witness1.toBuffer('be', 16), idup_and_pk_from_witness2.toBuffer('be', 16)])
  console.log(id_and_pk.toString('hex'))
  console.log(idup_and_pk_from_witness.toString('hex'))
  console.log(Buffer.compare(idup_and_pk_from_witness, id_and_pk))
  const idup_and_blinder_from_witness1 = new BN(output_[0][0], 10)
  const idup_and_blinder_from_witness2 = new BN(output_[0][1], 10) 
  const idup_and_blinder_from_witness = Buffer.concat([idup_and_blinder_from_witness1.toBuffer('be', 16), idup_and_blinder_from_witness2.toBuffer('be', 16)])
  const idup_and_blinder = crypto.createHash('sha256').update(id).update(Buffer.from(blinder, 'hex')).digest()
  console.log(idup_and_blinder.toString('hex'))
  console.log(idup_and_blinder_from_witness.toString('hex'))
  console.log(Buffer.compare(idup_and_blinder_from_witness, idup_and_blinder))

  console.log('generating proof')
  const proof = zokratesProvider.generateProof(artifacts.program, witness, keypair.pk);
  console.log(proof)
  console.log(zokratesProvider.verify(keypair.vk, proof))

  const blinder_from_proof = Buffer.concat([
      new BN(proof.inputs[0].slice(2), 16).toBuffer('be', 16), 
      new BN(proof.inputs[1].slice(2), 16).toBuffer('be', 16), 
  ])
  console.log(Buffer.compare(blinder_from_proof, Buffer.from(blinder, 'hex')))

  const pk_from_proof = Buffer.concat([
    new BN(proof.inputs[2].slice(2), 16).toBuffer('be', 16), 
    new BN(proof.inputs[3].slice(2), 16).toBuffer('be', 16), 
  ])
  console.log(Buffer.compare(pk_from_proof, pkhash))

  const idup_and_blinder_from_proof = Buffer.concat([
    new BN(proof.inputs[4].slice(2), 16).toBuffer('be', 16), 
    new BN(proof.inputs[5].slice(2), 16).toBuffer('be', 16), 
  ])

  console.log(Buffer.compare(idup_and_blinder_from_proof, idup_and_blinder))

  const idup_and_pk_from_proof = Buffer.concat([
    new BN(proof.inputs[6].slice(2), 16).toBuffer('be', 16), 
    new BN(proof.inputs[7].slice(2), 16).toBuffer('be', 16), 
  ])

  console.log(Buffer.compare(idup_and_pk_from_proof, id_and_pk))

  console.log(Buffer.compare(verification2.payload, idup_and_pk_from_proof))
  */

}


init().catch((err) => {
  console.log(err)
})