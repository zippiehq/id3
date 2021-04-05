import crypto from 'crypto'
import fs from 'fs'
import BLS from 'bls-wasm'

let login = crypto.randomBytes(32).toString('hex')
let password = crypto.randomBytes(32).toString('hex')

async function testStuff() {
  await BLS.init(BLS.BLS12_381)

  const k_1 = new BLS.SecretKey() 
  k_1.deserialize(Buffer.from('60d543481aab5edb0336479f86fd53d0193c72413fd363268307d8d1a0c42794', 'hex'))
  console.log('ok')
  const k_2 = new BLS.SecretKey()
  k_2.deserialize(Buffer.from('5e4863def9db32b1fbefb32291f23b63a089486d98952f0f5c680fb200c52776', 'hex'))
  //k_i.setByCSPRNG()

  const g_k_1 = k_1.getPublicKey()
  const g_k_2 = k_2.getPublicKey()
 
  const group_key = new BLS.PublicKey()
  group_key.deserialize(Buffer.from('8d70536f669c48e3ac9e08fd59d652d2ecd3af728b4320b0cf31f188b451e38218366ee0c4d976430072f8d298cf16a3', 'hex'))
  const condition = 'x'
  const initialiser = 'z'
  const conditionInitialiser = Buffer.from(JSON.stringify({ condition, initialiser }), 'utf8')

  console.log(Buffer.from(k_1.serialize()).toString('hex'))
  console.log(Buffer.from(k_2.serialize()).toString('hex'))
  const members = [1, 2].map(id => {
    const sk = new BLS.Id()
    sk.setInt(id)
    return sk
  })
  console.log('g_k:')
  console.log(g_k_1.serializeToHexStr())
  console.log(g_k_2.serializeToHexStr())
  const g_k_1_x = new BLS.PublicKey()
  const g_k_2_x = new BLS.PublicKey()
  
  const vvec = [new BLS.PublicKey(), new BLS.PublicKey()]
  vvec[0].deserialize(Buffer.from('8d70536f669c48e3ac9e08fd59d652d2ecd3af728b4320b0cf31f188b451e38218366ee0c4d976430072f8d298cf16a3', 'hex'))
  vvec[1].deserialize(Buffer.from('80e26003e90d7373b47f1229a80fe199aebbb3afb928fccd027ca7b60f31a2b352a76a19cc27bc08576291c64f20e558', 'hex'))

  console.log('g_k_1_x: ')
  const conditionInitialiser_k1 = k_1.sign(conditionInitialiser)
  const conditionInitialiser_k2 = k_2.sign(conditionInitialiser)
  
  g_k_1_x.share(vvec, members[0])
  g_k_2_x.share(vvec, members[1])

  console.log(g_k_1_x.serializeToHexStr())
  console.log(g_k_2_x.serializeToHexStr())
  
  const p = new BLS.Signature()
  p.recover([conditionInitialiser_k1, conditionInitialiser_k2], members)
  console.log(group_key.verify(p, conditionInitialiser))
  //  conditionInitialiser_comb.add(conditionInitialiser_k2)
}



testStuff().catch((err) => {
  console.log(err)
})