import BLS from '@zippie/bls-wasm'
import fs from 'fs'
import crypto from 'crypto'

let privateKey
let publicKey

export function getLoginAttestation (login, linkage_blinded) {

   // we need to give:
    // x, H(x)*k_t, H(condition|initialiser)*r * k_t
    // XXX: g*k_t attestation (later)

    let hx = crypto.createHash('sha256').update(login).digest()

    const hx_kt = privateKey.sign(hx)
    const bls_sig = new BLS.Signature()
    bls_sig.deserialize(Buffer.from(linkage_blinded, 'hex'))

    const linkage_blinded_kt = privateKey.blindSign(bls_sig, false)
    const ret = {
        x: login, 
        hx: hx.toString('hex'),
        hx_kt: Buffer.from(hx_kt.serialize()).toString('hex'),
        linkage_blinded_kt: Buffer.from(linkage_blinded_kt.serialize()).toString('hex')
    }

    return ret
}

export async function initPrivateKey() {
    await BLS.init(BLS.BLS12_381)

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
}

export function getPublicKey() {
    return Buffer.from(publicKey.serialize()).toString('hex')
}