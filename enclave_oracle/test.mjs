import { Registration,Login } from 'opaque-wasm'
import axios from 'axios'

const username = 'test@test.com'
const password = 'SuperSecure123'

async function register() {
        // User registration
        const registration = new Registration()
        const registration_tx = registration.start(password)

        console.log(registration_tx)

        const buf = Buffer.from(registration_tx)
        console.log(buf)
        let message = Buffer.from(registration_tx).toString('base64')

        console.log(message)

        const registerResponse = await axios.post('http://localhost:8099/opaque/register_user', {username, message})

        console.log(registerResponse.data)

        const bs64 = registerResponse.data.message
        const buf2 = Buffer.from(bs64, 'base64')

        const registration_final = registration.finish(Uint8Array.from(buf2))

        message = Buffer.from(registration_final).toString('base64')

        const finishResponse = await axios.post('http://localhost:8099/opaque/finish_user_registration', {username, message})

        console.log(finishResponse.data)

}

async function login() {
    const login = new Login()

    const start_tx = login.start(password)

    let message = Buffer.from(start_tx).toString('base64')

    const loginChallenge = await axios.post('http://localhost:8099/opaque/login_start', {username, message})

    const challenge = Buffer.from(loginChallenge.data.message, 'base64')

    message = Buffer.from(login.finish(challenge)).toString('base64')

    const login_finish_response = await axios.post('http://localhost:8099/opaque/login_finish', {username, message})

    const sessionKey = Buffer.from(login.get_session_key()).toString('base64')

    await axios.post('http://localhost:8099/opaque/get_login_attestation', {username, sessionKey, linkage_blinded: 'somethinggoeshere'})
}

//register()
login()
