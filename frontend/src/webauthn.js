import { browserSupportsWebAuthn, startAuthentication, startRegistration } from '@simplewebauthn/browser'
import { traceStore } from './trace.js'

export const passkeysSupported = () => browserSupportsWebAuthn()

const short = (s, a = 18, b = 8) => (s && s.length > a + b + 1 ? `${s.slice(0, a)}…${s.slice(-b)}` : s)

function friendly(err) {
  if (err?.name === 'NotAllowedError') return 'Passkey request was cancelled or timed out.'
  if (err?.name === 'InvalidStateError') return 'This device already has a passkey for your account.'
  if (err?.name === 'SecurityError') return 'Passkeys only work on the site address SecureWallet was set up for.'
  return err?.message || 'Your device could not complete the passkey request.'
}

export async function createPasskey(optionsJSON) {
  traceStore.client('WebAuthn registration (browser)', [
    { lane: 'Browser', title: 'navigator.credentials.create() called', data: [['rp.id', optionsJSON.rp?.id], ['challenge', optionsJSON.challenge], ['userVerification', optionsJSON.authenticatorSelection?.userVerification]], explain: 'The browser checks that this page\'s origin matches rp.id before asking the authenticator.' },
    { lane: 'Authenticator', title: 'Generate a new P-256 key pair on the device', explain: 'Windows Hello / Touch ID / the security key creates the key pair. The private key never leaves it.' },
  ])
  try {
    const cred = await startRegistration({ optionsJSON })
    traceStore.client('WebAuthn registration (browser)', [
      { lane: 'Authenticator', title: 'Attestation returned', status: 'pass', data: [['credential id', cred.id], ['attestationObject', short(cred.response.attestationObject)], ['transports', (cred.response.transports || []).join(', ') || '-']] },
    ])
    return cred
  } catch (e) {
    throw new Error(friendly(e))
  }
}

export async function approveWithPasskey(optionsJSON) {
  traceStore.client('WebAuthn assertion (browser)', [
    { lane: 'Browser', title: 'navigator.credentials.get() called', data: [['challenge', optionsJSON.challenge], ['allowCredentials', String(optionsJSON.allowCredentials?.length ?? 0)], ['userVerification', optionsJSON.userVerification]] },
    { lane: 'Authenticator', title: 'User verification on the device', explain: 'Fingerprint, face or PIN is checked locally. Only a signed "user verified" flag is sent.' },
  ])
  try {
    const cred = await startAuthentication({ optionsJSON })
    traceStore.client('WebAuthn assertion (browser)', [
      { lane: 'Authenticator', title: 'Challenge signed with the device private key', status: 'pass', data: [['authenticatorData', short(cred.response.authenticatorData)], ['signature', short(cred.response.signature)], ['clientDataJSON', short(cred.response.clientDataJSON)]] },
    ])
    return cred
  } catch (e) {
    throw new Error(friendly(e))
  }
}
