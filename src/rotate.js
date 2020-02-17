
import {fromPairsDeep} from '@sspiff/handy'
import client from '@sspiff/handyaws/client'
import parseArn from '@sspiff/handyaws/parseArn'
import {createKeyPair, publicKeyFromKeyPair} from '@sspiff/handy-keypair'


const STEPS = {}


STEPS.createSecret = function({SM, config, secretid, token, desc}) {
  // create a new key pair
  const secretShortName = parseArn(secretid).resource.split(':')[1]
  const validDays = desc.RotationRules.AutomaticallyAfterDays + 1
  const keyPair = createKeyPair({
    type: config.keyPair.type,
    options: config.keyPair.options,
    name: secretShortName,
    version: token,
    expiresAt: Math.trunc(Date.now()/1000) + (validDays * 24 * 60 * 60),
    graceDays: config.keyPair.graceDays || 0
  })
  // store the new key pair
  return SM.putSecretValue({
      SecretId: secretid,
      ClientRequestToken: token,
      SecretString: JSON.stringify(keyPair),
      VersionStages: ['AWSPENDING']
    }).promise().catch(error => {
      if (error.code === 'ResourceExistsException')
        // this is okay, can happen on a retry
        return null
      else
        throw error
    })
}


STEPS.setSecret = function({SM, config, secretid, token}) {
  return (
    // get the key pair
    SM.getSecretValue({SecretId: secretid, VersionId: token}).promise()
    // get the public key
    .then(data => publicKeyFromKeyPair(JSON.parse(data.SecretString)))
    // advertise the public key
    .then(publicKey => this.putPublicKey(
      config.publicKeyStore,
      publicKey.name,
      publicKey.version,
      publicKey))
  )
}


STEPS.testSecret = function () {
  // testing not supported
  return Promise.resolve(null)
}


STEPS.finishSecret = function({SM, secretid, token, desc}) {
  // find current version
  const currentVersion = Object.keys(desc.VersionIdsToStages)
    .find(v => desc.VersionIdsToStages[v].includes('AWSCURRENT'))
  if (token === currentVersion)
    // new version is already current
    return Promise.resolve(null)
  else
    // set new version as current, deprecate previous
    return SM.updateSecretVersionStage({
        SecretId: secretid,
        VersionStage: 'AWSCURRENT',
        MoveToVersionId: token,
        RemoveFromVersionId: currentVersion
      }).promise()
}


/**
 * Implements an AWS Secrets Manager key rotation Lambda using
 * {@link module:@sspiff/handy-keypair @sspiff/handy-keypair}, creating
 * key pairs using node.js's `crypto.generateKeyPairSync()`.
 *
 * ##### Bound this
 *
 * In addition to the configuration tags described below, `rotate()`
 * requires a helper function: `this.putPublicKey()`.  This function should
 * be placed in an object and that object bound to `rotate()` (or used with
 * `rotate.call()`).  See the example.
 *
 * `this.pubPublicKey()` should store the given public key data
 * (serializing to e.g. JSON if needed), and return a `Promise` that resolves
 * on a successful store.  It will receive the  following parameters (in order):
 *
 * | Parameter        | Description                         |
 * | ---------------- | ----------------------------------- |
 * | `publicKeyStore` | Copy of `cfg.publicKeyStore`        |
 * | `keyName`        | Name of the public key to store     |
 * | `keyVersion`     | Version of the key                  |
 * | `publicKey`      | The public key data object to store |
 *
 * ##### Configuration
 *
 * Besides the helper function in the bound `this`, `rotate()` is configured
 * using tags on the secret resource itself.
 * The following tags can be defined:
 *
 * | Tag                     | Description                             |
 * | ----------------------- | --------------------------------------- |
 * | `cfg.keyPair.type`      | Type of key pair (`'rsa'`, `'ec'`, etc) |
 * | `cfg.keyPair.options.*` | Additional options for `crypto.generateKeyPairSync()` specific to the key type |
 * | `cfg.keyPair.graceDays` | Additional days of public key validity beyond the private key expiration (which is set based on the rotation schedule) |
 * | `cfg.publicKeyStore`    | Passed to `this.putPublicKey()`         |
 *
 * @function rotate
 * @memberof module:@sspiff/handyaws-keypair-rotate
 * @param {Object} event - Lambda event object
 * @param {Object} context - Lambda context object
 *
 * @example
 * import {rotate} from '@sspiff/handyaws-keypair-rotate'
 * import setKeyValue from '@sspiff/handyaws/keyValue/set'
 *
 * // example configuration tags on the secret:
 * // cfg.keyPair.type                 'ec'
 * // cfg.keyPair.options.namedCurve   'prime256v1'
 * // cfg.keyPair.graceDays            '2'
 * // cfg.publicKeyStore               'ssm://us-east-1/keyStore/'
 *
 * export const handler = rotate.bind({
 *   putPublicKey: (store, name, version, publicKey) => {
 *     const u = new URL(store)
 *     u.pathname += `${name}/${version}`
 *     return setKeyValue(u.toString(), JSON.stringify(publicKey))
 *   }
 * })
 */
export default async function (event, context) {
  const SM = client('secretsmanager',
    {region: parseArn(event.SecretId).region})

  // get secret details
  const desc = await SM.describeSecret({SecretId: event.SecretId}).promise()

  // get configuration from tags on secret
  const config = fromPairsDeep(
    desc.Tags.map(t => [t.Key, t.Value]), '.', 'cfg.')
  if (config.keyPair && config.keyPair.graceDays)
    config.keyPair.graceDays = parseInt(config.keyPair.graceDays, 10)

  // check staging
  const versions = desc.VersionIdsToStages
  const token = event.ClientRequestToken
  if (!desc.RotationEnabled)
    throw 'ENOEXEC'
  if (!versions[token])
    throw 'ENOENT'
  if (versions[token].includes('AWSCURRENT'))
    return null
  if (!versions[token].includes('AWSPENDING'))
    throw 'EBUSY'

  // execute rotation step
  if (STEPS[event.Step])
    return STEPS[event.Step].call(this, {
      SM,
      secretid: event.SecretId,
      token,
      desc,
      config
    })
  else
    throw 'EINVAL'
}

