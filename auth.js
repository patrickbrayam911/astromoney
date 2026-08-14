const crypto = require('crypto');
const { promisify } = require('util');

const scryptAsync = promisify(crypto.scrypt);

/**
 * Cria um hash seguro da senha.
 *
 * O valor salvo terá o formato:
 *
 * salt:hash
 */
async function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');

    const derivedKey = await scryptAsync(
        password,
        salt,
        64
    );

    return `${salt}:${derivedKey.toString('hex')}`;
}

/**
 * Compara uma senha digitada com o hash salvo.
 */
async function verifyPassword(password, storedHash) {
    const [salt, hash] = storedHash.split(':');

    if (!salt || !hash) {
        return false;
    }

    const derivedKey = await scryptAsync(
        password,
        salt,
        64
    );

    const hashBuffer = Buffer.from(hash, 'hex');

    if (hashBuffer.length !== derivedKey.length) {
        return false;
    }

    return crypto.timingSafeEqual(
        hashBuffer,
        derivedKey
    );
}

/**
 * Gera um identificador aleatório para a sessão.
 */
function generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

module.exports = {
    hashPassword,
    verifyPassword,
    generateSessionId
};