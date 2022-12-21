const crypto = require('crypto')

function aes_derive_subkey(
    key,
    extension
) {
    const tmp = new Uint8Array(17);
    tmp.set(extension, 0);
    if (key.length === 32) {
        tmp[16] = 0x01;
        const b0 = aes_cbc_mac(tmp, key);
        tmp[16] = 0x02;
        const b1 = aes_cbc_mac(tmp, key);
        return new Uint8Array([...b0, ...b1]);
    }
    if (key.length === 16) {
        tmp[16] = 0xFF;
        return aes_cbc_mac(tmp, key);
    }
    throw new Error('Invalid key length');
}

function aes_cbc_mac(
    plaintext,
    key
) {
    const alg = (key.length === 32) ? 'aes-256-cbc' : 'aes-128-cbc';
    const mac = new Uint8Array(16);
    // CBC-MAC begins with an all-zero IV
    const cipher = crypto.createCipheriv(alg, key, new Uint8Array(16));
    cipher.setAutoPadding(true);
    const blocks = new Uint8Array([...cipher.update(plaintext), ...cipher.final()]);
    // XOR blocks together
    for (let i = 0; i < blocks.length; i += 16) {
        for (let j = 0; j < 16; j++) {
            mac[j] ^= blocks[i + j];
        }
    }
    return mac;
}

function aes_xgcm_encrypt(
    plaintext,
    aad,
    nonce,
    key
) {
    needs(nonce.length === 28, 'Nonce must be 28 bytes');
    needs([16, 32].indexOf(key.length) >= 0, `Invalid key length ${key.length}`);
    const alg = (key.length === 32) ? 'aes-256-gcm' : 'aes-128-gcm';

    const subkey = aes_derive_subkey(key, nonce.slice(0, 16));
    const encryptor = crypto.createCipheriv(alg, subkey, nonce.slice(16));
    encryptor.setAAD(aad);
    const ciphertext = encryptor.update(plaintext);
    encryptor.final();
    const tag = encryptor.getAuthTag();
    return [ciphertext, tag];
}

function aes_xgcm_decrypt(
    ciphertext,
    tag,
    aad,
    nonce,
    key
) {
    needs(ciphertext.length >= 16, 'Ciphertext is too short');
    needs(nonce.length === 28, 'Nonce must be 28 bytes');
    needs(key.length in [16, 32], 'Invalid key length');
    const alg = (key.length === 32) ? 'aes-256-gcm' : 'aes-128-gcm';

    const subkey = aes_derive_subkey(key, nonce.slice(0, 16));
    const decryptor = crypto.createDecipheriv(alg, subkey, nonce.slice(16));
    decryptor.setAuthTag(tag);
    decryptor.setAAD(aad);
    const plaintext = decryptor.update(ciphertext);

    // Throw if auth tag is invalid:
    decryptor.final();

    return plaintext;
}

function needs(statement, errorMsg = '') {
    if (!statement) {
        throw new Error(errorMsg);
    }
}

module.exports = {aes_derive_subkey, aes_cbc_mac, aes_xgcm_encrypt, aes_xgcm_decrypt};