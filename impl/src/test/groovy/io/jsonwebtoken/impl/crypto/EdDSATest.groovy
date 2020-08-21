package io.jsonwebtoken.impl.crypto

import io.jsonwebtoken.SignatureAlgorithm
import net.i2p.crypto.eddsa.EdDSAPrivateKey
import net.i2p.crypto.eddsa.EdDSAPublicKey
import net.i2p.crypto.eddsa.Utils
import org.junit.Test

import java.security.KeyPair

import static org.junit.Assert.assertTrue

class EdDSATest {

    @Test
    void testEd25519SignVerify() {
        SignatureAlgorithm alg = SignatureAlgorithm.ED25519
        byte[] target = Utils.hexToBytes("test message")
        KeyPair keyPair = EdDSAProvider.generateKeyPair()
        EdDSAPrivateKey sk = keyPair.private as EdDSAPrivateKey
        EdDSASigner signer = new EdDSASigner(alg, sk)
        byte[] signature = signer.sign(target)

        EdDSAPublicKey pk = keyPair.public as EdDSAPublicKey
        EdDSASignatureValidator validator = new EdDSASignatureValidator(alg, pk)
        assertTrue validator.isValid(target, signature)
    }
}
