package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureException;
import net.i2p.crypto.eddsa.EdDSAPublicKey;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PublicKey;

public class EdDSASignatureValidator extends EdDSAProvider implements SignatureValidator {

    public EdDSASignatureValidator(SignatureAlgorithm alg, Key key) {
        super(alg, key);
        if (!(key instanceof EdDSAPublicKey)) {
            String msg = "EdDSA signature validation must be computed using an EdDSAPublicKey.  The specified key of " +
                    "type " + key.getClass().getName() + " is not an EdDSAPublicKey.";
            throw new IllegalArgumentException(msg);
        }
        try {
            edDSAEngine.initVerify((PublicKey) key);
        } catch (InvalidKeyException e) {
            throw new SignatureException("Invalid EcDSA PublicKey. " + e.getMessage(), e);
        }
    }

    @Override
    public boolean isValid(byte[] data, byte[] signature) {
        try {
            return edDSAEngine.verifyOneShot(data, signature);
        } catch (java.security.SignatureException e) {
            String msg = "Unable to verify EdDSA signature using configured EdDSAPublicKey. " + e.getMessage();
            throw new SignatureException(msg, e);
        }
    }

}
