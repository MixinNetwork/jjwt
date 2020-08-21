package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.SignatureException;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;

public class EdDSASigner extends EdDSAProvider implements Signer {

    public EdDSASigner(SignatureAlgorithm alg, Key key) {
        super(alg, key);
        if (!(key instanceof EdDSAPrivateKey)) {
            String msg = "EdDSA signatures must be computed using an EdDSAPrivateKey.  The specified key of " +
                    "type " + key.getClass().getName() + " is not an EdDSAPrivateKey.";
            throw new IllegalArgumentException(msg);
        }
        try {
            edDSAEngine.initSign((PrivateKey) key);
        } catch (InvalidKeyException e) {
            throw new SignatureException("Invalid EcDSA PrivateKey. " + e.getMessage(), e);
        }
    }

    @Override
    public byte[] sign(byte[] data) throws SignatureException {
        try {
            return edDSAEngine.signOneShot(data);
        } catch (java.security.SignatureException e) {
            throw new SignatureException("Unable to calculate signature using EdDSA EdDSAPrivateKey. " + e.getMessage(), e);
        }
    }
}
