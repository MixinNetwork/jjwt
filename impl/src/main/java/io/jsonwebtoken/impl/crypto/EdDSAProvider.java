package io.jsonwebtoken.impl.crypto;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.lang.Assert;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;

import java.security.*;

public class EdDSAProvider extends SignatureProvider {

    protected final EdDSAEngine edDSAEngine;

    protected EdDSAProvider(SignatureAlgorithm alg, Key key) {
        super(alg, key);
        Assert.isTrue(alg.isEdDSA(), "SignatureAlgorithm must be an EdDSA algorithm.");

        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        try {
            edDSAEngine = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("The " + alg.getJcaName() + " algorithm is not available.  " +
                    "This should never happen on JDK 7 or later - please report this to the JJWT developers.", e);
        }
    }

    @SuppressWarnings("unused") //used by io.jsonwebtoken.security.Keys
    public static KeyPair generateKeyPair(SignatureAlgorithm alg) {
        Assert.isTrue(alg.isEdDSA(), "Only EdDSA algorithms are supported by this method.");

        return generateKeyPair();
    }

    protected static KeyPair generateKeyPair() {
        KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
        return keyPairGenerator.generateKeyPair();
    }

    @SuppressWarnings("unused") //used by io.jsonwebtoken.security.Keys
    public static PrivateKey generatePrivateKey(SignatureAlgorithm alg) {
        Assert.isTrue(alg.isEdDSA(), "Only EdDSA algorithms are supported by this method.");
        return generatePrivateKey();
    }

    protected static PrivateKey generatePrivateKey() {
        return generateKeyPair().getPrivate();
    }
}
