package blindrsa;

import org.junit.Test;
import static org.junit.Assert.*;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class BlindRSATest {

    @Test
    public void testBlindUnblindCycle() throws Exception {
        // 1. Generate RSA keypair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privKey = (RSAPrivateKey) keyPair.getPrivate();

        // 2. Prepare a message
        String message = "Test blind RSA message";
        BigInteger m = new BigInteger(1, message.getBytes());

        // 3. Generate blinding factor (r)
        SecureRandom random = new SecureRandom();
        BigInteger n = pubKey.getModulus();
        BigInteger e = pubKey.getPublicExponent();
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength() - 1, random);
        } while (r.gcd(n).intValue() != 1); // ensure r is coprime with n

        // 4. Compute blinded message: m' = (m * r^e) mod n
        BigInteger blindedMessage = m.multiply(r.modPow(e, n)).mod(n);

        // 5. Signer signs the blinded message: s' = (m')^d mod n
        BigInteger d = privKey.getPrivateExponent();
        BigInteger blindSignature = blindedMessage.modPow(d, n);

        // 6. Unblind the signature: s = (s' * r^-1) mod n
        BigInteger rInv = r.modInverse(n);
        BigInteger unblindedSignature = blindSignature.multiply(rInv).mod(n);

        // 7. Verify the signature matches direct RSA signature: s = m^d mod n
        BigInteger directSignature = m.modPow(d, n);
        assertEquals("Unblinded signature should match direct signature", directSignature, unblindedSignature);

        // 8. Verify that signature decrypts back to message with public key
        BigInteger verified = unblindedSignature.modPow(e, n);
        assertEquals("Signature should verify correctly", m, verified);
    }

    @Test
    public void testKeyGenerationConsistency() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair kp = keyGen.generateKeyPair();
        RSAPublicKey pub = (RSAPublicKey) kp.getPublic();
        RSAPrivateKey priv = (RSAPrivateKey) kp.getPrivate();

        assertNotNull(pub);
        assertNotNull(priv);
        assertTrue(pub.getModulus().bitLength() >= 1024);
        assertTrue(priv.getPrivateExponent().compareTo(BigInteger.ZERO) > 0);
    }
}
