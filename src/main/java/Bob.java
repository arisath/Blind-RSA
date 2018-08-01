import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;

/**
 * The class Bob represents Bob who wishes to get a signature from Alice over his message
 * but without Alice seeing the actual message
 */
public class Bob
{
    static BigInteger r;

    static BigInteger m;

    /**
     * Calculates and returns the mu
     * Bob uses ALice's public key and a random value r, such that r is relatively prime to N
     * to compute the blinding factor r^e mod N. Bob then computes the blinded message mu = H(msg) * r^e mod N
     * It is important that r is a random number so that mu does not leak any information about the actual message
     * @return the blinded messahe mu
     */
    public static BigInteger calculateMu(RSAPublicKey rsaPublicKey)
    {
        try
        {
            String message = DigestUtils.sha1Hex("X"); //calculate SHA1 hash over message;

            byte[] msg = message.getBytes("UTF8"); //get the bytes of the hashed message

            m = new BigInteger(msg);  //create a BigInteger object based on the extracted bytes of the message

            BigInteger e = rsaPublicKey.getPublicExponent(); //get the public exponent 'e' of Alice's key pair

            BigInteger N = BlindRsa.N; // get modulus 'N' of the key pair

            // Generate a random number so that it belongs to Z*n and is >1 and therefore r is invertible in Z*n
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");

            byte[] randomBytes = new byte[10]; //create byte array to store the r

            BigInteger one = new BigInteger("1"); // make BigInteger object equal to 1, so we can compare it later with the r produced to verify r>1

            BigInteger gcd = null; // initialise variable gcd to null

            do
            {
                random.nextBytes(randomBytes); //generate random bytes using the SecureRandom function

                r = new BigInteger(randomBytes); //make a BigInteger object based on the generated random bytes representing the number r

                gcd = r.gcd(BlindRsa.alicePublic.getModulus()); //calculate the gcd for random number r and the  modulus of the keypair

            }
            while (!gcd.equals(one) || r.compareTo(BlindRsa.N) >= 0 || r.compareTo(one) <= 0); //repeat until getting an r that satisfies all the conditions and belongs to Z*n and >1

            //now that we got an r that satisfies the restrictions described we can proceed with calculation of mu

            BigInteger mu = ((r.modPow(e, N)).multiply(m)).mod(N); //Bob computes mu = H(msg) * r^e mod N

            return mu;

        } 
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Calculate signature over mu'
     * Bob receives the signature over the blinded message that he sent to Alice
     * and removes the blinding factor to compute the signature over his actual message
     * @param muprime
     * @return signature
     */
    public static String signatureCalculation(BigInteger muprime)
    {
        try
        {

            BigInteger N = BlindRsa.N; //get modulus of the key pair

            BigInteger s = r.modInverse(N).multiply(muprime).mod(N); //Bob computes sig = mu'*r^-1 mod N, inverse of r mod N multiplied with muprime mod N, to remove the blinding factor

            byte[] bytes = new Base64().encode(s.toByteArray()); //encode with Base64 encoding to be able to read all the symbols

            String signature = (new String(bytes)); //make a string based on the byte array representing the signature

            System.out.println("Signature produced with Blind RSA procedure for message (hashed with SHA1): " + new String(m.toByteArray()) + " is: ");

            System.out.println(signature);

            return signature; 
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Checks if the signature received from Alice, is a valid signature for the message given, this can be easily computed because(m^d)^e modN = m
     * @param signature
     */
    public static void verify(String signature)
    {
        try
        {
            byte[] bytes = signature.getBytes(); //create a byte array extracting the bytes from the signature

            byte[] decodedBytes = new Base64().decode(bytes); // decode the bytes with Base64 decoding (remember we encoded with base64 earlier)

            BigInteger sig = new BigInteger(decodedBytes); // create the BigInteger object based on the bytes of the signature

            BigInteger e = BlindRsa.alicePublic.getPublicExponent();//get the public exponent of Alice's key pair

            BigInteger N = BlindRsa.N; //get the modulus of Alice's key pair

            BigInteger signedMessageBigInt = sig.modPow(e, N); //calculate sig^e modN, if we get back the initial message that means that the signature is valid, this works because (m^d)^e modN = m

            String signedMessage = new String(signedMessageBigInt.toByteArray()); //create a String based on the result of the above calculation

            String initialMessage = new String(m.toByteArray()); //create a String based on the initial message we wished to get a signature on

            if (signedMessage.equals(initialMessage)) //compare the two Strings, if they are equal the signature we got is a valid
            {
                System.out.println("Verification of signature completed successfully"); //print message for successful verification of the signature
            } 
            else
            {
                System.out.println("Verification of signature failed"); // print message for unsuccessful verification of the signature
            }
        } 
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

}

