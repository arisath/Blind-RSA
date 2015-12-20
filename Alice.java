import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * The class AliceRSA represents Alice who is in possesion of an RSA keypair and can issue signatures with her private key
 */
public class Alice
{
	/**
	 * Produces an RSA keypair (N,e,d)
	 * N: modulus, e: public exponent, d: private exponent
	 * The public exponent value is set to 3 and the keylength to 2048
	 * @return RSA keypair
	 */
	public static KeyPair produceKeyPair()
	{
		try
		{
			KeyPairGenerator rsaKeyPairGenerator = KeyPairGenerator.getInstance("RSA");  //get rsa key generator

			RSAKeyGenParameterSpec spec = new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3)); //set the parameters for they key, key length=2048, public exponent=3

			rsaKeyPairGenerator.initialize(spec); //initialise generator with the above parameters

			KeyPair keyPair = rsaKeyPairGenerator.generateKeyPair(); //generate the key pair, N:modulus, d:private exponent

			return (keyPair);  //return the key pair produced (N,e,d)

		}
		catch (Exception e)
		{
			System.out.println(e);

			return null;
		}
	}

	/**
	 * Calculate mu' using the Chinese Remainder Theorem for optimization
	 *
	 * @param mu
	 * @return mu'
	 */
	public static BigInteger calculateMuPrimeWithChineseRemainderTheorem(BigInteger mu)
	{
		try
		{
			BigInteger N = BlindRsa.N; //get modulus N

			BigInteger P = BlindRsa.alicePrivate.getPrimeP(); //get the prime number p used to produce the key pair

			BigInteger Q = BlindRsa.alicePrivate.getPrimeQ(); //get the prime number q used to produce the key pair

			//Chinese remainder theorem: we split the mu^d modN in two , one mode p , one mode q then we combine the results to calculate muprime, we can do this because of the isomorphism property f(x+y)=f(x)+f(y)
			BigInteger PinverseModQ = P.modInverse(Q); //calculate p inverse modulo q

			BigInteger QinverseModP = Q.modInverse(P); //calculate q inverse modulo p

			BigInteger d = BlindRsa.alicePrivate.getPrivateExponent(); //get private exponent d

			//split the message mu in to messages m1, m2 one mod p, one mod q
			BigInteger m1 = mu.modPow(d, N).mod(P); //calculate m1=(mu^d modN)modP

			BigInteger m2 = mu.modPow(d, N).mod(Q); //calculate m2=(mu^d modN)modQ

			//combine the calculated m1 and m2 in order to calculate muprime
			BigInteger muprime = ((m1.multiply(Q).multiply(QinverseModP)).add(m2.multiply(P).multiply(PinverseModQ))).mod(N); //calculate muprime: (m1*Q*QinverseModP + m2*P*PinverseModQ) mod N where N =P*Q

			return muprime; //return muprime

		}
		catch (Exception e)
		{
			System.out.println(e);
		}
		return null;
	}

}

