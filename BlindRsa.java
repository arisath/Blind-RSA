import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;


public class BlindRsa
{
	static KeyPair alicePair;  //alice key pair

	static RSAPrivateCrtKey alicePrivate; // alice private key d

	static RSAPublicKey alicePublic; // alice public key e

	static BigInteger N; // Key pair's modulus

	static BigInteger mu; //first message Bob sends to Alice, mu = H(msg) * r^e mod N

	static BigInteger muprime;// Alice's message to Bob, mu'=mu^d mod N


	public static void main(String[] args)
	{
		try
		{
			long start = System.currentTimeMillis(); //get current time in milliseconds

			alicePair = Alice.produceKeyPair(); // call Alice's function to produce a key pair (N, e ,d), and save it in alicePair variable

			alicePrivate = (RSAPrivateCrtKey) alicePair.getPrivate(); //get the private key d out of the key pair Alice produced

			alicePublic = (RSAPublicKey) alicePair.getPublic(); //get  the public key e out of the key pair Alice produced

			N = alicePublic.getModulus(); //get the modulus of the key pair produced by Alice

			mu = Bob.calculateMu(alicePublic); //call Bob's function calculateMu with alice Public key as input in order to calculate mu, and store it in mu variable

			muprime = Alice.calculateMuPrimeWithChineseRemainderTheorem(mu); // call Alice's function calculateMuPrime with mu produced earlier by Bob as input, to calculate  mu' and store it to muprime  variable

			String sig = Bob.signatureCalculation(muprime); // call Bob's function signatureCalculation with muprime as input and calculate the signature, then store it in sig variable

			Bob.verify(sig); //Bob is checking if the signature he got from Alice is valid, that can be easily computed because (m^d)^e modN = m

			System.out.println();
			long elapsedTimeMillis = System.currentTimeMillis() - start;
			System.out.println("Program executed in " + elapsedTimeMillis + " milliseconds");
		}
		catch (Exception e)
		{
			System.out.println(e);
		}
	}
}
