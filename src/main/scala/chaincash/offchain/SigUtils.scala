package chaincash.offchain

import sigmastate.basics.CryptoConstants
import special.sigma.GroupElement
import sigmastate.eval._
import sigmastate.basics.SecP256K1Group
import java.security.SecureRandom
import scala.annotation.tailrec

object SigUtils {

  def randBigInt: BigInt = {
    val random = new SecureRandom()
    val values = new Array[Byte](32)
    random.nextBytes(values)
    BigInt(values).mod(SecP256K1Group.q)
  }

  @tailrec
  def sign(msg: Array[Byte], secretKey: BigInt): (GroupElement, BigInt) = {
    val r = randBigInt
    val g: GroupElement = CryptoConstants.dlogGroup.generator
    val a: GroupElement = g.exp(r.bigInteger)
    val z = (r + secretKey * BigInt(scorex.crypto.hash.Blake2b256(msg))) % CryptoConstants.groupOrder

    if(z.bitLength <= 255) {
      (a, z)
    } else {
      sign(msg,secretKey)
    }
  }
  def forge(msg: Array[Byte], publicKey: GroupElement): (GroupElement, BigInt) = {
    // Instead of calculating z, choose an arbitrary value instead to forge the signature
    val z = randBigInt
    if (z.bitLength > 255) {
      return forge(msg, publicKey)
    }
    val g: GroupElement = CryptoConstants.dlogGroup.generator
    // Compute A = z * G - (publicKey * hash(message))
    val a: GroupElement = g.exp(z.bigInteger).multiply(publicKey.exp(BigInt(scorex.crypto.hash.Blake2b256(msg)).bigInteger).negate)
    return (a, z)
  }

}