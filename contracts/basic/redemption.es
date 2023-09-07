{
    // redemption box contract
    //
    // Tokens:
    // #0 - redemption contract token
    //
    // Registers:
    // R4: history tree (position -> (a, z)), where (a, z) is sig for (tree hash, reserve id, note id, note value, next reserve id)
    // R5: (current position, current reserve id)
    // R6: zero position signature
    // R7: zero position data (reserve id, note id, note value, next reserve id) // todo: zero proof?
    // R8: (max contested position, contestMode)
    // R9: deadline

    // 720 blocks for contestation

    // Dispute actions:
    // * wrong reserve id - collateral seized
    // * wrong collateral - collateral seized
    // * tree leaf not known - (collateral not seized if disclosure is correct) - !!!
    // * tree cut - collateral seized
    // * double spend - collateral seized
    // * wrong zero pos data - collateral seized
    // * earlier reserve exists (collateral not seized)
    // * wrong value transition - collateral seized

      val action = getVar[Byte](0).get

      val r: Boolean = if (action < 0) {
         // dispute
         if (action == -1) {
           // wrong reserve id
           false // todo: implement
         } else if (action == -2) {
           // wrong collateral
           SELF.value != 2000000000 // make collateral configurable via data-input
         } else if (action == -3) {
           val selfOutput = OUTPUTS(0)

           // tree leaf contents is asked or provided
           val selfPreservationExceptR8 = selfOutput.tokens == SELF.tokens && selfOutput.value == SELF.value &&
                                          selfOutput.R4[AvlTree].get == SELF.R4[AvlTree].get &&
                                          selfOutput.R5[(Long, Coll[Byte])] == SELF.R5[(Long, Coll[Byte])] &&
                                          selfOutput.R6[(GroupElement, Coll[Byte])] == SELF.R6[(GroupElement, Coll[Byte])] &&
                                          selfOutput.R7[Coll[Byte]] == SELF.R7[Coll[Byte]] &&
                                          selfOutput.R9[Int].get == SELF.R9[Int].get

           val r8 = SELF.R8[(Long, Boolean)].get
           val maxContestedPosition = r8._1
           val contested = r8._2
           if (contested) {
                // tree leaf provided
                val currentContestedPosition = maxContestedPosition + 1
                    val treeHashDigest = getVar[Coll[Byte]](1).get
                    val reserveId = getVar[Coll[Byte]](2).get
                    val noteId = getVar[Coll[Byte]](3).get
                    val noteValue = getVar[Long](4).get
                    val nextReserveId = getVar[Coll[Byte]](5).get
                    val a = getVar[GroupElement](6).get
                    val aBytes = a.getEncoded
                    val zBytes = getVar[Coll[Byte]](7).get
                    val properFormat = treeHashDigest.size == 32 && reserveId.size == 32 &&
                                        noteId.size == 32 && nextReserveId.size == 32
                    val message = treeHashDigest ++ reserveId ++ noteId ++ longToByteArray(noteValue) ++ nextReserveId

                    // Computing challenge
                    val e: Coll[Byte] = blake2b256(message) // weak Fiat-Shamir
                    val eInt = byteArrayToBigInt(e) // challenge as big integer

                    val g: GroupElement = groupGenerator
                    val z = byteArrayToBigInt(zBytes)
                    val reserve = CONTEXT.dataInputs(0)
                    val reserveIdValid = reserve.tokens(0)._1 == reserveId
                    val reservePk = reserve.R4[GroupElement].get
                    val properSignature = (g.exp(z) == a.multiply(reservePk.exp(eInt))) && properFormat && reserveIdValid

                    val keyBytes = longToByteArray(currentContestedPosition)

                    val proof = getVar[Coll[Byte]](8).get
                    val currentPosition = SELF.R5[(Long, Coll[Byte])].get._1
                    val history = SELF.R4[AvlTree].get
                    val properProof = history.get(keyBytes, proof).get == message && currentContestedPosition < currentPosition

                    val outR8 = selfOutput.R8[(Long, Boolean)].get
                    val outR8Valid = outR8._1 == currentContestedPosition && outR8._2 == false

                    properProof && properSignature && selfPreservationExceptR8 && outR8Valid
            } else {
                // tree leaf asked
                val outR8 = selfOutput.R8[(Long, Boolean)].get
                val outR8Valid = outR8._1 == maxContestedPosition && outR8._2 == true
                // todo: move deadline
                selfPreservationExceptR8 && outR8Valid
            }
         } else {
            // no more actions supported
            false
         }
      } else {
         // redemption
         // todo: implement
         false
      }

      sigmaProp(r)


  // there are three redemption related actions:
      //  * if Alice has enough reserves , Bob may redeem from it (get ERGs worth of the note)
      //  * if Alice does not have reserves, but Charlie signed next after Alice, the obligation to redeem the note can
      //    be transferred to Charlie
      //  * if Bob is trying to redeem from Alice, but then there was Charlie to whom the note was spent after,
      //    the right to obtain reserve can be moved to Charlie
      // no partial redemptions are supported

      // we just check current holder's signature here
      //todo: check that note token burnt ? or could be done offchain only?
      //todo: check that another box with the same tree and tokens could not be spent
/*
      val history = SELF.R4[AvlTree].get

      val zeroPosBytes = longToByteArray(0)
      val reserveId = getVar[Coll[Byte]](1).get
      val key = zeroPosBytes ++ reserveId

      val deadline = SELF.R5[Int].get

      val proof = getVar[Coll[Byte]](2).get
      if (history.get(key, proof).isDefined) {
        val deadlineMet = HEIGHT <= deadline
        sigmaProp(deadlineMet)
      } else {
        false
      }

      */

}