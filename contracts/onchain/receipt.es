{
    // receipt contract
    // it is possible to spend this box 3 years after, with tokens being necessarily burnt

    // registers:
    // R4 - AvlTree - history of ownership for corresponding redeemed note
    // R5 - Long - redeemed position
    // R6 - approx. height when this box was created
    // R7 - redeemer PK

    def noTokens(b: Box) = b.tokens.size == 0
    val noTokensInOutputs = OUTPUTS.forall(noTokens)

    val creationHeight = SELF.R6[Int].get
    val burnPeriod = 788400 // 3 years

    val burnDone = (HEIGHT > creationHeight + burnPeriod) && noTokensInOutputs

    // we check that the receipt is spent along with a reserve contract box.
    // for that, we fix reserve input position @ #1
    // we drop version byte during ergotrees comparison
    // signature of receipt holder is also required
    val reserveInputErgoTree = INPUTS(1).propositionBytes
    val treeHash = blake2b256(reserveInputErgoTree.slice(1, reserveInputErgoTree.size))
    val reserveSpent = treeHash == fromBase58("2DfY1K4rW9zPVaQgaDp2KXgnErjxKPbbKF5mq1851MJE")
    val reRedemption = proveDlog(SELF.R7[GroupElement].get) && sigmaProp(reserveSpent)

    burnDone || reRedemption
}