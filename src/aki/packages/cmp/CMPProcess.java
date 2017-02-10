package aki.packages.cmp;

import org.bouncycastle.asn1.x500.X500Name;

import java.security.KeyPair;

/**
 * Created by aakintol on 20/01/17.
 */
public final class CMPProcess {

    private CMPProcess() {}

    public static void execute(KeyPair keyPair, String issuerDN, String subjectDN) {
        long certReqId = 29L;
        byte[] senderNonce = "".getBytes();
        byte[] transactionID = "".getBytes();
        X500Name issuer = null;
    }

}
