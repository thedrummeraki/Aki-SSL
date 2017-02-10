package aki.packages.cmp;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.cmp.CMPException;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Provider;
import java.security.Security;
import java.util.Date;

/**
 * Created by aakintol on 19/01/17.
 */
public class RACMPClient extends CMPClient {

    // Please the execute the methods in the order they are currently in
    @Override
    public void request() throws CMPException, OperatorCreationException, CRMFException, IOException {
    }

    @Override
    public ProtectedPKIMessage getMessage() {
        return this.message();
    }
}
