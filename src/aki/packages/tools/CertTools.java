package aki.packages.tools;

import org.bouncycastle.asn1.eac.CVCertificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;

/**
 * Created by aakintol on 20/07/16.
 */
public class CertTools {

    /**
     *
     * @throws CertificateParsingException if the byte array does not contain a proper certificate.
     */
    public static Certificate getCertfromByteArray(byte[] cert) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        InputStream in = new ByteArrayInputStream(cert);
        return certificateFactory.generateCertificate(in);
    }



}
