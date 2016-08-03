package aki.packages.scep;

import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by aakintol on 03/08/16.
 */
public final class MakeA {

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private MakeA() {}

    public static int certificateRequest(String publicKeyFilename, String privateKeyFilename, String subject, boolean basicCon, boolean keyUsage, byte[] ski) {
        try {
            ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
            extensionsGenerator.addExtension(Extension.basicConstraints, basicCon, new BasicConstraints(true));
            extensionsGenerator.addExtension(Extension.keyUsage, keyUsage, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
            extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, false, ski);
            extensionsGenerator.addExtension(Extension.authorityKeyIdentifier, false,
                    ("3045801494d9981bfd79806b2ca2e31d072b0ed699676f78a12aa4283026310b30090603" +
                            "55040a13027161311730150603550403130e477579616e615141434132303131820101")
                            .getBytes());

            Extensions extensions = extensionsGenerator.generate();
            Attribute attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extensions));

            PKCS10CertificationRequest certificateRequest = getCertificateRequest(publicKeyFilename, privateKeyFilename, subject, attribute);
            if (certificateRequest == null) return 2;

            StringWriter writer = new StringWriter();
            JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
            pemWriter.writeObject(certificateRequest);
            pemWriter.close();
            writer.close();
            String pem = writer.toString().trim();
            FileWriter.write(pem, "request.csr");
            System.out.println(pem);
        } catch (IOException e) {
            e.printStackTrace();
            return 1;
        }
        return 0;
    }

    private static PKCS10CertificationRequest getCertificateRequest(String publicKeyFilename, String privateKeyFilename, String subject, Attribute extensions) {
        Key _pak = loadFromFile(privateKeyFilename, false);
        Key _puk = loadFromFile(publicKeyFilename, true);
        if (_pak == null || _puk == null) {
            return null;
        }
        PrivateKey privateKey = (PrivateKey) _pak;
        PublicKey publicKey = (PublicKey) _puk;
        return getCertificateRequest(publicKey, privateKey, subject, extensions);
    }

    private static Key loadFromFile(String filename, boolean publicKey) {
        try {
            File f = new File(filename);
            FileInputStream fis = new FileInputStream(f);
            DataInputStream dis = new DataInputStream(fis);
            byte[] keyBytes = new byte[(int) f.length()];
            dis.readFully(keyBytes);
            dis.close();
            KeySpec spec = publicKey ? new X509EncodedKeySpec(keyBytes) : new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return publicKey ?
                    kf.generatePublic(spec) :
                    kf.generatePrivate(spec);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private static PKCS10CertificationRequest getCertificateRequest(PublicKey publicKey, PrivateKey privateKey, String subject, Attribute extensions) {
        try {
            KeyPair keyPair = new KeyPair(publicKey, privateKey);
            PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(subject), keyPair.getPublic());
            JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("sha256WithRSA");
            requestBuilder.addAttribute(extensions.getAttrType(), extensions.getAttrValues());
            ContentSigner signer = csBuilder.build(keyPair.getPrivate());
            return requestBuilder.build(signer);
        } catch (OperatorCreationException e) {
            e.printStackTrace();
            return null;
        }
    }

}
