package aki.packages.scep;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Hashtable;

/**
 * Created by aakintol on 19/07/16.
 */
public class SCEP {

    public static final String id_Verisign = "2.16.840.1.113733";
    public static final String id_pki = id_Verisign + ".1";
    public static final String id_attributes = id_pki + ".9";
    public static final String id_messageType = id_attributes + ".2";
    public static final String id_pkiStatus = id_attributes + ".3";
    public static final String id_failInfo = id_attributes + ".4";
    public static final String id_senderNonce = id_attributes + ".5";
    public static final String id_recipientNonce = id_attributes + ".6";
    public static final String id_transId = id_attributes + ".7";
    public static final String id_extensionReq = id_attributes + ".8";

    private Certificate signerCert;
    private PrivateKey signerKey;

    private Certificate caCertificate;
    private Certificate recipientCert;
    private CMSSignedData signedData;

    private String senderNonce;
    private String recipientNonce;
    private String transactionId;
    private ResponseStatus status;
    private FailInfo failInfo = FailInfo.BAD_REQUEST;

    public SCEP() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public void setCaCertificate(Certificate caCertificate) {
        this.caCertificate = caCertificate;
    }

    public void setSignerCert(Certificate signerCert) {
        this.caCertificate = signerCert;
    }

    public void setSignerKey(PrivateKey signerKey) {
        this.signerKey = signerKey;
    }

    public void setRecipientCert(Certificate recipientCert) {
        this.recipientCert = recipientCert;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public void setSenderNonce(String senderNonce) {
        this.senderNonce = senderNonce;
    }

    public void setRecipientNonce(String recipientNonce) {
        this.recipientNonce = recipientNonce;
    }

    public void setFailure() {
        this.status = ResponseStatus.FAILURE;
    }

    public void setSuccess() {
        this.status = ResponseStatus.SUCCESS;
    }

    public void setPending() {
        this.status = ResponseStatus.PENDING;
    }

    public CMSSignedData getSignedData() {
        return signedData;
    }

    public int setCertificateFromFile(String filename) {
        try {
            File file = new File(filename);
            InputStream inputStream = new FileInputStream(file);
            this.setSignerCert(CertificateFactory.getInstance("X.509").generateCertificate(inputStream));
        } catch (IOException | CertificateException e) {
            e.printStackTrace();
            return 1;
        }
        return 0;
    }

    public int setPrivateKeyFromFile(String filename) {
        try {
            File f = new File(filename);
            FileInputStream fis = new FileInputStream(f);
            DataInputStream dis = new DataInputStream(fis);
            byte[] keyBytes = new byte[(int) f.length()];
            dis.readFully(keyBytes);
            dis.close();
            KeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            this.setSignerKey(kf.generatePrivate(spec));
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return 1;
        }
        return 0;
    }

    public int signData(ResponseStatus status, String outfile) {
        info("Signing data...");
        if ((signerCert == null && caCertificate == null )|| signerKey == null) {
            error("Missing certificate signer or/and its private key (null).");
            return 1;
        }
        return status == ResponseStatus.SUCCESS ? signSuccessData(outfile) : signData(outfile);
    }

    private int signSuccessData(String outfile) {

        return 0;
    }

    private int signData(String outfile) {

        /**
         * Necessary initial setup:
         * - We need the certificate signer
         * - We need its private key
         * - The status info
         * - The transaction id (A)
         * - The sender nonce (A)
         * - The recipient nonce (A)
         * */

        CMSSignedDataGenerator gen1 = new CMSSignedDataGenerator();

        /**
         * Creating the attributes
         * */
        Hashtable<ASN1ObjectIdentifier, Attribute> attributes = new Hashtable<>();
        ASN1ObjectIdentifier oid;
        Attribute attr;
        DERSet values;

        oid = new ASN1ObjectIdentifier(SCEP.id_messageType);
        values = new DERSet(new DERPrintableString("3"));
        attr = new Attribute(oid, values);
        attributes.put(attr.getAttrType(), attr);

        CMSTypedData msg = new CMSProcessableByteArray(new byte[0]);

        // TransactionId
        if (transactionId != null) {
            oid = new ASN1ObjectIdentifier(SCEP.id_transId);
            debug("Added transactionId: " + transactionId);
            values = new DERSet(new DERPrintableString(transactionId));
            attr = new Attribute(oid, values);
            attributes.put(attr.getAttrType(), attr);
        }

        // status
        oid = new ASN1ObjectIdentifier(SCEP.id_pkiStatus);
        values = new DERSet(new DERPrintableString(status.getStringValue()));
        attr = new Attribute(oid, values);
        attributes.put(attr.getAttrType(), attr);

        if (status.equals(ResponseStatus.FAILURE)) {
            oid = new ASN1ObjectIdentifier(SCEP.id_failInfo);
            debug("Added failInfo: " + failInfo.getValue());
            values = new DERSet(new DERPrintableString(failInfo.getValue()));
            attr = new Attribute(oid, values);
            attributes.put(attr.getAttrType(), attr);
        }

        // senderNonce
        if (senderNonce != null) {
            oid = new ASN1ObjectIdentifier(SCEP.id_senderNonce);
            debug("Added senderNonce: " + senderNonce);
            values = new DERSet(new DEROctetString(Base64.encode(senderNonce.getBytes())));
            attr = new Attribute(oid, values);
            attributes.put(attr.getAttrType(), attr);
        }

        // recipientNonce
        if (recipientNonce != null) {
            oid = new ASN1ObjectIdentifier(SCEP.id_recipientNonce);
            debug("Added recipientNonce: " + recipientNonce);
            values = new DERSet(new DEROctetString(Base64.decode(recipientNonce.getBytes())));
            attr = new Attribute(oid, values);
            attributes.put(attr.getAttrType(), attr);
        }

        // Add our signer info and sign the message
        Certificate ca = this.caCertificate;
//        String signatureAlgorithmName = AlgorithmTools.getAlgorithmNameFromDigestAndKey(CMSSignedDataGenerator.DIGEST_SHA256, signerKey.getAlgorithm());

        String signatureAlgorithmName = "sha256WithRSAEncryption";
        try {
            String provider = BouncyCastleProvider.PROVIDER_NAME;
            ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithmName).setProvider(provider).build(signerKey);
            JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder().setProvider(provider);
            JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build());
            builder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(attributes)));
            gen1.addSignerInfoGenerator(builder.build(contentSigner, (X509Certificate) ca));
        } catch (OperatorCreationException | CertificateEncodingException e) {
            e.printStackTrace();
            return 1;
        }

        try {
            final CMSSignedData sd = gen1.generate(msg, true);
            FileWriter.write(sd.getEncoded(), outfile, true, false);
            info("The signed data was written to the file: "+outfile);
        } catch (IOException | CMSException e) {
            e.printStackTrace();
            return 1;
        }

        return 0;
    }

    private void error(String message) {
        Logger.error(getClass(), message, false);
    }

    private void info(String message) {
        Logger.info(getClass(), message, false);
    }

    private void debug(String message) {
        Logger.debug(getClass(), message, false);
    }

    public ResponseStatus getStatus() {
        return status;
    }
}