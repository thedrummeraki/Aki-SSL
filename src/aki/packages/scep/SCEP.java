package aki.packages.scep;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;

import java.io.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.List;

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

    private boolean includeCA = true;
    private Certificate caCertificate;
    private Certificate certificate;
    private Certificate recipientCert;
    private CMSSignedData signedData;

    private String senderNonce;
    private String recipientNonce;
    private String transactionId;
    private ResponseStatus status;
    private FailInfo failInfo = FailInfo.BAD_REQUEST;

    public SCEP() {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        this.setPending();
        includeCA = false;
    }

    public void setCaCertificate(Certificate caCertificate) {
        this.caCertificate = caCertificate;
        debug("Set CA ceritificate: "+((X509Certificate) caCertificate).getSubjectDN().getName() + "# " + ((X509Certificate) caCertificate).getSerialNumber());
    }

    public void setSignerCert(Certificate signerCert) {
        this.signerCert = signerCert;
        debug("Set signer ceritificate: "+((X509Certificate) signerCert).getSubjectDN().getName() + "# " + ((X509Certificate) signerCert).getSerialNumber());
    }

    public void setSignerKey(PrivateKey signerKey) {
        this.signerKey = signerKey;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
        debug("Set ceritificate: "+((X509Certificate) certificate).getSubjectDN().getName() + "# " + ((X509Certificate) certificate).getSerialNumber());
    }

    public void setRecipientCert(Certificate recipientCert) {
        this.recipientCert = recipientCert;
        debug("Set recipient ceritificate: "+((X509Certificate) recipientCert).getSubjectDN().getName() + "# " + ((X509Certificate) recipientCert).getSerialNumber());
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

    public void setFailInfo(FailInfo failInfo) {
        if (failInfo == null) {
            failInfo = FailInfo.BAD_REQUEST; // default value
        }
        this.failInfo = failInfo;
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

    public boolean isFailure() {
        return this.status.equals(ResponseStatus.FAILURE);
    }

    public boolean isSuccess() {
        return this.status.equals(ResponseStatus.SUCCESS);
    }

    public boolean isPending() {
        return this.status.equals(ResponseStatus.PENDING);
    }

    public CMSSignedData getSignedData() {
        return signedData;
    }

    private static final int SIGNER_CERT = 0;
    private static final int RECIPIENT_CERT = 1;
    private static final int CERT = 2;
    private static final int CA = 3;

    public int setSignerCertFromFile(String filename) {
        if (filename == null) {
            return 1;
        }
        return this.setCertFromFile(filename, SIGNER_CERT);
    }

    public int setCertFromFile(String filename) {
        if (filename == null) {
            return 1;
        }
        return this.setCertFromFile(filename, CERT);
    }

    public int setRecipientCertFromFile(String filename) {
        if (filename == null) {
            return 1;
        }
        return this.setCertFromFile(filename, RECIPIENT_CERT);
    }

    public int setCaCertFromFile(String filename) {
        if (filename == null) {
            return 1;
        }
        return this.setCertFromFile(filename, CA);
    }

    private int setCertFromFile(String filename, int whichCert) {
        try {
            File file = new File(filename);
            InputStream inputStream = new FileInputStream(file);
            Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(inputStream);
            switch (whichCert) {
                case SIGNER_CERT: this.setSignerCert(certificate); break;
                case RECIPIENT_CERT: this.setRecipientCert(certificate); break;
                case CERT: this.setCertificate(certificate); break;
                case CA: this.setCaCertificate(certificate); break;
                default: return 2; // Invalid certificate
            }
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

        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
        CMSTypedData msg;
        // We need to add the issued certificate to the signed portion of the CMS
        List<X509Certificate> certList = new ArrayList<>();
        if (this.certificate != null) {
            debug("Adding certificates to response message.");
            certList.add((X509Certificate) this.certificate);
            if (includeCA) {
                if (caCertificate != null) {
                    debug("Including explicitly set CA certificate in SCEP response...");
                    certList.add((X509Certificate) caCertificate);
                } else {
                    warn("The CA is missing.");
                    return 1;
                }
            }
        }
        /**
         * Create the signed CMS message to be contained inside the envelope
         * this message does not contain any message, and no signerInfo
         **/
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        Collection<JcaX509CertificateHolder> x509CertificateHolder = new ArrayList<>();
        try {
            for (X509Certificate certificate : certList) {
                x509CertificateHolder.add(new JcaX509CertificateHolder(certificate));
                debug("Added a JcaX509CertificateHolder (1)");
            }
            CollectionStore<JcaX509CertificateHolder> store = new CollectionStore<>(x509CertificateHolder);
            gen.addCertificates(store);
            debug("All certificates have been added to the CMS signed data generator.");
        } catch (CMSException | CertificateEncodingException e) {
            e.printStackTrace();
            return 1;
        }

        // TODO: add support for CRLs, like in example below
        /**
         * if (this.crl != null)
         *     gen.addCRL(new JcaX509CRLHolder((X509CRL) crl));
         * */

        CMSSignedData s;
        try {
            s = gen.generate(new CMSAbsentContent(), true);
        } catch (CMSException e) {
            e.printStackTrace();
            return 1;
        }

        if (recipientCert != null) {
            try {
                X509Certificate rec = (X509Certificate) recipientCert;
                edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(rec).setProvider(BouncyCastleProvider.PROVIDER_NAME));
                debug("SCEP has added a recipient certificate: "+rec.getSubjectDN().getName() + "# " + rec.getSerialNumber());
            } catch (CertificateEncodingException e) {
                throw new IllegalArgumentException("SCEP can't decode the recipient's self signed certificate.", e);
            }
        } else {
            try {
                JceKeyTransRecipientInfoGenerator jceKeyTransRecipientInfoGenerator = new JceKeyTransRecipientInfoGenerator((X509Certificate) certificate);
                if (jceKeyTransRecipientInfoGenerator != null && edGen != null)
                    edGen.addRecipientInfoGenerator(jceKeyTransRecipientInfoGenerator.setProvider(BouncyCastleProvider.PROVIDER_NAME));
            } catch (CertificateEncodingException e) {
                throw new IllegalArgumentException("SCEP can't decode the self signed certificate.", e);
            }
        }
        try {
            JceCMSContentEncryptorBuilder jceCMSContentEncryptorBuilder = new JceCMSContentEncryptorBuilder(SMIMECapability.dES_CBC).setProvider(BouncyCastleProvider.PROVIDER_NAME);
            CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(s.getEncoded()), jceCMSContentEncryptorBuilder.build());
            byte[] edEncoded = ed.getEncoded();
            debug("The enveloped data is "+ edEncoded.length + " bytes long.");
            FileWriter.write(edEncoded, "test.env", true, false);
            msg = new CMSProcessableByteArray(edEncoded);
        } catch (IOException e) {
            throw new IllegalArgumentException("SCEP encountered an unexpected I/O error.", e);
        } catch (CMSException e) {
            throw new IllegalArgumentException("SCEP encountered an unexpected CMS error.", e);
        }

        return this.signData(msg, outfile);
    }

    private int signData(CMSTypedData msg, String outfile) {
        /**
         * Necessary initial setup:
         * - We need the certificate signer
         * - We need its private key
         * - The status info
         * - The transaction id (A)
         * - The sender nonce (A)
         * - The recipient nonce (A)
         * */

        if (msg == null) {
            msg = new CMSProcessableByteArray(new byte[0]);
            debug("Initializing a new CMS typed data instance...");
        }

        CMSSignedDataGenerator gen1 = new CMSSignedDataGenerator();
        List<X509Certificate> certificates = new ArrayList<>();
        certificates.add((X509Certificate) this.caCertificate);
        if (this.certificate != null)
            certificates.add((X509Certificate) this.certificate);
        if (this.recipientCert != null)
            certificates.add((X509Certificate) this.recipientCert);
        Collection<JcaX509CertificateHolder> x509CertificateHolder = new ArrayList<>();
        try {
            for (X509Certificate certificate : certificates) {
                x509CertificateHolder.add(new JcaX509CertificateHolder(certificate));
                debug("Added a JcaX509CertificateHolder (2)");
            }
            CollectionStore<JcaX509CertificateHolder> store = new CollectionStore<>(x509CertificateHolder);
            gen1.addCertificates(store);
        } catch (Exception e) {
            e.printStackTrace();
            return 1;
        }
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
            values = new DERSet(new DEROctetString(senderNonce.getBytes()));
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
            X509Certificate x509Ca = (X509Certificate) ca;
            gen1.addSignerInfoGenerator(builder.build(contentSigner, x509Ca));
            debug(status.getStringValue()+ ": Signed data with CA "+x509Ca.getIssuerDN().getName()+" | "+x509Ca.getSubjectDN().getName() + "# " + ((X509Certificate) caCertificate).getSerialNumber()+" ("+x509Ca.getSerialNumber()+")");
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

    private int signData(String outfile) {
        return this.signData(new CMSProcessableByteArray(new byte[0]), outfile);
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

    private void warn(String message) {
        Logger.warn(getClass(), message, false);
    }

    public ResponseStatus getStatus() {
        return status;
    }
}
