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
public class CACMPClient extends CMPClient {

    private Provider provider;

    private long certReqId; // Necessary
    private KeyPair keyPair; // Necessary
    private byte[] senderNonce; // Necessary
    private byte[] transactionId; // Necessary

    private String issuerDN, subjectDN; // Necessary
    private X500Name issuer, subject;
    private String regToken; // Necessary
    private GeneralName sender;

    public void setCertReqId(long certReqId) {
        this.certReqId = certReqId;
    }

    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public void setSenderNonce(byte[] senderNonce) {
        this.senderNonce = senderNonce;
    }

    public void setTransactionId(byte[] transactionId) {
        this.transactionId = transactionId;
    }

    public void setIssuerDN(String issuerDN) {
        this.issuerDN = issuerDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public void setRegToken(String regToken) {
        this.regToken = regToken;
    }

    // Please the execute the methods in the order they are currently in
    @Override
    public void request() throws CMPException, OperatorCreationException, CRMFException, IOException {
        this.checkForMissingArguments();
        CertificateRequestMessageBuilder messageBuilder = this.getCertificateRequestMessageBuilder();
        this.setupIssuerSubject(messageBuilder);
        this.setupPublicKey(messageBuilder);
        this.setupMiscAttributes(messageBuilder);
        CertificateRequestMessage message = this.getCertificateRequestMessage(messageBuilder);
        ProtectedPKIMessageBuilder pkiMessageBuilder = this.getProtectedPKIMessageBuilder(message);
        this.setMessage(this.getProtectedPKIMessage(pkiMessageBuilder));
    }

    @Override
    public ProtectedPKIMessage getMessage() {
        return this.message();
    }

    private CertificateRequestMessageBuilder getCertificateRequestMessageBuilder() {
        return new CertificateRequestMessageBuilder(BigInteger.valueOf(this.certReqId));
    }

    private void setupIssuerSubject(CertificateRequestMessageBuilder messageBuilder) {
        X509NameEntryConverter dnconverter = new X509DefaultEntryConverter();
        X500Name issuerDN = X500Name.getInstance(new X509Name(this.issuerDN).toASN1Object());
        X500Name subjectDN = X500Name.getInstance(new X509Name(this.subjectDN, dnconverter).toASN1Object());
        messageBuilder.setIssuer(issuerDN);
        messageBuilder.setSubject(subjectDN);
        this.issuer = issuerDN;
        this.subject = subjectDN;
    }

    private void setupPublicKey(CertificateRequestMessageBuilder messageBuilder) throws IOException {
        final byte[] bytes = keyPair.getPublic().getEncoded();
        final ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        final ASN1InputStream dIn = new ASN1InputStream(bIn);
        final SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((ASN1Sequence) dIn.readObject());
        messageBuilder.setPublicKey(keyInfo);
    }

    private void setupMiscAttributes(CertificateRequestMessageBuilder messageBuilder) throws OperatorCreationException {
        this.sender = new GeneralName(this.subject);
        messageBuilder.setAuthInfoSender(this.sender);
        Control control = new RegTokenControl(this.regToken); // "foo123"
        messageBuilder.addControl(control);
        this.provider = Security.getProvider("BC");
        ContentSigner popsigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider(this.provider).build(keyPair.getPrivate());
        messageBuilder.setProofOfPossessionSigningKeySigner(popsigner);
    }

    private CertificateRequestMessage getCertificateRequestMessage(CertificateRequestMessageBuilder messageBuilder) throws CRMFException {
        return messageBuilder.build();
    }

    private ProtectedPKIMessageBuilder getProtectedPKIMessageBuilder(CertificateRequestMessage message) {
        GeneralName recipient = new GeneralName(this.issuer);
        ProtectedPKIMessageBuilder pbuilder = new ProtectedPKIMessageBuilder(this.sender, recipient);
        pbuilder.setMessageTime(new Date());
        pbuilder.setSenderNonce(this.senderNonce);
        pbuilder.setTransactionID(this.transactionId);

        org.bouncycastle.asn1.crmf.CertReqMessages msgs = new org.bouncycastle.asn1.crmf.CertReqMessages(message.toASN1Structure());
        org.bouncycastle.asn1.cmp.PKIBody pkibody = new org.bouncycastle.asn1.cmp.PKIBody(org.bouncycastle.asn1.cmp.PKIBody.TYPE_INIT_REQ, msgs);
        pbuilder.setBody(pkibody);
        return pbuilder;
    }

    private ProtectedPKIMessage getProtectedPKIMessage(ProtectedPKIMessageBuilder builder) throws OperatorCreationException, CMPException {
        ContentSigner msgsigner = new JcaContentSignerBuilder("SHA1withRSA").setProvider(this.provider).build(keyPair.getPrivate());
        return builder.build(msgsigner);
    }

    private void checkForMissingArguments() throws IllegalArgumentException {
        Object[] requiredAttributes = {certReqId, keyPair, senderNonce, transactionId, issuerDN, subjectDN, regToken};
        for(Object attribute : requiredAttributes) {
            if (attribute == null) {
                throw new IllegalArgumentException(
                        "One of {certReqId, keyPair, senderNonce, transactionId, issuerDN, subjectDN, regToken} is" +
                                " missing. Please set ALL variables prior to making a request.");
            }
        }
    }
}
