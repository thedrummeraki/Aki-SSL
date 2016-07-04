package scep;

import attributes.Attribute;
import attributes.AttributeSet;
import pkcs7.PKCS7;
import pkcs7.PKCS7Exception;
import tools.FileWriter;
import tools.Logger;
import x509.Certificate;
import x509.PrivateKey;
import x509.SignatureException;

import java.io.File;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Stack;

/**
 * Created by aakintol on 30/06/16.
 */
public final class SCEPResponse {

    public static final String SCEP_STATUS_SUCCESS = "0";
    public static final String SCEP_STATUS_FAILED = "2";
    public static final String SCEP_STATUS_PENDING = "3";
    public static final String SCEP_CERTREP = "3";

    public static final String SCEP_FAILINFO_BADMESSAGECHECK = "1";
    public static final String SCEP_FAILINFO_BADREQUEST = "2";

    public static final String SCEP_PKCSREQ = "19";
    public static final String SCEP_GETCERTINITIAL = "20";
    public static final String SCEP_GETCERT = "21";
    public static final String SCEP_GETCRL = "22";

    private static final String DEF_LOG_ID = "SCEPResponse";
    private static String LOG_ID;

    public final static int SCEP_SUCCESS = 0;
    public final static int SCEP_FAILURE = 1;
    public final static int SCEP_PENDING = 2;

    /**
     * Error will be in the 200 series.
     * */
    public final static int SCEP_CA_CERT_ERROR = 200;
    public final static int SCEP_PKCS7_VERIFICATION_ERROR = 201;

    public final static int SCEP_NULL_ERROR = 210;
    public final static int WRITE_ERROR = 220;

    private File outputFile;
    private File failingResponseFile;
    private File pendingResponseFile;
    private File successResponseFile;

    private String message;
    private Certificate caCertificate;
    private String ip;

    private SCEPResponse() {}

    public int initialize(String caDump, String keyDump, String message, String ip) {
        // If we can't initialize the ca cert, the return the error
        try {
            Certificate certificate = Certificate.loadCertificateFromBuffer(caDump);
            PrivateKey privateKey = PrivateKey.loadPrivateKey(keyDump);
            caCertificate = certificate;
            caCertificate.setPrivateKey(privateKey);
        } catch (Throwable e) {
            Logger.error(LOG_ID, "Could initialize the CA certificate.");
            return SCEP_CA_CERT_ERROR;
        }
        this.message = message;
        this.ip = ip;
        return 0;
    }

    private int pkcs7() {
        LOG_ID = DEF_LOG_ID + ".pkcs7()";
        PKCS7 pkcs7 = new PKCS7(message, true);

        try {
            pkcs7.verifySignature(caCertificate);
        } catch (SignatureException e) {
            Logger.error(LOG_ID, "PKCS7 verification failed: "+e);
            AttributeSet attributeSet = pkcs7.getSignedAttributes();
            // Check if the keys are presents
            Attribute transactionIDAttr = attributeSet.getAttribute("transID");
            Attribute senderNonceAttr = attributeSet.getAttribute("senderNonce");

            return this.failureResponse(null, transactionIDAttr, senderNonceAttr, SCEP_FAILINFO_BADMESSAGECHECK);
        }

        AttributeSet signedAttributes;
        try {
            signedAttributes = pkcs7.getSignedAttributes();
            if (signedAttributes == null) {
                throw new PKCS7Exception("Invalid signed attributes (null)");
            }
        } catch (PKCS7Exception e) {
            Logger.error(LOG_ID, "PKCS7 signed attributes: "+e);
            return failureResponse(null, null, null, SCEP_FAILINFO_BADMESSAGECHECK);
        }

        String[] attrs = {"messageType", "senderNonce"};
        for (String attr : attrs) {
            if (!signedAttributes.contains(attr)) {
                Logger.error(LOG_ID, "Missing signed attribute: "+attr);
                return failureResponse(null, null, null, SCEP_FAILINFO_BADMESSAGECHECK);
            }
        }

        Attribute messageType = signedAttributes.getAttribute("messageType");
        String messType = messageType.toString();

        int returnCode = 0;

        if (messType.equals(SCEP_PKCSREQ)) {

        } else if (messType.equals(SCEP_GETCERTINITIAL)) {

        } else if (messType.equals(SCEP_GETCERT)) {

        } else {
            return failureResponse(null, null, null, SCEP_FAILINFO_BADREQUEST);
        }

        // The signed results will be found in a file
        return FileWriter.write("", outputFile.getPath()) ? returnCode : WRITE_ERROR;
    }

    private int handlePKCSReq(Certificate caCertificate, PKCS7 pkcs7, String ip) {
        LOG_ID = DEF_LOG_ID + ".handlePKCS7Req(Certificate,PKCS7,String)";
        Logger.info(LOG_ID, "Handling PKCS request...");

//        Envelope envelope = this.handleEnvelope(caCertificate, pkcs7, ip, false);
//        if (!envelope.isValid()) {
//            // Return its result.
//        }

        Stack<Certificate> certificateStack = new Stack<>();
        caCertificate.isSelfSigned();

        return 0;
    }

//    private Envelope handleEnvelope(Certificate caCertificate, PKCS7 pkcs7, String ip, boolean loadRequest) {
//
//        return new Envelope();
//    }

    private int failureResponse(Certificate certificate, Attribute transactionID, Attribute senderNonce, String messageType) {
        LOG_ID = DEF_LOG_ID + ".failureResponse(Certificate,Attribute,Attribute,String)";
        Logger.info(LOG_ID, "Creating a failure response");



        return SCEP_FAILURE;
    }

    private String createSenderNonce() {
        SecureRandom random = new SecureRandom();
        return new BigInteger(16, random).toString(32);
    }

    public static int loadSCEPResponse(String caDump, String keyDump, String message, String ip, String output, String failFile, String pendingFile, String successFile) {
        LOG_ID = DEF_LOG_ID + ".loadSCEPResponse(String,String,String,String,String,String,String,String)";
        Logger.info(LOG_ID, "Initializing the SCEP response...");
        SCEPResponse response = new SCEPResponse();
        int code = response.initialize(caDump, keyDump, message, ip);
        if (code != 0) {
            return code;
        }
        int returnCode = response.pkcs7();
        LOG_ID = DEF_LOG_ID + ".loadSCEPResponse(String,String,String,String,String,String,String,String)";
        Logger.info(LOG_ID, "SCEP response initialized");
        return returnCode;
    }

}
