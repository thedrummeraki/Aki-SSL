package scep;

import pkcs7.PKCS7;
import tools.FileWriter;
import tools.Logger;
import x509.Certificate;
import x509.CertificateException;
import x509.PrivateKey;

import java.io.File;

/**
 * Created by aakintol on 30/06/16.
 */
public final class SCEPResponse {

    private static final String LOG_ID = "SCEPResponse";

    public final static int SCEP_SUCCESS = 0;
    public final static int SCEP_FAILURE = 1;
    public final static int SCEP_PENDING = 2;

    /**
     * Error will be in the 200 series.
     * */
    public final static int SCEP_CA_CERT_ERROR = 200;
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
        } catch (Exception e) {
            Logger.error(LOG_ID, "Could initialize the CA certificate.");
            return SCEP_CA_CERT_ERROR;
        }
        this.message = message;
        this.ip = ip;
        return 0;
    }

    private int pkcs7() {
        PKCS7 pkcs7 = new PKCS7(message, true);
        // The signed results will be found in a file
        return FileWriter.write("", outputFile.getPath()) ? 0 : WRITE_ERROR;
    }

    public static int loadSCEPResponse(String caDump, String keyDump, String message, String ip, String output, String failFile, String pendingFile, String successFile) {
        SCEPResponse response = new SCEPResponse();
        int code = response.initialize(caDump, keyDump, message, ip);
        if (code != 0) {
            return code;
        }
        return response.pkcs7();
    }

}
