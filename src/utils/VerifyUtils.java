package utils;

import tools.BashReader;
import tools.FileWriter;
import tools.Logger;
import x509.*;

import java.io.File;

import static tools.Logger.info;
import static utils.Constants.*;
import static tools.Logger.debug;
import static tools.Logger.error;

/**
 * Created by aakintol on 05/07/16.
 */
public final class VerifyUtils {

    static {
        TAG = VerifyUtils.class.getSimpleName();
    }

    /**
     * This class contains static methods that allows a Signable object to
     * execute verification methods. Please make sure to fully initialize the object prior
     * to using this method with the following attributes:
     * [make sure your sign your Signable object before).
     * - Certificate signer
     * - Certificate signer filename
     * - Private key
     * - Private key filename
     * - Data
     * - Data filename
     *
     * These above can all be created with the method Signable.create().
     * Each method returns an integer, which is the return code of the method.
     * The return codes can be found in the package utils.Constants
     * */

    private VerifyUtils() {}

    private static boolean catchNullInOneOf(Object... objects) {
        for (Object o : objects) {
            if (o == null)
                return false;
        }
        return true;
    }

    public static boolean check(Signable signable) {
        return checkSignableAndIfSigned(signable) == 0;
    }

    public static int checkSignableAndIfSigned(Signable signable) {
        if (SignUtils.check(signable)) {
            if (signable.isSigned()) {
                return 0;
            }
        }
        return CHECK_SIGNABLE_INVALID_OR_NOT_SIGNED_ERROR;
    }

    /* OK */
    public static int generateKey(String alg, int bits, File keyOut, File certOut, Signable signable, Subject subject) {
        debug(TAG, "Generating Private Key.");
        if (!catchNullInOneOf(alg, keyOut, certOut, signable)) {
            error(TAG, "Null object caught.");
            return NULL_OBJECT_ERROR;
        }

        String keyout = keyOut.getPath();
        String out = certOut.getPath();

        String[] args;
        boolean isValidSubject = subject != null && Subject.checkRawString(subject.getRawString());
        if (isValidSubject) {
            args = new String[]{"openssl", "req", "-nodes", "-newkey", String.format("%s:%s", alg,bits), "-keyout", keyout, "-subj", subject.getRawString()};
        } else {
            args = new String[]{"openssl", "req", "-nodes", "-newkey", String.format("%s:%s", alg,bits), "-keyout", keyout};
        }

        String command = BashReader.toSingleString(args);
        debug(TAG, "Execution 1) Arguments: "+ command);

        BashReader br = BashReader.read(args);
        if (br == null) {
            error(TAG, "Null BashReader object caught.");
            return NULL_OBJECT_RESULT_ERROR;
        }

        int exitValue = br.getExitValue(); //PythonBashCaller.call(args);
        debug(TAG, "Execution 1) Exit value: "+ exitValue);


        if (isValidSubject) {
            args = new String[] {"openssl", "req", "-key", keyout, "-new", "-x509", "-days", "365", "-out", out, "-subj", subject.getRawString()};
        } else {
            args = new String[] {"openssl", "req", "-key", keyout, "-new", "-x509", "-days", "365", "-out", out};
        }

        command = BashReader.toSingleString(args);
        debug(TAG, "Execution 2) Arguments: "+ command);

//        exitValue = PythonBashCaller.call(args);

        br = BashReader.read(args);
        if (br == null) {
            error(TAG, "Null BashReader object caught.");
            return NULL_OBJECT_RESULT_ERROR;
        }
        debug(TAG, "Execution 2) Exit value: "+ exitValue);

        exitValue = br.getExitValue();

        System.out.println(br.getOutput());

//        if (exitValue != 0) {
//            error(TAG, "Non zero exit value: "+ exitValue);
//            return exitValue;
//        }

        PrivateKey privateKey = PrivateKey.loadPrivateKey(keyOut);
        try {
            Certificate certificate = Certificate.loadCertificateFromFile(certOut);
            setKeyAndSigner(privateKey, certificate, signable);
            return 0;
        } catch (CertificateException e) {
            return INVALID_CERTIFICATE_ERROR;
        }
    }

    /* OK */
    public static int setKeyAndSigner(PrivateKey privateKey, Certificate certificate, Signable signable) {
        if (!catchNullInOneOf(privateKey, certificate, signable)) {
            return NULL_OBJECT_ERROR;
        }
        signable.setCertSigner(certificate);
        signable.setPrivateKeySigner(privateKey);
        return 0;
    }

    /* OK */
    public static int setKeyAndSigner(File privateKey, File certificate, Signable signable) {
        if (!catchNullInOneOf(privateKey, certificate, signable)) {
            return NULL_OBJECT_ERROR;
        }
        PrivateKey privateKey1 = PrivateKey.loadPrivateKey(privateKey);
        try {
            Certificate certificate1 = Certificate.loadCertificateFromFile(certificate);
            if (!catchNullInOneOf(privateKey1, certificate1)) {
                return NULL_OBJECT_RESULT_ERROR;
            }
            return setKeyAndSigner(privateKey1, certificate1, signable);
        } catch (CertificateException e) {
            e.printStackTrace();
            return INVALID_CERTIFICATE_ERROR;
        }
    }

    /* OK */
    public static int locateSignature(String inform, Signable signable) {
        debug(TAG, "Locating the signature");
        if (!check(signable)) {
            error(TAG, "Invalid Signable.");
            return CHECK_SIGNABLE_INVALID_OR_NOT_SIGNED_ERROR;
        }

        if (!signable.isSigned()) {
            error(TAG, "Your signable is not signed.");
            return CHECK_SIGNABLE_INVALID_OR_NOT_SIGNED_ERROR;
        }

        debug(TAG, "The signable object is valid.");

        String in = inform.equalsIgnoreCase("DER") ? signable.getSignedFilenameDER() : signable.getSignedFilenamePEM();
        String[] args = {"openssl", "asn1parse", "-inform", inform, "-in", in};

        debug(TAG, "Execution: "+BashReader.toSingleString(false, args));
        BashReader br = BashReader.read(args);
        if (br == null) {
            error(TAG, "Null BashReader object caught.");
            return NULL_OBJECT_RESULT_ERROR;
        }

        return br.getExitValue();
    }

    public static int extractBinaryRSAEncryptedHash(File signatureOutput, Signable signable) {
        if (!catchNullInOneOf(signable, signatureOutput)) {
            return NULL_OBJECT_ERROR;
        }
        if (!check(signable)) {
            return CHECK_SIGNABLE_INVALID_OR_NOT_SIGNED_ERROR;
        }

        return 0;
    }

    public static int performHexdump(String path, Hexdump hexReceiver) {
        return performHexdump(new File(path), hexReceiver);
    }

    public static int performHexdump(File file, Hexdump hexReceiver) {
        if (file == null) {
            return NULL_OBJECT_ERROR;
        }

        String[] args = {"python", "hexdump", "-in", file.getPath()};
        BashReader br = BashReader.read(args);

        if (br == null) {
            return NULL_OBJECT_RESULT_ERROR;
        }

        if (hexReceiver == null || !hexReceiver.isEmpty()) {
            hexReceiver = new Hexdump();
        }
        hexReceiver.setDump(br.getOutput());
        return br.getExitValue();
    }

    public static int extractPublicKeyFromCertificate(String inform, Signable signable) {
        if (!check(signable)) {
            return CHECK_SIGNABLE_INVALID_OR_NOT_SIGNED_ERROR;
        }
        return extractPublicKeyFromCertificate(inform, signable.getCertSigner());
    }

    public static int extractPublicKeyFromCertificate(String inform, Certificate certificate) {
        if (!catchNullInOneOf(inform, certificate)) {
            return NULL_OBJECT_ERROR;
        }

        PublicKey publicKey = certificate.fetchPublicKey();
        if (publicKey == null) {
            return NULL_OBJECT_RESULT_ERROR;
        }

        return 0;
    }

    public static int verifySignature(PublicKey publicKey, File signedBinIn, File verifiedBinOut) {
        if (!catchNullInOneOf(publicKey, signedBinIn, verifiedBinOut)) {
            return NULL_OBJECT_ERROR;
        }

        return 0;
    }

    /**
     * Variables
     * */
    private static final String TAG;

}
