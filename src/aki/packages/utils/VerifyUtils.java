package aki.packages.utils;

import aki.packages.x509.*;
import aki.packages.tools.BashReader;

import java.io.File;
import java.util.ArrayList;

import static aki.packages.tools.Logger.*;

/**
 * Created by aakintol on 05/07/16.
 */
public final class VerifyUtils {

    static {
        TAG = VerifyUtils.class.getSimpleName();
        ASN1PARSE_OUTPUT = new ArrayList<>();
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

    /* OK */
    private static boolean catchNullInOneOf(Object... objects) {
        for (Object o : objects) {
            if (o == null)
                return false;
        }
        return true;
    }

    /* OK */
    public static boolean check(Signable signable) {
        return checkSignableAndIfSigned(signable) == 0;
    }

    /* OK */
    public static int checkSignableAndIfSigned(Signable signable) {
        if (SignUtils.check(signable)) {
            if (signable.isSigned()) {
                return 0;
            }
        }
        return Constants.CHECK_SIGNABLE_INVALID_OR_NOT_SIGNED_ERROR;
    }

    /* OK */
    public static int generateKey(String alg, int bits, File keyOut, File certOut, Signable signable, Subject subject) {
        alg = alg.trim();
        if (!catchNullInOneOf(alg, keyOut, certOut, signable)) {
            error(TAG, "Null object caught.");
            return Constants.NULL_OBJECT_ERROR;
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

//        String command = BashReader.toSingleString(args);

        BashReader br = BashReader.read(args);
        if (br == null) {
            error(TAG, "Null BashReader object caught.");
            return Constants.NULL_OBJECT_RESULT_ERROR;
        }

        int exitValue = br.getExitValue(); //PythonBashCaller.call(args);

        if (exitValue != 0) {
            error(TAG, "Non zero exit value: "+ exitValue + ". Error message(s): "+br.getErrorMessage());
            return exitValue;
        }

        if (isValidSubject) {
            args = new String[] {"openssl", "req", "-key", keyout, "-new", "-x509", "-days", "365", "-out", out, "-subj", subject.getRawString()};
        } else {
            args = new String[] {"openssl", "req", "-key", keyout, "-new", "-x509", "-days", "365", "-out", out};
        }

//        command = BashReader.toSingleString(args);

//        exitValue = PythonBashCaller.call(args);

        br = BashReader.read(args);
        if (br == null) {
            error(TAG, "Null BashReader object caught.");
            return Constants.NULL_OBJECT_RESULT_ERROR;
        }

        exitValue = br.getExitValue();
        if (exitValue != 0) {
            error(TAG, "Non zero exit value: "+ exitValue + ". Error message(s): "+br.getErrorMessage());
            return exitValue;
        }

        PrivateKey privateKey = PrivateKey.loadPrivateKey(keyOut);
        try {
            Certificate certificate = Certificate.loadCertificateFromFile(certOut);
            setKeyAndSigner(privateKey, certificate, signable);
            return 0;
        } catch (CertificateException e) {
            return Constants.INVALID_CERTIFICATE_ERROR;
        }
    }

    /* OK */
    public static int setKeyAndSigner(PrivateKey privateKey, Certificate certificate, Signable signable) {
        if (!catchNullInOneOf(privateKey, certificate, signable)) {
            return Constants.NULL_OBJECT_ERROR;
        }
        signable.setCertSigner(certificate);
        signable.setPrivateKeySigner(privateKey);
        return 0;
    }


    public static int setKeyAndSigner(String privateKey, String certificate, Signable signable) {
        return setKeyAndSigner(new File(privateKey), new File(certificate), signable);
    }

    /* OK */
    public static int setKeyAndSigner(File privateKey, File certificate, Signable signable) {
        if (!catchNullInOneOf(privateKey, certificate, signable)) {
            return Constants.NULL_OBJECT_ERROR;
        }
        PrivateKey privateKey1 = PrivateKey.loadPrivateKey(privateKey);
        try {
            Certificate certificate1 = Certificate.loadCertificateFromFile(certificate);
            if (!catchNullInOneOf(privateKey1, certificate1)) {
                return Constants.NULL_OBJECT_RESULT_ERROR;
            }
            return setKeyAndSigner(privateKey1, certificate1, signable);
        } catch (CertificateException e) {
            e.printStackTrace();
            return Constants.INVALID_CERTIFICATE_ERROR;
        }
    }

    /* OK */
    public static int locateSignature(String inform, Signable signable) {
        if (!check(signable)) {
            error(TAG, "Invalid Signable.");
            return Constants.CHECK_SIGNABLE_INVALID_OR_NOT_SIGNED_ERROR;
        }

        if (!signable.isSigned()) {
            error(TAG, "Your signable is not signed.");
            return Constants.CHECK_SIGNABLE_INVALID_OR_NOT_SIGNED_ERROR;
        }

        String in = inform.equalsIgnoreCase("DER") ? signable.getSignedFilenameDER() : signable.getSignedFilenamePEM();
        String[] args = {"openssl", "asn1parse", "-inform", inform, "-in", in};

        BashReader br = BashReader.read(args);
        if (br == null) {
            error(TAG, "Null BashReader object caught.");
            return Constants.NULL_OBJECT_RESULT_ERROR;
        }

        return br.getExitValue();
    }

    /* OK */
    public static int extractBinaryRSAEncryptedHash(String hashAlg, Signable signable) {
        if (!catchNullInOneOf(signable)) {
            return Constants.NULL_OBJECT_ERROR;
        }
        if (!check(signable)) {
            return Constants.CHECK_SIGNABLE_INVALID_OR_NOT_SIGNED_ERROR;
        }

        if (ASN1PARSE_OUTPUT.isEmpty()) {
            error(TAG, "You must successfully execute SignUtils.execOpemSSLASN1Parse(String,Signable,boolean) " +
                    "before extracting the binary RSA encryted hash.");
            return Constants.EMPTY_LIST_ERROR;
        }

        // Extract the binary RSA encrypted hash
        int offset, header, length;
        File ddOfFile = new File("signed-"+hashAlg+".bin");
        String lastLine = ASN1PARSE_OUTPUT.get(ASN1PARSE_OUTPUT.size()-1);
        /**
         * The last line should look like something like this:
         * >>> 1245:d=5  hl=4 l= 256 prim: OCTET STRING      [HEX
         * We need:
         *  > 1245 as the offset
         *  > 4 as the header
         *  > 256 as the length
         * */

        // Get the index of the colon and get the trimmed string before that: that is the offset
        // Get the index of the colon and get the trimmed string before that: that is the offset
        int index = lastLine.indexOf(":");
        String s = lastLine.substring(1, index);
        offset = Integer.parseInt(s);

        // Get the index of "hl=": add numbers between "=" and the next letter: this is the header
        String toFind = "hl=";
        index = lastLine.indexOf(toFind)+toFind.length();
        char current = lastLine.charAt(index);
        s = "";
        for (int i = index; current >= 48 && current <= 57; i++) {
            current = lastLine.charAt(i);
            s += current;
        }
        s = s.trim();
        header = Integer.parseInt(s);

        // Get the index of "l= ": add numbers between " " and the next letter: here is the length
        toFind = "l= ";
        index = lastLine.indexOf(toFind)+toFind.length();
        current = lastLine.charAt(index);
        s = "";
        for (int i = index; current >= 48 && current <= 57; i++) {
            current = lastLine.charAt(i);
            s += current;
        }
        s = s.trim();
        length = Integer.parseInt(s);

        String in = signable.getSignedFilenameDER();

        Object[] oargs = new Object[] {"python", "scripts/dder.py", "-in", in, "-out", ddOfFile.getPath(),
                "-bs", 1, "-l", offset, "-h", header, "-c", length};

        BashReader br = BashReader.read(oargs);
        if (br == null) {
            return Constants.NULL_OBJECT_RESULT_ERROR;
        }

        return br.getExitValue();
    }

    /* OK */
    public static int performHexdump(String path, Hexdump hexReceiver) {
        return performHexdump(new File(path), hexReceiver);
    }

    /* OK */
    public static int performHexdump(File file, Hexdump hexReceiver) {
        if (file == null) {
            return Constants.NULL_OBJECT_ERROR;
        }

        String[] args = {"python", "scripts/hexdump", "-in", file.getPath()};
        BashReader br = BashReader.read(args);

        if (br == null) {
            return Constants.NULL_OBJECT_RESULT_ERROR;
        }

        if (hexReceiver == null || !hexReceiver.isEmpty()) {
            hexReceiver = new Hexdump();
        }
        hexReceiver.setDump(br.getOutput().trim());
        if (br.getExitValue() != 0) {
            warn(TAG, BashReader.toSingleString(args));
            warn(TAG, br.getErrorMessage().isEmpty() ? "Error with exit code ("+br.getExitValue()+")" : br.getErrorMessage());
        }
        return br.getExitValue();
    }

    /* OK */
    public static int extractPublicKeyFromCertificate(String inform, Signable signable) {
        if (!check(signable)) {
            return Constants.CHECK_SIGNABLE_INVALID_OR_NOT_SIGNED_ERROR;
        }
        return extractPublicKeyFromCertificate(inform, signable.getCertSigner());
    }

    /* OK */
    public static int extractPublicKeyFromCertificate(String inform, Certificate certificate) {
        if (!catchNullInOneOf(inform, certificate)) {
            return Constants.NULL_OBJECT_ERROR;
        }

        PublicKey publicKey = certificate.fetchPublicKey();
        return publicKey != null ? 0 : Constants.NULL_OBJECT_RESULT_ERROR;
    }


    public static int verifySignature(String signedBinIn, String verifiedBinOut, Signable signable) {
        return verifySignature(new File(signedBinIn), new File(verifiedBinOut), signable);
    }


    public static int verifySignature(File signedBinIn, File verifiedBinOut, Signable signable) {
        if (!catchNullInOneOf(signable, signable.getCertSigner(), signedBinIn, verifiedBinOut)) {
            return Constants.NULL_OBJECT_ERROR;
        }

        signable.getCertSigner().fetchPublicKey();
        String inkey = signable.getCertSigner().getPublicKeyFilename();
        String in = signedBinIn.getPath();
        String out = verifiedBinOut.getPath();

        String[] args = {"python", "scripts/sigver.py", "-in", in, "-inkey", inkey, "-out", out};
        BashReader br = BashReader.read(args);
        if (br == null) {
            return Constants.NULL_OBJECT_ERROR;
        }

        return br.getExitValue();
    }

    /**
     * Variables
     * */
    private static final String TAG;
    static final ArrayList<String> ASN1PARSE_OUTPUT;

}
