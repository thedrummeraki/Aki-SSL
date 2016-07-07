package aki.packages.utils;

import aki.packages.tools.BashReader;
import aki.packages.tools.FileWriter;
import aki.packages.tools.Logger;
import aki.packages.x509.CertificateException;
import aki.packages.x509.PrivateKey;
import aki.packages.x509.Signable;
import aki.packages.tools.FileReader;

import java.io.File;
import aki.packages.x509.Certificate;

import java.util.ArrayList;

/**
 * Created by aakintol on 05/07/16.
 */
public final class SignUtils {

    /**
     * This class contains static methods that allows a Signable object to
     * execute signing methods. Please make sure to fully initialize the object prior
     * to using this method with the following attributes:
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

    private SignUtils() {}

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
//        if (signable == null) {
//            Logger.debug("2 for 0");
//            return false;
//        }
//        if (signable.getCertSigner() == null) {
//            Logger.debug("2 for 1");
//            return false;
//        }
//        if (signable.getPrivateKeySigner() == null) {
//            Logger.debug("2 for 2");
//            return false;
//        }
//        if (!signable.getPrivateKeySigner().doCheck(signable.getCertSigner())) {
//            Logger.debug("2 for 3");
//            return false;
//        }
        return signable != null && signable.getCertSigner() != null && signable.getPrivateKeySigner() != null &&
                signable.getPrivateKeySigner().doCheck(signable.getCertSigner()) && signable.getContents() != null;
    }

    /* OK */
    public static int checkCertificateAndPrivateKey(Certificate certificate, PrivateKey privateKey) {
        if (certificate == null || privateKey == null) {
            return Constants.NULL_OBJECT_ERROR;
        }
        try {
            privateKey.check(certificate);
        } catch (CertificateException e) {
            return Constants.CHECK_CERTIFICATE_PRIVATE_KEY_ERROR;
        }
        return 0;
    }

    /* OK */
    public static int writeRawData(File outFile, Signable signable) {
        if (!catchNullInOneOf(outFile, signable, signable.getContents())) {
            return Constants.NULL_OBJECT_ERROR;
        }
        if (!FileWriter.write(signable.getContents(), outFile.getPath())) {
            return Constants.IO_WRITE_ERROR;
        }
        return 0;
    }

    /* OK */
    public static int writeSignerBlob(File outFile, Signable signable) {
        if (!catchNullInOneOf(outFile, signable, signable.getCertSigner()) || !check(signable)) {
            return Constants.NULL_OBJECT_ERROR;
        }
        if (!FileWriter.write(signable.getCertSigner().getBlob(), outFile.getPath())) {
            return Constants.IO_WRITE_ERROR;
        }
        return 0;
    }

    /* OK */
    public static int writePrivateKey(File outFile, Signable signable) {
        if (!catchNullInOneOf(outFile, signable, signable.getPrivateKeySigner()) || !check(signable)) {
            return Constants.NULL_OBJECT_ERROR;
        }
        if (!FileWriter.write(signable.getPrivateKeySigner().dumpPEM(signable.getCertSigner().getSubject()), outFile.getPath())) {
            return Constants.IO_WRITE_ERROR;
        }
        return 0;
    }

    /* OK */
    public static int setSignedFilename(File file, Signable signable) {
        if (!catchNullInOneOf(file, signable)) {
            return Constants.NULL_OBJECT_ERROR;
        }
        signable.setSignedFilenamePEM(file.getPath());
        return 0;
    }

    /* OK */
    public static int execOpenSSLCMSSign(String alg, Signable signable) {
        return execOpenSSLCMSSign(alg, true, false, false, signable);
    }

    /* OK */
    public static int execOpenSSLCMSSign(String alg, boolean binary, Signable signable) {
        return execOpenSSLCMSSign(alg, binary, false, false, signable);
    }

    /* OK */
    public static int execOpenSSLCMSSign(String alg, boolean binary, boolean noCerts, boolean noAttr, Signable signable) {
        if (!catchNullInOneOf(alg, signable)) {
            return Constants.NULL_OBJECT_ERROR;
        }
        if (!check(signable)) {
            return Constants.CHECK_SIGNABLE_INVALID_OR_NOT_SIGNED_ERROR;
        }

        String in = signable.getContentsFilename();
        String inKey = signable.getPrivateKeyFilename();
        String signer = signable.getSignerFilename();

        String outform = "PEM";
        String out = signable.getSignedFilenamePEM();
        String[] args = getCMSSignArgs(alg, binary, noCerts, noAttr, outform, in, out, inKey, signer);
//        Logger.debug(BashReader.toSingleString(false, args));


        BashReader br = BashReader.read(args);
        if (br == null) {
            return Constants.NULL_OBJECT_RESULT_ERROR;
        }
        PEM_SIGNED_DATA = BashReader.toSingleString(true, FileReader.getLines(out));

        outform = "DER";
        out = signable.getSignedFilenameDER();
        args = getCMSSignArgs(alg, binary, noCerts, noAttr, outform, in, out, inKey, signer);
//        Logger.debug(BashReader.toSingleString(false, args));

        br = BashReader.read(args);
        if (br == null) {
            return Constants.NULL_OBJECT_RESULT_ERROR;
        }
        Logger.debug(br.getOutput());
        DER_SIGNED_DATA = BashReader.toSingleString(true, FileReader.getLines(out)).getBytes();

        setSignedData(signable);

        return br.getExitValue();
    }

    /* OK */
    private static String[] getCMSSignArgs(String alg, boolean binary, boolean noCerts, boolean noAttr, String outform,
                                                String in, String out, String inkey, String signer) {
        ArrayList<String> args = new ArrayList<>();
        args.add("openssl");
        args.add("cms");
        args.add("-sign");
        args.add("-md");
        args.add(alg);
        if (binary) args.add("-binary");
        if (noAttr) args.add("-noattr");
        if (noCerts) args.add("-nocerts");
        args.add("-outform");
        args.add(outform);
        args.add("-in");
        args.add(in);
        args.add("-out");
        args.add(out);
        args.add("-inkey");
        args.add(inkey);
        args.add("-signer");
        args.add(signer);

        return args.toArray(new String[0]);
    }

    /* OK */
    public static int execOpenSSLASN1Parse(String inform, Signable signable, boolean showOutput) {
        if (!catchNullInOneOf(inform, signable)) {
            return Constants.NULL_OBJECT_ERROR;
        }

        if (!inform.equalsIgnoreCase("DER") && !inform.equalsIgnoreCase("PEM")) {
            Logger.warn("Invalid inform: "+inform+". Setting inform to PEM by default.");
            inform = "PEM";
        }
        String in = inform.equalsIgnoreCase("DER") ? signable.getSignedFilenameDER() : signable.getSignedFilenamePEM();

        String[] args = {"openssl", "asn1parse", "-inform", inform, "-in", in};

        BashReader br = BashReader.read(args);

        if (br == null) {
            return Constants.NULL_OBJECT_RESULT_ERROR;
        }
        if (showOutput) {
            Logger.info("SignUtils", "execOpenSSLASN1Parse - "+br.getOutput());
        }

        VerifyUtils.ASN1PARSE_OUTPUT.addAll(br.getLines());

        return br.getExitValue();
    }

    /* OK */
    public static int setSignedData(Signable signable) {
        if (!catchNullInOneOf(signable, PEM_SIGNED_DATA, DER_SIGNED_DATA)) {
            return Constants.NULL_OBJECT_ERROR;
        }
        signable.setData(PEM_SIGNED_DATA);
        signable.setData(DER_SIGNED_DATA);
        return 0;
    }


    private static String PEM_SIGNED_DATA;
    private static byte[] DER_SIGNED_DATA;

}
