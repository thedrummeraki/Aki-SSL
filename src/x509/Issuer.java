package x509;

import java.util.ArrayList;

/**
 * Created by aakintol on 28/06/16.
 */
public class Issuer {

    private String o;
    private String cn;

    private String c;
    private String l;
    private String st;
    private String ou;

    private Issuer() {}

    public Issuer(String organization, String commonName) {
        this.o = organization;
        this.cn = commonName;
    }

    public Issuer(String organization, String commonName, String country, String locality, String stateProvince, String organizationalUnit) {
        this.o = organization;
        this.cn = commonName;
        this.c = country;
        this.l = locality;
        this.st = stateProvince;
        this.ou = organizationalUnit;
    }

    public Issuer(String country, String locality, String stateProvince, String organizationalUnit) {
        this.c = country;
        this.l = locality;
        this.st = stateProvince;
        this.ou = organizationalUnit;
    }

    public String getCountry() {
        return c;
    }

    public String getLocality() {
        return l;
    }

    public String getStateProvince() {
        return st;
    }

    public String getOrganizationUnit() {
        return ou;
    }

    public String getCommonName() {
        return cn;
    }

    public String getO() {
        return o;
    }

    public static Issuer load(String rawString) throws CertificateException {
        Issuer issuer = new Issuer();
        if (!rawString.startsWith("/")) {
            throw new CertificateException("Invalid issuer: doesn't start with a '/'");
        }
        ArrayList<String> lines = new ArrayList<>();
        char[] seq = rawString.toCharArray();
        String current = "";
        for (int i = 0; i<seq.length; i++) {
            char c = seq[i];
            if (c == '/' && i != 0) {
                lines.add(current);
                current = "/";
            } else {
                current += c;
            }
            if (i == seq.length - 1) {
                lines.add(current);
            }
        }
        String[] fieldsName = {"CN", "O", "C", "L", "ST", "OU"};
        for (String s : lines) {
            for (String fn : fieldsName) {
                if (s.startsWith(String.format("/%s=", fn))) {
                    int start = s.indexOf("=")+1;
                    String value = "";
                    for (int k = start; k<s.length(); k++) {
                        value += s.charAt(k);
                    }
                    issuer.setField(fn, value);
                }
            }
        }
        return issuer;
    }

    private void setField(String key, String value) {
        switch (key.toUpperCase()) {
            case "CN": cn = value; break;
            case "C": c = value; break;
            case "O": o = value; break;
            case "OU": ou = value; break;
            case "L": l = value; break;
            case "ST": st = value; break;
            default: System.out.println("Invalid key: "+key);
        }
    }

    public String getRawString() {
        String[] fields = {cn, o, c, l, st, ou};
        String[] fieldsName = {"CN", "O", "C", "L", "ST", "OU"};
        String result = "";
        for (int i = 0; i<fields.length; i++) {
            String field = fields[i];
            if (field != null) {
                result += String.format("/%s=%s", fieldsName[i], field);
            }
        }
        return result;
    }

    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }
        if (o instanceof Issuer || o instanceof Subject) {
            if (o instanceof Issuer) {
                return getRawString().equals(((Issuer) o).getRawString());
            }
            return getRawString().equals(((Subject) o).getRawString());
        }
        return false;
    }
}
