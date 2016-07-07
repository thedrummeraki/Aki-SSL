package aki.packages.x509;

import java.util.ArrayList;

/**
 * Created by aakintol on 28/06/16.
 */
public class Subject {

    private String o;
    private String cn;

    private String c;
    private String l;
    private String st;
    private String ou;

    private Subject() {}

    public Subject(String organization, String commonName) {
        this.o = organization;
        this.cn = commonName;
    }

    public Subject(String organization, String commonName, String country, String locality, String stateProvince, String organizationalUnit) {
        this.o = organization;
        this.cn = commonName;
        this.c = country;
        this.l = locality;
        this.st = stateProvince;
        this.ou = organizationalUnit;
    }

    public Subject(String country, String locality, String stateProvince, String organizationalUnit) {
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

    public static boolean checkRawString(String rawString) {
        if (rawString == null) {
            return false;
        }
        try {
            Subject s = load(rawString);
            return s != null && !s.getRawString().isEmpty();
        } catch (CertificateException e) {
            return false;
        }
    }

    public static Subject load(String rawString) throws CertificateException {
        Subject subject = new Subject();
        if (!rawString.startsWith("/")) {
            throw new CertificateException("Invalid subject: doesn't start with a '/'");
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
                    subject.setField(fn, value);
                }
            }
        }
        return subject;
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

    public String getPrettyString() {
        String[] fields = {cn, o, c, l, st, ou};
        String[] fieldsName = {"C.N.", "Org.", "Ctry.", "Loc.", "St./Prv.", "Org.U."};
        String result = "";
        for (int i = 0; i<fields.length; i++) {
            String field = fields[i];
            if (field != null) {
                result += String.format("%s: %s\n", fieldsName[i], field);
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

    @Override
    public String toString() {
        return getRawString();
    }

    public static void main(String[] args) {
        String raw = "/CN=www.akinyele.ca/C=CA/L=Ottawa/O=CBN";
        try {
            Subject subject = Subject.load(raw);
            System.out.println("Res: "+subject.o);
            System.out.println("Res: "+subject.cn);
            System.out.println("Res: "+subject.c);
            System.out.println("Res: "+subject.l);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
    }
}
