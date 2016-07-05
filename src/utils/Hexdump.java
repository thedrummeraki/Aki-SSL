package utils;

/**
 * Created by aakintol on 05/07/16.
 */
public final class Hexdump {

    private String dump;

    public Hexdump() {
        dump = "";
    }

    public void setDump(String dump) {
        if (!checkDump(dump)) return;
        this.dump = dump;
    }

    private boolean checkDump(String dump) {
        if (dump == null) {
            return false;
        }
        dump = dump.toUpperCase();
        for (char c : dump.toCharArray()) {
            boolean isNumber;
            try {
                Integer.parseInt(Character.toString(c));
                isNumber = true;
            } catch (NumberFormatException e) {
                isNumber = false;
            }
            if (isNumber) continue;
            boolean isLetter = c >= 'A' && c <= 'Z';
            if (!isLetter) {
                return false;
            }
        }
        return true;
    }

    public String getDump() {
        return dump;
    }

    public boolean isEmpty() {
        return dump.isEmpty();
    }

    @Override
    public String toString() {
        return dump;
    }
}
