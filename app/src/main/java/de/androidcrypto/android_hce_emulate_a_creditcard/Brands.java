package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Brand / issuer detection and card styling.
 *
 * NETWORK comes from the captured AID - authoritative, no guessing.
 * BANK comes from a BIN table on the first 4-6 digits of the PAN. A PAN has no
 * bank field in it, so a lookup table is the only way; extend BIN as you meet
 * new cards. Longest matching prefix wins.
 *
 * Colours are per-bank so the tile looks like the real card. Logo slugs point at
 * the Iconify API and are consumed by LogoLoader.
 */
public final class Brands {

    public enum Network { VISA, MASTERCARD, AMEX, DISCOVER, JCB, UNIONPAY, DINERS, UNKNOWN }

    /** Everything the adapter needs to paint one tile. Immutable. */
    public static final class Style {
        public final String bankName;        // "BANK OF AMERICA"; network label if unknown
        public final String bankIcon;        // "prefix/slug" or null
        public final String networkIcon;     // "prefix/slug" or null
        public final int bg;
        public final int fg;
        public final int muted;
        public final String bankIconTint;    // "FFFFFF" to force white, or null
        public final String networkIconTint;

        Style(String bankName, String bankIcon, String networkIcon,
              int bg, int fg, int muted, String bankIconTint, String networkIconTint) {
            this.bankName = bankName;
            this.bankIcon = bankIcon;
            this.networkIcon = networkIcon;
            this.bg = bg;
            this.fg = fg;
            this.muted = muted;
            this.bankIconTint = bankIconTint;
            this.networkIconTint = networkIconTint;
        }
    }

    /** prefix -> bankId. Longest match wins, so both "4117" and "411773" are fine. */
    private static final Map<String, String> BIN = new LinkedHashMap<>();

    static {
        BIN.put("4117", "bofa");
        BIN.put("411773", "bofa");
        BIN.put("43568", "bofa");

        BIN.put("4124", "chase");
        BIN.put("414734", "chase");
        BIN.put("4366", "chase");

        BIN.put("4128", "citi");
        BIN.put("436618", "usbank");
        BIN.put("412266", "td");

        // Capital One debit, mid-migration: the Mastercard BINs are being retired
        // onto these Discover ones. Same bank, same product, two networks.
        BIN.put("510805", "capitalone");
        BIN.put("514745", "capitalone");
        BIN.put("514759", "capitalone");
        BIN.put("601141", "capitalone");
        BIN.put("601144", "capitalone");
        BIN.put("601146", "capitalone");
    }

    private Brands() {
    }

    // ------------------------------------------------------------------ network

    public static Network network(String aid, String pan) {
        if (aid != null) {
            String a = aid.toUpperCase(Locale.US).replaceAll("[^0-9A-F]", "");
            if (a.startsWith("A000000152")) return Network.DISCOVER;    // D-PAS
            if (a.startsWith("A000000003")) return Network.VISA;
            if (a.startsWith("A000000004")) return Network.MASTERCARD;
            if (a.startsWith("A000000025")) return Network.AMEX;
            if (a.startsWith("A000000065")) return Network.JCB;
            if (a.startsWith("A000000333")) return Network.UNIONPAY;
            if (a.startsWith("A000000324")) return Network.DINERS;
        }
        return networkFromPan(pan);
    }

    /** Rule-only fallback, used when no AID was captured. */
    public static Network networkFromPan(String pan) {
        if (pan == null) return Network.UNKNOWN;
        String d = digits(pan);
        if (d.length() < 2) return Network.UNKNOWN;

        char c = d.charAt(0);
        if (c == '4') return Network.VISA;

        if (c == '3') {
            if (d.startsWith("34") || d.startsWith("37")) return Network.AMEX;
            if (d.startsWith("35")) return Network.JCB;
            if (d.startsWith("30") || d.startsWith("36") || d.startsWith("38") || d.startsWith("39"))
                return Network.DINERS;
            return Network.UNKNOWN;
        }

        if (c == '5') {
            int two = num(d, 2);
            return (two >= 51 && two <= 55) ? Network.MASTERCARD : Network.UNKNOWN;
        }

        if (c == '6') {
            if (d.startsWith("6011") || d.startsWith("65")) return Network.DISCOVER;
            if (d.startsWith("62")) return Network.UNIONPAY;
            if (d.startsWith("622")) return Network.DISCOVER;
            int three = num(d, 3);
            if (three >= 644 && three <= 649) return Network.DISCOVER;
            return Network.UNKNOWN;
        }

        if (c == '2') {
            int four = num(d, 4);
            if (four >= 2221 && four <= 2720) return Network.MASTERCARD;
        }
        return Network.UNKNOWN;
    }

    public static String networkLabel(Network n) {
        switch (n) {
            case VISA:       return "VISA";
            case MASTERCARD: return "MASTERCARD";
            case AMEX:       return "AMERICAN EXPRESS";
            case DISCOVER:   return "DISCOVER";
            case JCB:        return "JCB";
            case UNIONPAY:   return "UNIONPAY";
            case DINERS:     return "DINERS CLUB";
            default:         return "CARD";
        }
    }

    private static String networkIcon(Network n) {
        switch (n) {
            case VISA:       return "simple-icons/visa";
            case MASTERCARD: return "simple-icons/mastercard";
            case AMEX:       return "simple-icons/americanexpress";
            case DISCOVER:   return "simple-icons/discover";
            case JCB:        return "simple-icons/jcb";
            case UNIONPAY:   return "simple-icons/unionpay";
            case DINERS:     return "simple-icons/dinersclub";
            default:         return null;
        }
    }

    // --------------------------------------------------------------------- bank

    public static String bankId(String pan) {
        String d = digits(pan);
        if (d.isEmpty()) return null;
        String best = null;
        int bestLen = 0;
        for (Map.Entry<String, String> e : BIN.entrySet()) {
            String p = e.getKey();
            if (p.length() > bestLen && d.startsWith(p)) {
                best = e.getValue();
                bestLen = p.length();
            }
        }
        return best;
    }

    private static String bankName(String bankId) {
        if (bankId == null) return null;
        switch (bankId) {
            case "bofa":       return "BANK OF AMERICA";
            case "chase":      return "CHASE BANK";
            case "citi":       return "CITIBANK";
            case "usbank":     return "U.S. BANK";
            case "td":         return "TD BANK";
            case "capitalone": return "CAPITAL ONE";
            default:           return null;
        }
    }

    private static String bankIcon(String bankId) {
        if (bankId == null) return null;
        switch (bankId) {
            case "bofa":       return "simple-icons/bankofamerica";
            case "chase":      return "simple-icons/chase";
            case "citi":       return "simple-icons/citi";
            case "capitalone": return "logos/capital-one";   // not in the simple-icons set
            default:           return null;                  // blank logo, wordmark carries it
        }
    }

    // -------------------------------------------------------------------- style

    public static Style styleFor(String pan, String aid) {
        Network net = network(aid, pan);
        String bank = bankId(pan);

        if (bank != null) {
            String name = bankName(bank);
            String icon = bankIcon(bank);
            switch (bank) {
                case "bofa":
                    return new Style(name, icon, networkIcon(net),
                            0xFFFFFFFF, 0xFF0B1A3A, 0xFF5B6B8A, null, null);
                case "chase":
                    return new Style(name, icon, networkIcon(net),
                            0xFF0B2D5C, 0xFFFFFFFF, 0xFF9FC0E8, "FFFFFF", "FFFFFF");
                case "citi":
                    return new Style(name, icon, networkIcon(net),
                            0xFF056DAE, 0xFFFFFFFF, 0xFFB7DCF3, "FFFFFF", "FFFFFF");
                case "usbank":
                    return new Style(name, icon, networkIcon(net),
                            0xFF0C2074, 0xFFFFFFFF, 0xFFA9B8E8, "FFFFFF", "FFFFFF");
                case "td":
                    return new Style(name, icon, networkIcon(net),
                            0xFF54B948, 0xFF0B2B06, 0xFF2F6B27, null, null);
                case "capitalone":
                    return new Style(name, icon, networkIcon(net),
                            0xFFF7F7F5, 0xFF0D2B45, 0xFF6B7280, null, null);
                default:
                    break;
            }
        }

        // No bank match: neutral card in the network's own colours.
        String label = networkLabel(net);
        String icon = networkIcon(net);
        switch (net) {
            case VISA:
                return new Style(label, null, icon, 0xFF1A1F71, 0xFFFFFFFF, 0xFFB9BEDC, null, "FFFFFF");
            case AMEX:
                return new Style(label, null, icon, 0xFF006FCF, 0xFFFFFFFF, 0xFFCFE4FF, null, "FFFFFF");
            case DISCOVER:
                return new Style(label, null, icon, 0xFFF4F4F2, 0xFF1C1917, 0xFF6B7280, null, null);
            case JCB:
                return new Style(label, null, icon, 0xFF0B4EA2, 0xFFFFFFFF, 0xFFC2D6F0, null, "FFFFFF");
            case UNIONPAY:
                return new Style(label, null, icon, 0xFF00447C, 0xFFFFFFFF, 0xFFBFD4E6, null, "FFFFFF");
            case DINERS:
                return new Style(label, null, icon, 0xFF0079BE, 0xFFFFFFFF, 0xFFC2E0F2, null, "FFFFFF");
            case MASTERCARD:
                return new Style(label, null, icon, 0xFF141414, 0xFFFFFFFF, 0xFF9CA3AF, null, "FFFFFF");
            default:
                return new Style("UNKNOWN ISSUER", null, icon, 0xFF1F2937, 0xFFFFFFFF, 0xFF9CA3AF, null, "FFFFFF");
        }
    }

    // ---------------------------------------------------------------- formatting

    /** Groups the PAN correctly, including the 15-digit Amex 4-4-4-3 case. */
    public static String formatPan(String pan) {
        String d = digits(pan);
        if (d.isEmpty()) return "";
        Network n = networkFromPan(d);
        int[] groups = (n == Network.AMEX)   ? new int[]{4, 4, 4, 3}
                     : (n == Network.DINERS) ? new int[]{4, 6, 4}
                     :                         new int[]{4, 4, 4, 4, 3};
        StringBuilder sb = new StringBuilder();
        int i = 0;
        for (int g : groups) {
            if (i >= d.length()) break;
            if (sb.length() > 0) sb.append(' ');
            sb.append(d, i, Math.min(d.length(), i + g));
            i += g;
        }
        if (i < d.length()) sb.append(' ').append(d.substring(i));
        return sb.toString();
    }

    public static String last4(String pan) {
        String d = digits(pan);
        return d.length() >= 4 ? d.substring(d.length() - 4) : d;
    }

    private static String digits(String s) {
        return s == null ? "" : s.replaceAll("[^0-9]", "");
    }

    private static int num(String s, int len) {
        if (s.length() < len) return -1;
        try {
            return Integer.parseInt(s.substring(0, len));
        } catch (NumberFormatException e) {
            return -1;
        }
    }
}
