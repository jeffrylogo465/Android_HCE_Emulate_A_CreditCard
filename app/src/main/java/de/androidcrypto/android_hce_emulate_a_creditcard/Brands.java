package de.androidcrypto.android_hce_emulate_a_creditcard;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Card identity and styling.
 *
 * NETWORK  <- the captured AID. Authoritative.
 * BANK     <- a BIN quick table, else the issuer name BinLookup resolved.
 *            Keyword-matched, so it works for any bank on earth.
 * Unknown banks still get their real name on a neutral card.
 */
public final class Brands {

    public enum Network { VISA, MASTERCARD, AMEX, DISCOVER, JCB, UNIONPAY, DINERS, UNKNOWN }

    public static final class Style {
        public final String bankName;
        public final String bankIcon;     // full URL or null
        public final String networkIcon;  // iconify slug or null
        public final String networkTint;  // "FFFFFF" on dark cards, else null
        public final boolean knownBank;
        public final int bg, fg, muted;

        Style(String bankName, String bankIcon, String networkIcon, String networkTint,
              boolean knownBank, int bg, int fg, int muted) {
            this.bankName = bankName;
            this.bankIcon = bankIcon;
            this.networkIcon = networkIcon;
            this.networkTint = networkTint;
            this.knownBank = knownBank;
            this.bg = bg;
            this.fg = fg;
            this.muted = muted;
        }
    }

    private static final String LOGO = "https://logo.clearbit.com/";

    private static final class Bank {
        final String[] keywords;
        final String domain;
        final int bg, fg, muted;
        Bank(String keywords, String domain, int bg, int fg, int muted) {
            this.keywords = keywords.split("\\|");
            this.domain = domain;
            this.bg = bg; this.fg = fg; this.muted = muted;
        }
    }

    /** Specific before generic. Keywords are pre-normalised (no dots/punctuation). */
    private static final Bank[] BANKS = {
            new Bank("BANK OF AMERICA|B OF A|BAC", "bankofamerica.com", 0xFFFFFFFF, 0xFF0B1A3A, 0xFF5B6B8A),
            new Bank("CHASE|JPMORGAN",             "chase.com",         0xFF0B2D5C, 0xFFFFFFFF, 0xFF9FC0E8),
            new Bank("WELLS FARGO",                "wellsfargo.com",    0xFFC8102E, 0xFFFFFFFF, 0xFFF7C9D0),
            new Bank("CITI",                       "citi.com",          0xFF056DAE, 0xFFFFFFFF, 0xFFB7DCF3),
            new Bank("CAPITAL ONE",                "capitalone.com",    0xFFF7F7F5, 0xFF0D2B45, 0xFF6B7280),
            new Bank("DISCOVER",                   "discover.com",      0xFFF4F4F2, 0xFF1C1917, 0xFF6B7280),
            new Bank("US BANK|USBANK",             "usbank.com",        0xFF0C2074, 0xFFFFFFFF, 0xFFA9B8E8),
            new Bank("PNC",                        "pnc.com",           0xFF1F3B70, 0xFFFFFFFF, 0xFFB8C7E0),
            new Bank("TD BANK|TD BANKN",           "tdbank.com",        0xFF54B948, 0xFF0B2B06, 0xFF2F6B27),
            new Bank("ALLY",                       "ally.com",          0xFF6C2EB9, 0xFFFFFFFF, 0xFFD9C6F0),
            new Bank("AMERICAN EXPRESS|AMEX",      "americanexpress.com",0xFF006FCF, 0xFFFFFFFF, 0xFFCFE4FF),
            new Bank("BARCLAYS",                   "barclays.com",      0xFF00AEEF, 0xFF002A45, 0xFF00689C),
            new Bank("HSBC",                       "hsbc.com",          0xFFDB0011, 0xFFFFFFFF, 0xFFF7C7CC),
            new Bank("SANTANDER",                  "santander.com",     0xFFEC0000, 0xFFFFFFFF, 0xFFF7C7C7),
            new Bank("NAVY FEDERAL",               "navyfederal.org",   0xFF003057, 0xFFFFFFFF, 0xFFB3C4D6),
            new Bank("USAA",                       "usaa.com",          0xFF00447C, 0xFFFFFFFF, 0xFFBFD4E6),
            new Bank("SCHWAB",                     "schwab.com",        0xFF00A0DF, 0xFF002A45, 0xFF00689C),
            new Bank("FIDELITY",                   "fidelity.com",      0xFF4A9E2F, 0xFFFFFFFF, 0xFFCDE8C4),
            new Bank("REGIONS",                    "regions.com",       0xFF007A33, 0xFFFFFFFF, 0xFFBFE3CB),
            new Bank("KEYBANK",                    "keybank.com",       0xFF1B365D, 0xFFFFFFFF, 0xFFB9C5D6),
            new Bank("FIFTH THIRD|53",             "53.com",            0xFF00447C, 0xFFFFFFFF, 0xFFBFD4E6),
            new Bank("HUNTINGTON",                 "huntington.com",    0xFF007A33, 0xFFFFFFFF, 0xFFBFE3CB),
            new Bank("CITIZENS",                   "citizensbank.com",  0xFF00843D, 0xFFFFFFFF, 0xFFBFE4CE),
            new Bank("TRUIST|BBT|SUNTRUST",        "truist.com",        0xFF4F2D7F, 0xFFFFFFFF, 0xFFD2C6E5),
            new Bank("BMO|HARRIS BANK",            "bmo.com",           0xFF0079C1, 0xFFFFFFFF, 0xFFBEE0F4),
            new Bank("SYNCHRONY",                  "synchronybank.com", 0xFF1D3E8E, 0xFFFFFFFF, 0xFFC3CEEB),
            new Bank("GOLDMAN|MARCUS",             "goldmansachs.com",  0xFF7399C6, 0xFF0B1A3A, 0xFF4A6E9E),
            new Bank("SOFI",                       "sofi.com",          0xFF00A5B5, 0xFF00262B, 0xFF00838F),
            new Bank("CHIME",                      "chime.com",         0xFF1EC677, 0xFF00261A, 0xFF0E7A47),
            new Bank("VARO",                       "varo.com",          0xFF3B2E8C, 0xFFFFFFFF, 0xFFC8C2EC),
            new Bank("CURRENT",                    "current.com",       0xFF0B0B0B, 0xFFFFFFFF, 0xFF9CA3AF),
            new Bank("NETSPEND",                   "netspend.com",      0xFFF58220, 0xFF1A1A1A, 0xFFB25C10),
            new Bank("GREEN DOT|GREENDOT",         "greendot.com",      0xFF4CB748, 0xFFFFFFFF, 0xFFC9E8C6),
            new Bank("TARGET",                     "target.com",        0xFFCC0000, 0xFFFFFFFF, 0xFFF7C7C7),
            new Bank("WALMART",                    "walmart.com",       0xFF0071CE, 0xFFFFFFFF, 0xFFBFDFF5),
            new Bank("AMAZON",                     "amazon.com",        0xFF232F3E, 0xFFFFFFFF, 0xFFB9C0C9),
            new Bank("STARBUCKS",                  "starbucks.com",     0xFF00704A, 0xFFFFFFFF, 0xFFB8D9CB),
            new Bank("BEST BUY",                   "bestbuy.com",       0xFF0046BE, 0xFFFFF200, 0xFFBFCDE8),
            new Bank("HOME DEPOT",                 "homedepot.com",     0xFFF96302, 0xFF1A1A1A, 0xFFB34A02),
            new Bank("LOWES",                      "lowes.com",         0xFF004990, 0xFFFFFFFF, 0xFFB3C9DF),
            new Bank("MACYS",                      "macys.com",         0xFFE21A2C, 0xFFFFFFFF, 0xFFF7C7CC),
            new Bank("NORDSTROM",                  "nordstrom.com",     0xFF1A1A1A, 0xFFFFFFFF, 0xFF9CA3AF),
            new Bank("KOHLS",                      "kohls.com",         0xFF002D62, 0xFFFFFFFF, 0xFFB3C0D6),
            new Bank("COSTCO",                     "costco.com",        0xFFE31837, 0xFFFFFFFF, 0xFFF7C9D0),
            new Bank("KROGER",                     "kroger.com",        0xFF003DA5, 0xFFFFFFFF, 0xFFB3C8E8),
            new Bank("ALDI",                       "aldi.com",          0xFF001E5A, 0xFFFFFFFF, 0xFFB3BFD6),
            new Bank("APPLE",                      "apple.com",         0xFF1A1A1A, 0xFFFFFFFF, 0xFF9CA3AF),
            new Bank("SHELL",                      "shell.com",         0xFFFBCE07, 0xFF1A1A1A, 0xFF8A6F00),
            new Bank("CHEVRON",                    "chevron.com",       0xFF0C5AA8, 0xFFFFFFFF, 0xFFB6CDE8),
            new Bank("EXXON",                      "exxon.com",         0xFFE50000, 0xFFFFFFFF, 0xFFF7C7C7),
    };

    /** Instant offline hits for the BINs you already know. Value is a keyword. */
    private static final Map<String, String> BIN = new LinkedHashMap<>();
    static {
        BIN.put("4117",   "BANK OF AMERICA");
        BIN.put("411773", "BANK OF AMERICA");
        BIN.put("43568",  "BANK OF AMERICA");
        BIN.put("4124",   "CHASE");
        BIN.put("414734", "CHASE");
        BIN.put("4366",   "CHASE");
        BIN.put("4128",   "CITI");
        BIN.put("436618", "US BANK");
        BIN.put("412266", "TD BANK");
        BIN.put("510805", "CAPITAL ONE");
        BIN.put("514745", "CAPITAL ONE");
        BIN.put("514759", "CAPITAL ONE");
        BIN.put("601141", "CAPITAL ONE");
        BIN.put("601144", "CAPITAL ONE");
        BIN.put("601146", "CAPITAL ONE");
    }

    private Brands() {
    }

    // ------------------------------------------------------------------ network

    public static Network network(String aid, String pan) {
        if (aid != null) {
            String a = aid.toUpperCase(Locale.US).replaceAll("[^0-9A-F]", "");
            if (a.startsWith("A000000152")) return Network.DISCOVER;
            if (a.startsWith("A000000003")) return Network.VISA;
            if (a.startsWith("A000000004")) return Network.MASTERCARD;
            if (a.startsWith("A000000025")) return Network.AMEX;
            if (a.startsWith("A000000065")) return Network.JCB;
            if (a.startsWith("A000000333")) return Network.UNIONPAY;
            if (a.startsWith("A000000324")) return Network.DINERS;
        }
        return networkFromPan(pan);
    }

    public static Network networkFromPan(String pan) {
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
            // FIX: 622 must be tested BEFORE the bare 62. 62 used to swallow it,
            // so the 622126-622925 Discover co-brand range was unreachable.
            if (d.startsWith("622")) return Network.DISCOVER;
            if (d.startsWith("62")) return Network.UNIONPAY;
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

    /** Longest matching BIN prefix wins. */
    public static String bankKeywordFromBin(String pan) {
        String d = digits(pan);
        if (d.isEmpty()) return null;
        String best = null;
        int bestLen = 0;
        for (Map.Entry<String, String> e : BIN.entrySet()) {
            if (e.getKey().length() > bestLen && d.startsWith(e.getKey())) {
                best = e.getValue();
                bestLen = e.getKey().length();
            }
        }
        return best;
    }

    /**
     * Keyword match against an issuer name from BinLookup.
     *
     * FIX: LONGEST matching keyword wins, not the first one in array order.
     * First-match-wins meant "CITIZENS BANK" hit CITI's keyword at index 3 and
     * was labelled CITI before CITIZENS at index 22 was ever consulted. It also
     * stops the weak 2-char "53" keyword for Fifth Third from stealing any name
     * that merely contains "53".
     */
    public static String bankKeywordFromIssuer(String issuerName) {
        if (issuerName == null || issuerName.isEmpty()) return null;
        String n = normalise(issuerName);
        String best = null;
        int bestLen = 0;
        for (Bank b : BANKS) {
            for (String k : b.keywords) {
                if (k.length() > bestLen && n.contains(k)) {
                    best = k;
                    bestLen = k.length();
                }
            }
        }
        return best;
    }

    private static Bank bankFor(String keyword) {
        if (keyword == null) return null;
        for (Bank b : BANKS) {
            for (String k : b.keywords) {
                if (k.equals(keyword)) return b;
            }
        }
        return null;
    }

    // -------------------------------------------------------------------- style

    public static Style styleFor(String pan, String aid, String issuerName, String issuerDomain) {
        Network net = network(aid, pan);

        String keyword = bankKeywordFromBin(pan);
        if (keyword == null) keyword = bankKeywordFromIssuer(issuerName);

        Bank bank = bankFor(keyword);
        if (bank != null) {
            // keyword is a single split entry, so there are no pipes left to expand
            String name = keyword.replace("|", " / ");
            String icon = bank.domain == null ? null : LOGO + bank.domain;
            return new Style(name, icon, networkIcon(net), networkTint(net),
                    true, bank.bg, bank.fg, bank.muted);
        }

        // Issuer known by name but not in our keyword table: real name, real logo
        // from its domain, neutral colours. Still recognisably that bank.
        if (issuerName != null && !issuerName.isEmpty()) {
            String icon = issuerDomain == null ? null : LOGO + issuerDomain;
            return new Style(issuerName, icon, networkIcon(net), networkTint(net),
                    true, 0xFF1F2937, 0xFFFFFFFF, 0xFF9CA3AF);
        }

        String label = networkLabel(net);
        switch (net) {
            case VISA:
                return new Style(label, null, networkIcon(net), "FFFFFF", false, 0xFF1A1F71, 0xFFFFFFFF, 0xFFB9BEDC);
            case AMEX:
                return new Style(label, null, networkIcon(net), "FFFFFF", false, 0xFF006FCF, 0xFFFFFFFF, 0xFFCFE4FF);
            case DISCOVER:
                return new Style(label, null, networkIcon(net), null, false, 0xFFF4F4F2, 0xFF1C1917, 0xFF6B7280);
            case JCB:
                return new Style(label, null, networkIcon(net), "FFFFFF", false, 0xFF0B4EA2, 0xFFFFFFFF, 0xFFC2D6F0);
            case UNIONPAY:
                return new Style(label, null, networkIcon(net), "FFFFFF", false, 0xFF00447C, 0xFFFFFFFF, 0xFFBFD4E6);
            case DINERS:
                return new Style(label, null, networkIcon(net), "FFFFFF", false, 0xFF0079BE, 0xFFFFFFFF, 0xFFC2E0F2);
            case MASTERCARD:
                return new Style(label, null, networkIcon(net), "FFFFFF", false, 0xFF141414, 0xFFFFFFFF, 0xFF9CA3AF);
            default:
                return new Style("UNKNOWN ISSUER", null, networkIcon(net), "FFFFFF", false, 0xFF1F2937, 0xFFFFFFFF, 0xFF9CA3AF);
        }
    }

    /** White network mark on dark cards, brand colour on light ones. */
    private static String networkTint(Network n) {
        switch (n) {
            case DISCOVER: return null;
            default:       return "FFFFFF";
        }
    }

    // ---------------------------------------------------------------- formatting

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

    private static String normalise(String s) {
        return s.toUpperCase(Locale.US).replaceAll("[^A-Z0-9 ]", "").replaceAll(" +", " ").trim();
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
