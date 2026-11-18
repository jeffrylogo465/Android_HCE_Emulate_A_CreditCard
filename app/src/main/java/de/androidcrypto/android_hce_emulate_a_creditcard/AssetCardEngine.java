package de.androidcrypto.android_hce_emulate_a_creditcard;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * A card that answers from app/src/main/assets/profile.json instead of from
 * hand-typed bytes: the mrautio/emv-card-simulator test card (Zlib licence),
 * AID AFFFFFFFFF1234.
 *
 * Pure Java, no Android types, so the whole PPSE-to-GENERATE-AC flow runs as a
 * plain unit test. ShadowApduService owns one and persists the ATC around it.
 *
 * What it does, and the one place it differs from the source simulator:
 *  - GPO answers a format-2 template, as the simulator's own setup does:
 *    77 { 82 AIP, 94 AFL }.
 *  - The PDOL is read out of the selected application's A5 template (tag 9F38).
 *    The published profile has none, so for this card the GPO data is "83 00".
 *  - READ RECORD walks the AFL and builds each record from the tag list the
 *    profile gives for that SFI/record.
 *  - GENERATE AC derives SK from MK_AC and the ATC (Book 2 A1.3.1) and computes
 *    the AC with ISO 9797-1 MAC Algorithm 3 over CDOL1 data || AIP || ATC || 9F10.
 *    The second GENERATE AC of a transaction is parsed against CDOL2 and its AC
 *    is computed the same way over the CDOL2 data, so it differs from the first.
 *    The CID in both responses is the profile's 9F27. A third one is refused
 *    with 6985.
 *  - The ATC advances once per GPO, as in the simulator.
 */
final class AssetCardEngine {

    static final String AID = "AFFFFFFFFF1234";
    static final String ASSET = "profile.json";
    static final String ICC_KEY_ASSET = "icc_private_key.pem";

    private static final byte[] PPSE = Hex.hex("325041592E5359532E4444463031");

    // Tag order of the GENERATE AC response, from the profile's setup
    // "80 02 00 03 08 9F27 9F36 9F26 9F10".
    private static final int[] GENAC_TEMPLATE = {0x9F27, 0x9F36, 0x9F26, 0x9F10};

    private static final byte[] SW_OK = Hex.hex("9000");

    private final Map<String, String> tags = new HashMap<>();
    private final Map<String, String[]> records = new HashMap<>();
    private final String pan;
    private final String expiry;
    private final String serviceCode;
    private final String track2;
    private final String afl;
    private final String aip;
    private final String cdol1;
    private final String cdol2;
    private final String mkAc;

    private int atc;

    /** ICC RSA key for INTERNAL AUTHENTICATE, or null when none was loaded. */
    private BigInteger iccModulus;
    private BigInteger iccPrivateExponent;
    private final SecureRandom random = new SecureRandom();

    private boolean selected;
    /** The real brand this card is answering as, or null for its own AFFFFFFFFF1234 identity. */
    private AssetSchemeProfile scheme;
    /**
     * A captured real-card chain, loaded on top of the scheme/profile.json
     * cascade - see loadDump(). Separate mode from AssetSchemeProfile: this
     * never changes what a scheme profile serves, only what this engine
     * serves when no scheme (or any scheme) is bound and a dump is active.
     * Not reset by clearState(), same reasoning as a bound scheme used to
     * follow for the retired LoadedCard integration: a loaded dump outlives
     * one SELECT/GPO/GENERATE AC cycle.
     */
    private DumpChain dumpChain;
    /** The SDA result from the dump's own load - a warning badge, never a gate. */
    private OdaVerifier.Result dumpVerify;
    private boolean gpoOk;
    /** GENERATE ACs answered since the last GPO: 0, 1 or 2. */
    private int acCount;
    private final Map<String, String> terminal = new HashMap<>();

    private AssetCardEngine(JsonObject o) {
        pan = str(o, "pan");
        expiry = str(o, "expiry");
        serviceCode = str(o, "serviceCode");
        track2 = str(o, "track2");
        afl = str(o, "afl");
        aip = str(o, "aip");
        cdol1 = str(o, "cdol1");
        cdol2 = str(o, "cdol2");
        mkAc = str(o, "mkAc");
        atc = Integer.parseInt(str(o, "atc"), 16);

        for (Map.Entry<String, JsonElement> e : o.getAsJsonObject("tags").entrySet()) {
            tags.put(e.getKey().toUpperCase(Locale.ROOT), e.getValue().getAsString());
        }
        for (Map.Entry<String, JsonElement> e : o.getAsJsonObject("records").entrySet()) {
            JsonArray a = e.getValue().getAsJsonArray();
            String[] list = new String[a.size()];
            for (int i = 0; i < list.length; i++) list[i] = a.get(i).getAsString();
            records.put(e.getKey(), list);
        }
        if (Hex.hex(mkAc).length != 16) {
            throw new IllegalArgumentException("MK_AC must be a double-length 3DES key");
        }
        if (Hex.hex(afl).length % 4 != 0 || Hex.hex(aip).length != 2) {
            throw new IllegalArgumentException("bad AIP or AFL in profile");
        }
    }

    private static String str(JsonObject o, String k) {
        JsonElement e = o.get(k);
        if (e == null || e.isJsonNull()) throw new IllegalArgumentException("profile has no " + k);
        return e.getAsString().toUpperCase(Locale.ROOT);
    }

    static AssetCardEngine load(InputStream in) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
        String json = new String(bo.toByteArray(), StandardCharsets.UTF_8);
        return new AssetCardEngine(JsonParser.parseString(json).getAsJsonObject());
    }

    /** Profile plus the ICC private key (PEM, PKCS#1 or PKCS#8) used for DDA. */
    static AssetCardEngine load(InputStream profile, InputStream keyPem) throws IOException {
        AssetCardEngine e = load(profile);
        e.setIccKey(readAll(keyPem));
        return e;
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
        return bo.toByteArray();
    }

    private void setIccKey(byte[] pem) throws IOException {
        String text = new String(pem, StandardCharsets.US_ASCII);
        boolean pkcs1 = text.contains("BEGIN RSA PRIVATE KEY");
        String b64 = text.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        byte[] der;
        try {
            der = Base64.decode(b64);
        } catch (RuntimeException ex) {
            throw new IOException("ICC key is not a PEM file: " + ex.getMessage(), ex);
        }
        RSAPrivateKey k = RSAPrivateKey.getInstance(pkcs1
                ? ASN1Primitive.fromByteArray(der)
                : PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(der)).parsePrivateKey());
        iccModulus = k.getModulus();
        iccPrivateExponent = k.getPrivateExponent();
    }

    // ---------- profile accessors ----------

    /** This engine's own PAN, or - when a dump is loaded and carries one - the dump's own PAN (tag 5A). */
    String pan() {
        byte[] v = dumpChain == null ? null : dumpChain.tag(0x5A);
        return v == null ? pan : Hex.toHex(v);
    }

    /** Expiry (tag 5F24): the dump's own, when a dump is loaded and carries one. */
    String expiry() {
        byte[] v = dumpChain == null ? null : dumpChain.tag(0x5F24);
        return v == null ? expiry : Hex.toHex(v);
    }

    /** PAN Sequence Number (tag 5F34): the dump's own, when a dump is loaded and carries one. */
    String psn() {
        byte[] v = dumpChain == null ? null : dumpChain.tag(0x5F34);
        if (v != null) return Hex.toHex(v);
        String own = tags.get("5F34");
        return own == null ? null : own;
    }

    String serviceCode() { return serviceCode; }
    String track2() { return track2; }
    /** The AFL this engine actually serves/walks right now - see currentAfl(). */
    String afl() { return currentAfl(); }
    /** The AIP this engine actually serves/signs with right now - see currentAip(). */
    String aip() { return currentAip(); }
    String cdol1() { return cdol1; }
    String cdol2() { return cdol2; }
    String mkAc() { return mkAc; }

    int atc() { return atc; }
    void setAtc(int v) { atc = v & 0xFFFF; }

    /** A terminal data object received in the last GPO or GENERATE AC, or null. */
    String terminalData(String t) { return terminal.get(t.toUpperCase(Locale.ROOT)); }

    boolean isSelected() { return selected; }

    // ---------- dump mode ----------

    /**
     * Loads a captured TLV dump (see DumpChain) as this engine's active
     * identity: its own chain tags and AFL-named records, served verbatim,
     * replace the shared profile's; CDOL1/CDOL2/MK_AC/ATC and the generic
     * wire mechanism are untouched, since a dump cannot carry a secret key.
     *
     * Runs the SDA verifier immediately and keeps the result for
     * lastDumpVerify() - a badge, never a gate: a failed or unresolved
     * verification still serves the dump's own bytes exactly as captured.
     *
     * @param cas the CA keys to check the dump's issuer cert against, or
     *            null to skip straight to a CA_KEY failure (still just a
     *            badge)
     * @throws IllegalArgumentException naming the missing/malformed tag, if
     *                                   the blob does not parse
     */
    void loadDump(byte[] blob, CaKeySet cas) {
        DumpChain.Result r = DumpChain.parse(blob);
        if (!r.ok) throw new IllegalArgumentException("dump: " + r.error);
        dumpChain = r.chain;

        // No AID at all (or too short to even plausibly be one) is a
        // different failure from "AID present but not in the keyset": there
        // is no RID to look a CA key up by in the first place, so this
        // never reaches CA_KEY.
        if (dumpChain.aid == null || dumpChain.aid.length < 6) {
            dumpVerify = OdaVerifier.Result.fail(OdaVerifier.Step.NO_AID, "no tag 84 (AID), or under 6 bytes");
            return;
        }
        byte[] rid = dumpChain.rid();
        CaKeySet.Key ca = cas != null ? cas.find(rid, dumpChain.caIndex) : null;
        dumpVerify = OdaVerifier.verifySda(ca, dumpChain.issuerCert, dumpChain.issuerRemainder,
                dumpChain.issuerExponent, dumpChain.afl, dumpChain.recordSource(), dumpChain.aip,
                dumpChain.sdaTagList, dumpChain.ssad);
    }

    void clearDump() {
        dumpChain = null;
        dumpVerify = null;
    }

    boolean hasDump() { return dumpChain != null; }

    /** The SDA result from the dump's own load, or null when no dump is active. */
    OdaVerifier.Result lastDumpVerify() { return dumpVerify; }

    // ---------- dispatch ----------

    byte[] process(byte[] apdu) {
        if (apdu == null || apdu.length < 4) return sw("6700");
        int ins = apdu[1] & 0xFF;
        switch (ins) {
            case 0xA4: return select(apdu);
            case 0xA8: return gpo(apdu);
            case 0xB2: return readRecord(apdu);
            case 0xAE: return generateAc(apdu);
            case 0x88: return internalAuthenticate(apdu);
            default:   return sw("6D00");
        }
    }

    private static byte[] sw(String hex) { return Hex.hex(hex); }

    /** Command data, or null when Lc promises more than the APDU holds. */
    private static byte[] dataOf(byte[] apdu) {
        if (apdu.length < 5) return new byte[0];
        int lc = apdu[4] & 0xFF;
        if (apdu.length < 5 + lc) return null;
        return Arrays.copyOfRange(apdu, 5, 5 + lc);
    }

    private static byte[] ok(byte[] body) { return Tlv.cat(body, SW_OK); }

    private void clearState() {
        selected = false;
        scheme = null;
        gpoOk = false;
        acCount = 0;
        terminal.clear();
    }

    // ---------- SELECT ----------

    private byte[] select(byte[] apdu) {
        byte[] name = dataOf(apdu);
        if (name == null) return sw("6700");

        if (Arrays.equals(name, PPSE)) {
            byte[] entry = Tlv.t(0x61, Tlv.cat(
                    Tlv.t(0x4F, Hex.hex(AID)),
                    Tlv.t(0x50, Hex.hex(need("50"))),
                    Tlv.t(0x87, Hex.hex(need("87")))));
            byte[] fci = Tlv.t(0x6F, Tlv.cat(
                    Tlv.t(0x84, PPSE),
                    Tlv.t(0xA5, Tlv.t(0xBF0C, entry))));
            return ok(fci);
        }

        if (!Arrays.equals(name, Hex.hex(AID))) return sw("6A82");

        clearState();
        selected = true;
        return ok(Tlv.t(0x6F, Tlv.cat(
                Tlv.t(0x84, Hex.hex(need("84"))),
                Tlv.t(0xA5, Hex.hex(need("A5"))))));
    }

    /**
     * Binds this card as selected under a name that is not its own AID.
     *
     * A terminal that does not recognise AFFFFFFFFF1234 is offered the real
     * brand AID as a PPSE fallback entry (see ShadowApduService.buildAssetPpse),
     * and when it SELECTs that AID this card must answer exactly as it would
     * for its own AID - same A5, same selected state, same AIP/AFL once GPO
     * runs - with only the DF name in tag 84 rewritten to what was actually
     * requested. Without this, the SELECT fell through to the ordinary
     * dispatch, which has no AIP/AFL of its own to serve and left this card's
     * `selected` flag false, so the GPO that followed answered 6985.
     */
    byte[] selectAs(byte[] requestedName) {
        clearState();
        selected = true;
        return ok(Tlv.t(0x6F, Tlv.cat(
                Tlv.t(0x84, requestedName),
                Tlv.t(0xA5, Hex.hex(need("A5"))))));
    }

    /**
     * Binds this card as selected under one of the three real, scheme-shaped
     * fallback AIDs (see AssetSchemeProfile) rather than the generic
     * Mastercard-shaped selectAs(). The FCI's A5 is built fresh from the
     * scheme's own label/9F12/AIP and - unlike every other path through this
     * engine - carries a real 9F38 PDOL, so the terminal does not send an
     * empty GPO.
     */
    byte[] selectScheme(AssetSchemeProfile s, byte[] requestedAid) {
        clearState();
        selected = true;
        scheme = s;
        byte[] a5 = Tlv.cat(
                Tlv.t(0x50, s.label.getBytes(StandardCharsets.US_ASCII)),
                Tlv.t(0x5F2D, Hex.hex("656E")),
                Tlv.t(0x87, Hex.hex("01")),
                Tlv.t(0x9F12, Hex.hex(s.preferredName)),
                Tlv.t(0x9F38, Hex.hex(s.pdol(cdol1))));
        return ok(Tlv.t(0x6F, Tlv.cat(
                Tlv.t(0x84, requestedAid),
                Tlv.t(0xA5, a5))));
    }

    /**
     * The AIP to serve/sign with: a loaded dump's own (computed, not copied -
     * see dumpAip()), else the bound scheme's, else this card's own.
     * AssetSchemeProfile is never consulted once a dump is active - the two
     * are separate modes.
     */
    private String currentAip() {
        if (dumpChain != null) return Hex.toHex(dumpAip());
        return scheme != null ? scheme.aip() : aip;
    }

    /**
     * Dump mode's AIP: provenance, not a mask. Start from the dump's own
     * captured AIP (every bit, both bytes) and touch only what this mode's
     * own capabilities actually change:
     *  - CDA (0x01) is always cleared - a captured dump never carries an ICC
     *    private key, so CDA (which needs one) is never possible here.
     *  - Issuer Authentication (0x04) is always cleared - it needs an ARPC
     *    from the issuer's own authorisation network, which a dump cannot
     *    obtain any more than it can sign a cryptogram.
     *  - When the dump carries a tag 93, SDA (0x40) is set and DDA (0x20) is
     *    cleared - the dump itself is now how this card does ODA.
     *  - When the dump carries no tag 93, SDA and DDA are left exactly as
     *    the source card declared them, DDA included, even though this
     *    engine cannot back a DDA claim (internalAuthenticate() answers
     *    6985, not a silent 6D00, for exactly that reason: a real refusal
     *    to a capability the replayed AIP still claims, not "no such
     *    command").
     */
    private byte[] dumpAip() {
        int b1 = dumpChain.aip[0] & 0xFF;
        b1 &= ~0x01; // CDA: never possible in dump mode
        b1 &= ~0x04; // Issuer Authentication: needs an ARPC a dump cannot obtain
        if (dumpChain.ssad != null) {
            b1 |= 0x40;  // SDA: this dump is the SSAD
            b1 &= ~0x20; // DDA: superseded by SDA, not also claimed
        }
        int b2 = dumpChain.aip.length > 1 ? (dumpChain.aip[1] & 0xFF) : 0;
        return new byte[]{(byte) b1, (byte) b2};
    }

    /** The AFL to serve/walk: a loaded dump's own, else the bound scheme's (none today), else this card's own. */
    private String currentAfl() { return dumpChain != null ? Hex.toHex(dumpChain.afl) : afl; }

    private String need(String t) {
        String v = tag(t);
        if (v == null) throw new IllegalStateException("profile has no tag " + t);
        return v;
    }

    /**
     * A tag's value, with the bound scheme's own bytes taking priority over
     * the shared profile - today just 8F (CA index) and, for Amex, 8E (CVM
     * list). Every other tag, including the whole certificate chain, is
     * deliberately shared across schemes; see AssetSchemeProfile's class doc.
     */
    String tag(String t) {
        String up = t.toUpperCase(Locale.ROOT);
        if (up.equals("82")) return currentAip();
        if (up.equals("94")) return currentAfl();
        if (scheme != null) {
            if (up.equals("8F")) return scheme.caIndex;
            if (up.equals("8E") && scheme.cvmListOverride() != null) return scheme.cvmListOverride();
        }
        return tags.get(up);
    }

    // ---------- GET PROCESSING OPTIONS ----------

    private byte[] gpo(byte[] apdu) {
        if (!selected) return sw("6985");
        byte[] data = dataOf(apdu);
        if (data == null || data.length < 2 || (data[0] & 0xFF) != 0x83) return sw("6700");
        int len = data[1] & 0xFF;
        if (data.length != 2 + len) return sw("6700");

        int[] pdol = parseDol(pdolBytes());
        if (len != dolLength(pdol)) return sw("6700");
        if (atc >= 0xFFFF) return sw("6985");

        terminal.clear();
        takeTerminalData(pdol, Arrays.copyOfRange(data, 2, data.length));

        atc++;
        gpoOk = true;
        acCount = 0;
        return ok(Tlv.t(0x77, Tlv.cat(
                Tlv.t(0x82, Hex.hex(currentAip())),
                Tlv.t(0x94, Hex.hex(currentAfl())))));
    }

    /**
     * The PDOL for the selected identity: the bound scheme's own PDOL (built
     * in selectScheme(), brand tag then CDOL1's base set), or - for this
     * card's own AFFFFFFFFF1234 identity - whatever 9F38 the A5 template
     * carries, empty if it has none.
     */
    private byte[] pdolBytes() {
        if (scheme != null) return Hex.hex(scheme.pdol(cdol1));
        byte[] v = findTag(Hex.hex(need("A5")), 0x9F38);
        return v == null ? new byte[0] : v;
    }

    private void takeTerminalData(int[] dol, byte[] data) {
        int pos = 0;
        for (int i = 0; i < dol.length; i += 2) {
            terminal.put(String.format(Locale.ROOT, "%X", dol[i]),
                    Hex.toHex(Arrays.copyOfRange(data, pos, pos + dol[i + 1])));
            pos += dol[i + 1];
        }
    }

    // ---------- READ RECORD ----------

    private byte[] readRecord(byte[] apdu) {
        if (!gpoOk) return sw("6985");
        int rec = apdu[2] & 0xFF;
        int p2 = apdu[3] & 0xFF;
        if ((p2 & 0x07) != 0x04) return sw("6A86");
        int sfi = p2 >> 3;

        // Flat 4-byte hops, but a trailing, length-prefixed AID list after
        // the last real entry (the same non-spec shape ShadowApduService's
        // AFL_MC_PROBE_WITH_AID/aflContains() use) is skipped rather than
        // misread as further entries: the 4 bytes right after an entry are
        // only trusted as another entry when they pass the same last>=first
        // test a real entry must pass anyway (see DumpChain.afterAflEntry(),
        // which this mirrors - that class's AFLs are genuinely multi-entry,
        // unlike aflContains()'s one caller, so the same unconditional skip
        // would mis-walk them). Getting this wrong either falsely admits a
        // record outside the real AFL, or misaligns every entry after the
        // AID list so a legitimately named record is wrongly refused with
        // 6A83.
        byte[] a = Hex.hex(currentAfl());
        boolean inAfl = false;
        int i = 0;
        while (i + 4 <= a.length) {
            if (((a[i] & 0xFF) >> 3) == sfi && rec >= (a[i + 1] & 0xFF) && rec <= (a[i + 2] & 0xFF)) {
                inAfl = true;
            }
            int next = i + 4;
            if (next + 4 <= a.length && (a[next + 2] & 0xFF) >= (a[next + 1] & 0xFF)) {
                i = next; // looks like a real entry - let the loop read it as one
            } else if (next < a.length) {
                int len = a[next] & 0xFF;
                i = next + 1 + len;
            } else {
                i = next;
            }
        }
        if (!inAfl) return sw("6A83");

        if (dumpChain != null) {
            // Served verbatim: the raw captured 70 template, byte for byte,
            // including whichever of 8F/90/92/9F32/9F46/9F47/9F48/93 (and
            // anything else) the real card actually put in it - nothing
            // rebuilt from a tag list, so nothing added or dropped.
            byte[] raw = dumpChain.recordSource().read(sfi, rec);
            if (raw == null) return sw("6A83");
            return ok(raw);
        }

        String[] list = records.get(sfi + ":" + rec);
        if (list == null) return sw("6A83");

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (String t : list) {
            byte[] enc = Tlv.t(Integer.parseInt(t, 16), Hex.hex(need(t)));
            body.write(enc, 0, enc.length);
        }
        return ok(Tlv.t(0x70, body.toByteArray()));
    }

    // ---------- GENERATE AC ----------

    private byte[] generateAc(byte[] apdu) {
        if (!gpoOk || acCount >= 2) return sw("6985");
        byte[] data = dataOf(apdu);
        int[] dol = parseDol(Hex.hex(acCount == 0 ? cdol1 : cdol2));
        if (data == null || data.length != dolLength(dol)) return sw("6700");

        takeTerminalData(dol, data);

        byte[] atcBytes = EmvCrypto.atcField(atc);
        byte[] iad = Hex.hex(need("9F10"));
        byte[] macIn = Tlv.cat(Tlv.cat(data, Hex.hex(currentAip())), Tlv.cat(atcBytes, iad));
        byte[] ac;
        try {
            ac = EmvCrypto.mac(sessionKey(Hex.hex(mkAc), atcBytes), macIn);
        } catch (Exception e) {
            throw new IllegalStateException("AC computation failed: " + e.getMessage(), e);
        }

        acCount++;
        byte[] body = new byte[0];
        for (int t : GENAC_TEMPLATE) {
            byte[] v;
            if (t == 0x9F36) v = atcBytes;
            else if (t == 0x9F26) v = ac;
            else v = Hex.hex(need(String.format(Locale.ROOT, "%X", t)));
            body = Tlv.cat(body, Tlv.t(t, v));
        }
        return ok(Tlv.t(0x77, body));
    }

    /**
     * EMV Book 2 A1.3.1, Common Session Key Derivation Option.
     * SK = DES3(MK)[ATC || F0 || 00 x 5] || DES3(MK)[ATC || 0F || 00 x 5].
     * MK_AC is used as the ICC master key as it stands, as the simulator does.
     */
    static byte[] sessionKey(byte[] mk16, byte[] atc2) throws Exception {
        byte[] l = new byte[8];
        byte[] r = new byte[8];
        System.arraycopy(atc2, 0, l, 0, 2);
        System.arraycopy(atc2, 0, r, 0, 2);
        l[2] = (byte) 0xF0;
        r[2] = (byte) 0x0F;
        return Tlv.cat(EmvCrypto.des3(mk16, l), EmvCrypto.des3(mk16, r));
    }

    // ---------- INTERNAL AUTHENTICATE (DDA) ----------

    /**
     * EMV Book 2 6.5: the Signed Dynamic Application Data.
     *
     * Plain RSA over  6A | 05 | 01 | LDD | ICC dynamic data | BB.. | SHA-1 | BC
     * with the hash taken over everything from the 05 up to the padding,
     * followed by the terminal's DDOL data (here the 4-byte UN, per 9F49).
     * ICC dynamic data is the ICC Dynamic Number: length byte, then 8 random
     * bytes. The AIP is NOT part of this signature (it is in SDA's static data
     * only); the ATC is not either, as no CID/AC is carried.
     */
    private byte[] internalAuthenticate(byte[] apdu) {
        if (!selected || !gpoOk) return sw("6985");
        // A captured dump never carries an ICC private key - that is
        // terminal-side data, never transmitted - so dump mode can never do
        // DDA, regardless of whatever ICC key this engine was constructed
        // with for its own (non-dump) identity. 6985, not 6D00: the dump's
        // own AIP may still claim DDA (see dumpAip()) when it had no tag
        // 93 to supersede it, so this is a real refusal of a capability the
        // card still claims, not "no such command".
        if (dumpChain != null) return sw("6985");
        if (iccModulus == null) return sw("6D00");
        byte[] ddol = Hex.hex(need("9F49"));
        byte[] data = dataOf(apdu);
        if (data == null || data.length != dolLength(parseDol(ddol))) return sw("6700");

        int nic = (iccModulus.bitLength() + 7) / 8;
        byte[] dyn = new byte[9];
        dyn[0] = 8;
        byte[] num = new byte[8];
        random.nextBytes(num);
        System.arraycopy(num, 0, dyn, 1, 8);

        byte[] block = new byte[nic];
        block[0] = 0x6A;
        block[1] = 0x05;
        block[2] = 0x01;
        block[3] = (byte) dyn.length;
        System.arraycopy(dyn, 0, block, 4, dyn.length);
        Arrays.fill(block, 4 + dyn.length, nic - 21, (byte) 0xBB);
        block[nic - 1] = (byte) 0xBC;
        byte[] hash;
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            sha.update(block, 1, nic - 22);
            sha.update(data);
            hash = sha.digest();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        System.arraycopy(hash, 0, block, nic - 21, 20);

        byte[] sig = rsaPrivate(block, nic);
        return ok(Tlv.t(0x77, Tlv.t(0x9F4B, sig)));
    }

    private byte[] rsaPrivate(byte[] block, int len) {
        byte[] raw = new BigInteger(1, block).modPow(iccPrivateExponent, iccModulus).toByteArray();
        byte[] out = new byte[len];
        int copy = Math.min(raw.length, len);
        System.arraycopy(raw, raw.length - copy, out, len - copy, copy);
        return out;
    }

    // ---------- DOL and TLV helpers ----------

    /** A DOL as [tag, length, tag, length, ...]. Throws on a list that stops mid-entry. */
    static int[] parseDol(byte[] dol) {
        int[] out = new int[dol.length];   // upper bound
        int n = 0;
        int i = 0;
        while (i < dol.length) {
            int tag = dol[i++] & 0xFF;
            if ((tag & 0x1F) == 0x1F) {
                int b;
                do {
                    if (i >= dol.length) throw new IllegalArgumentException("DOL ends inside a tag");
                    b = dol[i++] & 0xFF;
                    tag = (tag << 8) | b;
                } while ((b & 0x80) != 0);
            }
            if (i >= dol.length) throw new IllegalArgumentException("DOL entry has no length");
            out[n++] = tag;
            out[n++] = dol[i++] & 0xFF;
        }
        return Arrays.copyOf(out, n);
    }

    private static int dolLength(int[] dol) {
        int sum = 0;
        for (int i = 1; i < dol.length; i += 2) sum += dol[i];
        return sum;
    }

    /** First occurrence of a tag at the top level of a TLV sequence, or null. */
    static byte[] findTag(byte[] tlv, int wanted) {
        int i = 0;
        while (i < tlv.length) {
            int tag = tlv[i++] & 0xFF;
            if ((tag & 0x1F) == 0x1F) {
                int b;
                do {
                    if (i >= tlv.length) return null;
                    b = tlv[i++] & 0xFF;
                    tag = (tag << 8) | b;
                } while ((b & 0x80) != 0);
            }
            if (i >= tlv.length) return null;
            int len = tlv[i++] & 0xFF;
            if (len == 0x81) {
                if (i >= tlv.length) return null;
                len = tlv[i++] & 0xFF;
            } else if (len == 0x82) {
                if (i + 1 >= tlv.length) return null;
                len = ((tlv[i] & 0xFF) << 8) | (tlv[i + 1] & 0xFF);
                i += 2;
            } else if (len > 0x82) {
                return null;
            }
            if (i + len > tlv.length) return null;
            if (tag == wanted) return Arrays.copyOfRange(tlv, i, i + len);
            i += len;
        }
        return null;
    }
}
