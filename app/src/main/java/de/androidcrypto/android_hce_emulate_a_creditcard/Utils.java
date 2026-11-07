package de.androidcrypto.android_hce_emulate_a_creditcard;

import static android.content.Context.VIBRATOR_SERVICE;

import android.app.Activity;
import android.os.Build;
import android.os.VibrationEffect;
import android.os.Vibrator;

import java.lang.reflect.Array;
import java.text.SimpleDateFormat;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Date;

public class Utils {

    /**
     * converts a byte to its hex string representation
     *
     * @param data
     * @return
     */
    public static String byteToHex(byte data) {
        int hex = data & 0xFF;
        return Integer.toHexString(hex);
    }

    public static String bytesToHexNpe(byte[] bytes) {
        if (bytes == null) return "";
        StringBuffer result = new StringBuffer();
        for (byte b : bytes)
            result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static byte[] concatenateByteArrays(byte[] dataA, byte[] dataB) {
        byte[] concatenated = new byte[dataA.length + dataB.length];
        for (int i = 0; i < dataA.length; i++) {
            concatenated[i] = dataA[i];
        }
        for (int i = 0; i < dataB.length; i++) {
            concatenated[dataA.length + i] = dataB[i];
        }
        return concatenated;
    }

    public static boolean arrayBeginsWith (byte[] fullArray, byte[] searchArray) {
        if ((fullArray == null) || (searchArray == null)) return false;
        if (fullArray.length == 0) return false;
        if (searchArray.length == 0) return false;
        return Arrays.equals(Arrays.copyOf(fullArray, searchArray.length), searchArray);
    }

    public static void doVibrate(Activity activity) {
        if (activity != null) {
            // Make a Sound
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                ((Vibrator) activity.getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(50, 10));
            } else {
                Vibrator v = (Vibrator) activity.getSystemService(VIBRATOR_SERVICE);
                v.vibrate(50);
            }
        }
    }

    /**
     * section for timestamps
     */

    private static String getTimestampMillis() {
        // O = SDK 26
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return ZonedDateTime
                    .now(ZoneId.systemDefault())
                    .format(DateTimeFormatter.ofPattern("uuuu.MM.dd HH:mm:ss.SSS"));
        } else {
            return new SimpleDateFormat("yyyy.MM.dd HH:mm:ss:SSS").format(new Date());
        }
    }

    // returns a String for a filename
    public static String getTimestampMillisFile() {
        return getTimestampMillis().replaceAll(":", "_").replaceAll(":", "_").replaceAll(" ", "_").replaceAll("\\.", "_");
    }

}
