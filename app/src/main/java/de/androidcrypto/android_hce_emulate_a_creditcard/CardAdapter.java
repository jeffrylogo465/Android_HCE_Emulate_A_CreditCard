package de.androidcrypto.android_hce_emulate_a_creditcard;
import android.graphics.drawable.GradientDrawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import java.util.ArrayList;
import java.util.List;

public class CardAdapter extends RecyclerView.Adapter<CardAdapter.CardHolder> {

    public static class CardModel {
        public String label = "";
        public String pan = "";
        public String expiry = "";
        public String aid = "";
        public int msd = 1;

        public CardModel() { }

        public CardModel(String label, String pan, String expiry, String aid, int msd) {
            this.label = label;
            this.pan = pan;
            this.expiry = expiry;
            this.aid = aid;
            this.msd = msd;
        }
    }

    private static final int[][] GRADIENTS = {
            {0xFF4F46E5, 0xFF7C3AED, 0xFFDB2777},
            {0xFF0F766E, 0xFF0D9488, 0xFF22C55E},
            {0xFFB45309, 0xFFF59E0B, 0xFFFDE047},
            {0xFFBE123C, 0xFFE11D48, 0xFFFB7185},
            {0xFF1D4ED8, 0xFF3B82F6, 0xFF60A5FA},
            {0xFF6D28D9, 0xFF8B5CF6, 0xFFC4B5FD}
    };

    private final List<CardModel> cards = new ArrayList<>();

    public void setCards(List<CardModel> list) {
        cards.clear();
        cards.addAll(list);
        notifyDataSetChanged();
    }

    public int size() {
        return cards.size();
    }

    @NonNull
    @Override
    public CardHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_card, parent, false);
        return new CardHolder(v);
    }

    @Override
    public void onBindViewHolder(@NonNull CardHolder h, int position) {
        CardModel c = cards.get(position);

        h.brand.setText(brandOf(c.pan, c.label));
        h.pan.setText(prettyPan(c.pan));
        h.expiry.setText(prettyExpiry(c.expiry));
        h.aid.setText(c.aid == null || c.aid.isEmpty() ? "--" : c.aid);
        h.mode.setText(c.msd == 1 ? "MSD" : "EMV");
        h.index.setText((position + 1) + "/" + cards.size());

        int[] g = GRADIENTS[position % GRADIENTS.length];
        GradientDrawable bg = new GradientDrawable(
                GradientDrawable.Orientation.TL_BR, new int[]{g[0], g[1], g[2]});
        bg.setCornerRadius(16 * h.itemView.getResources().getDisplayMetrics().density);
        h.itemView.setBackground(bg);
    }

    @Override
    public int getItemCount() {
        return cards.size();
    }

    static String brandOf(String pan, String label) {
        if (label != null && !label.trim().isEmpty()) return label.trim().toUpperCase();
        if (pan == null || pan.length() < 2) return "CARD";
        String p2 = pan.substring(0, 2);
        if (p2.equals("34") || p2.equals("37")) return "AMERICAN EXPRESS";
        if (pan.startsWith("6011") || pan.startsWith("65")) return "DISCOVER";
        if (p2.startsWith("4")) return "VISA";
        if (p2.startsWith("5") || p2.startsWith("2")) return "MASTERCARD";
        if (p2.startsWith("6")) return "DISCOVER";
        return "CARD";
    }

    static String prettyPan(String pan) {
        if (pan == null || pan.isEmpty()) return "\u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022 \u2022\u2022\u2022\u2022";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < pan.length(); i++) {
            if (i > 0 && i % 4 == 0) sb.append(' ');
            sb.append(pan.charAt(i));
        }
        return sb.toString();
    }

    static String prettyExpiry(String yymm) {
        if (yymm == null || yymm.length() < 4) return "--/--";
        return yymm.substring(2, 4) + "/" + yymm.substring(0, 2);
    }

    static class CardHolder extends RecyclerView.ViewHolder {
        final TextView brand, pan, expiry, aid, mode, index;

        CardHolder(@NonNull View v) {
            super(v);
            brand = v.findViewById(R.id.cardBrand);
            pan = v.findViewById(R.id.cardPan);
            expiry = v.findViewById(R.id.cardExpiry);
            aid = v.findViewById(R.id.cardAid);
            mode = v.findViewById(R.id.cardMode);
            index = v.findViewById(R.id.cardIndex);
        }
    }
}
