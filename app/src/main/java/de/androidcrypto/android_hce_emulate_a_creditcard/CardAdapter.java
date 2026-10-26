package de.androidcrypto.android_hce_emulate_a_creditcard;

import android.content.Context;
import android.graphics.drawable.GradientDrawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
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
        Context ctx = h.itemView.getContext();

        // Bank not known yet? Look it up once, then repaint the list.
        BinLookup.Info info = BinLookup.cached(ctx, c.pan);
        if (info == null && !BinLookup.seen(ctx, c.pan)) {
            BinLookup.fetch(ctx, c.pan, new BinLookup.Callback() {
                @Override
                public void onResult(String bin, BinLookup.Info i) {
                    notifyDataSetChanged();
                }
            });
        }

        bindTile(h.itemView, c, cards.size(), position, info);
    }

    @Override
    public int getItemCount() {
        return cards.size();
    }

    // ------------------------------------------------------------------ painting

    public static void bindTile(View root, CardModel c, int total, int position, BinLookup.Info info) {
        if (root == null || c == null) return;

        String issuerName = info == null ? null : info.name;
        String issuerDomain = info == null ? null : info.domain;

        Brands.Style s = Brands.styleFor(c.pan, c.aid, issuerName, issuerDomain);

        GradientDrawable bg = new GradientDrawable();
        bg.setShape(GradientDrawable.RECTANGLE);
        bg.setColor(s.bg);
        bg.setCornerRadius(dp(root, 16));
        root.setBackground(bg);

        set(root, R.id.cardBrand, s.bankName, s.fg);
        set(root, R.id.tvLabel, c.label, s.muted);
        set(root, R.id.cardPan, Brands.formatPan(c.pan), s.fg);
        set(root, R.id.cardExpiry, prettyExpiry(c.expiry), s.muted);
        set(root, R.id.cardAid, c.aid == null || c.aid.isEmpty() ? "--" : c.aid, s.muted);
        set(root, R.id.cardMode, c.msd == 1 ? "MSD" : "EMV", s.muted);
        set(root, R.id.cardIndex, (position + 1) + "/" + total, s.muted);

        // Bank logo sits on a small white chip so a dark logo still reads on a
        // dark card.
        ImageView ivBank = root.findViewById(R.id.ivBankLogo);
        if (ivBank != null) {
            if (s.bankIcon == null) {
                ivBank.setBackground(null);
                ivBank.setPadding(0, 0, 0, 0);
            } else {
                GradientDrawable chip = new GradientDrawable();
                chip.setShape(GradientDrawable.RECTANGLE);
                chip.setColor(0xFFFFFFFF);
                chip.setCornerRadius(dp(root, 6));
                ivBank.setBackground(chip);
                int p = dp(root, 4);
                ivBank.setPadding(p, p, p, p);
            }
        }
        LogoLoader.into(ivBank, s.bankIcon, dp(root, 26), null);

        LogoLoader.into((ImageView) root.findViewById(R.id.ivNetworkLogo),
                s.networkIcon, dp(root, 24), s.networkTint);
    }

    private static void set(View root, int id, String text, int colour) {
        TextView t = root.findViewById(id);
        if (t == null) return;
        t.setText(text);
        t.setTextColor(colour);
    }

    private static int dp(View v, int value) {
        return Math.round(value * v.getResources().getDisplayMetrics().density);
    }

    // ------------------------------------------------- kept for compatibility

    static String brandOf(String pan, String label) {
        if (label != null && !label.trim().isEmpty()) return label.trim().toUpperCase();
        if (pan == null || pan.length() < 2) return "CARD";
        return Brands.networkLabel(Brands.networkFromPan(pan));
    }

    static String prettyPan(String pan) {
        return Brands.formatPan(pan);
    }

    static String prettyExpiry(String yymm) {
        if (yymm == null || yymm.length() < 4) return "--/--";
        return yymm.substring(2, 4) + "/" + yymm.substring(0, 2);
    }

    static class CardHolder extends RecyclerView.ViewHolder {
        final TextView brand, pan, expiry, aid, mode, index;
        final ImageView bankLogo, netLogo;

        CardHolder(@NonNull View v) {
            super(v);
            brand = v.findViewById(R.id.cardBrand);
            pan = v.findViewById(R.id.cardPan);
            expiry = v.findViewById(R.id.cardExpiry);
            aid = v.findViewById(R.id.cardAid);
            mode = v.findViewById(R.id.cardMode);
            index = v.findViewById(R.id.cardIndex);
            bankLogo = v.findViewById(R.id.ivBankLogo);
            netLogo = v.findViewById(R.id.ivNetworkLogo);
        }
    }
}
