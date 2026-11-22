package com.escvratar.deeperwatchdog;

import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Handler;
import android.os.Looper;
import android.widget.RemoteViews;
import android.widget.Toast;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Helper for home screen widgets: background sync, panic and check actions, UI updates. */
public class WidgetHelper {
    public static final String ACTION_PANIC = "com.escvratar.deeperwatchdog.ACTION_PANIC";
    public static final String ACTION_CHECK = "com.escvratar.deeperwatchdog.ACTION_CHECK";
    public static final String ACTION_REFRESH = "com.escvratar.deeperwatchdog.ACTION_REFRESH";

    public static final int STATE_OK = 0;
    public static final int STATE_WARN = 1;
    public static final int STATE_BAD = 2;

    private static final ExecutorService EXECUTOR = Executors.newSingleThreadExecutor();

    public static void updateAll(Context context) {
        AppWidgetManager wm = AppWidgetManager.getInstance(context);
        SharedPreferences p = MainActivity.prefs(context);

        int state = p.getInt("w_state", STATE_OK);
        String status = p.getString("w_status", "Все туннели в норме");
        String details = p.getString("w_details", "Нажмите для обновления");
        String compact = p.getString("w_compact", "Все в норме");
        String time = p.getString("w_time", "—");

        int dotRes = state == STATE_BAD ? R.drawable.ic_dot_red :
                (state == STATE_WARN ? R.drawable.ic_dot_yellow : R.drawable.ic_dot_green);

        // 1. StatusWidget (full)
        ComponentName statusComponent = new ComponentName(context, StatusWidget.class);
        int[] statusIds = wm.getAppWidgetIds(statusComponent);
        if (statusIds != null && statusIds.length > 0) {
            for (int id : statusIds) {
                RemoteViews rv = new RemoteViews(context.getPackageName(), R.layout.widget_status);
                rv.setTextViewText(R.id.widget_status_text, status);
                rv.setTextViewText(R.id.widget_details_text, details);
                rv.setTextViewText(R.id.widget_time, time);
                rv.setImageViewResource(R.id.widget_status_dot, dotRes);

                // Open app on click
                PendingIntent openApp = PendingIntent.getActivity(context, 0,
                        new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
                rv.setOnClickPendingIntent(R.id.widget_header, openApp);
                rv.setOnClickPendingIntent(R.id.widget_center, openApp);

                // Panic action
                PendingIntent panicIntent = PendingIntent.getBroadcast(context, 10,
                        new Intent(context, StatusWidget.class).setAction(ACTION_PANIC),
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
                rv.setOnClickPendingIntent(R.id.widget_btn_panic, panicIntent);

                // Check action
                PendingIntent checkIntent = PendingIntent.getBroadcast(context, 11,
                        new Intent(context, StatusWidget.class).setAction(ACTION_CHECK),
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
                rv.setOnClickPendingIntent(R.id.widget_btn_check, checkIntent);

                wm.updateAppWidget(id, rv);
            }
        }

        // 2. CompactWidget
        ComponentName compactComponent = new ComponentName(context, CompactWidget.class);
        int[] compactIds = wm.getAppWidgetIds(compactComponent);
        if (compactIds != null && compactIds.length > 0) {
            for (int id : compactIds) {
                RemoteViews rv = new RemoteViews(context.getPackageName(), R.layout.widget_compact);
                rv.setTextViewText(R.id.widget_compact_status, compact);
                rv.setImageViewResource(R.id.widget_compact_dot, dotRes);

                PendingIntent openApp = PendingIntent.getActivity(context, 1,
                        new Intent(context, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
                rv.setOnClickPendingIntent(R.id.widget_compact_click, openApp);

                PendingIntent panicIntent = PendingIntent.getBroadcast(context, 12,
                        new Intent(context, CompactWidget.class).setAction(ACTION_PANIC),
                        PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
                rv.setOnClickPendingIntent(R.id.widget_compact_panic, panicIntent);

                wm.updateAppWidget(id, rv);
            }
        }
    }

    public static void setLoading(Context context, String msg) {
        SharedPreferences p = MainActivity.prefs(context);
        p.edit()
                .putString("w_status", msg)
                .putString("w_compact", msg)
                .putString("w_details", "Выполняется запрос…")
                .putInt("w_state", STATE_WARN)
                .apply();
        updateAll(context);
    }

    public static void fetchAndUpdate(Context context) {
        EXECUTOR.execute(() -> {
            try {
                JSONObject statusObj = httpGet(context, "api/status");
                JSONObject tunnels = statusObj.optJSONObject("tunnels");
                List<String> bad = new ArrayList<>();
                int total = 0;
                long latencySum = 0;
                int latencyCount = 0;

                if (tunnels != null) {
                    Iterator<String> keys = tunnels.keys();
                    while (keys.hasNext()) {
                        String code = keys.next();
                        JSONObject t = tunnels.optJSONObject(code);
                        if (t == null) continue;
                        total++;
                        boolean healthy = t.optBoolean("healthy", true);
                        if (!healthy) {
                            bad.add(code);
                        }
                        int lat = t.optInt("latency", 0);
                        if (lat > 0) {
                            latencySum += lat;
                            latencyCount++;
                        }
                    }
                }

                int avgLatency = latencyCount > 0 ? (int) (latencySum / latencyCount) : 0;
                String time = new SimpleDateFormat("HH:mm", Locale.getDefault()).format(new Date());

                int state;
                String status;
                String details;
                String compact;

                if (!bad.isEmpty()) {
                    state = STATE_BAD;
                    status = "Сбой: " + String.join(", ", bad);
                    compact = "Сбой: " + String.join(",", bad);
                    details = "В норме " + (total - bad.size()) + " из " + total + " туннелей";
                } else if (total == 0) {
                    state = STATE_WARN;
                    status = "Нет туннелей";
                    compact = "Нет туннелей";
                    details = "Список мониторинга пуст";
                } else {
                    state = STATE_OK;
                    status = "Все туннели в норме (" + total + ")";
                    compact = total + " тунн. · " + (avgLatency > 0 ? avgLatency + "мс" : "OK");
                    details = "Средний пинг " + (avgLatency > 0 ? avgLatency + " мс" : "—") + " · Ошибок: 0";
                }

                MainActivity.prefs(context).edit()
                        .putInt("w_state", state)
                        .putString("w_status", status)
                        .putString("w_compact", compact)
                        .putString("w_details", details)
                        .putString("w_time", time)
                        .apply();
            } catch (SecurityException se) {
                MainActivity.prefs(context).edit()
                        .putInt("w_state", STATE_WARN)
                        .putString("w_status", "Требуется вход")
                        .putString("w_compact", "Вход")
                        .putString("w_details", "Откройте приложение для авторизации")
                        .apply();
            } catch (Exception e) {
                MainActivity.prefs(context).edit()
                        .putInt("w_state", STATE_BAD)
                        .putString("w_status", "Нет связи с роутером")
                        .putString("w_compact", "Нет связи")
                        .putString("w_details", "Проверьте Wi-Fi и адрес в приложении")
                        .apply();
            }

            updateAll(context);
        });
    }

    public static void performPanic(Context context) {
        EXECUTOR.execute(() -> {
            setLoading(context, "Починка…");
            try {
                JSONObject res = httpPost(context, "api/panic-action", new JSONObject());
                boolean ok = res.optBoolean("ok", true);
                String msg = res.optString("message", ok ? "Починка завершена" : "Ошибка починки");
                toast(context, msg);
            } catch (Exception e) {
                toast(context, "Ошибка: " + e.getMessage());
            }

            try {
                Thread.sleep(1500);
            } catch (InterruptedException ignored) {}

            fetchAndUpdate(context);
        });
    }

    public static void performCheck(Context context) {
        EXECUTOR.execute(() -> {
            setLoading(context, "Проверка…");
            try {
                httpPost(context, "api/check-now", new JSONObject());
                toast(context, "Проверка туннелей запущена");
            } catch (Exception e) {
                toast(context, "Ошибка запуска: " + e.getMessage());
            }

            try {
                Thread.sleep(2500);
            } catch (InterruptedException ignored) {}

            fetchAndUpdate(context);
        });
    }

    private static void toast(Context c, String text) {
        new Handler(Looper.getMainLooper()).post(() ->
                Toast.makeText(c.getApplicationContext(), text, Toast.LENGTH_SHORT).show());
    }

    private static JSONObject httpGet(Context c, String path) throws Exception {
        HttpURLConnection con = (HttpURLConnection) new URL(MainActivity.baseUrl(c) + path).openConnection();
        con.setConnectTimeout(8000);
        con.setReadTimeout(15000);
        String cookie = MainActivity.prefs(c).getString("cookie", null);
        if (cookie != null) con.setRequestProperty("Cookie", cookie);

        int code = con.getResponseCode();
        if (code == 401) throw new SecurityException("Auth required");
        InputStream in = (code >= 200 && code < 300) ? con.getInputStream() : con.getErrorStream();
        String resp = in != null ? readStream(in) : "{}";
        return new JSONObject(resp.isEmpty() ? "{}" : resp);
    }

    private static JSONObject httpPost(Context c, String path, JSONObject body) throws Exception {
        HttpURLConnection con = (HttpURLConnection) new URL(MainActivity.baseUrl(c) + path).openConnection();
        con.setRequestMethod("POST");
        con.setConnectTimeout(10000);
        con.setReadTimeout(20000);
        con.setRequestProperty("Content-Type", "application/json");
        String cookie = MainActivity.prefs(c).getString("cookie", null);
        if (cookie != null) con.setRequestProperty("Cookie", cookie);
        con.setDoOutput(true);

        byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
        try (OutputStream out = con.getOutputStream()) {
            out.write(bytes);
        }

        int code = con.getResponseCode();
        if (code == 401) throw new SecurityException("Auth required");
        InputStream in = (code >= 200 && code < 300) ? con.getInputStream() : con.getErrorStream();
        String resp = in != null ? readStream(in) : "{}";
        return new JSONObject(resp.isEmpty() ? "{}" : resp);
    }

    private static String readStream(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        for (int n; (n = in.read(buf)) > 0; ) out.write(buf, 0, n);
        in.close();
        return out.toString("UTF-8");
    }
}
