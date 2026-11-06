package com.escvratar.deeperwatchdog;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Every 15 minutes: asks the watchdog for log entries newer than the last one seen and notifies about the chosen kinds. */
public class StatusJob extends JobService {
    private static final int JOB_ID = 1;
    private static final String CHANNEL = "events";
    private static final int AUTH_ID = 1;

    /** The watchdog's event categories (as for its emails): key, title. */
    static final String[][] CATEGORIES = {
            {"check", "Проверка не прошла"},
            {"recovery", "Восстановление туннеля"},
            {"failover", "Переезд при сбое"},
            {"no_nodes", "Нет нод в туннеле"},
            {"nodes_back", "Ноды появились"},
            {"all_empty", "Нет нод ни в одном туннеле"},
            {"all_slow", "Медленные все туннели"},
            {"service", "Сервис «Вручную» не работает"},
            {"rollback", "Не удалось вернуть сервис"},
            {"errors", "Deeper Connect недоступен"},
            {"changes", "Изменения"},
    };
    static final Set<String> DEFAULT_CATS = new HashSet<>(Arrays.asList(
            "check", "recovery", "failover", "no_nodes", "all_empty", "service", "rollback", "errors"));

    static Set<String> cats(Context c) {
        return MainActivity.prefs(c).getStringSet("cats", DEFAULT_CATS);
    }

    static String title(String cat) {
        for (String[] x : CATEGORIES) if (x[0].equals(cat)) return x[1];
        return "Deeper Watchdog";
    }

    static void schedule(Context c, boolean on) {
        JobScheduler js = (JobScheduler) c.getSystemService(JOB_SCHEDULER_SERVICE);
        if (!on) {
            js.cancel(JOB_ID);
            return;
        }
        if (js.getPendingJob(JOB_ID) != null) return;
        js.schedule(new JobInfo.Builder(JOB_ID, new ComponentName(c, StatusJob.class))
                .setPeriodic(15 * 60 * 1000L)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setPersisted(true)
                .build());
    }

    @Override
    public boolean onStartJob(JobParameters params) {
        new Thread(() -> {
            try {
                check(this);
            } catch (Exception ignored) {
                // No network or the server is restarting: the next run asks again, nothing is lost
            }
            jobFinished(params, false);
        }).start();
        return true;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        return true;
    }

    static void check(Context c) throws Exception {
        SharedPreferences p = MainActivity.prefs(c);
        if (!p.getBoolean("notify", true)) return;
        long last = p.getLong("seq", -1);
        HttpURLConnection con = (HttpURLConnection) new URL(MainActivity.baseUrl(c) + "api/events"
                + (last >= 0 ? "?since=" + last : "")).openConnection();
        con.setConnectTimeout(15000);
        con.setReadTimeout(30000);
        String cookie = p.getString("cookie", null);
        if (cookie != null) con.setRequestProperty("Cookie", cookie);
        int code = con.getResponseCode();
        if (code == 401) {
            // Signed out (the session expired or "Выйти везде"): said once, until the app is signed in again
            if (!p.getBoolean("auth_noted", false)) {
                p.edit().putBoolean("auth_noted", true).apply();
                show(c, AUTH_ID, "Войдите в приложении", "Иначе уведомления Deeper Watchdog не приходят", "info", null);
            }
            return;
        }
        if (code != 200) return;
        JSONObject r = new JSONObject(read(con.getInputStream()));
        p.edit().putBoolean("auth_noted", false).apply();
        if (!r.has("seq")) return;  // An older watchdog without numbered entries
        long seq = r.getLong("seq");
        p.edit().putLong("seq", seq).apply();
        // The first run only remembers where the log is: old entries aren't news
        if (last < 0 || seq <= last) return;

        Set<String> want = cats(c);
        JSONArray events = r.getJSONArray("events");  // Newest first
        List<JSONObject> news = new ArrayList<>();
        for (int i = events.length() - 1; i >= 0; i--) {
            JSONObject e = events.getJSONObject(i);
            if (e.optLong("n", 0) > last && want.contains(e.optString("cat", ""))) news.add(e);
        }
        if (news.isEmpty()) return;
        if (news.size() <= 4) {
            for (JSONObject e : news)
                show(c, (int) (100 + e.optLong("n") % 100000), title(e.optString("cat")), e.optString("text"), e.optString("kind"), null);
        } else {
            // Many at once (a bad night): one notification with all of them
            Notification.InboxStyle inbox = new Notification.InboxStyle();
            for (JSONObject e : news) inbox.addLine(e.optString("text"));
            inbox.setSummaryText("Deeper Watchdog");
            show(c, 2, news.size() + " событий", news.get(news.size() - 1).optString("text"), "warn", inbox);
        }
    }

    private static void show(Context c, int id, String title, String text, String kind, Notification.Style style) {
        NotificationManager nm = (NotificationManager) c.getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26 && nm.getNotificationChannel(CHANNEL) == null)
            nm.createNotificationChannel(new NotificationChannel(CHANNEL, "События Deeper Watchdog", NotificationManager.IMPORTANCE_DEFAULT));
        PendingIntent open = PendingIntent.getActivity(c, 0, new Intent(c, MainActivity.class)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        int color = "bad".equals(kind) ? 0xFFFF3B30 : "warn".equals(kind) ? 0xFFFF9500 : "ok".equals(kind) ? 0xFF34C759 : 0xFF007AFF;
        Notification.Builder b = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(c, CHANNEL) : new Notification.Builder(c);
        b.setSmallIcon(R.drawable.ic_stat).setContentTitle(title).setContentText(text).setColor(color)
                .setStyle(style != null ? style : new Notification.BigTextStyle().bigText(text))
                .setContentIntent(open).setAutoCancel(true).setWhen(System.currentTimeMillis()).setShowWhen(true);
        nm.notify(id, b.build());
    }

    private static String read(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        for (int n; (n = in.read(buf)) > 0; ) out.write(buf, 0, n);
        in.close();
        return out.toString("UTF-8");
    }
}
