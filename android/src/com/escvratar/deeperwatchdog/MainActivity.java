package com.escvratar.deeperwatchdog;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.DownloadManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.Color;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.URLUtil;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

/** The Deeper Watchdog web interface in a WebView: the sign-in stays (cookies), files download and upload. */
public class MainActivity extends Activity {
    static final String DEFAULT_URL = "http://192.168.31.10:8787/";
    static final String ACTION_SETTINGS = "com.escvratar.deeperwatchdog.SETTINGS";
    private static final int FILE_REQUEST = 1;
    private static final int INSTALL_REQUEST = 3;

    private WebView web;
    private LinearLayout errorView;
    private TextView errorText;
    private ValueCallback<Uri[]> fileCallback;
    private boolean failed;

    static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences("app", MODE_PRIVATE);
    }

    static String baseUrl(Context c) {
        return prefs(c).getString("url", DEFAULT_URL);
    }

    private boolean night() {
        return (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
    }

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        FrameLayout root = new FrameLayout(this);
        web = new WebView(this);
        root.addView(web, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        root.addView(buildErrorView(), new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        setContentView(root);
        applyBars();
        setupWeb();

        // First run: the address first (the dialog comes back if the activity is recreated meanwhile)
        if (!prefs(this).contains("url")) showStart();
        else if (state == null || web.restoreState(state) == null) web.loadUrl(baseUrl(this));
        handleIntent(getIntent());
        if (prefs(this).contains("url") && prefs(this).getBoolean("notify", true)) {
            askNotificationPermission();
            StatusJob.schedule(this, true);
        }
    }

    private void applyBars() {
        boolean dark = night();
        int bg = dark ? Color.BLACK : Color.rgb(242, 242, 247);
        getWindow().setStatusBarColor(bg);
        getWindow().setNavigationBarColor(bg);
        int flags = 0;
        if (!dark) {
            flags |= View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
            if (Build.VERSION.SDK_INT >= 26) flags |= View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
        }
        getWindow().getDecorView().setSystemUiVisibility(flags);
        errorView.setBackgroundColor(bg);
        errorText.setTextColor(dark ? Color.LTGRAY : Color.DKGRAY);
    }

    @Override
    public void onConfigurationChanged(Configuration c) {
        super.onConfigurationChanged(c);
        applyBars();
    }

    private void setupWeb() {
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setTextZoom(100);
        s.setSupportZoom(false);
        s.setUserAgentString(s.getUserAgentString() + " DeeperWatchdogApp/1.2");
        CookieManager.getInstance().setAcceptCookie(true);
        web.setBackgroundColor(night() ? Color.BLACK : Color.rgb(242, 242, 247));

        // The web UI's "Телефон → Уведомления на телефоне" opens the app's own settings
        web.addJavascriptInterface(new Object() {
            @android.webkit.JavascriptInterface
            public void openSettings() {
                runOnUiThread(() -> showSettings(false));
            }
        }, "DWApp");

        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri u = request.getUrl(), base = Uri.parse(baseUrl(MainActivity.this));
                if (u.getHost() != null && u.getHost().equals(base.getHost()) && u.getPort() == base.getPort()) return false;
                // Other sites open in the browser
                try {
                    startActivity(new Intent(Intent.ACTION_VIEW, u));
                } catch (Exception ignored) {
                }
                return true;
            }

            @Override
            public void onPageStarted(WebView view, String url, android.graphics.Bitmap icon) {
                failed = false;
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame()) {
                    failed = true;
                    showError(String.valueOf(error.getDescription()));
                }
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                CookieManager cm = CookieManager.getInstance();
                cm.flush();
                // The background check signs in with the same session as the page
                String cookie = cm.getCookie(baseUrl(MainActivity.this));
                if (cookie != null) prefs(MainActivity.this).edit().putString("cookie", cookie).putBoolean("auth_noted", false).apply();
                if (!failed) errorView.setVisibility(View.GONE);
            }
        });

        web.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onConsoleMessage(android.webkit.ConsoleMessage m) {
                android.util.Log.i("DeeperWatchdog", m.messageLevel() + " " + m.message() + " @" + m.lineNumber());
                return true;
            }

            @Override
            public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback, FileChooserParams params) {
                if (fileCallback != null) fileCallback.onReceiveValue(null);
                fileCallback = callback;
                try {
                    startActivityForResult(params.createIntent(), FILE_REQUEST);
                } catch (Exception e) {
                    fileCallback = null;
                    return false;
                }
                return true;
            }
        });

        web.setDownloadListener((url, userAgent, disposition, mime, length) -> {
            try {
                String name = URLUtil.guessFileName(url, disposition, mime);
                DownloadManager.Request r = new DownloadManager.Request(Uri.parse(url));
                String cookie = CookieManager.getInstance().getCookie(url);
                if (cookie != null) r.addRequestHeader("Cookie", cookie);
                r.addRequestHeader("User-Agent", userAgent);
                r.setTitle(name);
                r.setMimeType(mime);
                r.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
                r.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, name);
                ((DownloadManager) getSystemService(DOWNLOAD_SERVICE)).enqueue(r);
                Toast.makeText(this, "Скачивается в «Загрузки»: " + name, Toast.LENGTH_SHORT).show();
            } catch (Exception e) {
                Toast.makeText(this, "Не удалось скачать: " + e.getMessage(), Toast.LENGTH_LONG).show();
            }
        });
    }

    private View buildErrorView() {
        errorView = new LinearLayout(this);
        errorView.setOrientation(LinearLayout.VERTICAL);
        errorView.setGravity(Gravity.CENTER);
        int pad = dp(32);
        errorView.setPadding(pad, pad, pad, pad);
        TextView title = new TextView(this);
        title.setText("Нет связи с Deeper Watchdog");
        title.setTextSize(20);
        title.setGravity(Gravity.CENTER);
        title.setTextColor(Color.rgb(0, 122, 255));
        errorText = new TextView(this);
        errorText.setGravity(Gravity.CENTER);
        errorText.setPadding(0, dp(12), 0, dp(24));
        Button retry = new Button(this);
        retry.setText("Повторить");
        retry.setOnClickListener(v -> {
            errorView.setVisibility(View.GONE);
            web.loadUrl(baseUrl(this));
        });
        Button address = new Button(this);
        address.setText("Адрес сервера");
        address.setOnClickListener(v -> showSettings(false));
        errorView.addView(title);
        errorView.addView(errorText);
        errorView.addView(retry);
        errorView.addView(address);
        errorView.setVisibility(View.GONE);
        errorView.setClickable(true);
        return errorView;
    }

    private void showError(String why) {
        errorText.setText(baseUrl(this) + "\n" + why + "\n\nТелефон должен быть в домашней сети Wi-Fi (или в VPN до неё).");
        errorView.setVisibility(View.VISIBLE);
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    /** First run: connect to a running watchdog or install one on a server over SSH. */
    private void showStart() {
        new AlertDialog.Builder(this)
                .setTitle("Deeper Watchdog")
                .setMessage("Watchdog уже работает на сервере, NAS, роутере или компьютере?\n\n"
                        + "Если нет — приложение установит его в Docker на ваше устройство по SSH.")
                .setPositiveButton("Ввести адрес", (d, w) -> showSettings(true))
                .setNegativeButton("Установить на сервер", (d, w) -> startInstall())
                .setCancelable(false)
                .show();
    }

    private void startInstall() {
        startActivityForResult(new Intent(this, InstallActivity.class), INSTALL_REQUEST);
    }

    private void useUrl(String u) {
        SharedPreferences.Editor e = prefs(this).edit();
        // Another server: its log numbers start anew
        if (!u.equals(prefs(this).getString("url", null))) e.remove("seq").remove("cookie");
        e.putString("url", u).apply();
        errorView.setVisibility(View.GONE);
        web.loadUrl(u);
    }

    /** The server address, whether to notify and about which kinds of events. */
    void showSettings(boolean firstRun) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(22), dp(8), dp(22), dp(8));
        EditText url = new EditText(this);
        url.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        url.setSingleLine(true);
        url.setText(baseUrl(this));
        url.setHint(DEFAULT_URL);
        TextView help = new TextView(this);
        help.setText("Адрес веб-интерфейса Deeper Watchdog. Дома: http://192.168.31.10:8787. Через доменное имя "
                + "(например https://имя.synology.me/) приложение и уведомления работают и вне дома.");
        help.setTextSize(13);
        CheckBox notify = new CheckBox(this);
        notify.setText("Уведомления на телефон (проверка раз в 15 минут)");
        notify.setChecked(prefs(this).getBoolean("notify", true));
        TextView kinds = new TextView(this);
        kinds.setText("Какие события присылать");
        kinds.setTextSize(15);
        kinds.setPadding(0, dp(14), 0, dp(2));
        box.addView(url);
        box.addView(help);
        box.addView(notify);
        box.addView(kinds);
        java.util.Set<String> chosen = StatusJob.cats(this);
        java.util.List<CheckBox> boxes = new java.util.ArrayList<>();
        for (String[] c : StatusJob.CATEGORIES) {
            CheckBox cb = new CheckBox(this);
            cb.setText(c[1]);
            cb.setTag(c[0]);
            cb.setChecked(chosen.contains(c[0]));
            boxes.add(cb);
            box.addView(cb);
        }
        notify.setOnCheckedChangeListener((v, on) -> {
            for (CheckBox cb : boxes) cb.setEnabled(on);
        });
        for (CheckBox cb : boxes) cb.setEnabled(notify.isChecked());
        android.widget.ScrollView scroll = new android.widget.ScrollView(this);
        scroll.addView(box);
        AlertDialog.Builder b = new AlertDialog.Builder(this)
                .setTitle("Deeper Watchdog")
                .setView(scroll)
                .setPositiveButton("Сохранить", (d, w) -> {
                    String u = url.getText().toString().trim();
                    if (u.isEmpty()) u = DEFAULT_URL;
                    if (!u.startsWith("http://") && !u.startsWith("https://")) u = "http://" + u;
                    if (!u.endsWith("/")) u += "/";
                    boolean on = notify.isChecked();
                    java.util.Set<String> cats = new java.util.HashSet<>();
                    for (CheckBox cb : boxes) if (cb.isChecked()) cats.add((String) cb.getTag());
                    prefs(this).edit().putBoolean("notify", on).putStringSet("cats", cats).apply();
                    useUrl(u);
                    if (on) askNotificationPermission();
                    StatusJob.schedule(this, on);
                });
        b.setNeutralButton("Установить на сервер", (d, w) -> startInstall());
        if (!firstRun) b.setNegativeButton("Отмена", null);
        else b.setCancelable(false);
        b.show();
    }

    private void askNotificationPermission() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != android.content.pm.PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 2);
    }

    private void handleIntent(Intent i) {
        if (i != null && ACTION_SETTINGS.equals(i.getAction())) showSettings(false);
    }

    @Override
    protected void onNewIntent(Intent i) {
        super.onNewIntent(i);
        if (ACTION_SETTINGS.equals(i.getAction())) showSettings(false);
        else web.reload();
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        if (request == INSTALL_REQUEST) {
            if (result == RESULT_OK && data != null && data.getData() != null) {
                useUrl(data.getData().toString());
                if (prefs(this).getBoolean("notify", true)) {
                    askNotificationPermission();
                    StatusJob.schedule(this, true);
                }
            } else if (!prefs(this).contains("url")) showStart();
            return;
        }
        if (request == FILE_REQUEST && fileCallback != null) {
            fileCallback.onReceiveValue(WebChromeClient.FileChooserParams.parseResult(result, data));
            fileCallback = null;
            return;
        }
        super.onActivityResult(request, result, data);
    }

    @Override
    public void onBackPressed() {
        if (web.canGoBack()) web.goBack();
        else super.onBackPressed();
    }

    @Override
    protected void onSaveInstanceState(Bundle out) {
        super.onSaveInstanceState(out);
        web.saveState(out);
    }

    @Override
    protected void onPause() {
        super.onPause();
        CookieManager.getInstance().flush();
    }
}
