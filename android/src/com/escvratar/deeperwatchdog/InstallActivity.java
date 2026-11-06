package com.escvratar.deeperwatchdog;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.text.InputType;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.ForegroundColorSpan;
import android.text.style.StyleSpan;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.zip.GZIPOutputStream;

/** Installs the watchdog into Docker on a server, NAS or router over SSH: runs the bundled dw-install.sh there. */
public class InstallActivity extends Activity {
    private EditText host, sshPort, user, sshPass, deeperHost, deeperPass, webPort, webPass;
    private CheckBox installDocker;
    private LinearLayout form, progress;
    private TextView log;
    private ScrollView logScroll;
    private Button done;
    private volatile boolean running;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        setTitle("Установка на сервер");
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setFitsSystemWindows(true);
        root.addView(buildForm(), new LinearLayout.LayoutParams(-1, -1));
        root.addView(buildProgress(), new LinearLayout.LayoutParams(-1, -1));
        progress.setVisibility(View.GONE);
        setContentView(root);
        int bg = (getResources().getConfiguration().uiMode & android.content.res.Configuration.UI_MODE_NIGHT_MASK)
                == android.content.res.Configuration.UI_MODE_NIGHT_YES ? Color.BLACK : Color.rgb(242, 242, 247);
        root.setBackgroundColor(bg);
        getWindow().setStatusBarColor(bg);
        getWindow().setNavigationBarColor(bg);
        if (bg != Color.BLACK)
            getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }

    private TextView text(String s, int size, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(size);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private EditText field(LinearLayout box, String label, String value, String hint, int type) {
        TextView l = text(label, 13, false);
        l.setPadding(0, dp(10), 0, 0);
        box.addView(l);
        EditText e = new EditText(this);
        e.setSingleLine(true);
        e.setInputType(type);
        e.setText(value);
        e.setHint(hint);
        box.addView(e);
        return e;
    }

    private View buildForm() {
        ScrollView scroll = new ScrollView(this);
        form = new LinearLayout(this);
        form.setOrientation(LinearLayout.VERTICAL);
        form.setPadding(dp(20), dp(16), dp(20), dp(24));
        scroll.addView(form);
        form.addView(text("Установка Deeper Watchdog", 22, true));
        TextView about = text("Приложение подключится к устройству по SSH и установит Watchdog в Docker: сервер на Linux, "
                + "NAS (Synology, QNAP) или роутер с Docker. Телефон должен быть в той же сети, что и устройство.", 14, false);
        about.setPadding(0, dp(8), 0, dp(4));
        form.addView(about);

        int t = InputType.TYPE_CLASS_TEXT, num = InputType.TYPE_CLASS_NUMBER,
                pass = InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD;
        TextView s1 = text("Устройство", 17, true);
        s1.setPadding(0, dp(18), 0, 0);
        form.addView(s1);
        host = field(form, "IP-адрес или имя устройства", "", "например 192.168.31.10", t | InputType.TYPE_TEXT_VARIATION_URI);
        sshPort = field(form, "Порт SSH", "22", "22", num);
        user = field(form, "Пользователь SSH", "root", "root или администратор NAS", t);
        sshPass = field(form, "Пароль SSH (он же для sudo)", "", "", pass);
        TextView sshHelp = text("SSH включается в настройках устройства. Synology: Панель управления → Терминал и SNMP → "
                + "Включить SSH. QNAP: Панель управления → Telnet/SSH.", 12, false);
        sshHelp.setAlpha(0.7f);
        form.addView(sshHelp);

        TextView s2 = text("Deeper Connect", 17, true);
        s2.setPadding(0, dp(18), 0, 0);
        form.addView(s2);
        deeperHost = field(form, "IP-адрес Deeper Connect", "34.34.34.34", "34.34.34.34", t | InputType.TYPE_TEXT_VARIATION_URI);
        deeperPass = field(form, "Пароль администратора Deeper", "", "", pass);

        TextView s3 = text("Веб-интерфейс Watchdog", 17, true);
        s3.setPadding(0, dp(18), 0, 0);
        form.addView(s3);
        webPort = field(form, "Порт", "8787", "8787", num);
        webPass = field(form, "Пароль входа (можно не задавать: его попросит первая страница)", "", "необязательно", pass);
        installDocker = new CheckBox(this);
        installDocker.setText("Установить Docker, если его нет (Ubuntu, Debian и другие Linux)");
        installDocker.setChecked(true);
        installDocker.setPadding(0, dp(12), 0, 0);
        form.addView(installDocker);

        Button go = new Button(this);
        go.setText("Установить");
        go.setOnClickListener(v -> start());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.topMargin = dp(18);
        form.addView(go, lp);
        return scroll;
    }

    private View buildProgress() {
        progress = new LinearLayout(this);
        progress.setOrientation(LinearLayout.VERTICAL);
        progress.setPadding(dp(16), dp(16), dp(16), dp(16));
        progress.addView(text("Установка", 22, true));
        logScroll = new ScrollView(this);
        log = new TextView(this);
        log.setTextSize(13);
        log.setTextIsSelectable(true);
        log.setPadding(0, dp(10), 0, dp(10));
        logScroll.addView(log);
        progress.addView(logScroll, new LinearLayout.LayoutParams(-1, 0, 1));
        done = new Button(this);
        done.setVisibility(View.GONE);
        progress.addView(done, new LinearLayout.LayoutParams(-1, -2));
        return progress;
    }

    private static String val(EditText e) {
        return e.getText().toString().replace("\n", "").replace("\r", "").trim();
    }

    private void start() {
        String h = val(host), u = val(user), p = sshPass.getText().toString();
        if (h.isEmpty()) { host.setError("Укажите адрес устройства"); host.requestFocus(); return; }
        if (u.isEmpty()) { user.setError("Укажите пользователя"); user.requestFocus(); return; }
        if (p.isEmpty()) { sshPass.setError("Нужен пароль SSH"); sshPass.requestFocus(); return; }
        if (val(deeperHost).isEmpty()) deeperHost.setText("34.34.34.34");
        int port;
        try {
            port = Integer.parseInt(val(webPort));
            if (port < 1 || port > 65535) throw new NumberFormatException();
        } catch (NumberFormatException e) {
            webPort.setError("Число от 1 до 65535"); webPort.requestFocus(); return;
        }
        String wp = webPass.getText().toString();
        if (!wp.isEmpty() && wp.length() < 4) { webPass.setError("Хотя бы 4 символа"); webPass.requestFocus(); return; }

        ((View) form.getParent()).setVisibility(View.GONE);
        progress.setVisibility(View.VISIBLE);
        log.setText("");
        done.setVisibility(View.GONE);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        running = true;
        new Thread(this::run).start();
    }

    // ---------- the log ----------
    private void add(String line, int color, boolean bold) {
        runOnUiThread(() -> {
            SpannableStringBuilder sb = new SpannableStringBuilder(log.getText());
            int from = sb.length();
            sb.append(line).append('\n');
            if (color != 0) sb.setSpan(new ForegroundColorSpan(color), from, sb.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            if (bold) sb.setSpan(new StyleSpan(Typeface.BOLD), from, sb.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
            log.setText(sb);
            logScroll.post(() -> logScroll.fullScroll(View.FOCUS_DOWN));
        });
    }

    private static final int GREEN = 0xFF34C759, ORANGE = 0xFFFF9500, RED = 0xFFFF3B30, GRAY = 0xFF8E8E93;

    private boolean failed, finished;

    private void line(String l) {
        if (l.startsWith("@@STEP ")) add("\n▸ " + l.substring(7), 0, true);
        else if (l.startsWith("@@OK ")) add("✓ " + l.substring(5), GREEN, false);
        else if (l.startsWith("@@WARN ")) add("! " + l.substring(7), ORANGE, false);
        else if (l.startsWith("@@ERR ")) { failed = true; add("✗ " + l.substring(6), RED, true); }
        else if (l.startsWith("@@INFO ")) add("   " + l.substring(7), 0, false);
        else if (l.startsWith("@@URL ")) add("➜ " + l.substring(6), GREEN, true);
        else if (l.startsWith("@@DONE")) finished = true;
        else if (!l.trim().isEmpty()) add("   " + l, GRAY, false);
    }

    // ---------- SSH ----------
    private String installer() throws Exception {
        ByteArrayOutputStream raw = new ByteArrayOutputStream();
        try (InputStream in = getAssets().open("dw-install.sh"); GZIPOutputStream gz = new GZIPOutputStream(raw)) {
            byte[] buf = new byte[8192];
            for (int n; (n = in.read(buf)) > 0; ) gz.write(buf, 0, n);
        }
        return android.util.Base64.encodeToString(raw.toByteArray(), android.util.Base64.NO_WRAP);
    }

    private static String explain(Exception e) {
        Throwable c = e.getCause() != null ? e.getCause() : e;
        String m = String.valueOf(e.getMessage());
        if (m.contains("Auth fail") || m.contains("Auth cancel") || m.contains("USERAUTH fail") || m.contains("authentication failures"))
            return "Устройство не приняло пользователя или пароль SSH";
        if (c instanceof java.net.ConnectException || m.contains("refused"))
            return "Устройство отказало в подключении: SSH выключен или указан другой порт";
        if (c instanceof java.net.SocketTimeoutException || c instanceof java.net.NoRouteToHostException || m.contains("timeout") || m.contains("timed out"))
            return "Устройство не отвечает: проверьте адрес и что телефон в той же сети (Wi-Fi дома, не мобильный интернет)";
        if (c instanceof java.net.UnknownHostException)
            return "Не найдено устройство с таким именем: укажите IP-адрес";
        if (m.contains("Algorithm negotiation fail"))
            return "SSH-сервер устройства не поддерживает нужное шифрование: обновите прошивку или используйте установщик с компьютера";
        return "Ошибка SSH: " + m;
    }

    /** Answers the device's password questions (plain password and keyboard-interactive, as DSM asks). */
    private static class Answers implements com.jcraft.jsch.UserInfo, com.jcraft.jsch.UIKeyboardInteractive {
        private final String password;
        private int asked;  // One try: repeating a wrong password only gets "too many authentication failures"
        Answers(String password) { this.password = password; }
        public String getPassphrase() { return null; }
        public String getPassword() { return password; }
        public boolean promptPassword(String m) { return asked++ < 1; }
        public boolean promptPassphrase(String m) { return false; }
        public boolean promptYesNo(String m) { return true; }
        public void showMessage(String m) { }
        public String[] promptKeyboardInteractive(String dest, String name, String instruction, String[] prompt, boolean[] echo) {
            if (asked++ >= 1) return null;
            String[] r = new String[prompt.length];
            java.util.Arrays.fill(r, password);
            return r;
        }
    }

    private void run() {
        failed = false;
        finished = false;
        String h = val(host), u = val(user), p = sshPass.getText().toString();
        int sp;
        try { sp = Integer.parseInt(val(sshPort)); } catch (NumberFormatException e) { sp = 22; }
        Session s = null;
        int status = -1;
        try {
            add("▸ Подключение к " + u + "@" + h + ":" + sp, 0, true);
            JSch jsch = new JSch();
            s = jsch.getSession(u, h, sp);
            s.setPassword(p);
            Properties cfg = new Properties();
            // A home device: its key is taken on first use (shown below), there is no earlier key to compare with
            cfg.put("StrictHostKeyChecking", "no");
            cfg.put("PreferredAuthentications", "password,keyboard-interactive");
            s.setConfig(cfg);
            s.setUserInfo(new Answers(p));
            s.setServerAliveInterval(15000);
            s.connect(15000);
            add("✓ Подключено (ключ устройства " + s.getHostKey().getFingerPrint(jsch) + ")", GREEN, false);

            String cmd = "sh -c 'umask 077; T=/tmp/dw-install.$$.sh; echo " + installer()
                    + " | { base64 -d 2>/dev/null || openssl base64 -d -A; } | gzip -dc > $T && "
                    + "DW_SELF=$T DW_STDIN_CONFIG=1 DW_MACHINE=1 sh $T install; r=$?; rm -f $T; exit $r'";
            ChannelExec ch = (ChannelExec) s.openChannel("exec");
            ch.setCommand(cmd);
            ByteArrayOutputStream err = new ByteArrayOutputStream();
            ch.setErrStream(err);
            InputStream out = ch.getInputStream();
            OutputStream in = ch.getOutputStream();
            ch.connect(15000);

            // Passwords go through stdin, never on the device's command line
            StringBuilder c = new StringBuilder();
            c.append("DW_DEEPER_HOST=").append(val(deeperHost)).append('\n');
            c.append("DW_DEEPER_PASS=").append(deeperPass.getText().toString().replace("\n", "")).append('\n');
            c.append("DW_WEB_PASSWORD=").append(webPass.getText().toString().replace("\n", "")).append('\n');
            c.append("DW_PORT=").append(val(webPort)).append('\n');
            c.append("DW_SUDO_PASS=").append(p.replace("\n", "")).append('\n');
            if (installDocker.isChecked()) c.append("DW_INSTALL_DOCKER=1\n");
            c.append("END\n");
            in.write(c.toString().getBytes(StandardCharsets.UTF_8));
            in.flush();
            in.close();

            BufferedReader r = new BufferedReader(new InputStreamReader(out, StandardCharsets.UTF_8));
            for (String l; (l = r.readLine()) != null; ) line(l);
            while (!ch.isClosed()) Thread.sleep(100);
            status = ch.getExitStatus();
            for (String l : err.toString("UTF-8").split("\n")) if (!l.trim().isEmpty()) add("   " + l, GRAY, false);
            ch.disconnect();
        } catch (JSchException e) {
            failed = true;
            add("✗ " + explain(e), RED, true);
        } catch (Exception e) {
            failed = true;
            add("✗ " + (e.getMessage() != null ? e.getMessage() : e.toString()), RED, true);
        } finally {
            if (s != null) s.disconnect();
        }
        boolean ok = !failed && finished && status == 0;
        String url = "http://" + (h.contains(":") && !h.startsWith("[") ? "[" + h + "]" : h) + ":" + val(webPort) + "/";
        runOnUiThread(() -> {
            running = false;
            getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            done.setVisibility(View.VISIBLE);
            if (ok) {
                add("\nГотово! Watchdog работает: " + url, GREEN, true);
                done.setText("Открыть Watchdog");
                done.setOnClickListener(v -> {
                    setResult(RESULT_OK, new Intent().setData(Uri.parse(url)));
                    finish();
                });
            } else {
                add("\nУстановка не завершена. Исправьте данные и попробуйте снова.", RED, false);
                done.setText("Назад к настройкам");
                done.setOnClickListener(v -> {
                    progress.setVisibility(View.GONE);
                    ((View) form.getParent()).setVisibility(View.VISIBLE);
                });
            }
        });
    }

    @Override
    public void onBackPressed() {
        if (running) {
            Toast.makeText(this, "Идёт установка, подождите", Toast.LENGTH_SHORT).show();
            return;
        }
        if (progress.getVisibility() == View.VISIBLE) {
            progress.setVisibility(View.GONE);
            ((View) form.getParent()).setVisibility(View.VISIBLE);
            return;
        }
        super.onBackPressed();
    }
}
