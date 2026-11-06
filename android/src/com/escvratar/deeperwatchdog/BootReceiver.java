package com.escvratar.deeperwatchdog;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Keeps the background check after a reboot. */
public class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context c, Intent i) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(i.getAction()) && MainActivity.prefs(c).getBoolean("notify", true))
            StatusJob.schedule(c, true);
    }
}
