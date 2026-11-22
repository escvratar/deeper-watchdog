package com.escvratar.deeperwatchdog;

import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.Context;
import android.content.Intent;

/** Apps widget provider displaying Instagram, Telegram, YouTube with tunnel switch actions. */
public class AppsWidget extends AppWidgetProvider {

    @Override
    public void onUpdate(Context context, AppWidgetManager appWidgetManager, int[] appWidgetIds) {
        WidgetHelper.updateAll(context);
        WidgetHelper.fetchAndUpdate(context);
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        super.onReceive(context, intent);
        String action = intent.getAction();
        if (WidgetHelper.ACTION_CYCLE_APP.equals(action)) {
            String app = intent.getStringExtra("app");
            if (app != null && !app.isEmpty()) {
                WidgetHelper.cycleAppTunnel(context, app);
            }
        } else if (WidgetHelper.ACTION_REFRESH.equals(action)) {
            WidgetHelper.fetchAndUpdate(context);
        }
    }
}
