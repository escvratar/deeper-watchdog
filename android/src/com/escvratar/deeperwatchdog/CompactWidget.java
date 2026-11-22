package com.escvratar.deeperwatchdog;

import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.Context;
import android.content.Intent;

/** Compact 2x1 widget provider with quick panic button and concise status indicator. */
public class CompactWidget extends AppWidgetProvider {

    @Override
    public void onUpdate(Context context, AppWidgetManager appWidgetManager, int[] appWidgetIds) {
        WidgetHelper.updateAll(context);
        WidgetHelper.fetchAndUpdate(context);
    }

    @Override
    public void onReceive(Context context, Intent intent) {
        super.onReceive(context, intent);
        String action = intent.getAction();
        if (WidgetHelper.ACTION_PANIC.equals(action)) {
            WidgetHelper.performPanic(context);
        } else if (WidgetHelper.ACTION_CHECK.equals(action)) {
            WidgetHelper.performCheck(context);
        } else if (WidgetHelper.ACTION_REFRESH.equals(action)) {
            WidgetHelper.fetchAndUpdate(context);
        }
    }
}
