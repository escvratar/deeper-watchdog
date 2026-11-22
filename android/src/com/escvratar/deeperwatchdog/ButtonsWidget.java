package com.escvratar.deeperwatchdog;

import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.Context;
import android.content.Intent;

/** Action widget provider with 2 big buttons: COMPARE and REBUILD. */
public class ButtonsWidget extends AppWidgetProvider {

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
        } else if (WidgetHelper.ACTION_COMPARE.equals(action)) {
            WidgetHelper.performCompare(context);
        } else if (WidgetHelper.ACTION_REFRESH.equals(action)) {
            WidgetHelper.fetchAndUpdate(context);
        }
    }
}
