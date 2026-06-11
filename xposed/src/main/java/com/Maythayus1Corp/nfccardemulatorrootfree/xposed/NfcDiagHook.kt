package com.Maythayus1Corp.nfccardemulatorrootfree.xposed

import android.util.Log
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage

class NfcDiagHook : IXposedHookLoadPackage {
    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName != "com.android.nfc") return

        Log.i(TAG, "Loaded into com.android.nfc pid=${android.os.Process.myPid()}")

        hookIfExists(lpparam, "com.android.nfc.NfcService", "applyRouting")
        hookIfExists(lpparam, "com.android.nfc.NfcService", "sendMessage", Int::class.javaPrimitiveType, Any::class.java)
        hookIfExists(lpparam, "com.android.nfc.NfcService", "playSound", Int::class.javaPrimitiveType)
        hookIfExists(lpparam, "com.android.nfc.NfcDiscoveryParameters", "shouldEnableDiscovery")
        hookIfExists(lpparam, "com.android.nfc.NfcDiscoveryParameters", "shouldEnableHostRouting")
    }

    private fun hookIfExists(
        lpparam: XC_LoadPackage.LoadPackageParam,
        className: String,
        methodName: String,
        vararg parameterTypes: Class<*>?
    ) {
        try {
            val hook = object : XC_MethodHook() {
                override fun beforeHookedMethod(param: MethodHookParam) {
                    Log.d(TAG, "${className}#${methodName} BEFORE args=${param.args?.contentToString()}")
                }

                override fun afterHookedMethod(param: MethodHookParam) {
                    Log.d(TAG, "${className}#${methodName} AFTER result=${param.result}")
                }
            }

            if (parameterTypes.isEmpty()) {
                XposedHelpers.findAndHookMethod(className, lpparam.classLoader, methodName, hook)
            } else {
                val args = ArrayList<Any>(parameterTypes.size + 1)
                for (t in parameterTypes) {
                    args.add(t ?: Any::class.java)
                }
                args.add(hook)
                XposedHelpers.findAndHookMethod(className, lpparam.classLoader, methodName, *args.toTypedArray())
            }

            Log.i(TAG, "Hooked ${className}#${methodName}")
        } catch (t: Throwable) {
            Log.w(TAG, "Unable to hook ${className}#${methodName}: ${t.javaClass.simpleName}: ${t.message}")
        }
    }

    private companion object {
        private const val TAG = "NFCCardEmuXposed"
    }
}
