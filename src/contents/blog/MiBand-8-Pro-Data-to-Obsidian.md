---
title: 小米手环 8 Pro 自动上传数据到 Obsidian 的思路
date: 2024-02-01
tags: [reverse, investigate]
authors: [nova]
---

前几天学着 [DIYGOD](https://diygod.cc) 搞了一套生活管理系统。在各种插件的加持下算是做到了半自动化，然而，睡眠时间和步数，以及可能的心率血压等数据仍然需要手动记录手动填写实在是不算 Geek。搜索之后得知其实 Zepp(原 Huami) 存在有逆向后的 API 接口且明文存储步数等信息，于是便脑子一热入了 **_小米手环 8 Pro 原神联名版_**。拿到手后，才惊讶地发现 小米手环 8 已经不再支持 Zepp，小米手环 7 虽然表面上不支持，但也能使用修改 QRCode 和 Zepp 安装包的方式，然而小米手环 8 已经是彻底把 Zepp 给 Deprecated 了。

<!--truncate-->

## 初探 —— 抓包

首先，当然是看抓包有没有什么有用的信息了。我原来用 proxifier 做抓包，但是效果并不好，原因是有一些软件存在 SSLPinning，所以这次，采用了 mitmproxy + 系统级证书的方法。

### 工具链

- [mitmproxy - an interactive HTTPS proxy](https://mitmproxy.org/)
- [nccgroup/ConscryptTrustUserCerts](https://github.com/nccgroup/ConscryptTrustUserCerts)
- [shockeyzhang/magisk-delta](https://github.com/shockeyzhang/magisk-delta)

### 测试方法

长话短说，首先在 PC 上安装 mitmproxy，然后在 `$HOME/.mitmproxy` 目录下拿到 `mitmproxy-ca-cert.cer` 文件，按照正常的工作流安装在 Android 设备上。

> 在我的案例中，我在搜索中搜索 `cred` 相关字样，就找到了 `Credential storage`，并且有 `Install certificates from storage`，这就是我的正常工作流。不同的设备可能有不同的工作流

在 Magisk 中安装 `ConscryptTrustUserCerts`，重启，即可在 boot 阶段将 用户级证书 mount 到 系统级证书 目录下，这就完成了准备工作。

在 PC 上打开 mitmweb，手机 Wi-Fi 设置代理为 `<my-pc-ip>:8080`，测试，成功抓取 HTTPS 请求。

### 结论

没啥用。所有的请求都是经过加密的，也有 signature 和 hash、nounce 等来确保安全性。我实在是不想逆 apk，遂作罢。

## 窥见光明 —— BLE 连接

既然抓包行不通，那么我直接做一个 BLE 客户端，连接手环并且获取数据，这显然是非常合理的事情。而且这种方式也不需要我手机上做什么操作，Obsidian 运行一个脚本，一连接，一获取，似乎非常自动化

### 实现

代码主要参考了 [wuhan005/mebeats: 💓 小米手环实时心率数据采集 - Your Soul, Your Beats!](https://github.com/wuhan005/mebeats)。不过他的工具链是 MacOS，我没有，就找 GPT 问着改了改。

~~代码中有一个 `auth_key`，需要官方 APP 来获取。倒是可以直接使用 [这个网站](https://freemyband.com) 来获取，但是本着信不过第三方的原则，我们还是手动获取。~~
做了混淆，不在原来那个数据库里了。加上我突然发现 BLE 只能同时连接到一个，而官方 APP 优先级显然更高，遂作罢。

> 既然后面逆了，就回来前面写一点。

```java
public final void bindDeviceToServer(lg1 lg1Var) {

        Logger.i(getTAG(), "bindDeviceToServer start");

        HuaMiInternalApiCaller huaMiDevice = HuaMiDeviceTool.Companion.getInstance().getHuaMiDevice(this.mac);

        if (huaMiDevice == null) {

            String tag = getTAG();

            Logger.i(tag + "bindDeviceToServer huaMiDevice == null", new Object[0]);

            if (lg1Var != null) {

                lg1Var.onConnectFailure(4);

            }

        } else if (needCheckLockRegion() && isParallel(huaMiDevice)) {

            unbindHuaMiDevice(huaMiDevice, lg1Var);

        } else {

            DeviceInfoExt deviceInfo = huaMiDevice.getDeviceInfo();

            if (deviceInfo == null) {

                String tag2 = getTAG();

                Logger.i(tag2 + "bindDeviceToServer deviceInfo == null", new Object[0]);

                return;

            }

            String sn = deviceInfo.getSn();

            setMDid("huami." + sn);

            setSn(deviceInfo.getSn());

            BindRequestData create = BindRequestData.Companion.create(deviceInfo.getSn(), this.mac, deviceInfo.getDeviceId(), deviceInfo.getDeviceType(), deviceInfo.getDeviceSource(), deviceInfo.getAuthKey(), deviceInfo.getFirmwareVersion(), deviceInfo.getSoftwareVersion(), deviceInfo.getSystemVersion(), deviceInfo.getSystemModel(), deviceInfo.getHardwareVersion());

            String tag3 = getTAG();

            Logger.d(tag3 + create, new Object[0]);

            getMHuaMiRequest().bindDevice(create, new HuaMiDeviceBinder$bindDeviceToServer$1(this, lg1Var), new HuaMiDeviceBinder$bindDeviceToServer$2(lg1Var, this));

        }

    }
```

可以看到是从 `deviceInfo` 拿的，而它又来自于 `huamiDevice`。然后稍微溯下源，可以知道这个是由 mac 算出来的，但是具体的不会看了，感兴趣的可以看 `com.xiaomi.wearable.wear.connection` 这个包

## 大道至简 —— Frida Hook

到这里，其实我已经想好最终的思路了，开逆呗。既然最终发出去是加密的，那肯定有没加密的数据处理的过程。逆出来，hook 一下，写个 XPosed 插件监听着就好了。
在这里，由于时间晚了，我不想再花过多的精力写如何安装 [frida](https://frida.rs)。

首先 `jadx-gui` 自带了 `copy as frida snippets` 的功能，可以省去不少功夫。然而，由于 `kotlin` 数据类的各种奇怪原因，其实很多时候拿不到。由于我没有边踩坑边记录，因此就大概的回溯一下流程：

1. 首先，在 `/data/data/com.mi.health/databases` 文件夹下看到了用户所对应的文件夹，里面有 `fitness_summary` 这个数据库，读取发现存在有想要的数据。因此初步的搜索关键词 `fitness_summary` 进行交叉引用，溯源到了 `com.xiaomi.fit.fitness.persist.db.internal` 这个类
2. 看到了 `update、insert` 等函数，不断地进行尝试，但是始终没有办法看到输出，但是最终找到了 `com.xiaomi.fit.fitness.persist.db.internal.h.getDailyRecord` 这个函数可以在每次刷新时都有输出，但只有 `sid、time` 等值，不包含 `value`
3. 继续溯源，利用下面的代码片段来看重载以及参数类型。

```javascript
var insertMethodOverloads = hClass.updateAll.overloads;

for (var i = 0; i < insertMethodOverloads.length; i++) {
  var overload = insertMethodOverloads[i];
  console.log(
    "Overload #" + i + " has " + overload.argumentTypes.length + " arguments."
  );
  for (var j = 0; j < overload.argumentTypes.length; j++) {
    console.log(
      " - Argument " + j + ": " + overload.argumentTypes[j].className
    );
  }
}
```

4. 突然想到可以利用异常来查看函数调用栈，此时属于是守得云开见月明了。

```javascript
var callerMethodName = Java.use("android.util.Log").getStackTraceString(
  Java.use("java.lang.Exception").$new()
);
console.log("getTheOneDailyRecord called by: " + callerMethodName);
```

5. 一层一层的，找到了 `com.xiaomi.fit.fitness.export.data.aggregation.DailyBasicReport` 这个类，完美满足了我的需求。

```javascript
dbutilsClass.getAllDailyRecord.overload(
  "com.xiaomi.fit.fitness.export.data.annotation.HomeDataType",
  "java.lang.String",
  "long",
  "long",
  "int"
).implementation = function (homeDataType, str, j, j2, i) {
  console.log(
    "getAllDailyRecord called with args: " +
      homeDataType +
      ", " +
      str +
      ", " +
      j +
      ", " +
      j2 +
      ", " +
      i
  );
  var result = this.getAllDailyRecord(homeDataType, str, j, j2, i);
  var entrySet = result.entrySet();
  var iterator = entrySet.iterator();
  while (iterator.hasNext()) {
    var entry = iterator.next();
    console.log("entry: " + entry);
  }
  var callerMethodName = Java.use("android.util.Log").getStackTraceString(
    Java.use("java.lang.Exception").$new()
  );
  console.log("getTheOneDailyRecord called by: " + callerMethodName);
  return result;
};
// DailyStepReport(time=1706745600, time = 2024-02-01 08:00:00, tag='days', steps=110, distance=66, calories=3, minStartTime=1706809500, maxEndTime=1706809560, avgStep=110, avgDis=66, active=[], stepRecords=[StepRecord{time = 2024-02-02 01:30:00, steps = 110, distance = 66, calories = 3}])
```

6. 犯了难，因为这个 `steps` 是 `private` 属性，虽然 `jadx-gui` 中写出了复数个可以获取它的接口 `getSteps()`、`getSourceData()` 却没有一个能用，都提示 `not a function`。这里猜测还是 kotlin 和 java 的处理方式不同吧。最终是用反射的方式解决了。
   至此最终 `frida` 代码如下，可以获取当天的 `steps` 数据，修改 `HomeDataType` 即可获取其他数据。

```javascript
var CommonSummaryUpdaterCompanion = Java.use(
  "com.xiaomi.fitness.aggregation.health.updater.CommonSummaryUpdater$Companion"
);
var HomeDataType = Java.use(
  "com.xiaomi.fit.fitness.export.data.annotation.HomeDataType"
);
var instance = CommonSummaryUpdaterCompanion.$new().getInstance();
console.log("instance: " + instance);

var step = HomeDataType.STEP;
var DailyStepReport = Java.use(
  "com.xiaomi.fit.fitness.export.data.aggregation.DailyStepReport"
);

var result = instance.getReportList(step.value, 1706745600, 1706832000);
var report = result.get(0);
console.log("report: " + report + report.getClass());

var stepsField = DailyStepReport.class.getDeclaredField("steps");
stepsField.setAccessible(true);
var steps = stepsField.get(report);
console.log("Steps: " + steps);
// Steps: 110
```

## 最终 —— XPosed 插件

目前思路就是 XPosed 监听一个地址，然后再稍微的做一些~~保护防止明文传输~~鸽了，先用着。因为这个应用是一直开启的，所以我觉得可行。现在的问题就是我不会写 kotlin，更不会写 XPosed。

好在 kotlin 的编译器提示足够强大，以及 XPosed 本身除了配置的搭建之外并不需要什么额外的知识，加上强大的 GPT，琢磨了一两个小时就弄好了基本的环境（难评 gradle，不开代理下的慢，开了代理下不了）

### 环境搭建

反正直接 Android Studio 开一个 No Activity 的项目。没有人写 gradle kotlin 是怎么配 XPosed 的，这里简短说一下，主要是网上都是直接 settings.gradle，也很古早了，踩坑踩了一会。

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://api.xposed.info/") }
    }
}
```

```kotlin
// build.gradle.kts
dependencies {
    compileOnly("de.robv.android.xposed:api:82")  // 这行
    implementation("androidx.core:core-ktx:1.10.1")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.9.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
    implementation(kotlin("reflect"))
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.2")
}
```

```xml
<!-- AndroidManifest.xml，主要是下面的元数据 -->
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">

    <application
        android:allowBackup="true"
        android:dataExtractionRules="@xml/data_extraction_rules"
        android:fullBackupContent="@xml/backup_rules"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.MiBandUploader"
        tools:targetApi="31" >

        <meta-data
            android:name="xposedmodule"
            android:value="true" />
        <meta-data
            android:name="xposeddescription"
            android:value="Mi Fitness Data Uploader" />
        <meta-data
            android:name="xposedminversion"
            android:value="53" />
        <meta-data
            android:name="xposedscope"
            android:resource="@array/xposedscope" />
    </application>

</manifest>
```

```xml
<!-- res/values/array.xml，和上面 xposedscope 对应，就是作用域包名 -->
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string-array name="xposedscope" >
        <item>com.mi.health</item>
    </string-array>
</resources>
```

然后，还需要在 `app/src/main/` 下面新建一个 `assets/xposed_init` 文件，内容填写你的入口类

```
sh.ouo.miband.uploader.MainHook
```

至此，编译一下就可以在 LSPosed Manager 里看到你的插件了

### 思路

#### HOOK 点

我们思考，既然需要在后台启动，而小米健康本身就有一些保活和自启的机制，因此我们完全没必要 hook MainActivity 的 onCreate 方法，而是找一个自启的方法即可。

Android 自启的方法，经过一点搜索，可能有 `BOOT_COMPLETED` 广播监听、`AlarmManager ` 定时任务、`JobScheduler ` 工作以及 `Service` 等。在 jadx-gui 中搜索，我们找到了 `com.xiaomi.fitness.keep_alive.KeepAliveHelper` 这个类的 `startService` 方法。经过测试，确实可以使用。

在这里我们主要利用单例，让它不要重复注册。其中主要的函数就是 `handleLoadPackage` 来获取对应的 `LoadPackageParam`，之后对于想要 HOOK 的函数，继承 `XC_MethodHook` 即可。

下面就是我们拿了一个 `CommonSummaryUpdater` 的实例，用于和我们说的 frida 那里联动。

```kotlin
import android.util.Log
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage


class MainHook : IXposedHookLoadPackage {
    companion object {
        @Volatile
        var isReceiverRegistered = false
    }

    override fun handleLoadPackage(lpparam: XC_LoadPackage.LoadPackageParam) {
        if (lpparam.packageName != "com.mi.health") return
        hook(lpparam)
    }

    private fun hook(lpparam: XC_LoadPackage.LoadPackageParam) {
        XposedHelpers.findAndHookMethod(
            "com.xiaomi.fitness.keep_alive.KeepAliveHelper",
            lpparam.classLoader,
            "startService",
            object : XC_MethodHook() {
                @Throws(Throwable::class)
                override fun afterHookedMethod(param: MethodHookParam) {
                    if ( !isReceiverRegistered ) {
                        Log.d("MiBand", "MiUploader Hook Startup...")
                        val updaterClass = XposedHelpers.findClass("com.xiaomi.fitness.aggregation.health.updater.CommonSummaryUpdater", lpparam.classLoader)
                        val companionInstance = XposedHelpers.getStaticObjectField(updaterClass, "Companion")
                        val commonSummaryUpdaterInstance = XposedHelpers.callMethod(companionInstance, "getInstance")
                        Log.d("MiBand","MiUploader Receiver Deployed!")
                        isReceiverRegistered = true
                    }
                    super.afterHookedMethod(param)
                }
            })
    }
}
```

#### 数据提取

基本与 frida 类似，我们就是调用对应的方法然后解析呗。在这里，我稍微写了一个抽象基类，我也不知道到底用不用写这个基类

```kotlin
import android.util.Log
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import kotlinx.serialization.json.JsonElement
import java.time.LocalDate
import java.time.ZoneId
import java.time.format.DateTimeFormatter

abstract class DailyReportBase (
    protected val lpparam: LoadPackageParam,
    private val instance: Any
) {
    private lateinit var enumValue: Any

    protected fun setEnumValue(type: String) {
        val homeDataType = XposedHelpers.findClass("com.xiaomi.fit.fitness.export.data.annotation.HomeDataType", lpparam.classLoader)
        enumValue = XposedHelpers.getStaticObjectField(homeDataType, type)
    }

    private fun getDay(day: String?): Pair<Long, Long> {
        val formatPattern = DateTimeFormatter.ofPattern("yyyy-MM-dd")
        val beijingZoneId = ZoneId.of("Asia/Shanghai")
        val today = if (day == null) {
            LocalDate.now(beijingZoneId)
        } else {
            LocalDate.parse(day, formatPattern)
        }
        val startOfDay = today.atStartOfDay(beijingZoneId)
        Log.d("MiBand", startOfDay.toString())
        val startOfDayTimestamp = startOfDay.toEpochSecond()
        val endOfDayTimestamp = startOfDay.plusDays(1).minusSeconds(1).toEpochSecond() // 减去1秒以获取当天结束时间
        return Pair(startOfDayTimestamp, endOfDayTimestamp)
    }

    fun getDailyReport(day: String?): JsonElement {
        val (j1, j2) = getDay(day)
        Log.d("MiBand", "Ready to call: $instance, $enumValue, $j1, $j2")
        val result = XposedHelpers.callMethod(
            instance,
            "getReportList",
            enumValue,
            j1,
            j2
        ) as ArrayList<*>
        return toJson(result)
    }

    abstract fun toJson(obj: ArrayList<*>): JsonElement
}


```

不会 kotlin 所以写的很奇怪。但大体思路就是每个子类调用 `setEnumValue` 设置 `getDailyReport` 的枚举值，然后重写 `toJson` 就可以了。

在这里的 json 踩了很多坑，主要就还是那个类型注解，难崩。

让我们拿一个 stepReport 举例

```kotlin
import android.util.Log
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

class StepDailyReport(lpparam: XC_LoadPackage.LoadPackageParam,
                      instance: Any
) : DailyReportBase(lpparam, instance) {
    init {
        setEnumValue("STEP")
    }

    override fun toJson(obj: ArrayList<*>): JsonElement {
        Log.d("MiBand", obj.toString())
        val today = obj.getOrNull(0)
        if (today != null) {
            try {
                return // 写啥？
            }
            catch (e: Exception) {
                throw e
            }
        }
        throw NoSuchFieldException("No data fetched")
    }
}
```

那么问题来了，我们拿到的 `today` 是一个 `com.xiaomi.fit.fitness.export.data.aggregation.DailyStepReport` 的实例，我该怎么把它序列化成 json 呢？在类型注解里我只能是写一个 Any，它有哪些对象编译器也不知道，如何序列化更是不知道，更别提还有对象的嵌套。

反正测试了很久，搜索了不少，也没有找到直接的方法，不知道有没有大神帮帮。折腾了很久，最终还是决定自己做一个中间数据类。

```kotlin
    @Serializable
    data class SerializableDailyStepReport(
        val time: Long,
        val tag: String,
        val steps: Int,
        val distance: Int,
        val calories: Int,
        val minStartTime: Long?,
        val maxEndTime: Long?,
        val avgStep: Int,
        val avgDis: Int,
        val stepRecords: List<SerializableStepRecord>,
        val activeStageList: List<SerializableActiveStageItem>
    )

    @Serializable
     data class SerializableStepRecord(
        val time: Long,
        val steps: Int,
        val distance: Int,
        val calories: Int
    )

    @Serializable
    data class SerializableActiveStageItem(
        val calories: Int,
        val distance: Int,
        val endTime: Long,
        val riseHeight: Float?,
        val startTime: Long,
        val steps: Int?,
        val type: Int
    )

    private fun convertToSerializableReport(xposedReport: Any): SerializableDailyStepReport {
        val stepRecordsObject = XposedHelpers.getObjectField(xposedReport, "stepRecords") as List<*>
        val activeStageListObject = XposedHelpers.getObjectField(xposedReport, "activeStageList") as List<*>

        val stepRecords = stepRecordsObject.mapNotNull { record ->
            if (record != null) {
                SerializableStepRecord(
                    time = XposedHelpers.getLongField(record, "time"),
                    steps = XposedHelpers.getIntField(record, "steps"),
                    distance = XposedHelpers.getIntField(record, "distance"),
                    calories = XposedHelpers.getIntField(record, "calories")
                )
            } else null
        }

        val activeStageList = activeStageListObject.mapNotNull { activeStageItem ->
            if (activeStageItem != null) {
                SerializableActiveStageItem(
                    calories = XposedHelpers.getIntField(activeStageItem, "calories"),
                    distance = XposedHelpers.getIntField(activeStageItem, "distance"),
                    endTime = XposedHelpers.getLongField(activeStageItem, "endTime"),
                    riseHeight = XposedHelpers.getObjectField(activeStageItem, "riseHeight") as? Float,
                    startTime = XposedHelpers.getLongField(activeStageItem, "startTime"),
                    steps = XposedHelpers.getObjectField(activeStageItem, "steps") as? Int,
                    type = XposedHelpers.getIntField(activeStageItem, "type")
                )
            } else null
        }

        return SerializableDailyStepReport(
            time = XposedHelpers.getLongField(xposedReport, "time"),
            tag = XposedHelpers.getObjectField(xposedReport, "tag") as String,
            steps = XposedHelpers.getIntField(xposedReport, "steps"),
            distance = XposedHelpers.getIntField(xposedReport, "distance"),
            calories = XposedHelpers.getIntField(xposedReport, "calories"),
            minStartTime = XposedHelpers.getObjectField(xposedReport, "minStartTime") as Long?,
            maxEndTime = XposedHelpers.getObjectField(xposedReport, "maxEndTime") as Long?,
            avgStep = XposedHelpers.callMethod(xposedReport, "getAvgStepsPerDay") as Int,
            avgDis = XposedHelpers.callMethod(xposedReport, "getAvgDistancePerDay") as Int,
            stepRecords = stepRecords,
            activeStageList = activeStageList
        )
    }
}
```

反正搓的很难看，效率什么的估计也很低，但是我也是不知道咋办了。利用了 `serialization` 这个库。

```kotlin
// build.gradle.kts [Module]
plugins {
    ...
    kotlin("plugin.serialization") version "1.9.21"
}

dependencies {
    ...
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.2")
}
```

然后在返回的地方，由于我既可能返回 `String`，又可能返回一个 `Json`，所以用了 `JsonElement`，但是又是因为类型注解，所以我们必须写成这样(至少我问 GPT 是这样)

```kotlin
return Json.encodeToJsonElement(SerializableDailyStepReport.serializer(), convertToSerializableReport(today))
```

#### 监听

这里我真的折腾晕了。一开始，我想使用 `BroadcastReceiver`，因为省电。但这样会带来几个思考：

1. 电脑如何发出广播给 Android？

   adb，运行`adb shell am broadcast -a ACTION --es "extra_key" "extra_value"`。然而，在测试之后发现，在 Android 11 之后，adb 无线调试的端口就会变了（之前固定 5555），且在更换 WiFi / 断开 WiFi 后，还需要去开发者设置里重新打开无线调试。

   方法也是有的。在 `adb shell` 里运行 `setprop <key> <value>`，把下面几个值改了就可以了。前两个是调试的端口，后一个是不自动关闭无线调试。

   ```
   service.adb.tls.port=38420
   service.adb.tcp.port=38420

   persist.adb.tls_server.enable=1
   ```

   但是同样的，现在的 `/system` 目录已经不可写了。也就是说我们无法编辑 `build.prop` 把这几个值永久修改。那么一重启它就会恢复了，这显然会很让人心烦（虽然我一般不会关机）

   当然方法还是有的，写一个 Magisk Module，开机的时候设置一下就好了（笑）

2. 广播是单向通信，电脑又如何接消息呢？

   没想到好办法。目前的思考就是直接写入文件，然后电脑端 adb pull 再读。

于是放弃了，然后，我又开始思考 HTTP Restful API。我利用 Ktor 很快的实现了一个（利用 GPT）。

![image-20240203140011022](https://oss.nova.gal/img/image-20240203140011022.png)

但是此时又有一个问题：我们这个数据的获取频次是非常低的，却有这么一个特点：时间不固定。因此，为了稳定性，我们必须时刻保持 HTTP 服务器的开启，而 HTTP 服务器因为要维护的东西非常多，所以耗电量是非常可观的（虽然我没有测试）

于是又转向了 SOCKET 的怀抱。倒是反正也差不多。

```kotlin
class MySocketServer(
    private val port: Int,
    private val lpparam: LoadPackageParam,
    private val instance: Any
    ) {
    fun startServerInBackground() {
        Thread {
            try {
                val serverSocket = ServerSocket(port)
                Log.d("MiBand", "Server started on port: ${serverSocket.localPort}")
                while (!Thread.currentThread().isInterrupted) {
                    val clientSocket = serverSocket.accept()
                    val clientHandler = ClientHandler(clientSocket)
                    Thread(clientHandler).start()
                }
            } catch (e: Exception) {
                Log.e("MiBand", "Server Error: ${e.message}")
            }
        }.start()
    }
```

然后又突然意识到了一个尴尬的问题。我需要在 Obsidian 中使用 Templater 来获取每日的信息，也就是用 JavaScript，而 Obsidian 又是类似于沙箱的环境，所以我也没有办法运行外部脚本。JavaScript 没有办法上套接字啊？得，手搓 HTTP 协议了。安全性就算了，评价是能用就行。

```kotlin
override fun run() {
            try {
                Log.d("MiBand", "Connection: $clientSocket")
                val inputStream = BufferedReader(InputStreamReader(clientSocket.getInputStream()))
                val outputStream = PrintWriter(clientSocket.getOutputStream(), true)

                // 读取 HTTP 请求的第一行
                val requestLine = inputStream.readLine()
                println("Received: $requestLine")

                // 解析请求行
                val requestParts = requestLine?.split(" ")
                if (requestParts == null || requestParts.size < 3 || requestParts[0] != "GET") {
                    val resp = SerializableResponse(
                        status = 1,
                        data = JsonPrimitive("Invalid request")
                    )
                    sendSuccessResponse(outputStream, resp)
                    return
                }

                val pathWithParams = requestParts[1]
                val path = pathWithParams.split("?")[0]
                val params = parseQueryString(pathWithParams.split("?").getOrNull(1))

                when (path) {
                    "/getDailyReport" -> {
                        val type = params["type"]
                        val date = params["date"]
                        if (type == null) {
                            val resp = SerializableResponse(
                                status = 1,
                                data = JsonPrimitive("Missing 'type' parameter for /getDailyReport")
                            )
                            sendSuccessResponse(outputStream, resp)
                        } else {
                            // 处理 getDailyReport 请求
                            var resp: SerializableResponse
                            try {
                                val report = DailyReportFactory.createDailyReport(lpparam, instance, type)
                                val result = report.getDailyReport(date)
                                resp = SerializableResponse(
                                    status = 0,
                                    data = result
                                )

                            }
                            catch (e: Exception) {
                                resp = SerializableResponse(
                                    status = 1,
                                    data = JsonPrimitive(e.message)
                                )
                            }
                            sendSuccessResponse(outputStream, resp)

                        }
                    }
                    else -> {
                        val resp = SerializableResponse(
                            status = 1,
                            data = JsonPrimitive("Unknown path: $path")
                        )
                        sendSuccessResponse(outputStream, resp)
                    }
                }
                inputStream.close()
                outputStream.close()
                clientSocket.close()
                Log.d("MiBand", "Established")
            } catch (e: IOException) {
                e.printStackTrace()
            }
        }
    }

    private fun parseQueryString(query: String?): Map<String, String> {
        val queryPairs = LinkedHashMap<String, String>()
        val pairs = query?.split("&") ?: emptyList()
        for (pair in pairs) {
            val idx = pair.indexOf("=")
            if (idx != -1) {
                val key = pair.substring(0, idx)
                val value = pair.substring(idx + 1)
                queryPairs[key] = value
            }
        }
        return queryPairs
    }
    private fun sendSuccessResponse(outputStream: PrintWriter, result: SerializableResponse) {
        val jsonResponse = Json.encodeToString(result)
        val response = """
            HTTP/1.1 200 OK
            Content-Type: application/json
            Connection: close
            Content-Length: ${jsonResponse.toByteArray().size}

            $jsonResponse
        """.trimIndent()
        outputStream.println(response)
        outputStream.flush()
    }
```

![非常健康的睡眠状态](https://oss.nova.gal/img/image-20240203141224260.png)

源码后面再上传吧，现在纯半成品，评价是随便偷我的睡眠数据。
