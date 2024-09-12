---
title: 无人机集群的第一次尝试
date: 2021-12-31
tags: [AirSim, investigate]
authors: [nova]
---

# 配置 settings.json 文件

> [Microsoft 官方对于 Multi Vehicles 的文档](https://microsoft.github.io/AirSim/multi_vehicle/)

在`settings.json`中配置以下字段

<!--truncate-->

```json
  "Vehicles": {
    "UAV1": {
      "VehicleType": "SimpleFlight",
      "X": 0,
      "Y": 0,
      "Z": 0,
      "Yaw": 0
    },
    "UAV2": {
      "VehicleType": "SimpleFlight",
      "X": 2,
      "Y": 0,
      "Z": 0,
      "Yaw": 0
    },
    "UAV3": {
      "VehicleType": "SimpleFlight",
      "X": -2,
      "Y": 0,
      "Z": 0,
      "Yaw": 0
    }
  }
```

在 `Python`中获取无人机列表

```python
drones = client.listVehicles()
```

由于无人机集群需要协同运行，所以我们不能参考上文一样对所有动作都加入`.join()`方法，否则会使得无人机一架一架进行动作。而所有的无人机都不加入`.join()`方法又会导致接下来的动作无法正常运行。

这里我想到的解决方法如下：

> 检测如果是最后一架无人机，则加入到`Future`类中，使接下来的动作都要等待他完成后才进行。

```python
for i in drones:
    print(drones)
    if i == drones[-1]:
        client.takeoffAsync(vehicle_name=i).join()
    else:
        client.takeoffAsync(vehicle_name=i)
```

于是能动了![](https://oss.nova.gal/img/20210930153706.png)

那就激情尼尔机械纪元去啦，打大折直接进行一手**劲爆购买**
