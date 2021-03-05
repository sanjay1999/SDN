# Multipath routing

## Starting controller
```
sudo ryu-manager --observe-links controller.py
```

## Running mininet
```
sudo python topology.py
```

## Changing link parameters
```
py s1.connectionsTo(s2)[0][0].config(**{'delay':'1000ms'})
```