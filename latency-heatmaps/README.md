Traffic generator: POCDriver - https://github.com/johnlpage/POCDriver

Latency Heatmap: https://github.com/brendangregg/HeatMap

```
$ mlaunch init --single # tested with 4.0.12
$ java -jar POCDriver.jar
$ sudo bpftrace latency-op-end-to-end-heatmap.bt > heatmap.txt
$ # remove first line from heatmap.txt and any trailing lines at the end
$ ./trace2heatmap.pl --unitstime=us --unitslabel=us heatmap.txt > heatmap.svg
```

Sample output (it's an interactive SVG file, however GitHub seems to show a static view only):
![sample-heatmap](sample-heatmap.svg "Sample output")
