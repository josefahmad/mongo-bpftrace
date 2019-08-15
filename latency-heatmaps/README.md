Traffic generator: POCDriver - https://github.com/johnlpage/POCDriver
Latency Heatmap: https://github.com/brendangregg/HeatMap

$ mlunch init --single
$ java -jar POCDriver.jar

$ sudo bpftrace latency-op-end-to-end-heatmap.bt > heatmap.txt

$ # remove first line from heatmap.txt and any trailing lines at the end

$ ./trace2heatmap.pl --unitstime=us --unitslabel=us heatmap.txt > heatmap.svg

![sample-heatmap](sample-heatmap.svg "Sample output")
