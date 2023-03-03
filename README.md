###### simple-kpc

A dumb-as-rocks C library for accessing performance counters on macOS
through private APIs (kperf.framework and kperfdata.framework).
I don’t actually know how any of this works:
I just took [ibireme’s gist][ibireme],
stripped out the pieces I didn’t need,
and wrapped it all up in a nice-ish API.

###### lineage

1. [Henry Wong’s reorder buffer capacity measuring tool][henrywong]:
   _Measuring Reorder Buffer Capacity_
2. [Travis Downs’ updated version of that][travisdowns]:
   _robsize: ROB size testing utility_
3. [Dougall Johnson’s M1 reorder buffer capacity measuring tool][dougallj]:
   _m1_robsize.c: M1 buffer size measuring tool_
4. [Daniel Lemire’s M1 performance counter measuring code][lemire]:
   _m1cycles.cpp: Counting cycles and instructions on the Apple M1 processor_
5. [ibireme’s reverse-engineered kperf.framework / kperfdata.framework interface][ibireme]:
   _kpc_demo.c: A demo shows how to read Intel or Apple M1 CPU performance counter in macOS_

[ibireme]: https://gist.github.com/ibireme/173517c208c7dc333ba962c1f0d67d12
[henrywong]: https://web.archive.org/web/20230112063710/https://blog.stuffedcow.net/2013/05/measuring-rob-capacity/
[travisdowns]: https://github.com/travisdowns/robsize
[dougallj]: https://gist.github.com/dougallj/5bafb113492047c865c0c8cfbc930155
[lemire]: https://github.com/lemire/Code-used-on-Daniel-Lemire-s-blog/blob/dc95b3fd74d70b58a7eb332de45ad6534ccd0095/2021/03/24/m1cycles.cpp
