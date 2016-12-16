
.. code-block:: sh

    $ mkdir -p jni/libmp3lame/src

    $ cp -v lame-3.99.5/libmp3lame/*.c jni/libmp3lame/src/
    $ cp -v lame-3.99.5/libmp3lame/*.h jni/libmp3lame/src/

    $ cp -v lame-3.99.5/include/lame.h jni/libmp3lame/src/
    `lame-3.99.5/include/lame.h' -> `jni/libmp3lame/src/lame.h'

    $ vim jni/Android.mk
    $ vim jni/application.mk
    $ vim jni/libmp3lame/Android.mk

    $ vim jni/libmp3lame/src/fft.c
    /* #include "vector/lame_intrin.h" */ /* commentted out for Android */

    $ vim ./jni/libmp3lame/src/set_get.h
    /* #include <lame.h> */
    #include "lame.h"

    $ vim ./jni/libmp3lame/src/util.h
    /*  extern ieee754_float32_t fast_log2(ieee754_float32_t x); */
    extern float fast_log2(float x);
