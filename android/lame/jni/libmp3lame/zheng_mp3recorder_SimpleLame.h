/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class zheng_mp3recorder_SimpleLame */

#ifndef _Included_zheng_mp3recorder_SimpleLame
#define _Included_zheng_mp3recorder_SimpleLame
#ifdef __cplusplus
extern "C" {
#endif
    /*
     * Class:     zheng_mp3recorder_SimpleLame
     * Method:    close
     * Signature: ()V
     */
    JNIEXPORT void JNICALL Java_zheng_mp3recorder_SimpleLame_close
    ( JNIEnv *, jclass );

    /*
     * Class:     zheng_mp3recorder_SimpleLame
     * Method:    encode
     * Signature: ([S[SI[B)I
     */
    JNIEXPORT jint JNICALL Java_zheng_mp3recorder_SimpleLame_encode
    ( JNIEnv *, jclass, jshortArray, jshortArray, jint, jbyteArray );

    /*
     * Class:     zheng_mp3recorder_SimpleLame
     * Method:    flush
     * Signature: ([B)I
     */
    JNIEXPORT jint JNICALL Java_zheng_mp3recorder_SimpleLame_flush
    ( JNIEnv *, jclass, jbyteArray );

    /*
     * Class:     zheng_mp3recorder_SimpleLame
     * Method:    init
     * Signature: (IIIII)V
     */
    JNIEXPORT void JNICALL Java_zheng_mp3recorder_SimpleLame_init
    ( JNIEnv *, jclass, jint, jint, jint, jint, jint );

#ifdef __cplusplus
}
#endif
#endif