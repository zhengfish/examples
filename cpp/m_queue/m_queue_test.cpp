/**
 * @file m_queue_test.cpp
 *
 * @brief m_queue class test program
 *
 * @author zhengfish<zhengfish@gmail.com>
 *
 * @date 2016-07-18 12:22:39 Mon/29
 *
 * @reference https://github.com/juanchopanza/cppblog.git
 *
 * @bug No known bugs.
 *
 */

#include <iostream>
#include <thread>

#include "m_queue.h"

void producer ( m_queue<int>& q, unsigned int id )
{
    for ( int i = 0; i < 100; ++i ) {
        std::cout << "producer " << id  << " push " << i << "\n";
        q.push ( i );
    }
}

void consumer ( m_queue<int>& q, unsigned int id )
{
    for ( int i = 0; i < 100; ++i ) {
        auto item = q.pop();
        std::cout << "consumer " << id << " pop " << item << "\n";
    }
}

int main ( void )
{
    m_queue<int> q;

    // producer threads
    std::thread producer_1 ( std::bind ( &producer, std::ref ( q ), 1 ) );
    std::thread producer_2 ( std::bind ( &producer, std::ref ( q ), 2 ) );

    // consumer threads
    std::thread consumer_1 ( std::bind ( &consumer, std::ref ( q ), 1 ) );
    std::thread consumer_2 ( std::bind ( &consumer, std::ref ( q ), 2 ) );

    producer_1.join();
    producer_2.join();
    consumer_1.join();
    consumer_2.join();

    return 0;
}

