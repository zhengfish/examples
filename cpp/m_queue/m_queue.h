/**
 * @file m_queue.h
 *
 * @brief a simple message queue.
 *        it is thread-safe and concurrency supported.
 *
 * @author zhengfish<zhengfish@mail.com>
 *
 * @date 2016-07-18 12:22:39 Mon/29
 *
 * @reference https://github.com/juanchopanza/cppblog.git
 *
 * @bug No known bugs.
 *
 */

#ifndef M_QUEUE_H_
#define M_QUEUE_H_

#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>

template <typename T>
class m_queue
{
public:
    void push ( const T& item )
    {
        std::unique_lock<std::mutex> mlock ( mutex_ );
        queue_.push ( item );
        cond_.notify_one();
    }

    bool empty() const
    {
        std::unique_lock<std::mutex> mlock ( mutex_ );
        return queue_.empty();
    }

    std::size_t size() const
    {
        std::unique_lock<std::mutex> mlock ( mutex_ );
        return queue_.size();
    }

    bool try_pop ( T &item )
    {
        std::unique_lock<std::mutex> mlock ( mutex_ );

        if ( queue_.empty() ) {
            return false;
        }

        item = queue_.front();
        queue_.pop();

        return true;
    }

    T wait_and_pop()
    {
        std::unique_lock<std::mutex> mlock ( mutex_ );
        while ( queue_.empty() ) {
            cond_.wait ( mlock );
        }
        auto val = queue_.front();
        queue_.pop();
        return val;
    }

    void wait_and_pop ( T &item )
    {
        std::unique_lock<std::mutex> mlock ( mutex_ );

        while ( queue_.empty() ) {
            cond_.wait ( mlock );
        }
        item = queue_.front();

        queue_.pop();
    }

    m_queue() = default;
    m_queue ( const m_queue & ) = delete;                // disable copying
    m_queue & operator= ( const m_queue & ) = delete;    // disable assignment

private:
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable cond_;
};

#endif /* M_QUEUE_H_ */

