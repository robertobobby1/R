#pragma once

#include <chrono>
#include <thread>

#include "Utils.h"

namespace R::Time {

    template <class _Rep, class _Period>
    using TimerDelay = std::chrono::duration<_Rep, _Period>;

    typedef std::chrono::high_resolution_clock HighResClock;
    typedef std::chrono::time_point<HighResClock> TimePoint;

    typedef std::function<void()> VoidFunction;

    template <class _Rep, class _Period>
    static void setTimeout(TimerDelay<_Rep, _Period> delay, VoidFunction function) {
        t([function, delay]() {
            std::this_thread::sleep_for(delay);
            function();
        }).detach();
    };

    inline TimePoint now() {
        return HighResClock::now();
    }

    class Timer {
       private:
        std::mutex m_timerMutex;
        std::condition_variable m_timerCondition;

        std::atomic<bool> m_isWaiting = false;

        std::thread m_timerThread;

       public:
        std::atomic<bool> m_isTimerOn = true;

        Timer() {}
        ~Timer() {
            stopTimer();
        }

        template <class _Rep, class _Period>
        void startTimer(TimerDelay<_Rep, _Period> delay, VoidFunction callback = nullptr) {
            m_timerThread = std::thread([this, callback, delay]() {
                while (this->m_isTimerOn) {
                    std::unique_lock lock(this->m_timerMutex);

                    m_isWaiting = true;
                    auto status = this->m_timerCondition.wait_for(lock, delay);
                    m_isWaiting = false;

                    if (status == std::cv_status::no_timeout) {
                        continue;
                    }

                    this->m_isTimerOn = false;
                    if (callback != nullptr) {
                        callback();
                    }
                }
            });
        }

        void resetTimer() {
            m_timerCondition.notify_one();
        }

        void stopTimer() {
            while (m_isTimerOn && !m_isWaiting) {
            }

            // avoid race conditions, asigning the variable takes a little time
            std::this_thread::sleep_for(std::chrono::microseconds(1));
            m_isTimerOn = false;
            m_timerCondition.notify_one();
            m_timerThread.join();
        }
    };

    class SimpleTimer {
       public:
        SimpleTimer() : beg_(clock_::now()) {}

        void resetTimer() { beg_ = clock_::now(); }
        bool isTimerFinished() {}

        double elapsed() const {
            return std::chrono::duration_cast<second_>(clock_::now() - beg_).count();
        }

       private:
        typedef std::chrono::high_resolution_clock clock_;
        typedef std::chrono::duration<double, std::ratio<1> > second_;
        std::chrono::time_point<clock_> beg_;
    };

}  // namespace R::Time