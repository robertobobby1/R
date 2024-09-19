#pragma once

#include "Macros.h"

#include <chrono>
#include <thread>
#include <iostream>

namespace R::Time {

    template <class Rep, class Period>
    using Duration = std::chrono::duration<Rep, Period>;

    typedef std::chrono::high_resolution_clock HighResClock;
    typedef std::chrono::time_point<HighResClock> TimePoint;

    typedef std::chrono::seconds Seconds;
    typedef std::chrono::milliseconds MilliSeconds;
    typedef std::chrono::microseconds MicroSeconds;
    typedef std::chrono::nanoseconds NanoSeconds;

    typedef std::function<void()> VoidFunction;

    template <class Rep, class Period>
    inline void setTimeout(Duration<Rep, Period> delay, VoidFunction function) {
        std::thread([function, delay]() {
            std::this_thread::sleep_for(delay);
            function();
        }).detach();
    };

    inline TimePoint now() {
        return HighResClock::now();
    }

    template <class DurationType, class Rep, class Period>
    inline DurationType castTime(Duration<Rep, Period> value) {
        return std::chrono::duration_cast<DurationType>(value);
    }

    class Timer {
       public:
        Timer(Seconds delayInSeconds)
            : Timer(castTime<NanoSeconds>(delayInSeconds)) {}

        Timer(MilliSeconds delayInMiliSeconds)
            : Timer(castTime<NanoSeconds>(delayInMiliSeconds)) {}

        Timer(MicroSeconds delayInMicroSeconds)
            : Timer(castTime<NanoSeconds>(delayInMicroSeconds)) {}

        Timer(NanoSeconds delayInNanoSeconds)
            : m_delayInNanoSeconds(delayInNanoSeconds), m_start(now()) {}

        void resetTimer() {
            m_start = now();
        }

        NanoSeconds elapsed() {
            return now() - m_start;
        }

        bool isTimerFinished() {
            return elapsed() > m_delayInNanoSeconds;
        }

       private:
        TimePoint m_start;
        NanoSeconds m_delayInNanoSeconds;
    };

}  // namespace R::Time