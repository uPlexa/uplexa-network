#ifndef UDAP_CODEL_QUEUE_HPP
#define UDAP_CODEL_QUEUE_HPP
#include <udap/time.h>
#include <cmath>
#include <functional>
#include <mutex>
#include <queue>
#include <string>

namespace udap
{
  namespace util
  {
    template < typename T, typename GetTime, typename PutTime,
               udap_time_t dropMs = 20, udap_time_t initialIntervalMs = 100 >
    struct CoDelQueue
    {
      CoDelQueue(const std::string& name) : m_name(name)
      {
      }

      struct CoDelCompare
      {
        bool
        operator()(const T& left, const T& right) const
        {
          return GetTime()(left) < GetTime()(right);
        }
      };

      void
      Put(const T& i)
      {
        std::unique_lock< std::mutex > lock(m_QueueMutex);
        PutTime()(i);
        m_Queue.push(i);
        if(firstPut == 0)
          firstPut = GetTime()(i);
      }

      void
      Process(std::queue< T >& result)
      {
        udap_time_t lowest = 0xFFFFFFFFFFFFFFFFUL;
        std::unique_lock< std::mutex > lock(m_QueueMutex);
        auto start = firstPut;
        while(m_Queue.size())
        {
          const auto& item = m_Queue.top();
          auto dlt         = start - GetTime()(item);
          lowest           = std::min(dlt, lowest);
          if(m_Queue.size() == 1)
          {
            if(lowest > dropMs)
            {
              // drop
              nextTickInterval += initialIntervalMs / std::sqrt(++dropNum);
              udap::Info("CoDel quque ", m_name, " drop ", nextTickInterval,
                          " ms next interval lowest=", lowest);
              delete item;
              m_Queue.pop();
              break;
            }
            else
            {
              nextTickInterval = initialIntervalMs;
              dropNum          = 0;
            }
          }
          result.push(item);
          m_Queue.pop();
        }
        firstPut = 0;
      }

      udap_time_t firstPut         = 0;
      size_t dropNum                = 0;
      udap_time_t nextTickInterval = initialIntervalMs;
      std::mutex m_QueueMutex;
      std::priority_queue< T, std::vector< T >, CoDelCompare > m_Queue;
      std::string m_name;
    };
  }  // namespace util
}  // namespace udap

#endif