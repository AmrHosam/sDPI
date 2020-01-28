#include "ndpi_main.h"
#include <sys/time.h>
#include "ndpi_classify.h"
/**
 * \brief Calculate the difference betwen two times (result = a - b)
 * \param a First time value
 * \param b Second time value
 * \param result The difference between the two time values
 * \return none
 */
void ndpi_timer_sub(const struct timeval *a,
               const struct timeval *b,
               struct timeval *result)
{
    result->tv_sec = a->tv_sec - b->tv_sec;
    result->tv_usec = a->tv_usec - b->tv_usec;
    if (result->tv_usec < 0) 
    {
        --result->tv_sec;
        result->tv_usec += 1000000;
    }
}
/**
 * \brief Calculate the milliseconds representation of a timeval.
 * \param ts Timeval
 * \return unsigned int - Milliseconds
 */
unsigned int ndpi_timeval_to_milliseconds(struct timeval ts)
{
    unsigned int result = ts.tv_usec / 1000 + ts.tv_sec * 1000;
    return result;
}
