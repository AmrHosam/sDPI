#include <sys/types.h>
#include "ndpi_api.h"
#include <math.h>
void ndpi_init_data_analysis(struct ndpi_analyze_struct *ret, u_int16_t _max_series_len) {
  u_int32_t len;

  memset(ret, 0, sizeof(struct ndpi_analyze_struct));
  
  if(_max_series_len > MAX_SERIES_LEN) _max_series_len = MAX_SERIES_LEN;
  ret->num_values_array_len = _max_series_len;

  if(ret->num_values_array_len > 0) {
    len = sizeof(u_int32_t)*ret->num_values_array_len;
    if((ret->values = ndpi_malloc(len)) == NULL) {
      ndpi_free(ret);
      ret = NULL;
    } else
      memset(ret->values, 0, len);
  } else
    ret->values = NULL;
}
/* ********************************************************************************* */

struct ndpi_analyze_struct* ndpi_alloc_data_analysis(u_int16_t _max_series_len) {
  struct ndpi_analyze_struct *ret = ndpi_malloc(sizeof(struct ndpi_analyze_struct));

  if(ret != NULL)
    ndpi_init_data_analysis(ret, _max_series_len);  
  
  return(ret);
}
/* ********************************************************************************* */

/*
  Add a new point to analyze
 */
void ndpi_data_add_value(struct ndpi_analyze_struct *s, const u_int32_t value) 
{
  float tmp_mu;

  if(s->sum_total == 0)
    s->min_val = s->max_val = value;
  else 
  {
    if(value < s->min_val) s->min_val = value;
    if(value > s->max_val) s->max_val = value;
  }

  s->sum_total += value, s->num_data_entries++;
  
  if(s->num_values_array_len) 
  {
    s->values[s->next_value_insert_index] = value;

    if(++s->next_value_insert_index == s->num_values_array_len)
      s->next_value_insert_index = 0;
  }
  
  /* Update stddev */
  tmp_mu = s->stddev.mu;
  s->stddev.mu = ((s->stddev.mu * (s->num_data_entries - 1)) + value) / s->num_data_entries;
  s->stddev.q = s->stddev.q + (value - tmp_mu)*(value - s->stddev.mu);    
}
/* ********************************************************************************* */

void ndpi_free_data_analysis(struct ndpi_analyze_struct *d) {
  if(d->values) ndpi_free(d->values);
  ndpi_free(d);
}

const char* ndpi_data_ratio2str(float ratio) {
  if(ratio < -0.2) return("Download");
  else if(ratio > 0.2) return("Upload");
  else return("Mixed");
}

/* Compute the average on all values */
float ndpi_data_average(struct ndpi_analyze_struct *s) {
  return((s->num_data_entries == 0) ? 0 : ((float)s->sum_total / (float)s->num_data_entries));
}

/* ********************************************************************************* */

/* Return min/max on all values */
u_int32_t ndpi_data_min(struct ndpi_analyze_struct *s) { return(s->min_val); }
u_int32_t ndpi_data_max(struct ndpi_analyze_struct *s) { return(s->max_val); }

/* ********************************************************************************* */

/* Compute the variance on all values */
float ndpi_data_variance(struct ndpi_analyze_struct *s) {
  return(s->num_data_entries ? (s->stddev.q / s->num_data_entries) : 0);
}

/* ********************************************************************************* */

/* Compute the standard deviation on all values */
float ndpi_data_stddev(struct ndpi_analyze_struct *s) {
  return(sqrt(ndpi_data_variance(s)));
}