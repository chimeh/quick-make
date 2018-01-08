#include "linux/time.h"
#include "linux/random.h"
#include "hsl_types.h"
#include "hsl_oss.h"

/************************************************************************************
 * Function: oss_sem_new  - Service routine to create a new semaphore               *
 * Parameters:                                                                      *
 *   IN  sem_name        - semaphore descriptor.                                    *
 *   IN  sem_type        - type of semaphore (binary/counting/mutex).               *
 *   IN  num_of_tokens   - initial tokens count for counting semaphore.             *
 *   IN  sem_flags       - special flags - like SEM_DELETE_SAFE/SEM_INVERSION_SAFE  *
 *                                              SEM_Q_PRIORITY.                     *
 *   OUT sem_id_ptr      - pointer to newly created semaphore.                      *
 * Return value:                                                                    *
 *   0 - semaphore creation successful.                                             *
 *   otherwise - semaphore creation failed.                                         *
 ************************************************************************************/
int 
oss_sem_new( char * sem_name,
             oss_sem_type_t sem_type,
             u_int32_t num_of_tokens,
             void *sem_flags,
             ipi_sem_id *sem_id_ptr)
{

   return 0;
}


/************************************************************************************
 * Function: oss_sem_delete  - Service routine to delete a semaphore                *
 * Parameters:                                                                      *
 *   IN  sem_type        - type of semaphore (binary/counting/mutex)                *
 *   IN  sem_id_ptr      - pointer to semaphore                                     *
 * Return value:                                                                    *
 *   0 - semaphore was successfully deleted.                                        *
 *   otherwise - semaphore deletion failed                                          *
 ************************************************************************************/
int 
oss_sem_delete( oss_sem_type_t sem_type, ipi_sem_id sem_id_ptr)
{

   return 0;
}

/************************************************************************************
 * Function: oss_sem_lock    - Service routine to lock a semaphore                  *
 * Parameters:                                                                      *
 *   IN  sem_type        - type of semaphore (binary/counting/mutex).               *
 *   IN  sem_id_ptr      - pointer to semaphore.                                    *
 *   IN  timeout         - miliseconds lock timeout value.                          *
 * Return value:                                                                    *
 *   0 - semaphore was successfully locked.                                         *
 *   otherwise - semaphore lock failed.                                             *
 ************************************************************************************/
int 
oss_sem_lock( oss_sem_type_t sem_type, ipi_sem_id sem_id_ptr, int timeout)
{
    int status = 0;

   return (status)? -1 : 0;
}

/************************************************************************************
 * Function: oss_sem_unlock    - Service routine to unlock a semaphore              *
 * Parameters:                                                                      *
 *   IN  sem_type        - type of semaphore (binary/counting/mutex).               *
 *   IN  sem_id_ptr      - pointer to semaphore.                                    *
 * Return value:                                                                    *
 *   0 - semaphore was successfully unlocked.                                       *
 *   otherwise - semaphore unlock failed.                                           *
 ************************************************************************************/
int 
oss_sem_unlock( oss_sem_type_t sem_type, ipi_sem_id sem_id_ptr)
{
    int status = 0;

   return (status)? -1 : 0;
}

/*
  Atomic increment.
*/
inline void 
oss_atomic_inc (oss_atomic_t *val)
{
  atomic_t *p = (atomic_t *) val;
 
  atomic_inc (p);
}

/*
  Atomic decrement.
*/
inline void
oss_atomic_dec (oss_atomic_t *val)
{
  atomic_t *p = (atomic_t *) val;

  atomic_dec (p);
}

/*
  Atomic set.
*/
inline void
oss_atomic_set (oss_atomic_t *val, int set)
{
  atomic_t *p = (atomic_t *) val;

  atomic_set (p, set);
}

/* 
   Atomic decrement and check.
*/
inline int
oss_atomic_dec_and_test (oss_atomic_t *val)
{
  atomic_t *p = (atomic_t *) val;

  return atomic_dec_and_test (p);
}

/*
  Random.
*/
int
oss_rand (void)
{
  int r;
  static int sort_of_seed;

  get_random_bytes (&r, sizeof (r)); 

  return ((r ^ sort_of_seed) & OSS_RANDOM_MAX);
}
