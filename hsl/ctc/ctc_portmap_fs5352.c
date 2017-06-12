/** @file    ctc_portmap_fs5352.c
 *  @brief   
 *       
 *       
 *       
 *  @author  cdy
 *  @create  2016-05-11 10:46
 *  @version 0.1
 *  @note    
 *       
 *       
 *       
 *       
 *  $LastChangedDate$
 *  $LastChangedRevision$
 *  $LastChangedBy$
 *  Last modified: 2016-05-11 10:46
 */

/* ADS port map
** zebos use ifindex                                            sdk use gport
**  +---------+     +------------+      +------------+     +-------------+
**  |       0 |<--->| 0        0 |<---> | 0        0 |<--->| 28          |
**  |       1 |<--->| 1        1 |<---> | 1        1 |<--->| 29          |
**  | panel 2 |<--->| 2  8512  2 |<---> | 2  fpga  2 |<--->| 30  5160    |
**  | port  3 |<--->| 3  port  3 |<---> | 3  port  3 |<--->| 31  switch  |
**  |       4 |<--->| 4        4 |<---> | 4        4 |<--->| 8   port    |
**  |       5 |<--->| 5        5 |<---> | 5        5 |<--->| 9           |
**  +---------+     +------------+      +------------+     +-------------+
*/


/* NOTE: chip port and panel port is from 0 to 60 */

/* panel port(0 - 35) to lport(ctc sdk locale port), 
** panel port --> lport(5160 port) 
*/
const int  ctc_if_portmap_panel2lport_fs5352[] = {
/*  0 */   28, 29, 30, 31,  8,  9, 10, 11, 12, 13,
/* 10 */   14, 15, 40, 41, 42, 43, 16, 17, 18, 19,
/* 20 */   44, 45, 46, 47, 20, 21, 22, 23, 36, 37,
/* 30 */   38, 39, 32, 33, 34, 35, 51, 50, 49, 48,
/* 40 */   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/* 50 */   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

/* lport(5160 port) to panel port, 
** gport(5160 port) --> panel port 
*/
const int  ctc_if_portmap_lport2panel_fs5352[] = {
/*  0 */    -1, -1, -1, -1, -1, -1, -1, -1,  4,  5,
/* 10 */     6,  7,  8,  9, 10, 11, 16, 17, 18, 19,
/* 20 */    24, 25, 26, 27, -1, -1, -1, -1,  0,  1,
/* 30 */     2,  3, 32, 33, 34, 35, 28, 29, 30, 31,
/* 40 */    12, 13, 14, 15, 20, 21, 22, 23, 39, 38,
/* 50 */    37, 36, -1, -1, -1, -1, -1, -1, -1, -1,
};


