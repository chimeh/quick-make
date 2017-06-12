/** @file    ctc_portmap_xgs.c
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


/* XGS port, 
** front panel port: 0 to 5 are connected to 5160
** back plane port 10 to 13 are connected to fpga(a7), 
**     lport: 52, 53 are not connect to fpga(a7), so it down
*/

/* XGS port map(ALL port are 10G)
** zebos use ifindex                     sdk use gport
**  +---------+      +------------+     +----------------+     +------------+
**  |       0 |<---> | 0   A3   0 |<--->| 56          48 |<--->| 10   A7    |
**  |       1 |<---> | 1        1 |<--->| 57          49 |<--->| 11         |
**  | panel 2 |<---> | 2  fpga  2 |<--->| 58  5160    50 |<--->| 12  fpga   |
**  | port  3 |<---> | 3  port  3 |<--->| 59  switch  51 |<--->| 13  port   |
**  |       4 |<---> | 4        4 |<--->| 54  port    52 |<--  | 14         |
**  |       5 |<---> | 5        5 |<--->| 55          53 |<--  | 15         |
**  +---------+      +------------+     +----------------+     +------------+
*/

/* NOTE: chip port and panel port is from 0 to 60 */

/* panel port(0 - 35) to lport(ctc sdk locale port), 
** panel port --> lport(5160 port) 
*/

const int  ctc_if_portmap_panel2lport_xgs[] = {
/*  0 */   56, 57, 58, 59, 54, 55, -1, -1, -1, -1,  /* front panel port */
/* 10 */   48, 49, 50, 51, 52, 53, -1, -1, -1, -1,  /* backplane port */
/* 20 */   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/* 30 */   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/* 40 */   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/* 50 */   -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

/* lport(5160 port) to panel port, 
** gport(5160 port) --> panel port 
*/
const int  ctc_if_portmap_lport2panel_xgs[] = {
/*  0 */    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/* 10 */    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/* 20 */    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/* 30 */    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
/* 40 */    -1, -1, -1, -1, -1, -1, -1, -1, 10, 11,
/* 50 */    12, 13, 14, 15,  4,  5,  0,  1,  2,  3
};


