/* Copyright (C) 2002-2011 IP Infusion, Inc. All Rights Reserved. */

#ifndef _SMI_MESSAGE_H
#define _SMI_MESSAGE_H

#define SMI_PORT_XXX            13601
#define SMI_SERV_XXX_PATH       "/tmp/.xxxapiserv"
#define SMI_PORT_LACP           13601
#define SMI_SERV_LACP_PATH      "/tmp/.lacpapiserv"
#define SMI_PORT_MSTP           13602
#define SMI_SERV_MSTP_PATH      "/tmp/.mstpapiserv"
#define SMI_PORT_RMON           13603
#define SMI_SERV_RMON_PATH      "/tmp/.rmonapiserv"
#define SMI_PORT_ONM            13604
#define SMI_SERV_ONM_PATH       "/tmp/.onmapiserv"

#define SMI_PROTO_SMISERVER                  1
#define SMI_PROTO_SMICLIENT                  2

/* API protocol definition.  */

#define SMI_ERR_PKT_TOO_SMALL               -1
#define SMI_ERR_INVALID_SERVICE             -2
#define SMI_ERR_INVALID_PKT                 -3
#define SMI_ERR_SYSTEM_FAILURE              -4
#define SMI_ERR_MEM_ALLOC                   -5

#define SMI_SUCEESS                         0
#define SMI_ERROR                           -1
#define SMI_INVALID_VAL                     -2
#define SMI_INVALID_STRLEN                  -3
#define SMI_ERROR_NULL_STRING               -4
#define SMI_ERROR_QOS_DISABLED              -5

/* API protocol version is 1.  */
#define SMI_PROTOCOL_VERSION_1               1

/* API message max length.  */
#define SMI_MESSAGE_MAX_LEN    4096

/* API service types.  */
#define SMI_SERVICE_INTERFACE               0

#define SMI_SERVICE_MAX                     1

/* API events.  */
#define SMI_EVENT_CONNECT                    0
#define SMI_EVENT_DISCONNECT                 1

/*  API messages.  */
#define SMI_MSG_BUNDLE

#define SMI_DFLT_VRID                         0
#define ZEBOS_VERSION_LEN                     62

#define SMI_L2_IFINDEX_START                  5000

#define SMI_SET_FUNC                         -1
#define SMI_GET_FUNC                          1

/* These messages has VR-ID = 0, VRF-ID = 0. */
enum smi_msg_types {
  SMI_MSG_SERVICE_REQUEST,                      /* 0 */
  SMI_MSG_SERVICE_REPLY,                        /* 1 */
  SMI_MSG_STATUS,                               /* 2 */ 
  /* INTERFACE */
  SMI_MSG_IF_START,                             /* 3 */
  SMI_MSG_IF_SETMTU,                            /* 4 */
  SMI_MSG_IF_GETMTU,                            /* 5 */
  SMI_MSG_IF_SETBW,                             /* 6 */ 
  SMI_MSG_IF_GETBW,                             /* 7 */
  SMI_MSG_IF_SETFLAG,                           /* 8 */
  SMI_MSG_IF_UNSETFLAG,                         /* 9 */
  SMI_MSG_IF_SETAUTO,                           /* 10 */
  SMI_MSG_IF_GETAUTO,                           /* 11 */     
  SMI_MSG_IF_SETHWADDR,                         /* 12 */
  SMI_MSG_IF_GETHWADDR,                         /* 13 */
  SMI_MSG_IF_SETDUPLEX,                         /* 14 */
  SMI_MSG_IF_GETDUPLEX,                         /* 15 */
  SMI_MSG_IF_UNSETDUPLEX,                       /* 16 */ 
  SMI_MSG_IF_GETBRIEF,                          /* 17 */
  SMI_MSG_IF_SETMCAST,                          /* 18 */
  SMI_MSG_IF_GETMCAST,                          /* 19 */
  SMI_MSG_IF_UNSETMT,                           /* 20 */
  SMI_MSG_IF_CHANGE_GET,                        /* 21 */
  SMI_MSG_IF_GET_STATISTICS,                    /* 22 */
  SMI_MSG_IF_CLEAR_STATISTICS,                  /* 23 */  
  SMI_MSG_IF_SET_MDIX_CROSSOVER,                /* 24 */
  SMI_MSG_IF_GET_MDIX_CROSSOVER,                /* 25 */
  SMI_MSG_IPI_GET_TRAFFIC_CLASSTBL,             /* 26 */
  SMI_MSG_IF_BRIDGE_ADDMAC,                     /* 27 */
  SMI_MSG_IF_BRIDGE_DELMAC,                     /* 28 */
  SMI_MSG_IF_BRIDGE_MAC_ADD_PRIO_OVR,           /* 27 */
  SMI_MSG_IF_BRIDGE_MAC_DEL_PRIO_OVR,           /* 28 */
  SMI_MSG_IF_BRIDGE_FLUSH_DYNAMICENT,           /* 29 */ 
  SMI_MSG_ADD_BRIDGE,                           /* 30 */ 
  SMI_MSG_ADD_BRIDGE_PORT,                      /* 31 */
  SMI_MSG_CHANGE_TYPE,                          /* 32 */
  SMI_MSG_GETBRIDGE_TYPE,                       /* 33 */
  SMI_MSG_DEL_BRIDGE,                           /* 34 */
  SMI_MSG_DEL_BRIDGE_PORT,                      /* 35 */
  SMI_MSG_SET_PORT_NON_CONFIG,                  /* 36 */
  SMI_MSG_GET_PORT_NON_CONFIG,                  /* 37 */
  SMI_MSG_SET_PORT_LEARNING,                    /* 38 */
  SMI_MSG_GET_PORT_LEARNING,                    /* 39 */
  SMI_MSG_SET_EGRESS_PORT_MODE,                 /* 40 */
  SMI_MSG_SET_PORT_NON_SWITCHING,               /* 41 */
  SMI_MSG_GET_PORT_NON_SWITCHING,               /* 42 */
  SMI_MSG_IF_GETFLAGS,                          /* 43 */
  SMI_MSG_IF_LACP_ADDLINK,                      /* 44 */
  SMI_IF_MSG_LACP_DELETELINK,                   /* 45 */
  SMI_MSG_SW_RESET,                             /* 46 */
  SMI_IF_MSG_SET_DOT1Q_STATE,                   /* 47 */
  SMI_IF_MSG_GET_DOT1Q_STATE,                   /* 48 */
  SMI_IF_MSG_SET_DTAG_MODE,                     /* 49 */
  SMI_IF_MSG_GET_DTAG_MODE,                     /* 50 */
  SMI_IF_MSG_IF_EXIST,                          /* 51 */
  SMI_IF_MSG_BRIDGE_EXIST,                      /* 52 */
  SMI_MSG_IF_END,                               /* 53 */  
  /*** VLAN ***/
  SMI_MSG_VLAN_START,                           /* 52 */
  SMI_MSG_VLAN_ADD,                             /* VLAN_START + 1 */
  SMI_MSG_VLAN_DEL,                             /* VLAN_START + 2 */
  SMI_MSG_VLAN_SET_PORT_MODE,                   /* VLAN_START + 3 */
  SMI_MSG_VLAN_GET_PORT_MODE,                   /* VLAN_START + 4 */
  SMI_MSG_VLAN_SET_ACC_FRAME_TYPE,              /* 31 */    
  SMI_MSG_VLAN_GET_ACC_FRAME_TYPE,              /* 32 */
  SMI_MSG_VLAN_SET_INGRESS_FILTER,              /* 33 */
  SMI_MSG_VLAN_GET_INGRESS_FILTER,              /* 34 */
  SMI_MSG_VLAN_SET_DEFAULT_VID,                 /* 35 */
  SMI_MSG_VLAN_GET_DEFAULT_VID,                 /* 36 */
  SMI_MSG_VLAN_ADD_TO_PORT,                     /* 37 */
  SMI_MSG_VLAN_DEL_FROM_PORT,                   /* 38 */
  SMI_MSG_VLAN_CLEAR_PORT,                      /* 39 */
  SMI_MSG_VLAN_ADD_ALL_EXCEPT_VID,              /* 40 */
  SMI_MSG_VLAN_GET_ALL_VLAN_CONFIG,             /* 43 */
  SMI_MSG_VLAN_GET_VLAN_BY_ID,                  /* 44 */ 
  SMI_MSG_VLAN_GET_IF,                          /* 45 */
  SMI_MSG_VLAN_GET_BRIDGE,                      /* 46 */
  SMI_MSG_VLAN_SET_PORT_PROTO_PROCESS,          /* 47 */
  SMI_MSG_VLAN_GET_PORT_PROTO_PROCESS,          /* 48 */
  SMI_MSG_FORCE_DEFAULT_VLAN,                   /* 49 */
  SMI_MSG_SET_PRESERVE_CE_COS,                  /* 50 */
  SMI_MSG_SET_PORT_BASED_VLAN,                  /* 51 */
  SMI_MSG_SET_CPUPORT_DEFAULT_VLAN,             /* 52 */
  SMI_MSG_SET_CPUPORT_BASED_VLAN,               /* 53 */
  SMI_MSG_SVLAN_SET_PORT_ETHER_TYPE,            /* 54 */
  SMI_MSG_SET_WAYSIDEPORT_DEFAULT_VLAN,         /* 55 */
  SMI_MSG_NSM_HA_SWITCH,
  SMI_MSG_VLAN_RANGE_ADD,
  SMI_MSG_VLAN_RANGE_DEL,
  SMI_MSG_VLAN_END,                             /* 56 */
  /*** MSTP ***/
  SMI_MSG_MSTP_START,                           /* 50 */
  SMI_MSG_MSTP_ADDINSTANCE,                     /* 51 */
  SMI_MSG_MSTP_DELINSTANCE,                     /* 52 */
  SMI_MSG_MSTP_SETAGE,                          /* 53 */
  SMI_MSG_MSTP_GETAGE,                          /* 54 */
  SMI_MSG_MSTP_CHECK,                           /* 55 */
  SMI_MSG_MSTP_ADDPORT,                         /* 56 */
  SMI_MSG_MSTP_DELPORT,                         /* 57 */
  SMI_MSG_MSTP_SETHELLOTIME,                    /* 58 */
  SMI_MSG_MSTP_GETHELLOTIME,                    /* 59 */
  SMI_MSG_MSTP_SETMAXAGE,                       /* 60 */
  SMI_MSG_MSTP_GETMAXAGE,                       /* 61 */
  SMI_MSG_MSTP_SETPORTEDGE,                     /* 62 */
  SMI_MSG_MSTP_GETPORTEDGE,                     /* 63 */
  SMI_MSG_MSTP_SETVERSION,                      /* 64 */
  SMI_MSG_MSTP_GETVERSION,                      /* 65 */
  SMI_MSG_MSTP_SETPR,                           /* 66 */ 
  SMI_MSG_MSTP_GETPR,                           /* 67 */
  SMI_MSG_MSTP_SETFWDD,                         /* 68 */
  SMI_MSG_MSTP_GETFWDD,                         /* 69 */
  SMI_MSG_MSTP_SETMPR,                          /* 70 */
  SMI_MSG_MSTP_GETMPR,                          /* 71 */
  SMI_MSG_MSTP_SETCOST,                         /* 72 */
  SMI_MSG_MSTP_GETCOST,                         /* 73 */
  SMI_MSG_MSTP_SETRSTROLE,                      /* 74 */ 
  SMI_MSG_MSTP_GETRSTROLE,                      /* 75 */
  SMI_MSG_MSTP_SETRSTTCN,                       /* 76 */
  SMI_MSG_MSTP_GETRSTTCN,                       /* 77 */
  SMI_MSG_MSTP_SETPORT_PATHCOST,                /* 78 */
  SMI_MSG_MSTP_GETPORT_PATHCOST,                /* 79 */
  SMI_MSG_MSTP_SETP2P,                          /* 80 */
  SMI_MSG_MSTP_GETP2P,                          /* 81 */
  SMI_MSG_MSTP_SETPORT_HELLOTIME,               /* 82 */ 
  SMI_MSG_MSTP_GETPORT_HELLOTIME,               /* 83 */
  SMI_MSG_MSTP_SETPPR,                          /* 84 */
  SMI_MSG_MSTP_GETPPR,                          /* 85 */
  SMI_MSG_MSTP_SETMAXHOPS,                      /* 86 */
  SMI_MSG_MSTP_GETMAXHOPS,                      /* 87 */
  SMI_MSG_MSTP_SETPORT_PRIORITY,                /* 88 */ 
  SMI_MSG_MSTP_GETPORT_PRIORITY,                /* 89 */ 
  SMI_MSG_MSTP_SETPORT_RESTRICT,                /* 90 */
  SMI_MSG_MSTP_GETPORT_RESTRICT,                /* 91 */
  SMI_MSG_MSTP_SETPORT_RESTRICTTCN,             /* 92 */
  SMI_MSG_MSTP_GETPORT_RESTRICTTCN,             /* 93 */
  SMI_MSG_MSTP_SETPORT_ROOTGUARD,               /* 94 */
  SMI_MSG_MSTP_GETPORT_ROOTGUARD,               /* 95 */
  SMI_MSG_MSTP_SETPORT_BPDUFILTER,              /* 96 */
  SMI_MSG_MSTP_GETPORT_BPDUFILTER,              /* 97 */
  SMI_MSG_MSTP_ENABLE_BRIDGE,                   /* 98 */
  SMI_MSG_MSTP_DISABLE_BRIDGE,                  /* 99 */ 
  SMI_MSG_MSTP_SETPORT_BPDUGUARD,               /* 100 */
  SMI_MSG_MSTP_GETPORT_BPDUGUARD,               /* 101 */
  SMI_MSG_MSTP_SET_TXHOLDCOUNT,                 /* 102 */ 
  SMI_MSG_MSTP_GET_TXHOLDCOUNT,                 /* 103 */
  SMI_MSG_MSTP_SETBRIDGE_BPDUGUARD,             /* 104 */ 
  SMI_MSG_MSTP_GETBRIDGE_BPDUGUARD,             /* 105 */
  SMI_MSG_MSTP_SETBRIDGE_TIMEOUTEN,             /* 106 */ 
  SMI_MSG_MSTP_GETBRIDGE_TIMEOUTEN,             /* 107 */
  SMI_MSG_MSTP_SETBRIDGE_TIMEOUTINT,            /* 108 */
  SMI_MSG_MSTP_GETBRIDGE_TIMEOUTINT,            /* 109 */
  SMI_MSG_MSTP_SETMSTI_PORTPRIORITY,            /* 110 */
  SMI_MSG_MSTP_GETMSTI_PORTPRIORITY,            /* 111 */
  SMI_MSG_MSTP_SETREVISION_NUMBER,              /* 112 */
  SMI_MSG_MSTP_GETREVISION_NUMBER,              /* 113 */
  SMI_MSG_MSTP_GET_SPANNING_DETAILS,            /* 117 */ 
  SMI_MSG_MSTP_GET_SPANNING_INTERFACE,          /* 118 */
  SMI_MSG_MSTP_GET_SPANNING_MST,                /* 119 */
  SMI_MSG_MSTP_GET_SPANNING_MST_CONF,           /* 120 */ 
  SMI_MSG_MSTP_SETAUTOEDGE,                     /* 121 */
  SMI_MSG_MSTP_GETAUTOEDGE,                     /* 122 */
  SMI_MSG_MSTP_SETREGIONNAME,                   /* 123 */
  SMI_MSG_MSTP_GETREGIONNAME,                   /* 124 */
  SMI_MSG_MSTP_STP_MSTDETAIL,                   /* 128 */
  SMI_MSG_MSTP_STP_MSTDETAIL_IF,                /* 129 */ 
  SMI_MSG_MSTP_SETBRIDGE_BPDUFILTER,            /* 132 */ 
  SMI_MSG_MSTP_GETBRIDGE_BPDUFILTER,            /* 133 */
  SMI_MSG_GET_BRIDGE_STATUS,                    /* 134 */
  SMI_MSG_MSTP_HA_SWITCH,                       /**/
  SMI_MSG_MSTP_END,                             /* 135 */
  /*** RMON **/
  SMI_MSG_RMON_START,                           /* 135 */ 
  SMI_MSG_RMON_VALIDATEIF_STATS,                /* RMON_START + 1 */
  SMI_MSG_RMON_ADDSTAT_ENTRY,                   /* RMON_START + 2 */
  SMI_MSG_RMON_REMOVESTAT_ENTRY,                /* RMON_START + 3 */
  SMI_MSG_RMON_VALIDATE_HISTSTATS,              /* 140 */
  SMI_MSG_RMON_SETHISTORY_STATUS,               /* 141 */
  SMI_MSG_RMON_GETHISTORY_STATUS,               /* 142 */ 
  SMI_MSG_RMON_SETHISTORY_BUCKET,               /* 143 */
  SMI_MSG_RMON_GETHISTORY_BUCKET,               /* 144 */
  SMI_MSG_RMON_SETHISTORY_INACTIVE,             /* 145 */
  SMI_MSG_RMON_ADDHISTORY_INDEX,                /* 146 */
  SMI_MSG_RMON_SET_DATASOURCE,                  /* 147 */
  SMI_MSG_RMON_SETHISTORY_INDEX,                /* 148 */
  SMI_MSG_RMON_GETHISTORY_INDEX,                /* 149 */
  SMI_MSG_RMON_SETHISTORY_CTRLINTVAL,           /* 150 */
  SMI_MSG_RMON_GETHISTORY_CTRLINTVAL,           /* 151 */
  SMI_MSG_RMON_SETHISTORY_CTRLOWNER,            /* 152 */
  SMI_MSG_RMON_GETHISTORY_CTRLOWNER,            /* 153 */
  SMI_MSG_RMON_HISTINDEX_REMOVE,                /* 154 */ 
  SMI_MSG_RMON_SETALARM_POLLINTERVAL,           /* 155 */ 
  SMI_MSG_RMON_GETALARM_POLLINTERVAL,           /* 156 */
  SMI_MSG_RMON_SETALARM_VARIABLE,               /* 157 */
  SMI_MSG_RMON_GETALARM_VARIABLE,               /* 158 */
  SMI_MSG_RMON_SETSAMPLE_TYPE,                  /* 159 */ 
  SMI_MSG_RMON_GETSAMPLE_TYPE,                  /* 160 */ 
  SMI_MSG_RMON_SETALARM_STARTUP,                /* 161 */
  SMI_MSG_RMON_GETALARM_STARTUP,                /* 162 */
  SMI_MSG_RMON_SETRISING_THRESHOLD,             /* 163 */
  SMI_MSG_RMON_GETRISING_THRESHOLD,             /* 164 */ 
  SMI_MSG_RMON_SETFALLING_THRESHOLD,            /* 165 */
  SMI_MSG_RMON_GETFALLING_THRESHOLD,            /* 166 */
  SMI_MSG_RMON_SETRISING_EVNTINDX,              /* 167 */
  SMI_MSG_RMON_GETRISING_EVNTINDX,              /* 168 */ 
  SMI_MSG_RMON_SETFALLING_EVNTINDX,             /* 169 */  
  SMI_MSG_RMON_GETFALLING_EVNTINDX,             /* 170 */
  SMI_MSG_RMON_SETALARM_OWNER,                  /* 171 */
  SMI_MSG_RMON_GETALARM_OWNER,                  /* 172 */
  SMI_MSG_RMON_SETALARM_ENTRY,                  /* 173 */ 
  SMI_MSG_RMON_GETALARM_ENTRY,                  /* 174 */
  SMI_MSG_RMON_SETALARM_INDEXRM,                /* 175 */
  SMI_MSG_RMON_SETEVENT_INDEXRM,                /* 176 */
  SMI_MSG_RMON_SETEVENT_INDEX,                  /* 177 */
  SMI_MSG_RMON_GETEVENT_INDEX,                  /* 178 */
  SMI_MSG_RMON_SETEVENT_ACTIVE,                 /* 179 */
  SMI_MSG_RMON_GETEVENT_STATUS,                 /* 180 */
  SMI_MSG_RMON_SETEVENT_COMM,                   /* 181 */ 
  SMI_MSG_RMON_GETEVENT_COMM,                   /* 182 */ 
  SMI_MSG_RMON_SETEVENT_DESCRIPTION,            /* 183 */ 
  SMI_MSG_RMON_GETEVENT_DESCRIPTION,            /* 184 */
  SMI_MSG_RMON_SETEVENT_OWNER,                  /* 185 */
  SMI_MSG_RMON_GETEVENT_OWNER,                  /* 186 */
  SMI_MSG_RMON_SETEVENT_TYPE,                   /* 187 */
  SMI_MSG_RMON_GETEVENT_TYPE,                   /* 188 */
  SMI_MSG_RMON_SETSNMP_EVENTTYPE,               /* 189 */ 
  SMI_MSG_RMON_GETSNMP_EVENTTYPE,               /* 190 */
  SMI_MSG_RMON_SETSNMP_COMMUNITY,               /* 191 */
  SMI_MSG_RMON_GETSNMP_COMMUNITY,               /* 192 */
  SMI_MSG_RMON_SETSNMP_EVENTOWNER,              /* 193 */
  SMI_MSG_RMON_GETSNMP_EVENTOWNER,              /* 194 */
  SMI_MSG_RMON_SETSNMP_ETHERSTATUS,             /* 195 */
  SMI_MSG_RMON_GETSNMP_ETHERSTATUS,             /* 196 */
  SMI_MSG_RMON_SETSNMP_DESCRIPTION,             /* 197 */  
  SMI_MSG_RMON_GETSNMP_DESCRIPTION,             /* 198 */ 
  SMI_MSG_RMON_GETIFSTATS,                       /* 199 */
  SMI_MSG_RMON_GET_RT_IF_COUNTER,               /* 200 */
  SMI_MSG_RMON_GET_IF_COUNTER,                  /* 201 */
  SMI_MSG_RMON_FLUSH_PORT,                      /* 202 */
  SMI_MSG_RMON_FLUSH_ALL_PORT,                  /* 203 */
  SMI_MSG_RMON_SETALARM_STATUS,                 /* 204 */
  SMI_MSG_RMON_SETEVENT_STATUS,                 /* 205 */
  SMI_MSG_RMON_END,                             /* 205 */
  /*** LACP **/
  SMI_MSG_LACP_START,                           /* 206 */   
  SMI_MSG_LACP_ADDLINK,                         /* 206 */
  SMI_MSG_LACP_DELETELINK,                      /* 207 */
  SMI_MSG_LACP_GET_CHANNELACT,                  /* 208 */
  SMI_MSG_LACP_GET_CHANNELADMIN_KEY,            /* 209 */          
  SMI_MSG_LACP_SET_CHANNEL_PRIORITY,            /* 210 */
  SMI_MSG_LACP_GET_CHANNEL_PRIORITY,            /* 211 */
  SMI_MSG_LACP_UNSET_CHANNEL_PRIORITY,          /* 212 */
  SMI_MSG_LACP_SET_CHANNEL_TIMEOUT,             /* 213 */
  SMI_MSG_LACP_GET_CHANNEL_TIMEOUT,             /* 214 */
  SMI_MSG_LACP_SET_SYSTEM_PRIORITY,
  SMI_MSG_LACP_GET_SYSTEM_PRIORITY,
  SMI_MSG_LACP_UNSET_SYSTEM_PRIORITY,
  SMI_MSG_LACP_GET_ETHERCHANNEL_DETAIL,
  SMI_MSG_LACP_GET_ETHERCHANNEL_SUMMARY,
  SMI_MSG_LACP_GET_COUNTER,                       /* 220 */
  SMI_MSG_LACP_GET_SYSTEMID,                      /* 221 */
  SMI_MSG_LACP_GET_AGG_BMP,
  SMI_MSG_LACP_GET_AGG_PORTS_BMP,
  SMI_MSG_LACP_HA_SWITCH,                        /**/
  SMI_MSG_LACP_END,
  /***LLDP***/
  SMI_MSG_LLDP_START,
  SMI_MSG_LLDP_DISABLE_PORT,
  SMI_MSG_LLDP_ENABLE_PORT,
  SMI_MSG_LLDP_SET_LOCALLY_ASSIGNED,
  SMI_MSG_LLDP_GET_LOCALLY_ASSIGNED,
  SMI_MSG_LLDP_SET_PORTBASIC_TLVENABLE,
  SMI_MSG_LLDP_GET_PORTBASIC_TLVENABLE,
  SMI_MSG_LLDP_SETPORT_MSGTXHOLD,
  SMI_MSG_LLDP_GETPORT_MSGTXHOLD,
  SMI_MSG_LLDP_SETPORT_MSGTXINTERVAL,
  SMI_MSG_LLDP_GETPORT_MSGTXINTERVAL,
  SMI_MSG_LLDP_SETPORT_REINITDELAY,
  SMI_MSG_LLDP_GETPORT_REINITDELAY,
  SMI_MSG_LLDP_SETPORT_TOOMANY_NEIGHBOURS,
  SMI_MSG_LLDP_GETPORT_TOOMANY_NEIGHBOURS,
  SMI_MSG_LLDP_SETPORT_TXDELAY,
  SMI_MSG_LLDP_GETPORT_TXDELAY,
  SMI_MSG_LLDP_SETSYSTEM_DESCRIPTION,
  SMI_MSG_LLDP_GETSYSTEM_DESCRIPTION,
  SMI_MSG_LLDP_SET_SYSTEMNAME,
  SMI_MSG_LLDP_GET_SYSTEMNAME,
  SMI_MSG_LLDP_GET_PORT_REM_MAC_ARRAY,
  SMI_MSG_LLDP_GET_PORT,
  SMI_MSG_LLDP_GET_PORT_STATISTICS,
  SMI_MSG_LLDP_SET_HWADDR,
  SMI_MSG_LLDP_GET_HWADDR,
  SMI_MSG_LLDP_SET_CHASSISID_TYPE,
  SMI_MSG_LLDP_GET_CHASSISID_TYPE,
  SMI_MSG_LLDP_SET_CHASSIS_IPADDRESS,
  SMI_MSG_LLDP_GET_CHASSIS_IPADDRESS,
  SMI_MSG_LLDP_END,
 /* EFM Get/Set APIs */
  SMI_MSG_EFM_START,
  SMI_MSG_EFM_OAM_PROTO_ENABLE,
  SMI_MSG_EFM_OAM_PROTO_DISABLE,
  SMI_MSG_EFM_OAM_SET_LINKTIMER,
  SMI_MSG_EFM_OAM_GET_LINKTIMER,
  SMI_MSG_EFM_OAM_REMOTELB_START,
  SMI_MSG_EFM_OAM_REMOTELB_STOP,
  SMI_MSG_EFM_OAM_SETMODE_ACTIVE,
  SMI_MSG_EFM_OAM_SETMODE_PASSIVE,
  SMI_MSG_EFM_OAM_GET_MODE,
  SMI_MSG_EFM_OAM_SET_PDUTIMER,
  SMI_MSG_EFM_OAM_GET_PDUTIMER,
  SMI_MSG_EFM_OAM_SET_MAXRATE,
  SMI_MSG_EFM_OAM_GET_MAXRATE,
  SMI_MSG_EFM_OAM_SET_LINKMONITOR,
  SMI_MSG_EFM_OAM_GET_LINKMONITOR,
  SMI_MSG_EFM_OAM_SET_REMOTE_LB,
  SMI_MSG_EFM_OAM_GET_REMOTE_LB,
  SMI_MSG_EFM_OAM_SET_REMOTELOOPB_TOUT,
  SMI_MSG_EFM_OAM_GET_REMOTELOOPB_TOUT,
  SMI_MSG_EFM_OAM_SET_ERRFRAME_LOTHRES,
  SMI_MSG_EFM_OAM_GET_ERRFRAME_LOTHRES,
  SMI_MSG_EFM_OAM_SET_ERRFRAME_HITHRES,
  SMI_MSG_EFM_OAM_GET_ERRFRAME_HITHRES,
  SMI_MSG_EFM_OAM_SET_ERRFRM_SECLOTHRS,
  SMI_MSG_EFM_OAM_GET_ERRFRM_SECLOTHRS,
  SMI_MSG_EFM_OAM_SET_ERRFRM_SECHITHRS,
  SMI_MSG_EFM_OAM_GET_ERRFRM_SECHITHRS,
  SMI_MSG_EFM_OAM_SET_ERRFRMPER_WINDOW,
  SMI_MSG_EFM_OAM_GET_ERRFRMPER_WINDOW,
  SMI_MSG_EFM_OAM_DISABLE_IFEVENT_SET,
  SMI_MSG_EFM_OAM_DISABLE_IFEVENT_GET,
  SMI_MSG_EFM_OAM_SHOW_STATS,
  SMI_MSG_EFM_OAM_SHOW_INTERFACE_STATUS,
  SMI_MSG_EFM_OAM_GET_DISCOVERY,
  SMI_MSG_EFM_OAM_GET_ETHERNET,
  SMI_MSG_EFM_SEND_DATA_FRAME,
  SMI_MSG_EFM_GET_LOCAL_LOOPBACK_STATUS,
  SMI_MSG_EFM_END,
  /*** CFM ***/
  SMI_MSG_CFM_START,
  SMI_MSG_CFM_ADD_MA,
  SMI_MSG_CFM_ADD_MD,
  SMI_MSG_CFM_ADD_MEP,
  SMI_MSG_CFM_ADD_MIP,
  SMI_MSG_CFM_ADD_RMEP,
  SMI_MSG_CFM_CC_ENABLE,
  SMI_MSG_CFM_MA_GET,
  SMI_MSG_CFM_MD_GET,
  SMI_MSG_CFM_MEP_GET,
  SMI_MSG_CFM_REMOVE_MA,
  SMI_MSG_CFM_REMOVE_MD,
  SMI_MSG_CFM_REMOVE_MEP,
  SMI_MSG_CFM_SEND_PING,
  SMI_MSG_CFM_ITERATE_MEP,
  SMI_MSG_CFM_ITERATE_RMEP,
  SMI_MSG_CFM_ITERATE_TRACEROUTE_CACHE,
  SMI_MSG_CFM_SEND_TRACEROUTE,
  SMI_MSG_CFM_GET_ERRORS_CLEAR,
  SMI_MSG_CFM_GET_RMEP_CLEAR,
  SMI_MSG_CFM_SET_HWADDR,
  SMI_MSG_CFM_GET_HWADDR,
  SMI_MSG_CFM_SET_ETHER_TYPE,
  SMI_MSG_CFM_GET_ETHER_TYPE,
  SMI_MSG_CFM_RMEP_GET,
  SMI_MSG_CFM_IF_MEP_LIST,
  SMI_MSG_CFM_RMEP_LIST,
  SMI_MSG_CFM_GET_RMEP_INFO, 
  SMI_MSG_CFM_GET_MEP_INFO,
  SMI_MSG_CFM_NUM_ERROR_ENTRY,
  SMI_MSG_CFM_GET_ERROR_ENTRY, 
  SMI_MSG_CFM_END,
  /***GVRP***/
  SMI_MSG_GVRP_START,
  SMI_MSG_GVRP_SET_TIMER,
  SMI_MSG_GVRP_GET_TIMER,
  SMI_MSG_GVRP_ENABLE,
  SMI_MSG_GVRP_DISABLE,
  SMI_MSG_GVRP_ENABLE_PORT,
  SMI_MSG_GVRP_DISABLE_PORT,
  SMI_MSG_GVRP_SET_REG_MODE,
  SMI_MSG_GVRP_GET_REG_MODE,
  SMI_MSG_GVRP_GET_PER_VLAN_STATS,
  SMI_MSG_GVRP_CLEAR_ALL_STATS,
  SMI_MSG_GVRP_SET_DYNAMIC_VLAN_LEARNING,
  SMI_MSG_GVRP_GET_BRIDGE_CONFIG,
  SMI_MSG_GVRP_GET_VID_DETAILS,
  SMI_MSG_GVRP_GET_STATE_MACHINE_BRIDGE,
  SMI_MSG_GVRP_GET_PORT_STATS,
  SMI_MSG_GVRP_GET_TIMER_DETAILS,
  SMI_MSG_GVRP_END,
  /***QOS***/
  SMI_MSG_QOS_START,
  SMI_MSG_QOS_GLOBAL_ENABLE,
  SMI_MSG_QOS_GLOBAL_DISABLE,
  SMI_MSG_QOS_GET_GLOBAL_STATUS,
  SMI_MSG_QOS_SET_PMAP_NAME,
  SMI_MSG_QOS_GET_POLICY_MAP_NAMES,
  SMI_MSG_QOS_GET_POLICY_MAP,
  SMI_MSG_QOS_PMAP_DELETE,
  SMI_MSG_QOS_SET_CMAP_NAME,
  SMI_MSG_QOS_GET_CMAP_NAME,
  SMI_MSG_QOS_DELETE_CMAP_NAME,
  SMI_MSG_QOS_CMAP_MATCH_TRAFFIC_SET,
  SMI_MSG_QOS_CMAP_MATCH_TRAFFIC_GET,
  SMI_MSG_QOS_CMAP_MATCH_TRAFFIC_UNSET,
  SMI_MSG_QOS_PMAPC_POLICE,
  SMI_MSG_QOS_PMAPC_POLICE_GET,
  SMI_MSG_QOS_PMAPC_POLICE_DELETE,
  SMI_MSG_QOS_SET_PORT_SCHEDULING,
  SMI_MSG_QOS_GET_PORT_SCHEDULING,
  SMI_MSG_QOS_SET_DEFAULT_USER_PRIORITY,
  SMI_MSG_QOS_GET_DEFAULT_USER_PRIORITY,
  SMI_MSG_QOS_PORT_SET_REGEN_USER_PRIORITY,
  SMI_MSG_QOS_PORT_GET_REGEN_USER_PRIORITY,
  SMI_MSG_QOS_GLOBAL_COS_TO_QUEUE,
  SMI_MSG_QOS_GET_COS_TO_QUEUE,
  SMI_MSG_QOS_GLOBAL_DSCP_TO_QUEUE,
  SMI_MSG_QOS_GET_DSCP_TO_QUEUE,
  SMI_MSG_QOS_SET_TRUST_STATE,
  SMI_MSG_QOS_GET_TRUST_STATE,
  SMI_MSG_QOS_SET_FORCE_TRUST_COS,
  SMI_MSG_QOS_GET_FORCE_TRUST_COS,
  SMI_MSG_QOS_SET_FRAME_TYPE_PRIORITY_OVERRIDE,
  SMI_MSG_QOS_SET_VLAN_PRIORITY,
  SMI_MSG_QOS_GET_VLAN_PRIORITY,
  SMI_MSG_QOS_UNSET_VLAN_PRIORITY,
  SMI_MSG_QOS_SET_PORT_VLAN_PRIORITY,
  SMI_MSG_QOS_GET_PORT_VLAN_PRIORITY,
  SMI_MSG_QOS_SET_QUEUE_WEIGHT,
  SMI_MSG_QOS_GET_QUEUE_WEIGHT,
  SMI_MSG_QOS_SET_PORT_SERVICE_POLICY,
  SMI_MSG_QOS_UNSET_PORT_SERVICE_POLICY,
  SMI_MSG_QOS_GET_PORT_SERVICE_POLICY,
  SMI_MSG_QOS_SET_TRAFFIC_SHAPE,
  SMI_MSG_QOS_UNSET_TRAFFIC_SHAPE,
  SMI_MSG_QOS_GET_TRAFFIC_SHAPE,
  SMI_MSG_QOS_SET_PORT_DA_PRIORITY,
  SMI_MSG_QOS_GET_PORT_DA_PRIORITY,
  SMI_MSG_QOS_PMAPC_DELETE_CMAP,
  SMI_MSG_QOS_END,
  /***FC***/
  SMI_MSG_FC_START,
  SMI_MSG_ADD_FC,
  SMI_MSG_DELETE_FC,
  SMI_MSG_FC_STATISTICS,
  SMI_MSG_FC_GET_INTERFACE,
  SMI_MSG_FC_END,
  /*** API ALARM MSG ***/
  SMI_MSG_ALARM,
  /*** API MSG MAX ***/
  SMI_MSG_MAX,   
};

typedef enum _smi_api_module {
  SMI_AC_NSM_MODULE,
  SMI_AC_LACP_MODULE,
  SMI_AC_MSTP_MODULE,
  SMI_AC_RMON_MODULE,
  SMI_AC_ONM_MODULE,
  SMI_AC_MAX,
  SMI_AC_API_CLIENT,
} smi_api_module;

#define SMI_DECODE_TLV_HEADER(TH)                                             \
    do {                                                                      \
      TLV_DECODE_GETW ((TH).type);                                            \
      TLV_DECODE_GETW ((TH).length);                                          \
      (TH).length -= SMI_TLV_HEADER_SIZE;                                     \
    } while (0)


#define SMI_CHECK_CTYPE(F,C)        (CHECK_FLAG (F, (1 << C)))
#define SMI_SET_CTYPE(F,C)          (SET_FLAG (F, (1 << C)))
#define SMI_UNSET_CTYPE(F,C)        (UNSET_FLAG (F, (1 << C)))

/* Flag manipulation macros. */
#define SMI_CHECK_FLAG(V,F)      ((V) & (F))
#define SMI_SET_FLAG(V,F)        (V) = (V) | (F)
#define SMI_UNSET_FLAG(V,F)      (V) = (V) & ~(F)
#define SMI_FLAG_ISSET(V,F)      (((V) & (F)) == (F))

#define SMI_CINDEX_SIZE                     32
typedef u_int32_t  smi_cindex_t;

/*****************************************************
 * Bitmap related defines *
 ****************************************************/
#define SMI_BMP_MAX                 4094            
#define SMI_BMP_WORD_WIDTH          32
#define SMI_BMP_WORD_MAX ((SMI_BMP_MAX + SMI_BMP_WORD_WIDTH) /       \
                           SMI_BMP_WORD_WIDTH)

#define SMI_BMP_INIT(bmp)                                             \
   do {                                                               \
       pal_mem_set ((bmp).bitmap, 0, sizeof ((bmp).bitmap));          \
   } while (0)

#define SMI_BMP_SET(bmp, bit_num)                                         \
   do {                                                                   \
        int _word = (bit_num) / SMI_BMP_WORD_WIDTH;                       \
        (bmp).bitmap[_word] |= (1U << ((bit_num) % SMI_BMP_WORD_WIDTH));  \
   } while (0)

#define SMI_BMP_UNSET(bmp, bit_num)                                       \
   do {                                                                   \
        int _word = (bit_num) / SMI_BMP_WORD_WIDTH;                       \
        (bmp).bitmap[_word] &= ~(1U <<((bit_num) % SMI_BMP_WORD_WIDTH));  \
   } while (0)

#define SMI_SET_BMP_ITER_BEGIN(bmp, bit_num)                              \
    do {                                                                  \
        int _w, _i;                                                       \
        (bit_num) = 0;                                                    \
        for (_w = 0; _w < SMI_BMP_WORD_MAX; _w++)                         \
          for (_i = 0; _i < SMI_BMP_WORD_WIDTH; _i++, (bit_num)++)        \
            if ((bmp).bitmap[_w] & (1U << _i))

#define SMI_SET_BMP_ITER_END(bmp, bit_num)                                \
    } while (0)

#define SMI_BMP_SETALL(bmp)                                               \
   do {                                                                   \
        pal_mem_set ((bmp).bitmap, 0xff, sizeof ((bmp).bitmap));          \
   } while (0)

#define SMI_BMP_IS_MEMBER(bmp, bit_num)                                   \
  ((bmp).bitmap[(bit_num) / SMI_BMP_WORD_WIDTH] &                         \
                         (1U << ((bit_num) % SMI_BMP_WORD_WIDTH)))


/* API Context Header
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             VR-ID                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            VRF-ID                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   API Message Header
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Message Type         |           Message Len         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Message Id                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct smi_msg_header
{
  /* Message Type. */
  u_int16_t type;

  /* Message Len. */
  u_int16_t length;

  /* Message ID. */
  u_int32_t message_id;
};
#define SMI_MSG_HEADER_SIZE   8

/* API TLV Header
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Type               |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

struct smi_tlv_header
{
  u_int16_t type;
  u_int16_t length;
};
#define SMI_TLV_HEADER_SIZE   4

/* API Service message format

  This message is used by:

  SMI_MSG_SERVICE_REQUEST
  SMI_MSG_SERVICE_REPLY

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |             Version           |             Reserved          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                          Protocol Id                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                           Client Id                           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                            Services                           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

/* API services structure.  */
struct smi_msg_service
{
  /* TLV flags. */
  u_int32_t cindex;

#define SMI_LINK_CTYPE_NAME                      0
#define SMI_LINK_CTYPE_FLAGS                     1
#define SMI_LINK_CTYPE_METRIC                    2
#define SMI_LINK_CTYPE_MTU                       3

  /* API Protocol Version. */
  u_int16_t version;

  /* Reserved. */
  u_int16_t reserved;

  /* Protocol ID. */
  u_int32_t protocol_id;

  /* Client Id. */
  u_int32_t client_id;

  /* Service Bits. */
  u_int32_t bits;

};

#define SMI_MSG_SERVICE_SIZE                    16
/* API message send queue.  */
struct smi_message_queue
{
  struct smi_message_queue *next;
  struct smi_message_queue *prev;

  u_char *buf;
  u_int16_t length;
  u_int16_t written;
};

typedef enum _smi_alarm {
  SMI_ALARM_MEMORY_FAILURE,
  SMI_ALARM_HARDWARE_FAILURE,
  SMI_ALARM_NSM_SERVER_SOCKET_DISCONNECT,
  SMI_ALARM_NSM_CLIENT_SOCKET_DISCONNECT,
  SMI_ALARM_TRANSPORT_FAILURE,
  SMI_ALARM_CFM,
  SMI_ALARM_EFM,
  SMI_ALARM_STP,
  SMI_ALARM_RMON,
  SMI_ALARM_LOC,
  SMI_ALARM_SMI_SERVER_CONNECT,
  SMI_ALARM_SMI_SERVER_DISCONNECT,
  SMI_ALARM_NSM_VLAN_ADD_TO_PORT,
  SMI_ALARM_NSM_VLAN_DEL_FROM_PORT,
  SMI_ALARM_NSM_VLAN_PORT_MODE,
  SMI_ALARM_NSM_BRIDGE_PROTO_CHANGE,
  SMI_ALARM_SMI_MAX 
} smi_alarm;

typedef enum smi_nsm_client_e {
  SMI_NSM_CLIENT_LACP = 15,    /* IPI_PROTO_LACP */
  SMI_NSM_CLIENT_MSTP = 18,    /* IPI_PROTO_MSTP */
  SMI_NSM_CLIENT_IMI  = 19,    /* IPI_PROTO_IMI  */
  SMI_NSM_CLIENT_RMON = 24,    /* IPI_PROTO_RMON */
  SMI_NSM_CLIENT_ONM  = 25,    /* IPI_PROTO_ONM  */
  SMI_NSM_CLIENT_MAX  = 34     /* IPI_PROTO_MAX  */
} smi_nsm_client;

struct cfm_alarm_info_s {
  u_char var[10];
};

#define SMI_MESSAGE_ALARM_SIZE 12
struct smi_msg_alarm
{
      smi_cindex_t cindex;
#define SMI_ALARM_CTYPE_MODULE_NAME                      0
#define SMI_ALARM_CTYPE_ALARM_TYPE                       1
#define SMI_ALARM_CTYPE_DATA_NSM_CLIENT                  2
#define SMI_ALARM_CTYPE_DATA_TRANSPORT_DESC              3
#define SMI_ALARM_CTYPE_DATA_CFM_ALARM                   4
#define SMI_ALARM_CTYPE_DATA_EFM_ALARM                   5
#define SMI_ALARM_CTYPE_DATA_STP_ALARM                   6
#define SMI_ALARM_CTYPE_DATA_RMON_ALARM                  7
#define SMI_ALARM_CTYPE_LOC_ALARM                        8
#define SMI_ALARM_CTYPE_VLAN_ALARM                       9
#define SMI_ALARM_CTYPE_VLAN_PORT_MODE_ALARM             10
#define SMI_ALARM_CTYPE_BRIDGE_PROTOCOL_CHANGE_ALARM     11

  smi_api_module smi_module;
  smi_alarm alarm_type;
  smi_nsm_client nsm_client;
  /* data for SMI_ALARM_ SMI_ALARM_TRANSPORT_FAILURE */
#define SMI_TRANSPORT_DESC_MAX 512
  u_char description [SMI_TRANSPORT_DESC_MAX];
  struct cfm_alarm_info_s cfm_alarm_info;
};
typedef void (* smi_alarm_callback_t) (smi_alarm alarm,
                                       smi_api_module module,
                                       void *data);
typedef int (*SMI_CALLBACK) (struct smi_msg_header *, void *, void *);
typedef int (*SMI_DISCONNECT_CALLBACK) ();

typedef int (*SMI_PARSER) (u_char **, u_int16_t *, struct smi_msg_header *,
                           void *, SMI_CALLBACK);

int
smi_parse_service (u_char **pnt, u_int16_t *size,
                   struct smi_msg_header *header, void *arg,
                   SMI_CALLBACK callback);
#endif /* _SMI_MESSAGE_H */
