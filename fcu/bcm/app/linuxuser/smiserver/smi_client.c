/* Copyright (C) 2002-2011 IP Infusion, Inc. All Rights Reserved. */

/* SMI client.  */
#include <sys/un.h>
#include "zebra.h"
#include "thread.h"
#include "vector.h"
#include "memory.h"
#include "tlv.h"
#include "log.h"
#include "message.h"
#include "smi_message.h"
#include "smi_client.h"


pthread_mutex_t smi_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Specify each SMI service is sync or async.  */
struct
{
  int message;
  int type;
} smi_service_type[] =
{
  {SMI_SERVICE_INTERFACE,         MESSAGE_TYPE_ASYNC},
};

static smi_alarm_callback_t smi_alarm_callback;

int
smi_process_alarm_message (struct smi_msg_header *header,
                           void *arg, void *message)
{
  int ret = 0;
  struct smi_msg_alarm *msg = (struct smi_msg_alarm *)message;

  smi_alarm_callback (msg->alarm_type, msg->smi_module, msg);

  return ret;
}

void
smi_capture_client_alarm_info (int smi_client, int alarm_type)
{
  struct smi_msg_alarm msg;

  msg.alarm_type = alarm_type;
  msg.nsm_client = smi_client;
  msg.smi_module = SMI_AC_API_CLIENT;

  smi_alarm_callback (msg.alarm_type, msg.smi_module, &msg);

  return;
}
/* SMI message strings.  */
static const char *smi_msg_str[] =
{
  "Service Request",                            /* 0 */
  "Service Reply",                              /* 1 */
  "Status message",                             /* 2 */
  "Interface Start",                            /* 3 */
  "Interface set mtu",                          /* 4 */
  "Interface get mtu",                          /* 5 */
  "Interface set bw",                           /* 6 */
  "Interface get bw",                           /* 7 */
  "Interface set flagup",                       /* 8 */
  "Interface unset flagup",                     /* 9 */
  "Interface set autoneg",                      /* 10 */
  "Interface get autoneg",                      /* 11 */
  "Interface set hw addr",                      /* 12 */
  "Interface get hw addr",                      /* 13 */
  "Interface set duplex",                       /* 14 */
  "Interface get duplex",                       /* 15 */
  "Interface unset duplex",                     /* 16 */
  "Interface get brief",                        /* 17 */
  "Interface set mcast",                        /* 18 */
  "Interface get mcast",                        /* 19 */
  "Interface unset mcast",                      /* 20 */
  "Interface get change",                       /* 21 */
  "Interface get statistics"                    /* 22 */
  "Interface clear statistics"                  /* 23 */
  "Interface set MDIX crossover",               /* 24 */
  "Interface get MDIX crossover",               /* 25 */
  "Interface get traffic class table",          /* 26 */
  "Interface bridge add mac",                   /* 27 */                  
  "Interface bridge delete mac",                /* 28 */
  "Interface bridge mac add priority override", /* 29 */                  
  "Interface bridge mac delete priority override", /* 30 */
  "Interface bridge flush dynamic entry",       /* 31 */           
  "Interface bridge add",                       /* 32 */
  "Interface bridge add to port ",              /* 33 */    
  "Interface set port non-conf",                /* 26 */
  "Interface get port non-conf",                /* 27 */
  "Interface set port learning",                /* 28 */
  "Interface get port non-learning",            /* 29 */
  "Interface set port egress mode",             /* 30 */
  "Interface get bridge change type",           /* 31 */
  "Interface get bridge type",                  /* 32 */
  "Interface get flags",                        /* 33 */
  "Interface set dtag mode",                    /* 34 */
  "Interface get dtag mode",                    /* 35 */
  "Interface set dot1q",                        /* 36 */
  "Interface get dot1q",                        /* 37 */
  "check if exist",                             /* 38 */
  "check bridge exist",                         /* 39 */
  "software reset",                             /* 40 */
  "Interface end",                              /* 41 */
  /* VLAN */
  "VLAN start",                                  /* 26 */
  "VLAN add",                                    /* 27 */
  "VLAN delete",                                 /* 28 */
  "VLAN set port mode",                          /* 29 */
  "VLAN get port mode",                          /* 30 */
  "VLAN set frame type",                         /* 31 */
  "VLAN get frame type",                         /* 32 */
  "VLAN set ingress filter",                     /* 33 */
  "VLAN get ingress filter",                     /* 34 */
  "VLAN set default vid",                        /* 35 */
  "VLAN get default vid",                        /* 36 */
  "VLAN add to port",                            /* 37 */
  "VLAN delete from port",                       /* 38 */
  "VLAN clear hybrid port",                      /* 39 */
  "VLAN clear trunk port",                       /* 40 */
  "VLAN add all except vid",                     /* 41 */
  "VLAN set native vlan",                        /* 42 */
  "VLAN get native vlan",                        /* 43 */
  "VLAN get all vlan config",                    /* 44 */
  "VLAN get vlan by id",                         /* 45 */
  "VLAN get interface info",                     /* 46 */
  "VLAN get bridge info",                        /* 47 */
  "VLAN set port proto process",                 /* 48 */
  "VLAN set force default vlan",                 /* 49 */
  "VLAN set preserve ce cos",                    /* 50 */
  "VLAN set port based vlan",                    /* 51 */
  "VLAN set cpu port default vlan",              /* 52 */
  "VLAN set svlan port ether type",              /* 53 */
  "VLAN set wayside ether type",                 /* 54 */
  "VLAN set port egress mode",                   /* 55 */
  "HA switchover",                               /* 56 */
  "Vlan Add Range",                              /* 56 */
  "Vlan Del Range",
  "VLAN end",                                    /* 57 */
  /* MSTP */
  "MSTP start",                                  /* 50 */
  "MSTP add instance",                           /* 51 */
  "MSTP delete instance",                        /* 52 */
  "MSTP set age",                                /* 53 */
  "MSTP get age",                                /* 54 */
  "MSTP check",                                  /* 55 */
  "MSTP add port",                               /* 56 */
  "MSTP delete port",                            /* 57 */
  "MSTP set hello time",                         /* 58 */
  "MSTP get hello time",                         /* 59 */
  "MSTP set max age",                            /* 60 */
  "MSTP get max age",                            /* 61 */
  "MSTP set port edge",                          /* 62 */
  "MSTP get port edge",                          /* 63 */
  "MSTP set version",                            /* 64 */
  "MSTP get version",                            /* 65 */
  "MSTP set priority",                           /* 66 */
  "MSTP get priority",                           /* 67 */
  "MSTP set frwd delay",                         /* 68 */
  "MSTP get fwrd delay",                         /* 69 */
  "MSTP set max priority",                       /* 70 */
  "MSTP get max priority",                       /* 71 */
  "MSTP set path cost",                          /* 72 */
  "MSTP get path cost",                          /* 73 */
  "MSTP set restricted role",                    /* 74 */
  "MSTP get restricted role",                    /* 75 */
  "MSTP set restricted tcn",                     /* 76 */
  "MSTP get restricted tcn",                     /* 77 */
  "MSTP set port path cost",                     /* 78 */
  "MSTP get port path cost",                     /* 79 */
  "MSTP set p2p",                                /* 80 */
  "MSTP get p2p",                                /* 81 */
  "MSTP set port hello time",                    /* 82 */
  "MSTP get port hello time",                    /* 83 */
  "MSTP set port priority",                      /* 84 */
  "MSTP get port priority",                      /* 85 */
  "MSTP set max hops",                           /* 86 */
  "MSTP get max hops",                           /* 87 */
  "MSTP set bridge port priority",               /* 88 */
  "MSTP get bridge port priority",               /* 89 */
  "MSTP set port restricted role",               /* 90 */
  "MSTP get port restricted role",               /* 91 */
  "MSTP set port restricted tcn",                /* 92 */
  "MSTP get port restricted tcn",                /* 93 */
  "MSTP set port rootguard",                     /* 94 */
  "MSTP get root guard",                         /* 95 */
  "MSTP set port BPDU filter",                   /* 96 */
  "MSTP get port BPDU filter",                   /* 97 */
  "MSTP enable bridge",                          /* 98 */
  "MSTP disable bridge",                         /* 99 */
  "MSTP set port BPDU guard",                    /* 100 */
  "MSTP get port BPDU guard",                    /* 101 */
  "MSTP set txholdcount",                        /* 102 */
  "MSTP get txholdcount",                        /* 103 */
  "MSTP set bridge BPDUguard",                   /* 104 */
  "MSTP get bridge BPDUguard",                   /* 105 */
  "MSTP set bridge timeout enable",              /* 106 */
  "MSTP get bridge timeout enable",              /* 107 */
  "MSTP set bridge timeout interval",            /* 108 */
  "MSTP get bridge timeout interval",            /* 109 */
  "MSTP set msti port priority",                 /* 110 */
  "MSTP get msti port priority",                 /* 111 */
  "MSTP set revision number",                    /* 112 */
  "MSTP get revision number",                    /* 113 */
  "MSTP add bridge",                             /* 114 */
  "MSTP add bridge port",                        /* 115 */
  "MSTP change topology type",                   /* 116 */
  "MSTP get spanning details",                   /* 117 */
  "MSTP get spanning interface",                 /* 118 */
  "MSTP get spanning mst",                       /* 119 */
  "MSTP get spanning mst configuration",         /* 120 */
  "MSTP set autoedge",                           /* 121 */
  "MSTP get autoedge",                           /* 122 */
  "MSTP set region name",                        /* 123 */
  "MSTP get region name",                        /* 124 */
  "MSTP add bridge MAC address",                 /* 125 */
  "MSTP delete bridge MAC address",              /* 126 */
  "MSTP bridge flush dynamic entries",           /* 127 */
  "MSTP stp mstdetails",                         /* 128 */
  "MSTP get SPT mstdetail interface",            /* 129 */
  "MSTP ipi get traffic class",                  /* 130 */
  "MSTP ipi get user priority",                  /* 131 */
  "MSTP set bridge BPDU filter",                 /* 132 */
  "MSTP get bridge BPDU filter",                 /* 133 */
  "MSTP get bridge type",                        /* 134 */
  "MSTP set port non-switching",                 /* 135 */
  "MSTP get port non-switching",                 /* 136 */
  "MSTP end",                                    /* 137 */
  /*** RMON **/
  "RMON start",                                  /* 136 */
  "RMON validate stat interface",                /* 137 */
  "RMON add stat entry",                         /* 138 */
  "RMON remove stat entry",                      /* 139 */
  "RMON validate history stat",                  /* 140 */
  "RMON set history status",                     /* 141 */
  "RMON get history status",                     /* 142 */
  "RMON set history bucket",                     /* 143 */
  "RMON get history bucket",                     /* 144 */
  "RMON set history inactive",                   /* 145 */
  "RMON add history index",                      /* 146 */
  "RMON set datasource",                         /* 147 */
  "RMON set history index",                      /* 148 */
  "RMON get history index",                      /* 149 */
  "RMON set history ctrl interval",              /* 150 */
  "RMON set history ctrl interval",              /* 151 */
  "RMON set history ctrl owner",                 /* 152 */
  "RMON get history ctrl owner",                 /* 153 */
  "RMON history index remove",                   /* 154 */
  "RMON set alarm poll interval",                /* 155 */
  "RMON get alarm poll interval"                 /* 156 */
  "RMON set alarm variable",                     /* 157 */
  "RMON get alarm variable",                     /* 158 */
  "RMON set sample type",                        /* 159 */
  "RMON get sample type",                        /* 160 */
  "RMON set alarm start up",                     /* 161 */
  "RMON get alarm start up",                     /* 162 */
  "RMON set rising threshold",                   /* 163 */
  "RMON get rising threshold",                   /* 164 */
  "RMON set falling threshold",                  /* 165 */
  "RMON get falling threshold",                  /* 166 */
  "RMON set rising event index",                 /* 167 */
  "RMON get rising event index",                 /* 168 */
  "RMON set falling event index",                /* 169 */
  "RMON get falling event index",                /* 170 */
  "RMON set alarm owner",                        /* 171 */
  "RMON get alarm owner",                        /* 172 */
  "RMON set alarm entry",                        /* 173 */
  "RMON get alarm entry",                        /* 174 */
  "RMON set alarm index RM",                     /* 175 */
  "RMON set event index RM",                     /* 176 */
  "RMON set event index",                        /* 177 */
  "RMON get event index",                        /* 178 */
  "RMON set event active",                       /* 179 */
  "RMON get event status",                       /* 180 */
  "RMON set event community",                    /* 181 */
  "RMON get event community",                    /* 182 */
  "RMON set evnet description",                  /* 183 */
  "RMON get event description",                  /* 184 */
  "RMON set event owner",                        /* 185 */
  "RMON get event owner",                        /* 186 */
  "RMON set event type",                         /* 187 */
  "RMON get event type",                         /* 188 */
  "RMON set snmp eventtype",                     /* 189 */
  "RMON get snmp eventtype",                     /* 190 */
  "RMON set snmp community",                     /* 191 */
  "RMON get snmp community",                     /* 192 */
  "RMON set snmp eventowner",                    /* 193 */
  "RMON get snmp eventowner",                    /* 194 */
  "RMON set snmp etherstatus",                   /* 195 */
  "RMON get snmp etherstatus",                   /* 196 */
  "RMON set snmp description",                   /* 197 */
  "RMON get snmp description",                   /* 198 */
  "RMON get if stats",                           /* 199 */
  "RMON Rt if counter",                          /* 20O */
  "RMON get if counter",                         /* 201 */
  "RMON flush port",                             /* 202 */
  "RMON flush all port",                         /* 203 */
  "RMON set alarm status",
  "RMON set event status",
  "RMON end",                                    /* 204 */
  /*** LACP **/
  "LACP start ",                                 /* 205 */
  "LACP add link",                               /* 206 */
  "LACP delete link",                            /* 207 */
  "LACP get channel activity",                   /* 208 */
  "LACP get channel admin key",                  /* 209 */
  "LACP set channel priority",                   /* 210 */
  "LACP get channel priority",                   /* 211 */
  "LACP unset channel priority",                 /* 212 */
  "LACP set channel timeout",                    /* 213 */
  "LACP get channel timeout",                    /* 214 */
  "LACP set system priority",                    /* 215 */
  "LACP get system priority",                    /* 216 */
  "LACP unset system priority",                  /* 217 */
  "LACP get ether channel detail",               /* 218 */
  "LACP get ether channel summary",              /* 219 */
  "LACP get counter",                            /* 220 */
  "LACP get system id",                          /* 221 */
  "LACP get agg bmp",                            /* 222 */
  "LACP get agg ports bmp",                      /* 223 */
  "LACP end",                                    /* 224 */
  /***LLDP***/
  "LLDP start",                                  /* 225 */
  "LLDP disable port",                           /* 226 */
  "LLDP enable port",                            /* 227 */
  "LLDP set locally assigned string",            /* 228 */
  "LLDP get locally assigned string",            /* 229 */
  "LLDP set portbasic tlv enable",               /* 230 */
  "LLDP get portbasic tlv enable",               /* 231 */
  "LLDP set port msg txholdcount",               /* 232 */
  "LLDP get port msg txholdcount",               /* 233 */
  "LLDP set port msg txinterval",                /* 234 */
  "LLDP get port mag txinterval",                /* 235 */
  "LLDP set port reinitdelay",                   /* 236 */
  "LLDP get port reinitdelay",                   /* 237 */
  "LLDP set port too many neighbours",           /* 238 */
  "LLDP get port too many neighbours",           /* 239 */
  "LLDP set port txdelay",                       /* 240 */
  "LLDP get port txdelay",                       /* 241 */
  "LLDP set system description",                 /* 242 */
  "LLDP get system description",                 /* 243 */
  "LLDP set system name",                        /* 244 */
  "LLDP get system name",                        /* 245 */
  "LLDP get port",                               /* 246 */
  "LLDP get port statistics",                    /* 247 */
  "LLDP set hardware address",                   /* 248 */
  "LLDP get hardware address",                   /* 249 */
  "LLDP set chassis id type",                    /* 250 */
  "LLDP get chassis id type",                    /* 251 */
  "LLDP set chassis ip",                         /* 252 */
  "LLDP get chassis ip",                         /* 253 */
  "LLDP end",                                    /* 254 */
 /* EFM Get/Set SMIs */ 
  "EFM start",                                   /* 251 */
  "EFM OAM proto enable",                        /* 252 */
  "EFM OAM prorto disable",                      /* 253 */
  "EFM OAM set linktimer",                       /* 254 */
  "EFM OAM get linktimer",                       /* 255 */
  "EFM OAM remotelb start",                      /* 256 */
  "EFM OAM remotelb stop",                       /* 257 */
  "EFM OAM set mode active",                     /* 258 */
  "EFM OAM set mode passive",                    /* 259 */
  "EFM OAM get mode",                            /* 260 */
  "EFM OAM set pdutimer",                        /* 261 */
  "EFM OAM get pdutimer",                        /* 262 */
  "EFM OAM set maxrate",                         /* 263 */
  "EFM OAM get maxrate",                         /* 264 */
  "EFM OAM set linkmonitor"                      /* 265 */
  "EFM OAM get linkmonitor",                     /* 266 */
  "EFM OAM set remote lb",                       /* 267 */
  "EFM OAM get remote lb",                       /* 268 */
  "EFM OAM set remoteloopback timeout",          /* 269 */
  "EFM OAM get remoteloopback timeout",          /* 270 */
  "EFM OAM set errframes low threshold",         /* 271 */
  "EFM OAM get errframes low threshold",         /* 272 */
  "EFM OAM set errframes high threshold",        /* 273 */
  "EFM OAM get errframes high threshold",        /* 274 */
  "EFM OAM set errframes second low threshold",  /* 275 */
  "EFM OAM get errframe second low threshold",   /* 276 */
  "EFM OAM set errframes second high threshold", /* 277 */
  "EFM OAM get errframes second high threshold", /* 278 */
  "EFM OAM set errframe per window",             /* 279 */
  "EFM_OAM get errframe per window",             /* 280 */
  "EFM OAM disable ifevent set",                 /* 281 */
  "EFM OAM disable ifevent get",                 /* 282 */
  "EFM OAM show stats",                          /* 283 */
  "EFM OAM show interface"                       /* 284 */
  "EFM OAM get discovery",                       /* 285 */
  "EFM OAM get ethernet",                        /* 286 */
  "EFM send data frame",                         /* 287 */
  "EFM loopback status",                         /* 288 */
  "EFM end",                                     /* 289 */
  /*** CFM ***/
  "CFM start",                                   /* 289 */
  "CFM add ma",                                  /* 290 */
  "CFM add md",                                  /* 291 */
  "CFM add mep",                                 /* 292 */
  "CFM add mip",                                 /* 293 */
  "CFM add rmep",                                /* 294 */
  "CFM cc enable",                               /* 295 */
  "CFM ma get",                                  /* 296 */
  "CFM md get",                                  /* 297 */
  "CFM mep get",                                 /* 298 */
  "CFM remove ma",                               /* 299 */
  "CFM remove md",                               /* 300*/
  "CFM remove mep",                              /* 301 */
  "CFM send ping",                               /* 302 */
  "CFM iterate mep",                             /* 303 */
  "CFM iterate rmep",                            /* 304 */
  "CFM iterate traceroute cache",                /* 305 */
  "CFM send traceroute",                         /* 306 */
  "CFM get errors",                              /* 307 */
  "CFM get rmep clear",                          /* 308 */
  "CFM set hwaddr" ,                             /* 309 */
  "CFM get hwaddr",                              /* 310 */
  "CFM set ether type",                          /* 311 */
  "CFM get ether type",                          /* 312 */
  "CFM rmep get",                                /* 313 */
  "CFM IF mep list",                             /* 314 */
  "CFM rmep list",
  "CFM get rmep info",
  "CFM get mep info",
  "CFM get number of errors",
  "CFM get error entry",
  "CFM end",                                     /* 314 */
  /***GVRP***/
  "GVRP start",                                  /* 315 */
  "GVRP set timer",                              /* 316 */
  "GVRP get timer",                              /* 317 */
  "GVRP enable"                                  /* 318 */
  "GVRP disable",                                /* 319 */
  "GVRP enable port",                            /* 320 */
  "GVRP disable port",                           /* 321 */
  "GVRP set_reg mode",                           /* 322 */
  "GVRP get reg mode",                           /* 323 */
  "GVRP get per vlan stats",                     /* 324 */
  "GVRP clear all stats",                        /* 325 */
  "GVRP set dynamic vlan learning",              /* 326 */
  "GVRP get bridge config",                      /* 327 */
  "GVRP get vid details",                        /* 328 */
  "GVRP get state machine bridge",               /* 329 */
  "GVRP get port stats",                         /* 330 */
  "GVRP end",                                    /* 331 */
    /*QOS*/
  "QOS start",                                   /* 332 */         
  "QOS global enable",                           /* 333 */
  "QOS global disable",                          /* 334 */ 
  "QOS get global status",                       /* 335 */
  "QOS set policy map name",                     /* 336 */
  "QOS get policy map names",                    /* 337 */  
  "QOS get policy map",                          /* 338 */
  "QOS delete policy map",                       /* 339 */
  "QOS set cmap name",                           /* 340 */
  "QOS get cmap name",                           /* 341 */
  "QOS delete cmap name",                        /* 342 */
  "QOS cmap match traffic set",                  /* 343 */ 
  "QOS cmap match traffic unset",                /* 344 */
  "QOS set police params",                       /* 345 */
  "QOS get police params",                       /* 345 */
  "QOS delete police params",                    /* 346 */
  "QOS set port scheduling",                     /* 347 */
  "QOS get port scheduling",                     /* 348 */
  "QOS set default user prio",                   /* 349 */
  "QOS get default user prio",                   /* 350 */
  "QOS set regen user prio",                     /* 351 */
  "QOS get regen user prio",                     /* 352 */
  "QOS set cos to queue",                        /* 353 */
  "QOS get cos to queue",                        /* 354 */
  "QOS set dscp to queue",                       /* 355 */
  "QOS get dscp to queue",                       /* 356 */
  "QOS set trust state",                         /* 357 */
  "QOS get trust state",                         /* 358 */
  "QOS force trust state",                       /* 359 */ 
  "QOS get force trust state",                   /* 360 */
  "QOS override frame type prio",                /* 361 */
  "QOS set vlan prio",                           /* 362 */
  "QOS unset vlan prio",                         /* 363 */
  "QOS override port vlan prio",                 /* 364 */ 
  "QOS get override port vlan prio",             /* 365 */ 
  "QOS set queue weight",                        /* 366 */
  "QOS get queue weight",                        /* 366 */
  "QOS set policy map to interface",             /* 367 */
  "QOS get policy map to interface",             /* 367 */
  "QOS unset policy map to interface",           /* 368 */
  "QOS get policy map for interface",            /* 369 */
  "QOS set traffic shape",                       /* 370 */
  "QOS unset traffic shape",                     /* 371 */
  "QOS get traffic shape",                       /* 372 */
  "QOS Delete Class-Map from Policy-Map",        /* New */
  "QOS_END",                                     /* 373 */ 
  /***FC***/
  "FC_START",                                    /* 370 */ 
  "FC set flow control",                         /* 371 */
  "FC unset flow control",                       /* 372 */
  "FC get flow control stats",                   /* 373 */ 
  "FC get interface stats",                      /* 374 */
  "FC_END",                                      /* 375 */
  "Alarm Message",                               /* 376 */
  "Alarm Message",                               /* 376 */
  /***DUMMY MESSAGE ***/
  "DUMMY MESSAGE 1",
  "DUMMY MESSAGE 2",
  "DUMMY MESSAGE 3",
  "DUMMY MESSAGE 4",
  "DUMMY MESSAGE 5",
  "DUMMY MESSAGE 6",
  "DUMMY MESSAGE 7",
  "DUMMY MESSAGE 8",
  "DUMMY MESSAGE 9",
 
};

/* SMI message to string.  */
const char *
smi_msg_to_str (int type)
{
  if (type <= SMI_MSG_MAX)
    return smi_msg_str [type];

  return "Unknown";
}


/* Dump SMI header */
void
smi_header_dump (void *zg, struct smi_msg_header *header)
{
  zlog_info ("SMI Message Header");
  zlog_info (" Message type: %s (%d)", smi_msg_to_str (header->type),
             header->type);
  zlog_info (" Message length: %d", header->length);
  zlog_info (" Message ID: 0x%08x", header->message_id);
}

/* Set packet parser.  */
void
smi_client_set_parser (struct smi_client *ac, int message_type,
                       SMI_PARSER parser)
{
  ac->parser[message_type] = parser;
}

/* Register callback.  */
void
smi_client_set_callback (struct smi_client *ac, int message_type,
                         SMI_CALLBACK callback)
{
  ac->callback[message_type] = callback;
}

void
smi_client_set_client_id (struct smi_client *ac, u_int32_t client_id)
{
  ac->client_id = client_id;
}


/* Read from the socket.  */
int
smi_client_read (struct smi_client_handler *ach, int sock)
{
  struct smi_msg_header *header;
  u_int16_t length;
  int nbytes = 0;

  ach->size_in = 0;
  ach->pnt_in = ach->buf_in;

  nbytes = readn (sock, ach->buf_in, SMI_MSG_HEADER_SIZE);
  if (nbytes < SMI_MSG_HEADER_SIZE)
    return SMI_ERROR;

  header = (struct smi_msg_header *) ach->buf_in;
  length = ntohs (header->length);

  nbytes = readn (sock, ach->buf_in + SMI_MSG_HEADER_SIZE,
                  length - SMI_MSG_HEADER_SIZE);
  if (nbytes <= 0)
    return nbytes;

  ach->size_in = length;

  return length;
}

/* Read API message body.  */
int
smi_client_read_msg (struct message_handler *mc,
                     struct message_entry *me,
                     int sock)
{
  struct smi_client_handler *ach;
  struct smi_client *ac;
  struct smi_msg_header header;
  int nbytes;
  int type;
  int ret;

  /* Get API client handler from message entry. */
  ach = mc->info;
  ac = ach->ac;

  /* Read data. */
  nbytes = smi_client_read (ach, sock);
  if (nbytes <= 0)
    return nbytes;

  /* Parse API message header. */
  ret = smi_decode_header (&ach->pnt_in, &ach->size_in, &header);
  if (ret < 0)
    return SMI_ERROR;

  /* Dump API header */
  if (ac->debug)
    smi_header_dump (mc->zg, &header);

  type = header.type;

  /* Invoke parser with call back function pointer.  There is no callback
     set by protocols for MPLS replies. */
  if (type < SMI_MSG_MAX && ac->parser[type] && ac->callback[type])
    {
      ret = (*ac->parser[type]) (&ach->pnt_in, &ach->size_in, &header, ach,
                                 ac->callback[type]);
      if (ret < 0)
        zlog_err ("Parse error for message %s", smi_msg_to_str (type));
    }

  return nbytes;
}

/* Read API message body. Don't parse and call callback  */
int
smi_client_read_sync (struct message_handler *mc, struct message_entry *me,
                      int sock,
                      struct smi_msg_header *header, int *type)
{
  struct smi_client_handler *ach;
  struct smi_client *ac;
  int nbytes;
  int ret;

  /* Get API server entry from message entry.  */
  ach = mc->info;
  ac = ach->ac;

  /* Read msg */
  nbytes = smi_client_read (ach, sock);
  if (nbytes <= 0)
    {
      message_client_disconnect (mc, sock);
      return SMI_ERROR;;
    }

  /* Parse API message header.  */
  ret = smi_decode_header (&ach->pnt_in, &ach->size_in, header);
  if (ret < 0)
    return SMI_ERROR;;

  /* Dump API header */
  if (ac->debug)
    smi_header_dump (mc->zg, header);

  *type = header->type;

  return nbytes;
}

void
smi_client_pending_message (struct smi_client_handler *ach,
                            struct smi_msg_header *header)
{
  struct smi_client_pend_msg *pmsg;

  /* Queue the message for later processing. */
  pmsg = XMALLOC (MTYPE_SMI_PENDING_MSG, sizeof (struct smi_client_pend_msg));
  pmsg->header = *header;

  memcpy (pmsg->buf, ach->pnt_in, ach->size_in);

  /* Add to pending list. */
  listnode_add (&ach->pend_msg_list, pmsg);
}

/* Generic function to send message to API server.  */
int
smi_client_send_message (struct smi_client_handler *ach,
                         u_int32_t vr_id, u_int32_t vrf_id,
                         int type, u_int16_t len, u_int32_t *msg_id)
{
  struct smi_msg_header header;
  u_int16_t size;
  u_char *pnt;
  int ret;

  pnt = ach->buf;
  size = SMI_MESSAGE_MAX_LEN;

  /* If message ID warparounds, start from 1. */
  ++ach->message_id;
  if (ach->message_id == 0)
    ach->message_id = 1;

  /* Prepare API message header.  */
  header.type = type;
  header.length = len + SMI_MSG_HEADER_SIZE;
  header.message_id = ach->message_id;

  /* Encode header.  */
  smi_encode_header (&pnt, &size, &header);

  /* Write message to the socket.  */
  ret = writen (ach->mc->sock, ach->buf, len + SMI_MSG_HEADER_SIZE);
  if (ret != len + SMI_MSG_HEADER_SIZE)
    return SMI_ERROR;;

  if (msg_id)
    *msg_id = header.message_id;

  return SMI_SUCEESS;
}

/* Send service message.  */
int
smi_client_send_service (struct smi_client_handler *ach)
{
  u_int32_t msg_id;
  u_int16_t size;
  u_char *pnt;
  int nbytes;
  u_int32_t vr_id = 0;
  u_int32_t vrf_id = 0;

  if (! ach || ! ach->up)
    return SMI_ERROR;

  pnt = ach->buf + SMI_MSG_HEADER_SIZE;
  size = ach->len - SMI_MSG_HEADER_SIZE;

  nbytes = smi_encode_service (&pnt, &size, &ach->service);
  if (nbytes < 0)
    return nbytes;

  return smi_client_send_message (ach, vr_id, vrf_id,
                                  SMI_MSG_SERVICE_REQUEST, nbytes, &msg_id);
}

int
smi_client_reconnect (struct thread *t)
{
  struct smi_client *ac;

  pthread_mutex_lock (&smi_mutex);

  ac = THREAD_ARG (t);
  ac->t_connect = NULL;
  smi_client_start (ac);

  pthread_mutex_unlock (&smi_mutex);

  return SMI_SUCEESS;
}

/* Start to connect API services.  This function always return success. */
int
smi_client_start (struct smi_client *ac)
{
  int ret;

  if (ac->async)
    {
      ret = message_client_start (ac->async->mc);
      if (ret < 0)
        {
          /* Start reconnect timer.  */
          if (ac->t_connect == NULL)
            {
              ac->t_connect
                = thread_add_timer (ac->zg, smi_client_reconnect,
                                    ac, ac->reconnect_interval);
              if (ac->t_connect == NULL)
                return SMI_ERROR;
            }
        } else {
            //ac->t_keepalive  = thread_add_timer (ac->zg, smi_client_keepalive,
            //                        ac, ac->keepalive_interval);
        }
    }
  return SMI_SUCEESS;
}

/* Stop API client. */
void
smi_client_stop (struct smi_client *ac)
{
  if (ac->async)
    message_client_stop (ac->async->mc);
}

/* Client connection is established.  Client send service description
   message to the server.  */
int
smi_client_connect (struct message_handler *mc, struct message_entry *me,
                    int sock)
{
  struct smi_client_handler *ach = mc->info;
#if 0 /* TODO: Check this */
  struct thread t;
#endif

  ach->up = 1;

#if 0 /* TODO: Check this */
  /* Send service message to API server.  */
  smi_client_send_service (ach);

  /* Always read service message synchronously */
  THREAD_ARG (&t) = mc;
  THREAD_FD (&t) = mc->sock;
  message_client_read (&t);
#endif

  /* Register read thread. */
  message_client_read_register (mc);

  if (ach->ac->client_id > 0)
  {
    smi_capture_client_alarm_info (ach->ac->client_id,
                                 SMI_ALARM_SMI_SERVER_CONNECT);
  }

  return SMI_SUCEESS;
}

/* Reconnect to API. */
int
smi_client_reconnect_start (struct smi_client *ac)
{
  /* Start reconnect timer.  */
  ac->t_connect = thread_add_timer (ac->zg, smi_client_reconnect,
                                    ac, ac->reconnect_interval);
  if (! ac->t_connect)
    return SMI_ERROR;;

  return SMI_SUCEESS;
}

int
smi_client_disconnect (struct message_handler *mc, struct message_entry *me,
                       int sock)
{
  struct smi_client_handler *ach;
  struct smi_client *ac;
  struct listnode *node, *next;

  ach = mc->info;
  ac = ach->ac;

  if (ach->ac->client_id > 0)
  smi_capture_client_alarm_info (ach->ac->client_id,
                                 SMI_ALARM_SMI_SERVER_DISCONNECT);

  /* Set status to down.  */
  ach->up = 0;

  /* Cancel pending read thread. */
  if (ac->pend_read_thread)
    THREAD_OFF (ac->pend_read_thread);

  /* Free all pending reads. */
  for (node = listhead (&ach->pend_msg_list); node; node = next)
    {
      struct smi_client_pend_msg *pmsg = getdata (node);

      next = node->next;

      XFREE (MTYPE_SMI_PENDING_MSG, pmsg);
      list_delete_node (&ach->pend_msg_list, node);
    }

  /* Stop async connection.  */
  if (ac->async)
    message_client_stop (ac->async->mc);

  /* Call client specific disconnect handler. */
  if (ac->disconnect_callback)
    ac->disconnect_callback ();
  else
    smi_client_reconnect_start (ac);

  return SMI_SUCEESS;
}

struct smi_client_handler *
smi_client_handler_create (struct smi_client *ac, int type, int module)
{
  struct smi_client_handler *ach;
  struct message_handler *mc;

  /* Allocate API client handler.  */
  ach = XCALLOC (MTYPE_SMICLIENT_HANDLER, sizeof (struct smi_client_handler));
  ach->type = type;
  ach->ac = ac;

  /* Set max message length.  */
  ach->len = SMI_MESSAGE_MAX_LEN;
  ach->len_in = SMI_MESSAGE_MAX_LEN;
  ach->len_ipv4 = SMI_MESSAGE_MAX_LEN;

  /* Create async message client. */
  mc = message_client_create (ac->zg, type);

  switch(module) {
    case SMI_AC_NSM_MODULE:
#ifndef HAVE_TCP_MESSAGE
  /* Use UNIX domain socket connection.  */
      message_client_set_style_domain (mc, SMI_SERV_XXX_PATH);
#else /* HAVE_TCP_MESSAGE */
      message_client_set_style_tcp (mc, SMI_PORT_XXX);
#endif /* !HAVE_TCP_MESSAGE */
      break;
    case SMI_AC_LACP_MODULE:
#ifndef HAVE_TCP_MESSAGE
  /* Use UNIX domain socket connection.  */
      message_client_set_style_domain (mc, SMI_SERV_LACP_PATH);
#else /* HAVE_TCP_MESSAGE */
      message_client_set_style_tcp (mc, SMI_PORT_LACP);
#endif /* !HAVE_TCP_MESSAGE */
      break;

    case SMI_AC_MSTP_MODULE:
#ifndef HAVE_TCP_MESSAGE
  /* Use UNIX domain socket connection.  */
      message_client_set_style_domain (mc, SMI_SERV_MSTP_PATH);
#else /* HAVE_TCP_MESSAGE */
      message_client_set_style_tcp (mc, SMI_PORT_MSTP);
#endif /* !HAVE_TCP_MESSAGE */
      break;

    case SMI_AC_RMON_MODULE:
#ifndef HAVE_TCP_MESSAGE
  /* Use UNIX domain socket connection.  */
      message_client_set_style_domain (mc, SMI_SERV_RMON_PATH);
#else /* HAVE_TCP_MESSAGE */
      message_client_set_style_tcp (mc, SMI_PORT_RMON);
#endif /* !HAVE_TCP_MESSAGE */
      break;

    case SMI_AC_ONM_MODULE:
#ifndef HAVE_TCP_MESSAGE
  /* Use UNIX domain socket connection.  */
      message_client_set_style_domain (mc, SMI_SERV_ONM_PATH);
#else /* HAVE_TCP_MESSAGE */
      message_client_set_style_tcp (mc, SMI_PORT_ONM);
#endif /* !HAVE_TCP_MESSAGE */
      break;

    default:
      break;
  }

  /* Initiate connection using API connection manager.  */
  message_client_set_callback (mc, MESSAGE_EVENT_CONNECT,
                               smi_client_connect);
  message_client_set_callback (mc, MESSAGE_EVENT_DISCONNECT,
                               smi_client_disconnect);
  message_client_set_callback (mc, MESSAGE_EVENT_READ_MESSAGE,
                               smi_client_read_msg);

  /* Link each other.  */
  ach->mc = mc;
  mc->info = ach;

  ach->pnt = ach->buf;
  ach->pnt_in = ach->buf_in;

  return ach;
}

int
smi_client_handler_free (struct smi_client_handler *ach)
{
  THREAD_TIMER_OFF (ach->t_ipv4);
  if (ach->mc)
    message_client_delete (ach->mc);

  XFREE (MTYPE_SMICLIENT_HANDLER, ach);

  return SMI_SUCEESS;
}

/* Set service type flag.  */
int
smi_client_set_service (struct smi_client *ac, int service, int module)
{
  int type;

  if (service >= SMI_SERVICE_MAX)
    return SMI_ERR_INVALID_SERVICE;

  /* Set service bit to API client.  */
  SMI_SET_CTYPE (ac->service.bits, service);

  /* Check the service is sync or async.  */
  type = smi_service_type[service].type;

  /* Create client handler corresponding to message type.  */
  if (type == MESSAGE_TYPE_ASYNC)
    {
      if (! ac->async)
        {
          ac->async = smi_client_handler_create(ac, MESSAGE_TYPE_ASYNC, module);
          ac->async->service.version = ac->service.version;
          ac->async->service.protocol_id = ac->service.protocol_id;
        }
      SMI_SET_CTYPE (ac->async->service.bits, service);
    }

  return SMI_SUCEESS;
}

void
smi_client_set_version (struct smi_client *ac, u_int16_t version)
{
  ac->service.version = version;
}

void
smi_client_set_protocol (struct smi_client *ac, u_int32_t protocol_id)
{
  ac->service.protocol_id = protocol_id;
}

/* Register disconnect callback. */
void
smi_client_set_disconnect_callback (struct smi_client *ac,
                                    SMI_DISCONNECT_CALLBACK callback)
{
  ac->disconnect_callback = callback;
}

/* Initialize API client.  This function allocate API client
   memory.  */
int
smi_client_create (struct smiclient_globals *azg, int module)
{
  struct smi_client *tmp_ac = NULL;

  switch(module) {
    case SMI_AC_NSM_MODULE:
      tmp_ac = XCALLOC (MTYPE_SMICLIENT, sizeof (struct smi_client));
      if (!tmp_ac)
        return SMI_ERR_MEM_ALLOC;
      tmp_ac->zg = azg->smi_zg;
      azg->ac[SMI_AC_NSM_MODULE] = tmp_ac;
      break;

    case SMI_AC_LACP_MODULE:
      tmp_ac = XCALLOC (MTYPE_SMICLIENT, sizeof (struct smi_client));
      if (!tmp_ac)
          return SMI_ERR_MEM_ALLOC;
      tmp_ac->zg = azg->smi_zg;
      azg->ac[SMI_AC_LACP_MODULE] = tmp_ac;
      break;

    case SMI_AC_MSTP_MODULE:
      tmp_ac = XCALLOC (MTYPE_SMICLIENT, sizeof (struct smi_client));
      if (!tmp_ac)
        return SMI_ERR_MEM_ALLOC;
      tmp_ac->zg = azg->smi_zg;
      azg->ac[SMI_AC_MSTP_MODULE] = tmp_ac;
      break;

     case SMI_AC_RMON_MODULE:
      tmp_ac = XCALLOC (MTYPE_SMICLIENT, sizeof (struct smi_client));
      if (!tmp_ac)
        return SMI_ERR_MEM_ALLOC;
      tmp_ac->zg = azg->smi_zg;
      azg->ac[SMI_AC_RMON_MODULE] = tmp_ac;
      break;

    case SMI_AC_ONM_MODULE:
      tmp_ac = XCALLOC (MTYPE_SMICLIENT, sizeof (struct smi_client));
      if (!tmp_ac)
        return SMI_ERR_MEM_ALLOC;
      tmp_ac->zg = azg->smi_zg;
      azg->ac[SMI_AC_ONM_MODULE] = tmp_ac;
      break;

     default:
       break;
   }

  /* Set parsers. */
  smi_client_set_parser (tmp_ac, SMI_MSG_SERVICE_REPLY, smi_parse_service);

  tmp_ac->reconnect_interval = 5;
  tmp_ac->keepalive_interval = 3;
  tmp_ac->t_keepalive = 3;
  tmp_ac->debug = azg->debug;

  return SMI_SUCEESS;
}

/* Cancel pending read threads and free up the memory. */
int
smi_client_delete (struct smi_client *ac)
{
  struct listnode *node, *node_next;
  struct smi_client_handler *ach;

  if (ac)
    {
      if (ac->t_connect)
        THREAD_OFF (ac->t_connect);

      /* Cancel pending read thread. */
      if (ac->pend_read_thread)
        THREAD_OFF (ac->pend_read_thread);

      ach = ac->async;
      /* Free all pending reads. */
      if (ach)
        {
          for (node = listhead (&ach->pend_msg_list); node; node = node_next)
            {
              struct smi_client_pend_msg *pmsg = getdata (node);

              node_next = node->next;

              XFREE (MTYPE_SMI_PENDING_MSG, pmsg);
              list_delete_node (&ach->pend_msg_list, node);
            }

          smi_client_handler_free (ach);
        }

      XFREE (MTYPE_SMICLIENT, ac);
    }
  return SMI_SUCEESS;
}

/* Receive status msg */
int
smi_client_recv_status (struct smi_msg_header *header, void *arg, void *message)
{
  struct smi_client *ac;
  struct smi_client_handler *ach;
  struct smi_msg_status *msg;

  msg = (struct smi_msg_status *)message;
  ach = arg;
  ac = ach->ac;

  return SMI_SUCEESS;
}

/* Process pending message requests. */
int
smi_client_process_pending_msg (struct thread *t)
{
  struct smi_client_handler *ach;
  struct smi_client *ac;
  struct listnode *node;
  u_int16_t size;
  u_char *pnt;
  int ret;

  ach = THREAD_ARG (t);
  ac = ach->ac;

  /* Reset thread. */
  ac->pend_read_thread = NULL;

  node = listhead (&ach->pend_msg_list);
  if (node)
    {
      struct smi_client_pend_msg *pmsg = getdata (node);
      int type;

      pnt = pmsg->buf;
      size = pmsg->header.length - SMI_MSG_HEADER_SIZE;
      type = pmsg->header.type;

      ret = (*ac->parser[type]) (&pnt, &size, &pmsg->header, ach,
                                 ac->callback[type]);
      if (ret < 0)
        zlog_err ("Parse error for message %d", type);

      /* Free processed message and node. */
      XFREE (MTYPE_SMI_PENDING_MSG, pmsg);
      list_delete_node (&ach->pend_msg_list, node);
    }
  else
    return SMI_SUCEESS;

  node = listhead (&ach->pend_msg_list);
  if (node)
    {
      /* Process pending requests. */
      if (!ac->pend_read_thread)
        ac->pend_read_thread
          = thread_add_read_pend (ac->zg, smi_client_process_pending_msg, ach, 0);
    }

  return SMI_SUCEESS;
}

#if 0
/* Read synchronous message from the server. */
int
smi_client_read_sync_msg(struct smi_client_handler *ach,
                         int msgtype, void *getmsg)
{
  struct smi_msg_header header;
  struct smi_msg_status smsg;
  int ret=0, ret_type, nbytes;
  u_char *pnt;
  u_int16_t size;


  do
    {
      /* Sync wait for reply */
      nbytes = smi_client_read_sync(ach->mc, NULL, ach->mc->sock,
                                    &header, &ret_type);
      if(nbytes < 0) {
         pthread_mutex_unlock (&smi_mutex);
         return SMI_ERROR;
      }

      if((ret_type != msgtype) && (ret_type != SMI_MSG_STATUS))
        smi_client_pending_message(ach, &header);
     }
   while ((ret_type != msgtype) && (ret_type != SMI_MSG_STATUS));

  /* At here read thread may already registered as readable.
   Re-register read thread avoid hang.  */

  message_client_read_reregister (ach->mc);

  if(ret_type == SMI_MSG_STATUS)
    {
      /* Set pnt and size. */
      pnt = ach->buf_in + SMI_MSG_HEADER_SIZE;
      size = ach->size_in;
      /* Decode status msg */
      smi_decode_statusmsg (&pnt, &size, &smsg);
      ret = smsg.status_code;
    } else if(ret_type > SMI_MSG_IF_START && ret_type < SMI_MSG_IF_END)
    {
      //ret = smi_client_read_sync_if_msg(ach, ret_type, getmsg);
      ret = 0;
    }

  if(ret < 0)
  {
    pthread_mutex_unlock (&smi_mutex);
    return ret;
  }

  /* Launch event to process pending requests. */
  if (!ac->pend_read_thread)
    ac->pend_read_thread
      = thread_add_read_pend (ac->zg, smi_client_process_pending_msg, ach, 0);

  pthread_mutex_unlock (&smi_mutex);

  return SMI_SUCEESS;
}
#endif

